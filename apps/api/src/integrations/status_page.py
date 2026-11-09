"""Kleine Nederlandse statuspagina op ``GET /`` (contract §1) + koppelen met koppelcode (contract §3).

Veiligheid:
- Geen geheimen of accountnamen op de pagina; alleen koppelstatus, versie, gezondheid en totaalniveaus.
- Formulieren: CSRF-token (double-submit-cookie, SameSite=Strict) + Origin-controle; geen JavaScript; strikte CSP.
- Koppelen kan alleen als de dienst **niet** gekoppeld is. Ontkoppelen via deze pagina vereist de lokale
  ontkoppelcode die bij elke start in de app-log staat (TrueNAS → Apps → home-control-hub → Logs); zo kan alleen
  wie de NAS beheert een verloren Hub vervangen.
- Meldingen komen uit een vaste lijst (geen weerspiegelde invoer).
"""

from __future__ import annotations

import hmac
import html
import secrets
import time
from collections import deque
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import APP_ID, __version__, audit, events
from .domains import DOMAIN_TITLES_NL, DOMAINS
from .domains.sso import service as sso_service
from .errors import trace_id_for
from .health import readiness
from .security.auth import sha256_hex
from .sources import ALL_SOURCES

router = APIRouter(include_in_schema=False)

CSRF_COOKIE = "hch_csrf"
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
NOTICES = {
    "gekoppeld": ("ok", "Gekoppeld met de Hub."),
    "ontkoppeld": ("ok", "Ontkoppeld. Je kunt nu opnieuw koppelen met een nieuwe koppelcode."),
    "al_gekoppeld": (
        "fout",
        "Deze dienst is al gekoppeld. Ontkoppel eerst (met de lokale ontkoppelcode uit de app-log).",
    ),
    "niet_gekoppeld": ("fout", "Deze dienst is niet gekoppeld."),
    "ongeldig_formulier": (
        "fout",
        "Het formulier is verlopen of ongeldig. Laad de pagina opnieuw en probeer het nog eens.",
    ),
    "te_veel_pogingen": ("fout", "Te veel pogingen. Wacht een paar minuten en probeer het opnieuw."),
    "ontkoppelcode_onjuist": ("fout", "De ontkoppelcode klopt niet. Je vindt hem in de app-log van deze start."),
    "ongeldig_hub_adres": (
        "fout",
        "Het Hub-adres is ongeldig. Gebruik http(s)://<NAS-adres>:<poort> (geen localhost).",
    ),
    "hub_onbereikbaar": ("fout", "De Hub is niet bereikbaar op dit adres. Controleer het adres en of de Hub draait."),
    "hub_weigerde_code": (
        "fout",
        "De Hub weigerde de koppelcode (verlopen, al gebruikt of ongeldig). Maak een nieuwe.",
    ),
    "enroll_endpoint_ontbreekt": ("fout", "Deze Hub-versie kent het aanmeld-endpoint niet."),
    "hub_antwoord_ongeldig": ("fout", "Het antwoord van de Hub was ongeldig."),
}


def new_unpair_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(12))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


class Throttle:
    """Max. ``limit`` pogingen per ``window_s`` (in het geheugen; per proces)."""

    def __init__(self, limit: int = 10, window_s: float = 600) -> None:
        self.limit, self.window_s = limit, window_s
        self.hits: deque[float] = deque()

    def allow(self) -> bool:
        now = time.monotonic()
        while self.hits and now - self.hits[0] > self.window_s:
            self.hits.popleft()
        if len(self.hits) >= self.limit:
            return False
        self.hits.append(now)
        return True


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}

STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f6f7f9;color:#1b1f24}
main{max-width:760px;margin:0 auto;padding:16px}
h1{font-size:1.4rem;margin:.5rem 0}h2{font-size:1.1rem;margin:1.2rem 0 .5rem}
.card{background:#fff;border:1px solid #d9dde3;border-radius:8px;padding:12px 14px;margin:10px 0}
.tag{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.85rem;font-weight:600}
.ok{background:#e3f4e8;color:#14532d}.let{background:#fff4d6;color:#713f12}.fout{background:#fde2e2;color:#7f1d1d}
.onb{background:#e8eaee;color:#374151}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 4px;border-bottom:1px solid #eef0f3;
vertical-align:top}small,.muted{color:#5b6470}
label{display:block;margin:.5rem 0 .2rem;font-weight:600}input{width:100%;box-sizing:border-box;padding:8px;
border:1px solid #b8bfc8;border-radius:6px;font-size:1rem}
button{margin-top:.8rem;padding:9px 16px;border:0;border-radius:6px;background:#1d4ed8;color:#fff;font-size:1rem}
@media (prefers-color-scheme: dark){body{background:#111418;color:#e6e8eb}.card{background:#1a1e24;border-color:#2c323b}
td,th{border-color:#262b33}small,.muted{color:#9aa3ad}input{background:#0f1216;color:#e6e8eb;border-color:#3a414b}}
"""


def _tag(status: str) -> str:
    cls = {
        "ok": "ok",
        "gekoppeld": "ok",
        "healthy": "ok",
        "ready": "ok",
        "risico": "let",
        "degraded": "let",
        "koppelen_mislukt": "fout",
        "down": "fout",
        "fout": "fout",
    }.get(status, "onb")
    label = {
        "healthy": "gezond",
        "degraded": "beperkt",
        "down": "storing",
        "unknown": "onbekend",
        "niet_gekoppeld": "niet gekoppeld",
        "koppelen_mislukt": "koppelen mislukt",
        "ready": "klaar",
        "not_ready": "niet klaar",
    }.get(status, status)
    return f'<span class="tag {cls}">{html.escape(label)}</span>'


def _csrf_token(request: Request) -> str:
    tok = request.cookies.get(CSRF_COOKIE)
    if tok and 20 <= len(tok) <= 100:
        return tok
    return secrets.token_urlsafe(24)


def _with_headers(resp: Response, csrf: str | None = None) -> Response:
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    if csrf is not None:
        resp.set_cookie(CSRF_COOKIE, csrf, httponly=True, samesite="strict", path="/", max_age=3600)
    return resp


def _form_ok(request: Request, token: str) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie or not token or not hmac.compare_digest(cookie, token):
        return False
    origin = request.headers.get("origin")
    if origin and origin != "null":
        host = request.headers.get("host", "")
        if urlsplit(origin).netloc != host:
            return False
    return True


def _redirect(notice: str) -> Response:
    return _with_headers(RedirectResponse(f"/?melding={notice}", status_code=303))


@router.get("/", response_class=HTMLResponse)
def status_page(request: Request, melding: str | None = None) -> Response:
    state = request.app.state
    csrf = _csrf_token(request)
    ready, checks = readiness(request)
    link: dict[str, Any] = {"status": "onbekend", "message_nl": "Database niet bereikbaar."}
    readiness_level = None
    configured = 0
    if state.db.ping():
        with state.db.sessions() as s:
            link = state.enrollment.public_state(s)
            try:
                readiness_level = sso_service.overall(s, state.settings.break_glass_test_max_age_days)
            except Exception:
                readiness_level = None
            from .models import IntegrationSource

            configured = sum(1 for r in s.query(IntegrationSource).all() if r.enabled and r.base_url)

    parts: list[str] = []
    if melding in NOTICES:
        cls, text = NOTICES[melding]
        parts.append(
            f'<div class="card"><span class="tag {cls}">{"Gelukt" if cls == "ok" else "Let op"}</span> '
            f"{html.escape(text)}</div>"
        )
    parts.append(
        '<div class="card"><table>'
        f"<tr><th>Dienst</th><td>{APP_ID} · versie {html.escape(__version__)}</td></tr>"
        f"<tr><th>Gereed</th><td>{_tag('ready' if ready else 'not_ready')} "
        + " ".join(f"<small>{html.escape(c['name'])}: {html.escape(c['status'])}</small>" for c in checks)
        + "</td></tr>"
        f"<tr><th>Koppeling met de Hub</th><td>{_tag(str(link.get('status')))}<br><small>"
        f"{html.escape(str(link.get('message_nl') or ''))}</small>"
        + (
            f"<br><small>Hub: {html.escape(str(link.get('hub_url')))} · sinds {html.escape(str(link.get('enrolled_at')))}"
            f" · token …{html.escape(str(link.get('service_token_last4') or ''))}</small>"
            if link.get("status") == "gekoppeld"
            else ""
        )
        + "</td></tr></table></div>"
    )
    if readiness_level is not None:
        lvl = readiness_level["level"]
        reasons = ", ".join(r["code"] for r in readiness_level["reasons"]) or "geen"
        parts.append(
            '<div class="card"><h2>Beheerherstel (B13-001)</h2>'
            f"<p>{_tag(lvl)} <small>{readiness_level['counts']['accounts']} beheeraccount(s) geregistreerd · "
            f"aandachtspunten: {html.escape(reasons)}</small></p>"
            '<p class="muted">Details en oefeningen staan in de Hub (alleen voor beheerders). '
            "Noodtoegang is niet afhankelijk van Authentik.</p></div>"
        )
    rows = "".join(
        f"<tr><td>{html.escape(DOMAIN_TITLES_NL[d])}</td><td>"
        f"{sum(1 for s in ALL_SOURCES.values() if s.domain == d)} bron(nen) in de inventaris</td></tr>"
        for d in DOMAINS
    )
    parts.append(
        '<div class="card"><h2>Integraties</h2>'
        f"<p>{_tag('unknown') if configured == 0 else ''} <small>{configured} bron(nen) geconfigureerd. "
        "Niet-geconfigureerde bronnen tonen 'onbekend', nooit 'gezond'.</small></p>"
        f"<table>{rows}</table></div>"
    )
    if link.get("status") != "gekoppeld":
        parts.append(
            '<div class="card"><h2>Koppelen met de Hub</h2>'
            '<p class="muted">Maak in de Hub een koppelcode voor <b>home-control-hub</b> en vul die hier in. '
            "Gebruik het LAN-adres van de NAS met de poort van de Hub (bijv. de poort uit het Custom App-formulier).</p>"
            '<form method="post" action="/koppelen" autocomplete="off">'
            f'<input type="hidden" name="csrf" value="{html.escape(csrf)}">'
            '<label for="hub_url">Hub-adres</label>'
            '<input id="hub_url" name="hub_url" type="url" required placeholder="http://&lt;NAS-adres&gt;:&lt;poort&gt;">'
            '<label for="code">Koppelcode</label>'
            '<input id="code" name="code" required maxlength="128" autocomplete="one-time-code">'
            '<button type="submit">Koppelen</button></form></div>'
        )
    else:
        parts.append(
            '<div class="card"><h2>Ontkoppelen</h2>'
            '<p class="muted">Alleen nodig als de Hub opnieuw is geïnstalleerd. Vul de lokale ontkoppelcode in uit de '
            "app-log van deze start (TrueNAS → Apps → home-control-hub → Logs).</p>"
            '<form method="post" action="/ontkoppelen" autocomplete="off">'
            f'<input type="hidden" name="csrf" value="{html.escape(csrf)}">'
            '<label for="unpair">Lokale ontkoppelcode</label>'
            '<input id="unpair" name="unpair_code" required maxlength="20">'
            '<button type="submit">Ontkoppelen</button></form></div>'
        )
    body = (
        '<!doctype html><html lang="nl"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Home Control Hub</title><style>{STYLE}</style></head><body><main>"
        "<h1>Home Control Hub</h1>"
        '<p class="muted">Integratiedienst van het TrueNAS Home Platform (netwerk, automatisering, toegang, energie). '
        "Alle schermen staan in de Hub; dit is alleen de statuspagina.</p>" + "".join(parts) + "</main></body></html>"
    )
    return _with_headers(HTMLResponse(body), csrf)


@router.post("/koppelen")
def pair(request: Request, csrf: str = Form(""), hub_url: str = Form(""), code: str = Form("")) -> Response:
    state = request.app.state
    if not _form_ok(request, csrf):
        return _redirect("ongeldig_formulier")
    if not state.pair_throttle.allow():
        return _redirect("te_veel_pogingen")
    with state.db.sessions() as s:
        if state.enrollment.state(s).get("status") == "gekoppeld":
            return _redirect("al_gekoppeld")
        outcome = state.enrollment.enroll_with_code(s, hub_url[:500], code[:128])
        tid = trace_id_for(request)
        audit.record(
            s,
            domain="sso",
            action="hub.pair" if outcome.ok else "hub.pair_failed",
            entity_type="hub_link",
            entity_id="hub",
            principal=None,
            trace_id=tid,
            actor_override=("user", "statuspagina"),
            message_nl=outcome.message_nl,
            details={"reason": outcome.reason},
        )
        if outcome.ok:
            events.emit(
                s,
                event_type="service.hub_link.paired",
                entity_type="hub_link",
                entity_id="hub",
                actor_type="user",
                actor_id="statuspagina",
                trace_id=tid,
                payload={"via": "koppelcode"},
            )
        s.commit()
    state.link.invalidate()
    return _redirect("gekoppeld" if outcome.ok else outcome.reason if outcome.reason in NOTICES else "hub_onbereikbaar")


@router.post("/ontkoppelen")
def unpair(request: Request, csrf: str = Form(""), unpair_code: str = Form("")) -> Response:
    state = request.app.state
    if not _form_ok(request, csrf):
        return _redirect("ongeldig_formulier")
    if not state.pair_throttle.allow():
        return _redirect("te_veel_pogingen")
    given = unpair_code.strip().upper()
    if not hmac.compare_digest(sha256_hex(given), state.unpair_code_sha256):
        return _redirect("ontkoppelcode_onjuist")
    with state.db.sessions() as s:
        if state.enrollment.state(s).get("status") != "gekoppeld":
            return _redirect("niet_gekoppeld")
        state.enrollment.unpair(s)
        tid = trace_id_for(request)
        audit.record(
            s,
            domain="sso",
            action="hub.unpair",
            entity_type="hub_link",
            entity_id="hub",
            principal=None,
            trace_id=tid,
            actor_override=("user", "statuspagina+ontkoppelcode"),
            message_nl="Ontkoppeld via de statuspagina met de lokale ontkoppelcode.",
        )
        s.commit()
    state.link.invalidate()
    return _redirect("ontkoppeld")
