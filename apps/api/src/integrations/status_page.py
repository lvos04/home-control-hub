"""Kleine Nederlandse statuspagina op ``GET /`` (contract §1) + koppelen met koppelcode (contract 1.2 §3.7).

Veiligheid:
- Geen geheimen, accountnamen, aantallen of aandachtspunten op de pagina; alleen de witte lijst van de koppelstatus
  (§3.5), versie, gezondheid en totaalniveaus.
- Het koppelformulier bestaat **alleen zolang de dienst nog nooit gekoppeld is** (``first_linked_at`` leeg). Daarna:
  alleen de status en "ontkoppelen of opnieuw koppelen gaat via de Hub". Er is geen ontkoppelen, geen lokale
  ontkoppelcode en geen herkoppelen na intrekking op deze pagina.
- Velden: Hub-adres (zelfde regels als ``HUB_URL``), koppelcode en de verplichte Hub-vingerafdruk.
- Formulieren: CSRF-token (double-submit-cookie, SameSite=Strict, HttpOnly) + ``Origin``-controle; geen JavaScript;
  strikte CSP. Rate-limit: max. 5 pogingen per 15 min per bron-IP (adres van de TCP-verbinding; ``X-Forwarded-For``
  wordt nooit gebruikt) én max. 20 per 15 min voor de hele dienst; overschrijding → vaste melding, geen verzoek naar
  de Hub. De teller staat in het geheugen: de image draait precies één API-proces (§3.7).
- Meldingen komen uit een vaste lijst (geen weerspiegelde invoer); het Hub-adres van een mislukte poging wordt
  nergens bewaard.
"""

from __future__ import annotations

import hmac
import html
import secrets
import threading
import time
from collections import deque
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from . import APP_ID, __version__, audit
from .domains import DOMAIN_TITLES_NL, DOMAINS
from .domains.sso import service as sso_service
from .errors import trace_id_for
from .health import readiness
from .hublink_store import ERROR_MESSAGES
from .sources import ALL_SOURCES

router = APIRouter(include_in_schema=False)

CSRF_COOKIE = "hch_csrf"
VIA_HUB_NL = "Ontkoppelen of opnieuw koppelen gaat via de Hub."
NOTICES: dict[str, tuple[str, str]] = {
    "gekoppeld": ("ok", "Gekoppeld met de Hub. Vergelijk de sleutelset-vingerafdruk hieronder met die in de Hub."),
    "al_gekoppeld": (
        "fout",
        "Koppelen via deze pagina kan alleen zolang de dienst nog nooit gekoppeld is. " + VIA_HUB_NL,
    ),
    "koppelen_bezig": ("fout", "Er loopt al een koppelpoging. Wacht even en laad de pagina opnieuw."),
    "ongeldig_formulier": (
        "fout",
        "Het formulier is verlopen of ongeldig. Laad de pagina opnieuw en probeer het nog eens.",
    ),
    "te_veel_pogingen": ("fout", "Te veel pogingen. Wacht een kwartier en probeer het opnieuw."),
    "ongeldig_hub_adres": (
        "fout",
        "Het Hub-adres is ongeldig. Gebruik http(s)://<NAS-adres>:<poort> zonder pad (geen localhost).",
    ),
    "ongeldige_koppelcode": ("fout", "De koppelcode moet 12 tekens zijn (XXXX-XXXX-XXXX), zoals de Hub hem toont."),
    "ongeldige_vingerafdruk": (
        "fout",
        "De Hub-vingerafdruk moet 16 tekens zijn (XXXX-XXXX-XXXX-XXXX), zoals de Hub hem naast de koppelcode toont.",
    ),
    "database_onbereikbaar": ("fout", "De eigen database is nu niet bereikbaar; probeer het over een minuut opnieuw."),
    **{code: ("fout", text) for code, text in ERROR_MESSAGES.items()},
}
STATE_LABELS = {
    "nooit_gekoppeld": ("onb", "nooit gekoppeld"),
    "gekoppeld": ("ok", "gekoppeld"),
    "ontkoppeld": ("let", "ontkoppeld"),
    "ingetrokken": ("fout", "ingetrokken"),
}
STATE_HELP = {
    "nooit_gekoppeld": "Niet gekoppeld: maak in de Hub een koppelcode voor home-control-hub en vul die hieronder in, "
    "of laat het platform de dienst met een eenmalig token installeren.",
    "gekoppeld": "Gekoppeld met de Hub. " + VIA_HUB_NL,
    "ontkoppeld": "Niet gekoppeld: de koppeling met de Hub is verwijderd. " + VIA_HUB_NL,
    "ingetrokken": "Ingetrokken door de Hub: deze dienst weigert alle Hub-aanroepen. Opnieuw koppelen gaat via de Hub.",
}


class PairThrottle:
    """Max. ``per_ip`` pogingen per bron-IP en ``total`` pogingen voor de hele dienst per ``window_s`` (§3.7)."""

    def __init__(self, per_ip: int = 5, total: int = 20, window_s: float = 900) -> None:
        self.per_ip, self.total, self.window_s = per_ip, total, window_s
        self.hits: deque[tuple[float, str]] = deque()
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            while self.hits and now - self.hits[0][0] > self.window_s:
                self.hits.popleft()
            if len(self.hits) >= self.total or sum(1 for _, h in self.hits if h == ip) >= self.per_ip:
                return False
            self.hits.append((now, ip))
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
    if status in STATE_LABELS:
        cls, label = STATE_LABELS[status]
        return f'<span class="tag {cls}">{html.escape(label)}</span>'
    cls = {
        "ok": "ok",
        "healthy": "ok",
        "ready": "ok",
        "risico": "let",
        "degraded": "let",
        "down": "fout",
        "fout": "fout",
    }.get(status, "onb")
    label = {
        "healthy": "gezond",
        "degraded": "beperkt",
        "down": "storing",
        "unknown": "onbekend",
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


def _link_rows(link: dict[str, Any]) -> str:
    rows: list[tuple[str, str]] = []
    if link.get("koppelen_bezig"):
        rows.append(("Koppelen", "bezig"))
    for key, label in (
        ("hub_url", "Hub-adres"),
        ("service_id", "Dienst-ID in de Hub"),
        ("via", "Gekoppeld via"),
        ("first_linked_at", "Eerste koppeling"),
        ("linked_at", "Laatst gekoppeld"),
        ("keyset_fingerprint", "Sleutelset-vingerafdruk van de Hub"),
    ):
        if link.get(key):
            rows.append((label, str(link[key])))
    if link.get("service_token_last4"):
        rows.append(("Service-token", "…" + str(link["service_token_last4"])))
    err = link.get("last_error")
    if isinstance(err, dict) and err.get("message"):
        rows.append(("Laatste melding", str(err["message"])))
    return "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in rows)


@router.get("/", response_class=HTMLResponse)
def status_page(request: Request, melding: str | None = None) -> Response:
    state = request.app.state
    csrf = _csrf_token(request)
    ready, checks = readiness(request)
    current = state.hublink.state()
    link = current.public()
    readiness_level = None
    configured = 0
    if state.db.ping():
        with state.db.sessions() as s:
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
    help_nl = (
        "Koppelstatus onleesbaar; de dienst vertrouwt niets van de Hub. " + VIA_HUB_NL
        if current.corrupt
        else (STATE_HELP.get(current.state, ""))
    )
    parts.append(
        '<div class="card"><table>'
        f"<tr><th>Dienst</th><td>{APP_ID} · versie {html.escape(__version__)}</td></tr>"
        f"<tr><th>Gereed</th><td>{_tag('ready' if ready else 'not_ready')} "
        + " ".join(f"<small>{html.escape(c['name'])}: {html.escape(c['status'])}</small>" for c in checks)
        + "</td></tr>"
        f"<tr><th>Koppeling met de Hub</th><td>{_tag(current.state)}<br><small>{html.escape(help_nl)}</small></td></tr>"
        + _link_rows(link)
        + "</table></div>"
    )
    if readiness_level is not None:
        # alleen het totaalniveau: aantallen en aandachtspunten (bv. 'geen noodaccount') zijn beveiligingsinformatie
        # en blijven achter de beheerdersrol in de Hub
        parts.append(
            '<div class="card"><h2>Beheerherstel (B13-001)</h2>'
            f"<p>{_tag(readiness_level['level'])}</p>"
            '<p class="muted">Details en oefeningen staan in de Hub (alleen voor beheerders). '
            "De noodlogin zelf zit in de Hub en hangt niet van deze dienst of van Authentik af.</p></div>"
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
    if not current.ever_linked and current.pending is None:
        parts.append(
            '<div class="card"><h2>Koppelen met de Hub</h2>'
            '<p class="muted">Kan alleen zolang deze dienst nog nooit gekoppeld is. Maak in de Hub een koppelcode voor '
            "<b>home-control-hub</b>; de Hub toont daarnaast de sleutelset-vingerafdruk. Vul beide hier in, met het "
            "LAN-adres van de NAS en de poort van de Hub. Aanbevolen is installeren via de Hub (eenmalig token).</p>"
            '<form method="post" action="/koppelen" autocomplete="off">'
            f'<input type="hidden" name="csrf" value="{html.escape(csrf)}">'
            '<label for="hub_url">Hub-adres</label>'
            '<input id="hub_url" name="hub_url" type="url" required maxlength="500" '
            'placeholder="http://&lt;NAS-adres&gt;:&lt;poort&gt;">'
            '<label for="code">Koppelcode</label>'
            '<input id="code" name="code" required maxlength="32" autocomplete="one-time-code" '
            'placeholder="XXXX-XXXX-XXXX">'
            '<label for="fingerprint">Hub-vingerafdruk</label>'
            '<input id="fingerprint" name="fingerprint" required maxlength="64" placeholder="XXXX-XXXX-XXXX-XXXX">'
            '<button type="submit">Koppelen</button></form></div>'
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
def pair(
    request: Request,
    csrf: str = Form(""),
    hub_url: str = Form(""),
    code: str = Form(""),
    fingerprint: str = Form(""),
) -> Response:
    state = request.app.state
    if not _form_ok(request, csrf):
        return _redirect("ongeldig_formulier")
    if state.hublink.state().ever_linked:
        return _redirect("al_gekoppeld")  # geen poging, telt niet mee
    ip = request.client.host if request.client else "onbekend"  # TCP-bron; nooit X-Forwarded-For (§3.7)
    if not state.pair_throttle.allow(ip):
        return _redirect("te_veel_pogingen")
    tid = trace_id_for(request)
    outcome = state.hublink.pair_with_code(
        hub_url=hub_url[:500], pairing_code=code[:64], fingerprint=fingerprint[:64], trace_id=tid
    )
    if not outcome.ok and state.db.ping():
        with state.db.sessions() as s:
            audit.record(
                s,
                domain="hub_link",
                action="hub.pair_failed",
                entity_type="hub_link",
                entity_id="hub",
                principal=None,
                trace_id=tid,
                actor_override=("user", "statuspagina"),
                message_nl="Koppelen via de statuspagina mislukt.",
                details={"code": outcome.code},
            )
            s.commit()
    notice = "gekoppeld" if outcome.ok else str(outcome.code)
    return _redirect(notice if notice in NOTICES else "hub_onbereikbaar")
