"""Integratie (PostgreSQL, Hub-simulator): ``GET /`` en ``POST /koppelen`` in Peil 1.1.1 (HC11, contract 1.3 §3.7,
ONTWERPTAAL §13.2) per toestand — niet gekoppeld, koppelen mislukt, gekoppeld, ingetrokken, ontkoppeld, niet gereed en
onleesbaar — met HTTP-status, vaste code en de trace-ID van het verzoek. Sim-getest."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from integrations import peil
from integrations.models import AuditEvent
from tests.conftest import HUB_URL, PAIR_CODE, FakeHub, idem

pytestmark = pytest.mark.integration

CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"


def _csrf(client: Any) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', client.get("/").text)
    assert m, "geen koppelformulier"
    return m.group(1)


def _koppel(client: Any, csrf: str, **velden: str) -> Any:
    data = {"csrf": csrf, "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": "", **velden}
    return client.post("/koppelen", data=data, follow_redirects=False)


def _code(r: Any) -> str:
    m = re.search(r"Code <code>([a-z_]+)</code>", r.text)
    assert m, r.text[:300]
    return m.group(1)


def _trace(r: Any) -> str:
    m = re.search(r'<code class="selecteer">([0-9a-f-]{36})</code>', r.text)
    assert m
    return m.group(1)


def _totaal(html: str) -> tuple[str, str]:
    m = re.search(r'<p class="totaal"><span class="pil pil-(\w+)">.*?</svg>([^<]+)</span>', html)
    assert m
    return m.group(1), m.group(2)


def _gereed(html: str) -> str:
    m = re.search(r"<dt>Gereed</dt><dd>([^<]+)</dd>", html)
    assert m
    return m.group(1)


def _zichtbaar(html: str) -> str:
    return re.sub(r"<!--.*?-->", "", html, flags=re.S)


def _veiligheid(r: Any) -> None:
    assert r.headers["content-security-policy"] == CSP
    assert r.headers["x-frame-options"] == "DENY" and r.headers["cache-control"] == "no-store"
    assert r.headers["content-type"].startswith("text/html") and "<script" not in r.text.lower()
    assert r.text.startswith("<!doctype html>\n<!-- Peil statuspagina-sjabloon 1.1.1 · sha256:")
    assert r.headers["referrer-policy"] == "same-origin"  # contract 1.3 §3.7 punt 1 (nooit no-referrer)


# ------------------------------------------------------------------ niet gekoppeld
def test_not_linked(client: Any) -> None:
    r = client.get("/")
    assert r.status_code == 200
    _veiligheid(r)
    html = r.text
    assert "<title>Home Control Hub — niet gekoppeld, niet gereed</title>" in html
    assert _totaal(html) == ("onbekend", "Niet gereed") and _gereed(html) == "Nee — wacht op koppeling met de Hub"
    for naam in ("csrf", "hub_adres", "koppelcode", "hub_vingerafdruk"):
        assert f'name="{naam}"' in html
    assert "Geldig 60 minuten, één keer te gebruiken." in html and "Vingerafdruk van de Hub" in html
    assert "ontkoppelcode" not in html.lower() and 'action="/ontkoppelen"' not in html
    assert r.cookies.get("hch_csrf") and "samesite=strict" in r.headers["set-cookie"].lower()
    assert "httponly" in r.headers["set-cookie"].lower()


# ------------------------------------------------------------------ koppelen mislukt
def test_failed_pairing_shows_code_trace_id_and_field_error(
    client: Any, fake_hub: FakeHub, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="integrations.statuspagina")
    csrf = _csrf(client)
    r = _koppel(client, csrf, koppelcode="AAAA-BBBB-CCCC", hub_vingerafdruk=fake_hub.fingerprint())
    assert r.status_code == 400
    _veiligheid(r)
    tid = _trace(r)
    assert _code(r) == "hub_weigerde" and tid == r.headers["x-trace-id"]
    assert "<title>Home Control Hub — niet gekoppeld (koppelen mislukt)</title>" in r.text
    assert '<p id="melding-titel"><strong>Koppelen is mislukt</strong></p>' in r.text
    assert re.search(r'<input id="koppelcode"[^>]*aria-invalid="true"', r.text)
    assert (
        '<a class="spring" href="#koppelcode">' in r.text
        and '<a href="#koppelcode">Naar het veld Koppelcode</a>' in r.text
    )
    # ingevulde waarden worden nooit teruggetoond; het formulier blijft (de dienst is nog nooit gekoppeld)
    assert "AAAA-BBBB-CCCC" not in r.text and fake_hub.fingerprint() not in r.text and "hub.test" not in r.text
    assert 'action="/koppelen"' in r.text and _totaal(r.text)[0] != "gezond"
    assert re.search(r'<div class="melding melding-fout" role="alert"', r.text)  # fout van dít verzoek (E05)
    # de trace-ID is terug te vinden in de log (precies één regel per poging, §3.7) en in het auditspoor
    regels = [rec.getMessage() for rec in caplog.records if tid in rec.getMessage()]
    assert len(regels) == 1 and "code=hub_weigerde" in regels[0] and "hub.test" not in regels[0]
    with client.app.state.db.sessions() as s:
        rij = s.scalars(select(AuditEvent).where(AuditEvent.action == "hub.pair_failed")).one()
        assert str(rij.trace_id) == tid


@pytest.mark.parametrize(
    ("velden", "status", "code", "veld"),
    [
        ({"hub_adres": "http://localhost:30400"}, 422, "ongeldig_hub_adres", "hub"),
        ({"koppelcode": "KORT"}, 422, "ongeldige_koppelcode", "koppelcode"),
        ({"hub_vingerafdruk": ""}, 422, "ongeldige_vingerafdruk", "vingerafdruk"),
        ({"hub_vingerafdruk": "0000-0000-0000-0000"}, 400, "hub_vingerafdruk_onjuist", "vingerafdruk"),
    ],
)
def test_input_and_fingerprint_errors(
    client: Any, fake_hub: FakeHub, velden: dict[str, str], status: int, code: str, veld: str
) -> None:
    csrf = _csrf(client)
    if "hub_vingerafdruk" not in velden:
        velden = {**velden, "hub_vingerafdruk": fake_hub.fingerprint()}
    r = _koppel(client, csrf, **velden)
    assert (r.status_code, _code(r)) == (status, code)
    assert re.search(rf'<input id="{veld}"[^>]*aria-invalid="true"', r.text)
    assert r.text.count('aria-invalid="true"') == 1 and _trace(r) == r.headers["x-trace-id"]
    if status == 422:
        assert fake_hub.enroll_requests == []  # ongeldige invoer: niets naar de Hub
    st = client.app.state.hublink.state()
    assert st.state == "nooit_gekoppeld" and st.hub_url is None  # het adres van een mislukte poging wordt niet bewaard


def test_form_and_rate_limit_refusals(client: Any, fake_hub: FakeHub) -> None:
    csrf = _csrf(client)
    r = _koppel(client, "verkeerd", hub_vingerafdruk=fake_hub.fingerprint())
    assert (r.status_code, _code(r)) == (403, "ongeldig_formulier")
    r = client.post(
        "/koppelen",
        data={"csrf": csrf, "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": fake_hub.fingerprint()},
        headers={"Origin": "http://kwaadaardig.example"},
        follow_redirects=False,
    )
    assert (r.status_code, _code(r)) == (403, "herkomst_onjuist")
    # geweigerd op herkomst telt niet als poging: hieronder nog vijf pogingen tot de grens
    fake_hub.sim.max_failures = 1000
    codes = [
        _koppel(client, csrf, koppelcode="AAAA-BBBB-CCCC", hub_vingerafdruk="0000-0000-0000-0000") for _ in range(6)
    ]
    assert [r.status_code for r in codes] == [400] * 5 + [429]
    assert _code(codes[-1]) == "te_veel_pogingen" and codes[-1].headers["retry-after"] == "900"


def test_hub_unreachable_and_hub_rate_limit(client: Any, fake_hub: FakeHub) -> None:
    import time as _time

    csrf = _csrf(client)
    fake_hub.up = False
    r = _koppel(client, csrf, hub_vingerafdruk=fake_hub.fingerprint())
    assert (r.status_code, _code(r)) == (502, "hub_onbereikbaar") and "Controleer het adres en de poort" in r.text
    fake_hub.up = True
    fake_hub.sim.failures[fake_hub.client_ip] = [_time.time()] * 10
    r = _koppel(client, csrf, hub_vingerafdruk=fake_hub.fingerprint())
    assert (r.status_code, _code(r)) == (429, "rate_limited") and "te veel mislukte pogingen" in r.text


# ------------------------------------------------------------------ gekoppeld
def test_successful_pairing_then_linked_page(client: Any, fake_hub: FakeHub) -> None:
    csrf = _csrf(client)
    r = _koppel(client, csrf, hub_vingerafdruk=fake_hub.fingerprint())
    assert r.status_code == 303 and re.fullmatch(r"/\?melding=[A-Za-z0-9_-]{16,64}", r.headers["location"])
    r = client.get(r.headers["location"])
    _veiligheid(r)
    html = r.text
    assert "<title>Home Control Hub — gekoppeld, alles gezond</title>" in html
    assert _totaal(html) == ("gezond", "Alles gezond") and _gereed(html) == "Ja"
    assert '<p id="melding-titel"><strong>Gekoppeld met de Hub</strong></p>' in html and "melding-info" in html
    assert 'class="melding melding-info" role="status"' in html  # info na dít verzoek (Peil 1.1.1, E05)
    assert (
        '<span class="pil pil-neutraal"><svg aria-hidden="true"><use href="#i-gekoppeld"/></svg>Gekoppeld</span>'
        in html
    )
    assert fake_hub.fingerprint() in html and f'<a class="knop knop-secundair" href="{HUB_URL}">Hub openen</a>' in html
    assert "Ontkoppelen of opnieuw koppelen gaat via de Hub" in html
    assert 'action="/koppelen"' not in html and "Koppelcode" not in _zichtbaar(html)
    token = client.app.state.hublink.state().service_token
    assert token and token not in html
    # na de eerste koppeling: koppelen via de pagina wordt geweigerd zonder verzoek naar de Hub
    before = len(fake_hub.enroll_requests)
    r = _koppel(client, csrf, koppelcode=fake_hub.sim.new_pairing_code(), hub_vingerafdruk=fake_hub.fingerprint())
    assert (r.status_code, _code(r)) == (409, "al_gekoppeld") and len(fake_hub.enroll_requests) == before
    assert 'aria-invalid="true"' not in r.text


def test_success_notice_never_contradicts_link_state(client: Any) -> None:
    html = client.get("/?melding=gekoppeld").text
    assert "Gekoppeld met de Hub</strong>" not in html and 'class="melding' not in html
    assert "<script>" not in client.get("/?melding=<script>alert(1)</script>").text


# ------------------------------------------------------------------ ingetrokken en ontkoppeld
def test_revoked(paired_client: Any, fake_hub: FakeHub) -> None:
    c = paired_client
    fake_hub.sim.revoke()
    assert c.app.state.hublink.confirm(trace_id="00000000-0000-4000-8000-000000000001") is False
    r = c.get("/")
    _veiligheid(r)
    assert "<title>Home Control Hub — ingetrokken, niet gereed</title>" in r.text
    assert '<use href="#i-niet-gekoppeld"/></svg>Ingetrokken</span>' in r.text
    assert _totaal(r.text) == ("onbekend", "Niet gereed")
    assert _gereed(r.text) == "Nee — de Hub heeft de koppeling ingetrokken"
    assert 'action="/koppelen"' not in r.text and "Opnieuw koppelen gaat via de Hub" in r.text


def test_unlinked(paired_client: Any, fake_hub: FakeHub) -> None:
    c = paired_client
    assert c.post("/connector/v1/hub-link/unlink", headers=idem(fake_hub.service_auth())).status_code == 200
    r = c.get("/")
    assert '<use href="#i-niet-gekoppeld"/></svg>Ontkoppeld</span>' in r.text
    assert _totaal(r.text) == ("onbekend", "Niet gereed") and 'action="/koppelen"' not in r.text


# ------------------------------------------------------------------ niet gereed en onleesbaar
def test_database_down_is_not_ready(app_factory: Any) -> None:
    c = app_factory(database_url="postgresql+psycopg://postgres@127.0.0.1:1/hch_onbereikbaar?connect_timeout=2")
    r = c.get("/")
    assert r.status_code == 200
    _veiligheid(r)
    assert _totaal(r.text) == ("storing", "Niet gereed")
    assert _gereed(r.text).startswith("Nee — de eigen database antwoordt niet")
    assert "<title>Home Control Hub — niet gekoppeld, niet gereed</title>" in r.text
    assert "Niet te meten: de eigen database antwoordt niet." in r.text


def test_unreadable_link_file(client: Any, data_dir: Path) -> None:
    (data_dir / "secrets" / "hub-link.json").write_text("geen json", encoding="utf-8")
    r = client.get("/")
    assert r.status_code == 200 and _code(r) == "koppelstatus_onleesbaar"
    # Peil 1.1.1 (E01/E05/E06): een toestand die bij het laden al bestond: geen live-regio en geen trace-ID, wel de
    # code en het pad van het bestand; het koppelblok zegt "Onleesbaar" en toont geen formulier
    assert 'class="selecteer"' not in r.text and 'role="alert"' not in r.text
    assert "<p><code>/appdata/secrets/hub-link.json</code></p>" in r.text
    assert '<use href="#i-storing"/></svg>Onleesbaar</span>' in r.text and "Hier staat bewust geen formulier." in r.text
    assert _totaal(r.text) == ("storing", "Niet gereed") and 'action="/koppelen"' not in r.text


def test_missing_template_gives_plain_error(client: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(peil, "kandidaten", lambda _dir: [tmp_path / "bestaat-niet.html"])
    r = client.get("/")
    assert r.status_code == 503 and r.headers["content-type"].startswith("text/plain")
    assert "statuspagina_sjabloon_ontbreekt" in r.text and r.headers["x-trace-id"] in r.text
    assert r.headers["content-security-policy"] == CSP
