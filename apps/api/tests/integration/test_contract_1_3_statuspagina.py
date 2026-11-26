"""Integratie (PostgreSQL, Hub-simulator): het koppelformulier volgens contract 1.3 §3.7 (C1.3-HCH-01, C1.3-HCH-02).

- Herkomst: ``Origin`` exact ``<schema>://<Host>`` (ontbreekt of ``null`` → 403), ``Sec-Fetch-Site`` alleen
  ``same-origin``/``none``, de ``Host``-beperking tegen DNS-rebinding (403 ``host_niet_toegestaan``) en het
  formuliercookie. Een geweigerd verzoek gaat niet naar de Hub, verandert niets en telt niet als poging.
- Pogingen: elke POST die de herkomst doorstaat telt, ook bij ongeldige invoer, een lopende poging, een onleesbaar
  koppelbestand of een al gekoppelde dienst (RV7); invoer nooit eerst afkappen; één logregel per POST.
- Meldingen alleen bij een echte, recente poging van deze browser.

De browserversie van dezelfde negatieve gevallen (Chromium tegen de echte dienst) staat in ``tests/ui/herkomst.mjs``.
Sim-getest; geen echte Hub of NAS."""

from __future__ import annotations

import logging
import re
import stat
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from integrations.hublink_store import LinkState, Pending
from integrations.status_page import PairThrottle
from tests import netwerk
from tests.conftest import BROWSER_HEADERS, HUB_URL, PAIR_CODE, FakeHub, acl_dataset

pytestmark = pytest.mark.integration


def _csrf(client: Any) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', client.get("/").text)
    assert m, "geen koppelformulier op de statuspagina"
    return m.group(1)


def _code(r: Any) -> str:
    if r.status_code == 303:
        return "gekoppeld"
    m = re.search(r"Code <code>([a-z_]+)</code>", r.text)
    assert m and r.status_code >= 400, (r.status_code, r.text[:200])
    return m.group(1)


def _post(client: Any, csrf: str, fake_hub: FakeHub, headers: dict[str, str] | None = None, **velden: str) -> Any:
    data = {"csrf": csrf, "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": fake_hub.fingerprint()}
    data.update(velden)
    return client.post("/koppelen", data=data, headers=headers or {}, follow_redirects=False)


def _kaal(client: Any) -> TestClient:
    """Dezelfde app zonder de browserheaders van de fixture (om een ontbrekende Origin te testen)."""
    c = TestClient(client.app)
    c.cookies.update(client.cookies)
    return c


# ------------------------------------------------------------------ herkomst (§3.7 punt 1–5)
@pytest.mark.parametrize(
    ("headers", "code"),
    [
        ({"Origin": "null"}, "herkomst_onjuist"),
        ({"Origin": "http://kwaadaardig.example"}, "herkomst_onjuist"),
        ({"Origin": "https://testserver"}, "herkomst_onjuist"),  # ander schema
        ({"Origin": "http://testserver:8080"}, "herkomst_onjuist"),  # andere poort
        ({"Sec-Fetch-Site": "same-site"}, "herkomst_onjuist"),  # andere app op hetzelfde NAS-adres
        ({"Sec-Fetch-Site": "cross-site"}, "herkomst_onjuist"),
        ({"Host": "nas.voorbeeld.nl:30420", "Origin": "http://nas.voorbeeld.nl:30420"}, "host_niet_toegestaan"),
        ({"Host": "127.1:30420", "Origin": "http://127.1:30420"}, "host_niet_toegestaan"),
    ],
)
def test_origin_sec_fetch_site_and_host_are_refused_before_anything(
    client: Any, fake_hub: FakeHub, headers: dict[str, str], code: str
) -> None:
    csrf = _csrf(client)
    r = _post(client, csrf, fake_hub, headers=headers)
    assert (r.status_code, _code(r)) == (403, code)
    assert "Er is niets naar de Hub gestuurd." in r.text and 'role="alert"' in r.text
    assert fake_hub.enroll_requests == []  # een geweigerd verzoek gaat niet naar de Hub
    st = client.app.state.hublink.state()
    assert st.state == "nooit_gekoppeld" and st.pending is None and st.last_error is None  # verandert niets
    assert len(client.app.state.pair_throttle.hits) == 0  # telt niet als poging


def test_missing_origin_and_missing_cookie_are_refused(client: Any, fake_hub: FakeHub) -> None:
    csrf = _csrf(client)
    zonder_origin = _kaal(client)
    r = _post(zonder_origin, csrf, fake_hub)
    assert (r.status_code, _code(r)) == (403, "herkomst_onjuist")
    client.cookies.clear()
    r = _post(client, csrf, fake_hub)
    assert (r.status_code, _code(r)) == (403, "ongeldig_formulier")
    assert fake_hub.enroll_requests == [] and len(client.app.state.pair_throttle.hits) == 0


def test_allowed_hosts_and_sec_fetch_site_values_pass(client: Any, fake_hub: FakeHub) -> None:
    """IP-adres, naam zonder punt en .local/.lan/.internal/.home.arpa mogen; ``Sec-Fetch-Site: none`` ook."""
    csrf = _csrf(client)
    for host in (
        f"{netwerk.LAN[10]}:30420",
        f"[{netwerk.ULA[16]}]:30420",
        "nas:30420",
        "nas.local:30420",
        "nas.home.arpa",
    ):
        r = _post(
            client,
            csrf,
            fake_hub,
            headers={"Host": host, "Origin": f"http://{host}", "Sec-Fetch-Site": "none"},
            hub_vingerafdruk="",
        )
        assert _code(r) == "ongeldige_vingerafdruk", host  # door de herkomst heen; daarna een gewone veldfout
    assert fake_hub.enroll_requests == []


def test_domain_name_shows_notice_before_the_form_is_filled(client: Any) -> None:
    r = client.get("/", headers={"Host": "nas.voorbeeld.nl:30420"})
    assert r.status_code == 200 and "Code <code>host_niet_toegestaan</code>" in r.text
    assert "Koppelen kan niet via dit adres" in r.text and 'role="alert"' not in r.text
    r = client.get("/", headers={"Host": f"{netwerk.LAN[10]}:30420"})
    assert "host_niet_toegestaan" not in r.text


def test_referrer_policy_is_same_origin(client: Any) -> None:
    assert client.get("/").headers["referrer-policy"] == "same-origin"


# ------------------------------------------------------------------ pogingen (§3.7, RV7)
def test_every_post_after_origin_counts_also_when_already_linked(paired_client: Any, fake_hub: FakeHub) -> None:
    c = paired_client
    csrf = c.cookies.get("hch_csrf") or c.get("/").cookies.get("hch_csrf")
    c.cookies.set("hch_csrf", csrf)
    before = len(fake_hub.enroll_requests)
    codes = [_code(_post(c, csrf, fake_hub)) for _ in range(6)]
    assert codes == ["al_gekoppeld"] * 5 + ["te_veel_pogingen"]
    assert len(fake_hub.enroll_requests) == before


def test_pairing_in_progress_gives_409_and_counts(client: Any, fake_hub: FakeHub) -> None:
    csrf = _csrf(client)

    def bezig(st: LinkState) -> LinkState:
        st.pending = Pending(kind="token", secret_sha256="f" * 64, hub_url=HUB_URL, started_at="2026-11-10T11:54:00Z")
        return st

    client.app.state.hublink_store.update(bezig)
    page = client.get("/").text
    assert 'action="/koppelen"' not in page and "Koppelen bezig</span>" in page  # Peil 1.1.1, E02
    r = _post(client, csrf, fake_hub)
    assert (r.status_code, _code(r)) == (409, "koppelen_bezig")
    assert fake_hub.enroll_requests == [] and len(client.app.state.pair_throttle.hits) == 1
    assert client.app.state.hublink.state().pending is not None  # de lopende poging blijft


def test_unreadable_link_file_gives_409_and_counts(client: Any, fake_hub: FakeHub, data_dir: Path) -> None:
    csrf = _csrf(client)
    (data_dir / "secrets" / "hub-link.json").write_text("geen json", encoding="utf-8")
    r = _post(client, csrf, fake_hub)
    assert (r.status_code, _code(r)) == (409, "koppelstatus_onleesbaar")
    assert fake_hub.enroll_requests == [] and len(client.app.state.pair_throttle.hits) == 1
    assert (data_dir / "secrets" / "hub-link.json").read_text(encoding="utf-8") == "geen json"  # niets vervangen


@pytest.mark.parametrize(
    ("veld", "waarde", "code"),
    [
        ("hub_adres", "http://hub.test:30400/" + "a" * 495, "ongeldig_hub_adres"),  # 513 tekens
        ("koppelcode", PAIR_CODE + " " * 19, "ongeldige_koppelcode"),  # 33 tekens; afgekapt zou hij geldig zijn
        ("hub_vingerafdruk", "-" * 49, "ongeldige_vingerafdruk"),  # 65 tekens
    ],
)
def test_input_is_checked_whole_never_truncated(
    client: Any, fake_hub: FakeHub, veld: str, waarde: str, code: str
) -> None:
    csrf = _csrf(client)
    if veld == "hub_vingerafdruk":
        waarde = fake_hub.fingerprint() + waarde
    r = _post(client, csrf, fake_hub, **{veld: waarde})
    assert (r.status_code, _code(r)) == (422, code)
    assert fake_hub.enroll_requests == [] and len(client.app.state.pair_throttle.hits) == 1


def test_exactly_one_log_line_per_post(client: Any, fake_hub: FakeHub, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)  # ook DEBUG meetellen: de enrollment-logregels van een koppelcode staan daar
    csrf = _csrf(client)
    gevallen = [
        ({"Origin": "null"}, {}),
        ({}, {"hub_vingerafdruk": ""}),
        ({}, {"koppelcode": "AAAA-BBBB-CCCC"}),
        ({}, {}),
    ]
    for headers, velden in gevallen:
        caplog.clear()
        r = _post(client, csrf, fake_hub, headers=headers, **velden)
        tid = r.headers["x-trace-id"]
        regels = [  # de app-log van deze dienst (niet de httpx-regels van de testclient zelf)
            rec for rec in caplog.records if rec.levelno >= logging.INFO and rec.name.startswith("integrations")
        ]
        assert len(regels) == 1, [rec.getMessage() for rec in regels]
        tekst = regels[0].getMessage()
        assert tid in tekst and "code=" in tekst and "hub.test" not in tekst and PAIR_CODE not in tekst


# ------------------------------------------------------------------ meldingen (§3.7)
def test_success_notice_needs_the_key_of_this_browser(client: Any, fake_hub: FakeHub) -> None:
    csrf = _csrf(client)
    r = _post(client, csrf, fake_hub)
    assert r.status_code == 303
    locatie = r.headers["location"]
    assert "Gekoppeld met de Hub</strong>" in client.get(locatie).text
    ander = TestClient(client.app, headers=BROWSER_HEADERS)  # een andere browser (ander cookie)
    assert "Gekoppeld met de Hub</strong>" not in ander.get(locatie).text
    assert "Gekoppeld met de Hub</strong>" not in client.get("/?melding=gekoppeld").text


def test_rate_limit_still_applies_after_refused_origins(client: Any, fake_hub: FakeHub) -> None:
    """Herkomst-weigeringen tellen niet; daarna gelden nog steeds vijf echte pogingen per bron-IP."""
    fake_hub.sim.max_failures = 1000
    client.app.state.pair_throttle = PairThrottle()
    csrf = _csrf(client)
    for _ in range(10):
        assert _code(_post(client, csrf, fake_hub, headers={"Origin": "null"})) == "herkomst_onjuist"
    codes = [_code(_post(client, csrf, fake_hub, koppelcode="AAAA-BBBB-CCCC")) for _ in range(6)]
    assert codes == ["hub_weigerde"] * 5 + ["te_veel_pogingen"]


# ------------------------------------------------------------------ koppelen op een ACL-dataset (TrueNAS-preset Apps)
def _koppel_via_formulier(c: Any, fake_hub: FakeHub) -> Any:
    assert 'name="koppelcode"' in c.get("/").text  # verse installatie: het koppelformulier staat er
    return _post(c, _csrf(c), fake_hub)


def test_koppelen_op_een_lege_appdata(app_factory: Any, fake_hub: FakeHub, data_dir: Path) -> None:
    """De volledige koppelflow op een verse /appdata: formulier → Hub → gekoppeld en bevestigd, bestand 0600."""
    assert not any(data_dir.iterdir())
    c = app_factory()
    r = _koppel_via_formulier(c, fake_hub)
    assert _code(r) == "gekoppeld", r.text[:300]
    st = c.app.state.hublink.state()
    assert st.linked and st.confirmed_at is not None and not st.corrupt
    assert stat.S_IMODE((data_dir / "secrets" / "hub-link.json").stat().st_mode) == 0o600


@pytest.mark.parametrize(("chmod", "herkend"), [("werkt", False), ("geweigerd", True), ("genegeerd", True)])
def test_koppelen_op_een_acl_dataset(
    app_factory: Any, fake_hub: FakeHub, data_dir: Path, monkeypatch: pytest.MonkeyPatch, chmod: str, herkend: bool
) -> None:
    """Koppelfout 0.1.0 (zoals bij de executor): op een dataset met preset Apps las de dienst zijn eigen hub-link.json
    als onleesbaar terug, zodat koppelen mislukte en het formulier verdween. Nu slaagt koppelen."""
    acl_dataset(monkeypatch, chmod=chmod, herkend=herkend)
    c = app_factory()
    r = _koppel_via_formulier(c, fake_hub)
    assert _code(r) == "gekoppeld", r.text[:300]
    st = c.app.state.hublink.state()
    assert st.linked and st.confirmed_at is not None and not st.corrupt
    assert not list((data_dir / "secrets").glob("hub-link.json.onleesbaar-*"))


def test_koppelen_laat_nooit_een_onleesbaar_bestand_achter(
    app_factory: Any, fake_hub: FakeHub, data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """chmod geweigerd en de ACL niet herkenbaar: een nette 503 ``koppelbestand_niet_opgeslagen``, niets naar de Hub,
    geen (onleesbaar) bestand, het formulier blijft; na herstel van de dataset lukt koppelen gewoon."""
    acl_dataset(monkeypatch, chmod="geweigerd", herkend=False)
    c = app_factory()
    r = _koppel_via_formulier(c, fake_hub)
    assert (r.status_code, _code(r)) == (503, "koppelbestand_niet_opgeslagen") and 'role="alert"' in r.text
    assert fake_hub.enroll_requests == []
    assert not (data_dir / "secrets" / "hub-link.json").exists()
    assert not list((data_dir / "secrets").glob("hub-link.json.onleesbaar-*"))
    assert not c.app.state.hublink.state().corrupt and 'name="koppelcode"' in c.get("/").text
    monkeypatch.undo()
    assert _code(_post(c, _csrf(c), fake_hub)) == "gekoppeld"
