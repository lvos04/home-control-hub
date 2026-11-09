"""Integratie (PostgreSQL, nep-Hub): statuspagina (§3.7), ``GET /connector/v1/hub-link`` en
``POST /connector/v1/hub-link/unlink`` (§3.8, §6), de 1 MiB-grens vóór auth (§5) en de vaste ``reason``-waarden
over HTTP (§4.7). Sim-getest."""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from integrations.security.hubkeys import sha256_hex
from integrations.status_page import PairThrottle
from tests.conftest import HUB_URL, PAIR_CODE, FakeHub, idem, pair

pytestmark = pytest.mark.integration


def _csrf(client: Any) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', client.get("/").text)
    assert m, "geen koppelformulier op de statuspagina"
    return m.group(1)


_VELD = {"hub_url": "hub_adres", "code": "koppelcode", "fingerprint": "hub_vingerafdruk"}


def _code(r: Any) -> str:
    """Geslaagd → ``gekoppeld`` (303); mislukt → de vaste code op de foutpagina (HC11: direct, met trace-ID)."""
    if r.status_code == 303:
        return str(r.headers["location"]).removeprefix("/?melding=")
    m = re.search(r"Code <code>([a-z_]+)</code>", r.text)
    assert m and r.status_code >= 400, r.status_code
    return m.group(1)


def _post(client: Any, csrf: str, **form: str) -> str:
    data = {"csrf": csrf, "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": ""}
    data.update({_VELD.get(k, k): v for k, v in form.items()})
    return _code(client.post("/koppelen", data=data, follow_redirects=False))


def _client_from(client: Any, ip: str) -> TestClient:
    """Zelfde app, ander bron-IP van de TCP-verbinding (TestClient kan het client-adres zetten)."""
    c = TestClient(client.app, client=(ip, 50000))
    c.cookies.update(client.cookies)
    return c


# ------------------------------------------------------------------ statuspagina (§3.7)
def test_pairing_via_status_page_requires_fingerprint_and_csrf(client: Any, fake_hub: FakeHub, data_dir: Path) -> None:
    c, fp = client, fake_hub.fingerprint()
    page = c.get("/").text
    assert "Niet gekoppeld" in page and 'name="hub_vingerafdruk"' in page and "ontkoppelcode" not in page.lower()
    csrf = _csrf(c)
    assert _post(c, "fout", fingerprint=fp) == "ongeldig_formulier"
    r = c.post(
        "/koppelen",
        data={"csrf": csrf, "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": fp},
        headers={"Origin": "http://kwaadaardig.example"},
        follow_redirects=False,
    )
    assert _code(r) == "ongeldig_formulier"  # cross-site formulier geweigerd
    assert _post(c, csrf, fingerprint="") == "ongeldige_vingerafdruk"  # verplicht veld
    assert _post(c, csrf, fingerprint=fp, code="KORT") == "ongeldige_koppelcode"
    # elke poging telt mee voor de rate-limit (5 per bron-IP); voor de rest van deze test een verse teller
    c.app.state.pair_throttle = PairThrottle()
    for bad in ("http://localhost:30400", "http://hub.test:30400/pad", "http://169.254.0.9:30400", "ftp://x"):
        assert _post(c, csrf, fingerprint=fp, hub_url=bad) == "ongeldig_hub_adres"
    assert fake_hub.enroll_requests == []  # ongeldige invoer: geen verzoek naar de Hub
    c.app.state.pair_throttle = PairThrottle()
    # verkeerde vingerafdruk: de Hub gebruikt de code wel, maar de dienst slaat niets op
    assert _post(c, csrf, fingerprint="0000-0000-0000-0000") == "hub_vingerafdruk_onjuist"
    st = c.app.state.hublink.state()
    assert st.state == "nooit_gekoppeld" and st.hub_url is None and st.pending is None
    raw = (data_dir / "secrets" / "hub-link.json").read_text(encoding="utf-8")
    assert "hub.test" not in raw  # het Hub-adres van een mislukte poging wordt nergens bewaard
    # een nieuwe code + juiste vingerafdruk (kleine letters, zonder streepjes) → gekoppeld
    code = fake_hub.sim.new_pairing_code()
    assert _post(c, csrf, fingerprint=fp.lower().replace("-", ""), code=code.lower()) == "gekoppeld"
    body = fake_hub.enroll_requests[-1]
    assert set(body) == {"app_id", "version", "base_url", "public_key_jwk"}  # + pairing_code (niet gelogd)
    last = json.loads(next(r for r in reversed(fake_hub.requests) if r.url.path == "/api/v1/services/enroll").content)
    assert set(last) == {"app_id", "pairing_code", "version", "base_url", "public_key_jwk"}
    page = c.get("/?melding=gekoppeld").text
    assert "Gekoppeld met de Hub" in page and fp in page and "Koppelcode" not in page
    assert "Ontkoppelen of opnieuw koppelen gaat via de Hub" in page
    assert "<script>" not in c.get("/?melding=<script>alert(1)</script>").text  # geen weerspiegelde invoer


def test_pairing_refused_after_first_link_even_when_unlinked_or_revoked(paired_client: Any, fake_hub: FakeHub) -> None:
    c = paired_client
    m = re.search(r'name="csrf" value="([^"]+)"', c.get("/").text)
    assert m is None  # geen formulier meer
    csrf = c.cookies.get("hch_csrf")
    code = fake_hub.sim.new_pairing_code()
    before = len(fake_hub.enroll_requests)
    assert _post(c, csrf, code=code, fingerprint=fake_hub.fingerprint()) == "al_gekoppeld"
    assert c.post("/connector/v1/hub-link/unlink", headers=idem(fake_hub.service_auth())).status_code == 200
    assert c.app.state.hublink.state().state == "ontkoppeld"
    assert 'action="/koppelen"' not in c.get("/").text
    assert _post(c, csrf, code=code, fingerprint=fake_hub.fingerprint()) == "al_gekoppeld"
    assert len(fake_hub.enroll_requests) == before  # nooit een verzoek naar de Hub
    # er is geen lokaal ontkoppelen of ontkoppelcode meer
    assert c.post("/ontkoppelen", data={"csrf": csrf, "unpair_code": "AAAA-BBBB-CCCC"}).status_code in (404, 405)


def test_status_page_rate_limit_per_source_ip_and_per_service(client: Any, fake_hub: FakeHub) -> None:
    """Max. 5 pogingen per 15 min per bron-IP (TCP-adres, nooit X-Forwarded-For) en 20 voor de hele dienst."""
    fake_hub.sim.max_failures = 1000  # alleen de grens van deze dienst testen, niet die van de Hub
    a = _client_from(client, "192.0.2.21")
    csrf = _csrf(a)
    a.cookies.set("hch_csrf", csrf)
    wrong = "0000-0000-0000-0000"
    results = [_post(a, csrf, code="AAAA-BBBB-CCCC", fingerprint=wrong) for _ in range(6)]
    assert results[:5] == ["hub_weigerde"] * 5 and results[5] == "te_veel_pogingen"
    sent = len(fake_hub.enroll_requests)
    # vervalste X-Forwarded-For telt niet als ander adres
    r = a.post(
        "/koppelen",
        data={"csrf": csrf, "hub_adres": HUB_URL, "koppelcode": "AAAA-BBBB-CCCC", "hub_vingerafdruk": wrong},
        headers={"X-Forwarded-For": "198.51.100.7", "X-Real-IP": "198.51.100.7"},
        follow_redirects=False,
    )
    assert _code(r) == "te_veel_pogingen" and len(fake_hub.enroll_requests) == sent
    # een ander bron-IP mag wel, tot de dienstbrede grens van 20
    outcomes = []
    for i in range(4):
        b = _client_from(client, f"192.0.2.{30 + i}")
        b.cookies.set("hch_csrf", csrf)
        outcomes += [_post(b, csrf, code="AAAA-BBBB-CCCC", fingerprint=wrong) for _ in range(5)]
    assert outcomes.count("hub_weigerde") == 15 and outcomes[-5:] == ["te_veel_pogingen"] * 5
    assert len(fake_hub.enroll_requests) == 20


def test_hub_rate_limit_shown_on_status_page(client: Any, fake_hub: FakeHub) -> None:
    import time as _time

    fake_hub.sim.failures[fake_hub.client_ip] = [_time.time()] * 10
    csrf = _csrf(client)
    r = client.post(
        "/koppelen",
        data={"csrf": csrf, "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": fake_hub.fingerprint()},
        follow_redirects=False,
    )
    assert r.status_code == 429 and _code(r) == "rate_limited" and "te veel mislukte pogingen" in r.text


# ------------------------------------------------------------------ hub-link (§6) en ontkoppelen (§3.8)
def test_hub_link_view_is_a_whitelist(paired_client: Any, auth: Any, fake_hub: FakeHub) -> None:
    c = paired_client
    for who in (auth("viewer"), fake_hub.service_auth()):
        r = c.get("/connector/v1/hub-link", headers=who)
        assert r.status_code == 200
        v = r.json()
        assert v["state"] == "gekoppeld" and v["koppelen_bezig"] is False and v["via"] == "koppelcode"
        assert v["keyset_fingerprint"] == fake_hub.fingerprint() and v["rotation_sequence"] == 0
        assert v["pinned_kids"] == {"jwt": [fake_hub.keys.kid], "policy": [fake_hub.sim.policy_keys[0].kid]}
        token = c.app.state.hublink.state().service_token
        assert token not in r.text and "secret_sha256" not in r.text and 'service_token"' not in r.text
        assert v["service_token_last4"] == token[-4:]
    assert c.get("/connector/v1/hub-link", headers=auth("kind")).status_code == 403
    # readyz toont dezelfde witte lijst (zonder auth, zonder geheimen)
    ready = c.get("/readyz").json()
    assert ready["hub_link"]["state"] == "gekoppeld" and token not in json.dumps(ready)


def test_unlink_by_hub_service_jwt_and_repeat_counts_as_done(paired_client: Any, fake_hub: FakeHub, auth: Any) -> None:
    c = paired_client
    svc = fake_hub.service_auth()
    assert c.post("/connector/v1/hub-link/unlink", headers=fresh_headers(svc)).status_code == 400  # Idempotency-Key
    key = str(uuid.uuid4())
    r = c.post("/connector/v1/hub-link/unlink", headers=idem(svc, key), json={})
    assert r.status_code == 200 and r.json()["state"] == "ontkoppeld" and r.json()["service_token_last4"] is None
    st = c.app.state.hublink.state()
    assert st.service_token is None and st.pins is None and st.previous_pins is not None
    assert st.first_linked_at is not None
    # daarna weigert de dienst elke Hub-JWT; een herhaalde unlink geeft 401 not_linked (telt voor de Hub als gelukt)
    for headers in (idem(svc, key), idem(svc), idem(auth("admin"))):
        r = c.post("/connector/v1/hub-link/unlink", headers=headers)
        assert r.status_code == 401 and r.json()["details"]["reason"] == "not_linked"
    r = c.get("/connector/v1/discover", headers=auth("admin"))
    assert r.status_code == 401 and r.json()["details"]["reason"] == "not_linked"


def fresh_headers(h: Any) -> dict[str, str]:
    from tests.conftest import fresh

    return fresh(h)


def test_unlink_roles(paired_client: Any, auth: Any) -> None:
    c = paired_client
    for role in ("viewer", "operator", "kind"):
        assert c.post("/connector/v1/hub-link/unlink", headers=idem(auth(role))).status_code == 403
    r = c.post("/connector/v1/hub-link/unlink", headers=idem(auth("admin")), json={"iets": 1})
    assert r.status_code == 422
    r = c.post("/connector/v1/hub-link/unlink", headers=idem(auth("admin")))
    assert r.status_code == 200 and r.json()["state"] == "ontkoppeld"


def test_unlink_with_jti_replay_is_refused(paired_client: Any, fake_hub: FakeHub) -> None:
    c = paired_client
    token = fake_hub.sim.service_jwt()
    h = {"Authorization": f"Bearer {token}"}
    r = c.post("/connector/v1/propose", headers={**h, "Idempotency-Key": str(uuid.uuid4())}, json={})
    assert r.status_code != 401
    r = c.post("/connector/v1/hub-link/unlink", headers={**h, "Idempotency-Key": str(uuid.uuid4())})
    assert r.status_code == 401 and r.json()["details"]["reason"] == "token_replayed"
    assert c.app.state.hublink.state().state == "gekoppeld"


# ------------------------------------------------------------------ inkomende auth over HTTP (§4.3, §4.7)
def test_inbound_service_token_refused_even_the_real_one(paired_client: Any) -> None:
    c = paired_client
    token = c.app.state.hublink.state().service_token
    r = c.get("/connector/v1/discover", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401 and r.json()["details"]["reason"] == "service_token_not_accepted"
    assert r.headers["WWW-Authenticate"] == "Bearer" and token not in r.text


def test_dienst_jwt_for_another_registration_is_refused(paired_client: Any, fake_hub: FakeHub) -> None:
    other = fake_hub.sim.service_jwt(str(uuid.uuid4()))
    r = paired_client.get("/connector/v1/discover", headers={"Authorization": f"Bearer {other}"})
    assert r.status_code == 401 and r.json()["details"]["reason"] == "token_use_invalid"


# ------------------------------------------------------------------ 1 MiB vóór auth (§5)
def test_body_over_1_mib_is_413_before_auth_also_chunked(paired_client: Any, fake_hub: FakeHub) -> None:
    c = paired_client
    big = b'{"x":"' + b"a" * (1024 * 1024) + b'"}'
    for path in ("/connector/v1/hub-link/unlink", "/connector/v1/propose", "/koppelen"):
        r = c.post(path, content=big, headers={"Content-Type": "application/json"})
        assert r.status_code == 413 and r.json()["code"] == "payload_too_large", path
        assert r.json()["details"]["max_bytes"] == 1048576

    def chunks() -> Any:
        for _ in range(33):
            yield b"a" * 32768  # 1 081 344 bytes zonder Content-Length

    r = c.post("/connector/v1/hub-link/unlink", content=chunks(), headers=idem(fake_hub.service_auth()))
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"
    assert c.app.state.hublink.state().state == "gekoppeld"  # niets ontkoppeld
    r = c.post("/connector/v1/hub-link/unlink", content=b"x" * 10, headers={"Content-Length": str(2 * 1024 * 1024)})
    assert r.status_code == 413


def test_pair_then_relink_via_status_page_is_impossible_but_env_still_works(
    client: Any, fake_hub: FakeHub, make_settings: Any
) -> None:
    from integrations.worker import Worker

    assert pair(client, fake_hub).ok
    first = client.app.state.hublink.state()
    w = Worker(make_settings(hub_url=HUB_URL, enrollment_token=fake_hub.sim.new_enrollment_token()), fake_hub.transport)
    w.run_once()
    st = w.store.read()
    assert st.state == "gekoppeld" and st.via == "token" and st.service_token != first.service_token
    assert sha256_hex(str(w.settings.enrollment_token)) in st.used_enrollment_token_sha256


def test_unreadable_link_file_stays_fail_closed_after_a_failed_env_token(
    client: Any, fake_hub: FakeHub, make_settings: Any, data_dir: Path
) -> None:
    """Review contract 1.2 (ADR-0013): een onleesbaar ``hub-link.json`` + een env-token dat definitief mislukt mocht het
    bestand niet stil terugzetten naar ``nooit_gekoppeld`` (dan kwam het koppelformulier terug en kon iemand op het LAN
    de dienst aan een eigen "Hub" koppelen). Herstel blijft: een nieuw, geldig env-token van de Hub."""
    from integrations.worker import Worker

    secrets_dir = data_dir / "secrets"
    (secrets_dir / "hub-link.json").write_text('{"state": ', encoding="utf-8")
    csrf = client.cookies.get("hch_csrf") or "x" * 32
    assert 'action="/koppelen"' not in client.get("/").text
    bad = "enr_" + "Q" * 43  # onbekend bij de Hub → 401 invalid_enrollment (definitief)
    w = Worker(make_settings(hub_url=HUB_URL, enrollment_token=bad), fake_hub.transport)
    w.run_once()
    w.run_once()
    st = w.store.read()
    assert st.corrupt and st.ever_linked and not st.linked and st.last_error is not None
    assert sha256_hex(bad) in st.used_enrollment_token_sha256 and len(fake_hub.enroll_requests) == 1  # niet opnieuw
    assert len(list(secrets_dir.glob("hub-link.json.onleesbaar-*"))) == 1
    page = client.get("/")
    assert 'action="/koppelen"' not in page.text and "koppelstatus_onleesbaar" in page.text
    client.cookies.set("hch_csrf", csrf)
    assert (
        _post(client, csrf, code=fake_hub.sim.new_pairing_code(), fingerprint=fake_hub.fingerprint()) == "al_gekoppeld"
    )
    assert len(fake_hub.enroll_requests) == 1  # geen koppelpoging via de statuspagina
    ready = client.get("/readyz").json()["hub_link"]
    assert ready["state"] == "nooit_gekoppeld" and ready["last_error"]["code"] == "koppelstatus_onleesbaar"
    assert client.get("/connector/v1/discover", headers=fake_hub.service_auth()).json()["details"]["reason"] == (
        "not_linked"
    )
    # herstel: een nieuw, geldig env-token van de Hub koppelt (en maakt de status weer bekend)
    w2 = Worker(
        make_settings(hub_url=HUB_URL, enrollment_token=fake_hub.sim.new_enrollment_token()), fake_hub.transport
    )
    w2.run_once()
    st = w2.store.read()
    assert st.state == "gekoppeld" and not st.corrupt and st.unreadable_replaced_at is None
    assert client.get("/connector/v1/hub-link", headers=fake_hub.service_auth()).status_code == 200
