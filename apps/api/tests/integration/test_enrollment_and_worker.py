"""Integratie (PostgreSQL, nep-Hub = ``tests/e2e/sim_hub.py``): koppelen volgens contract 1.2 §3.3–§3.8 met het
env-token (worker), bevestigen, intrekken, token- en sleutelrotatie, de outbox en de eenmalige overzetting van een
koppeling uit de database naar ``hub-link.json``. Alles Sim-getest; geen echte Hub of NAS."""

from __future__ import annotations

import json
import stat
import time
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text

from integrations.enrollment import ENROLL_PATH, HubLink
from integrations.events import MAX_ATTEMPTS
from integrations.hublink_store import LinkState
from integrations.timeutil import utcnow
from integrations.worker import Worker
from tests.conftest import ENV_TOKEN, HUB_URL, FakeHub, SimKey, idem

pytestmark = pytest.mark.integration


def _worker(make_settings: Any, fake_hub: FakeHub, **over: Any) -> Worker:
    base = {"hub_url": HUB_URL, "enrollment_token": ENV_TOKEN, **over}
    return Worker(make_settings(**base), transport=fake_hub.transport)


def _link(w: Worker) -> LinkState:
    return w.store.read()


def _file(data_dir: Path) -> dict[str, Any]:
    return json.loads((data_dir / "secrets" / "hub-link.json").read_text(encoding="utf-8"))


def _all_db_text(w: Worker) -> str:
    with w.db.sessions() as s:
        tables = [r[0] for r in s.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='public'"))]
        return " ".join(
            str(s.execute(text(f'SELECT json_agg(t)::text FROM "{t}" t')).scalar())  # noqa: S608 - eigen tabellen
            for t in tables
        )


# ------------------------------------------------------------------ geslaagd koppelen met het env-token
def test_env_token_enrollment_exact_request_pins_file_and_confirmation(
    make_settings: Any, fake_hub: FakeHub, app_factory: Any, data_dir: Path
) -> None:
    w = _worker(make_settings, fake_hub, hub_key_fingerprint=fake_hub.fingerprint().lower().replace("-", " "))
    w.run_once()
    # §3.3: exact deze velden, geen kind/secret/api_prefix/connector_prefix, JWK zonder use/alg
    enroll = [r for r in fake_hub.requests if r.url.path == ENROLL_PATH]
    body = json.loads(enroll[0].content)
    assert set(body) == {"app_id", "enrollment_token", "version", "base_url", "public_key_jwk"}
    assert body["app_id"] == "home-control-hub" and body["enrollment_token"] == ENV_TOKEN and body["base_url"] is None
    assert set(body["public_key_jwk"]) == {"kty", "crv", "x", "kid"}
    st = _link(w)
    assert st.state == "gekoppeld" and st.via == "token" and st.confirmed_at is not None
    assert st.service_id == fake_hub.sim.service_id() and st.first_linked_at == st.linked_at
    assert st.pins is not None and st.pins.keyset_fingerprint == fake_hub.fingerprint()
    assert [p.kid for p in st.pins.jwt] == [fake_hub.keys.kid] and st.pins.rotation_sequence == 0
    assert st.pending is None and len(st.used_enrollment_token_sha256) == 1
    # §3.6 stap 3: bevestigd met services/self en het nieuwe token
    assert any(r.url.path == "/api/v1/services/self" for r in fake_hub.requests)
    # §3.5: 0600 in /appdata/secrets (0700); het token staat nooit in de database
    f = data_dir / "secrets" / "hub-link.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600 and stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    token = st.service_token
    assert token is not None and token.startswith("svc_")
    assert token not in _all_db_text(w) and ENV_TOKEN not in _all_db_text(w)
    # statuspagina: witte lijst (vingerafdruk + laatste 4), nooit het token of het env-token
    c = app_factory(hub_url=HUB_URL, enrollment_token=ENV_TOKEN)
    page = c.get("/").text
    assert fake_hub.fingerprint() in page and token[-4:] == st.service_token_last4
    assert token not in page and ENV_TOKEN not in page and "Koppelcode" not in page
    # tweede ronde: het token is afgehandeld en wordt nooit opnieuw verstuurd
    w.run_once()
    Worker(make_settings(hub_url=HUB_URL, enrollment_token=ENV_TOKEN), transport=fake_hub.transport).run_once()
    assert len([r for r in fake_hub.requests if r.url.path == ENROLL_PATH]) == 1


def test_fingerprint_mismatch_stores_nothing_and_is_final(make_settings: Any, fake_hub: FakeHub) -> None:
    w = _worker(make_settings, fake_hub, hub_key_fingerprint="0000-0000-0000-0000")
    w.run_once()
    st = _link(w)
    assert st.state == "nooit_gekoppeld" and st.service_token is None and st.pins is None
    assert st.last_error is not None and st.last_error.code == "hub_vingerafdruk_onjuist"
    assert st.pending is None and len(st.used_enrollment_token_sha256) == 1  # definitief voor dit token
    w.run_once()
    assert len(fake_hub.enroll_requests) == 1


def test_malformed_fingerprint_never_contacts_the_hub(make_settings: Any, fake_hub: FakeHub) -> None:
    w = _worker(make_settings, fake_hub, hub_key_fingerprint="geen-vingerafdruk")
    w.run_once()
    st = _link(w)
    assert st.last_error is not None and st.last_error.code == "vingerafdruk_ongeldig"
    assert not fake_hub.requests and st.used_enrollment_token_sha256 == []  # pas na herstel opnieuw proberen


def test_forged_response_fingerprint_is_rejected(make_settings: Any, fake_hub: FakeHub) -> None:
    """De Hub (of een vervalser) meldt een vingerafdruk die niet bij zijn sleutels past → niets opslaan."""
    sim = fake_hub.sim
    orig = sim.enroll

    def forged(raw: bytes, ip: str) -> Any:
        r = orig(raw, ip)
        if r.status == 200:
            r.body["keyset_fingerprint"] = "AAAA-BBBB-CCCC-DDDD"
        return r

    sim.enroll = forged
    w = _worker(make_settings, fake_hub)
    w.run_once()
    st = _link(w)
    assert st.state == "nooit_gekoppeld" and st.service_token is None
    assert st.last_error is not None and st.last_error.code == "hub_vingerafdruk_onjuist"


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda b: b.pop("policy_public_key"), "hub_antwoord_ongeldig"),
        (lambda b: b.update(schema_version="2.0"), "hub_antwoord_ongeldig"),
        (lambda b: b.update(app_id="andere-app"), "hub_antwoord_ongeldig"),
        (lambda b: b.update(service_id="geen-uuid"), "hub_antwoord_ongeldig"),
        (lambda b: b.update(service_token="svc-oud-formaat"), "hub_antwoord_ongeldig"),
        (lambda b: b.update(enrollment_replayed="nee"), "hub_antwoord_ongeldig"),
        (lambda b: b["jwks"]["keys"][0].update(d="privé"), "hub_antwoord_ongeldig"),
        (lambda b: b["jwks"]["keys"][0].pop("use"), "hub_antwoord_ongeldig"),
        (lambda b: b["jwks"]["keys"].append(dict(b["jwks"]["keys"][0])), "hub_antwoord_ongeldig"),
        (lambda b: b.update(token=b.pop("service_token")), "hub_antwoord_ongeldig"),  # alias bestaat niet
    ],
)
def test_invalid_enroll_response_stores_nothing(make_settings: Any, fake_hub: FakeHub, mutate: Any, code: str) -> None:
    sim = fake_hub.sim
    orig = sim.enroll

    def tampered(raw: bytes, ip: str) -> Any:
        r = orig(raw, ip)
        mutate(r.body)
        return r

    sim.enroll = tampered
    w = _worker(make_settings, fake_hub)
    w.run_once()
    st = _link(w)
    assert st.state == "nooit_gekoppeld" and st.service_token is None and st.pins is None
    assert st.last_error is not None and st.last_error.code == code


# ------------------------------------------------------------------ geweigerd / storing (§3.3-foutentabel)
def test_expired_enrollment_token_is_final(make_settings: Any, fake_hub: FakeHub) -> None:
    fake_hub.sim.expire_grants()
    w = _worker(make_settings, fake_hub)
    w.run_once()
    st = _link(w)
    assert st.last_error is not None and st.last_error.code == "hub_weigerde" and st.pending is None
    assert len(st.used_enrollment_token_sha256) == 1
    w.run_once()
    assert len(fake_hub.enroll_requests) == 1  # 401 invalid_enrollment: nooit automatisch opnieuw


def test_reused_enrollment_token_is_refused_by_the_hub(
    make_settings: Any, fake_hub: FakeHub, tmp_path: Path, clean_db: str
) -> None:
    """Een al gebruikt token (andere sleutel = andere dienst) → 401 invalid_enrollment; geen orakel."""
    _worker(make_settings, fake_hub).run_once()
    from integrations.config import Settings

    other = Settings(
        data_dir=tmp_path / "andere-installatie",
        database_url=clean_db,
        hub_url=HUB_URL,
        enrollment_token=ENV_TOKEN,
    )
    w2 = Worker(other, transport=fake_hub.transport)
    w2.run_once()
    st = w2.store.read()
    assert st.state == "nooit_gekoppeld" and st.last_error is not None and st.last_error.code == "hub_weigerde"


def test_allowed_replay_after_lost_response(make_settings: Any, fake_hub: FakeHub) -> None:
    """§3.6: de Hub verwerkte het verzoek, het antwoord ging verloren; dezelfde poging opnieuw → 200 met
    ``enrollment_replayed`` en het eerder uitgegeven (nooit gebruikte) token is ingetrokken."""
    fake_hub.drop_response.append(ENROLL_PATH)
    w = _worker(make_settings, fake_hub)
    w.run_once()
    st = _link(w)
    assert st.state == "nooit_gekoppeld" and st.pending is not None and st.pending.attempts == 1
    assert st.last_error is not None and st.last_error.code == "hub_onbereikbaar"
    w.hublink._next_env_attempt = 0  # backoff overslaan
    w.run_once()
    st = _link(w)
    assert st.state == "gekoppeld" and st.confirmed_at is not None and st.pending is None
    revoked = [t for t in fake_hub.sim.tokens.values() if t.revoked]
    assert len(revoked) == 1  # het eerste, verloren token


def test_validation_error_404_and_413_are_final(make_settings: Any, fake_hub: FakeHub) -> None:
    from tests.conftest import sim_hub

    for status, code in ((422, "hub_incompatibel"), (404, "enroll_endpoint_ontbreekt"), (413, "hub_incompatibel")):
        fake_hub.sim.enroll_override = lambda _b, s=status: sim_hub.Reply(s, {"code": "x"})
        w = _worker(make_settings, fake_hub, enrollment_token="enr_" + uuid.uuid4().hex + "A" * 11)
        w.run_once()
        st = _link(w)
        assert st.last_error is not None and st.last_error.code == code and st.pending is None


def test_rate_limited_waits_for_retry_after(make_settings: Any, fake_hub: FakeHub) -> None:
    sim = fake_hub.sim
    sim.failures[fake_hub.client_ip] = [time.time()] * 10  # 10 mislukte pogingen van dit bron-IP
    w = _worker(make_settings, fake_hub)
    before = time.monotonic()
    w.run_once()
    st = _link(w)
    assert st.pending is not None and st.last_error is not None and st.last_error.code == "rate_limited"
    assert w.hublink._next_env_attempt - before >= 60  # Retry-After (≈ 15 min), niet eerder
    calls = len(fake_hub.enroll_requests)
    w.run_once()
    assert len(fake_hub.enroll_requests) == calls


def test_storing_backoff_and_stop_after_60_minutes(make_settings: Any, fake_hub: FakeHub) -> None:
    from tests.conftest import sim_hub

    fake_hub.sim.enroll_override = lambda _b: sim_hub.Reply(503, {"code": "service_unavailable"})
    w = _worker(make_settings, fake_hub)
    before = time.monotonic()
    w.run_once()
    assert w.hublink._next_env_attempt - before >= 4.0  # start 5 s (± jitter)
    st = _link(w)
    assert st.pending is not None and st.last_error is not None and st.last_error.code == "hub_onbereikbaar"
    # redirect is ook een storing en wordt nooit gevolgd
    fake_hub.sim.enroll_override = lambda _b: sim_hub.Reply(302, None, {"Location": "http://evil.test/x"})
    w.hublink._next_env_attempt = 0
    w.run_once()
    assert not [r for r in fake_hub.requests if r.url.host == "evil.test"]
    assert _link(w).pending is not None and _link(w).pending.attempts == 2  # type: ignore[union-attr]

    def older(st: LinkState) -> LinkState:
        assert st.pending is not None
        st.pending.started_at = (utcnow() - timedelta(minutes=61)).isoformat().replace("+00:00", "Z")
        return st

    w.store.update(older)
    w.run_once()
    st = _link(w)
    assert st.pending is None and st.last_error is not None and st.last_error.code == "token_verlopen_na_60_min"
    assert len(st.used_enrollment_token_sha256) == 1


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"hub_url": "http://localhost:30400"}, "hub_adres_ongeldig"),
        ({"hub_url": "http://hub.test:30400/api"}, "hub_adres_ongeldig"),
        ({"hub_url": "http://169.254.1.1:30400"}, "hub_adres_ongeldig"),
        ({"enrollment_token": "oud-formaat-token-0123456789"}, "token_ongeldig"),
    ],
)
def test_invalid_env_values_never_contact_the_hub(
    make_settings: Any, fake_hub: FakeHub, over: dict[str, str], code: str
) -> None:
    w = _worker(make_settings, fake_hub, **over)
    w.run_once()
    st = _link(w)
    assert st.last_error is not None and st.last_error.code == code
    assert not fake_hub.requests


def test_legacy_enrollment_token_name_still_works_with_warning(
    monkeypatch: pytest.MonkeyPatch, fake_hub: FakeHub, data_dir: Path, clean_db: str, caplog: Any
) -> None:
    from integrations.config import Settings

    monkeypatch.delenv("HUB_ENROLLMENT_TOKEN", raising=False)
    monkeypatch.setenv("ENROLLMENT_TOKEN", ENV_TOKEN)
    monkeypatch.setenv("HUB_URL", HUB_URL)
    monkeypatch.setenv("HCH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("HCH_DATABASE_URL", clean_db)
    s = Settings.from_env()
    assert s.enrollment_token == ENV_TOKEN and s.enrollment_token_legacy_name
    caplog.set_level("WARNING")
    w = Worker(s, transport=fake_hub.transport)
    w.run_once()
    assert w.store.read().state == "gekoppeld"
    assert "ENROLLMENT_TOKEN is verouderd" in caplog.text and ENV_TOKEN not in caplog.text


# ------------------------------------------------------------------ herstart halverwege (§3.6 stap 5)
def test_restart_with_pending_token(make_settings: Any, fake_hub: FakeHub) -> None:
    from tests.conftest import sim_hub

    fake_hub.sim.enroll_override = lambda _b: sim_hub.Reply(503, {"code": "service_unavailable"})
    w = _worker(make_settings, fake_hub)
    w.run_once()
    assert _link(w).pending is not None
    # zelfde env-token na een herstart: dezelfde poging gaat door
    fake_hub.sim.enroll_override = None
    _worker(make_settings, fake_hub).run_once()
    assert _link(w).state == "gekoppeld"


def test_restart_with_other_token_interrupts_pending(make_settings: Any, fake_hub: FakeHub) -> None:
    from tests.conftest import sim_hub

    fake_hub.sim.enroll_override = lambda _b: sim_hub.Reply(503, {"code": "service_unavailable"})
    w = _worker(make_settings, fake_hub)
    w.run_once()
    # herstart zonder env-token: de poging is onderbroken
    w2 = Worker(make_settings(), transport=fake_hub.transport)
    w2.run_once()
    st = _link(w2)
    assert st.pending is None and st.last_error is not None and st.last_error.code == "koppelen_onderbroken"


def test_api_restart_interrupts_pending_pairing_code(app_factory: Any, data_dir: Path, fake_hub: FakeHub) -> None:
    c = app_factory()
    store = c.app.state.hublink_store

    def pending(st: LinkState) -> LinkState:
        from integrations.hublink_store import Pending

        st.pending = Pending(
            kind="koppelcode", secret_sha256="0" * 64, hub_url=HUB_URL, started_at="2026-11-09T12:00:00Z"
        )
        return st

    store.update(pending)
    c2 = app_factory()  # nieuw API-proces: het geheim van de koppelcode is weg
    st = c2.app.state.hublink.state()
    assert st.pending is None and st.last_error is not None and st.last_error.code == "koppelen_onderbroken"
    assert "Koppelen is onderbroken" in c2.get("/").text


# ------------------------------------------------------------------ opnieuw koppelen via de Hub (§3.8)
def test_new_env_token_relinks_and_failed_relink_keeps_old_link(make_settings: Any, fake_hub: FakeHub) -> None:
    w = _worker(make_settings, fake_hub)
    w.run_once()
    old = _link(w)
    assert old.state == "gekoppeld"
    # een nieuw, geldig token (de Hub koppelt opnieuw via app.update): vervangt token en pins
    new = fake_hub.sim.new_enrollment_token()
    w2 = _worker(make_settings, fake_hub, enrollment_token=new)
    w2.run_once()
    st = _link(w2)
    assert st.state == "gekoppeld" and st.service_token != old.service_token
    assert st.first_linked_at == old.first_linked_at and st.previous_pins is not None
    assert st.service_id == old.service_id  # de Hub houdt dezelfde registratie
    # een ongeldig nieuw token laat de bestaande koppeling ongemoeid
    bad = "enr_" + "Z" * 43
    w3 = _worker(make_settings, fake_hub, enrollment_token=bad)
    w3.run_once()
    after = _link(w3)
    assert after.state == "gekoppeld" and after.service_token == st.service_token
    assert after.last_error is not None and after.last_error.code == "hub_weigerde"


def test_new_env_token_relinks_after_revocation(make_settings: Any, fake_hub: FakeHub) -> None:
    w = _worker(make_settings, fake_hub)
    w.run_once()
    fake_hub.sim.revoke()
    assert w.hublink.confirm(trace_id=str(uuid.uuid4())) is False
    assert _link(w).state == "ingetrokken"
    w2 = _worker(make_settings, fake_hub, enrollment_token=fake_hub.sim.new_enrollment_token())
    w2.run_once()
    assert _link(w2).state == "gekoppeld"


# ------------------------------------------------------------------ intrekken (§3.8)
def _due(w: Worker) -> None:
    with w.db.sessions() as s:
        s.execute(text("UPDATE outbox_event SET next_attempt_at = now() WHERE delivery_status='pending'"))
        s.commit()


def test_revocation_needs_401_on_services_self(
    paired_client: Any, make_settings: Any, fake_hub: FakeHub, auth: Any
) -> None:
    c, h = paired_client, auth("admin")
    c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "hub_local", "username": "a", "login_kind": "lokaal"},
        headers=idem(h),
    )
    w = Worker(make_settings(), transport=fake_hub.transport)
    # 5xx en 429 op de inbox zijn nooit een intrekking
    for status in (503, 429, 500):
        fake_hub.sim.inbox_status = status
        _due(w)
        w.run_once()
        assert w.store.read().state == "gekoppeld", status
    # netwerkfout ook niet (bevestigen geeft dan 'onbekend')
    fake_hub.up = False
    _due(w)
    w.run_once()
    assert w.hublink.confirm(trace_id=str(uuid.uuid4())) is None and w.store.read().state == "gekoppeld"
    # 401 op de inbox maar services/self 200 (bv. tijdelijk): nog steeds gekoppeld
    fake_hub.up = True
    fake_hub.sim.inbox_status = 401
    _due(w)
    w.run_once()
    assert w.store.read().state == "gekoppeld"
    fake_hub.sim.inbox_status = None
    fake_hub.sim.revoke()
    _due(w)
    w.run_once()  # inbox 401 → services/self 401 → ingetrokken
    st = w.store.read()
    assert st.state == "ingetrokken" and st.service_token is None and st.pins is None and st.previous_pins
    assert st.last_error is not None and st.last_error.code == "ingetrokken_door_hub"
    r = c.get("/connector/v1/discover", headers=h)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "revoked"
    page = c.get("/").text
    assert "ingetrokken" in page and "Koppelcode" not in page  # geen herkoppelen na intrekking op de pagina


# ------------------------------------------------------------------ rotatie service-token (§3.8)
def test_token_rotation_on_hub_request(paired_client: Any, make_settings: Any, fake_hub: FakeHub) -> None:
    w = Worker(make_settings(hub_heartbeat_interval_s=0), transport=fake_hub.transport)
    w.run_once()
    old = w.store.read().service_token
    fake_hub.sim.request_rotation()
    w.run_once()  # heartbeat ziet Hub-Token-Rotation: required → self/rotate → bevestigen
    st = w.store.read()
    assert st.service_token != old and st.confirmed_at is not None and st.token_rotation_requested_at is None
    assert st.service_token is not None and st.service_token_last4 == st.service_token[-4:]
    calls = [p for m, p in fake_hub.sim.calls if p == "/api/v1/services/self/rotate"]
    assert len(calls) == 1


def test_token_rotation_after_interrupted_rotation(paired_client: Any, make_settings: Any, fake_hub: FakeHub) -> None:
    """Crash tijdens de rotatie (antwoord verloren): de dienst gebruikt het oude token terwijl het nieuwste nooit
    gebruikt is → de Hub zet opnieuw ``Hub-Token-Rotation: required`` → de dienst roteert opnieuw."""
    w = Worker(make_settings(hub_heartbeat_interval_s=0), transport=fake_hub.transport)
    w.run_once()
    old = w.store.read().service_token
    fake_hub.sim.request_rotation()
    fake_hub.drop_response.append("/api/v1/services/self/rotate")
    w.run_once()
    assert w.store.read().service_token == old  # antwoord kwijt: oud token blijft
    w.hublink._next_rotate = 0
    w.run_once()  # heartbeat met het oude token → header opnieuw → rotatie
    w.hublink._next_rotate = 0
    w.run_once()
    st = w.store.read()
    assert st.service_token != old and st.confirmed_at is not None
    never_used = [t for t in fake_hub.sim.tokens.values() if t.first_used_at is None and not t.revoked]
    assert never_used == []  # het verloren nieuwe token is bij de herhaalde rotatie ingetrokken


# ------------------------------------------------------------------ sleutelrotatie (§4.5)
def test_signed_key_rotation_is_applied(
    paired_client: Any, make_settings: Any, fake_hub: FakeHub, hub_keys: Any
) -> None:
    c = paired_client
    new = SimKey()
    fake_hub.sim.add_key_rotation("jwt", add=[new])
    token = fake_hub.sim.user_jwt(["admin"], key=new)
    r = c.get("/connector/v1/discover", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401 and r.json()["details"]["reason"] == "unknown_key"  # direct, poll op de achtergrond
    w = Worker(make_settings(), transport=fake_hub.transport)
    w.run_once()
    st = w.store.read()
    assert st.pins is not None and st.pins.rotation_sequence == 1 and new.kid in [p.kid for p in st.pins.jwt]
    assert st.pins.keyset_fingerprint == fake_hub.fingerprint()
    r = c.get(
        "/connector/v1/discover", headers={"Authorization": f"Bearer {fake_hub.sim.user_jwt(['admin'], key=new)}"}
    )
    assert r.status_code == 200
    view = c.get("/connector/v1/hub-link", headers={"Authorization": f"Bearer {hub_keys.token(['viewer'])}"}).json()
    assert view["rotation_sequence"] == 1 and new.kid in view["pinned_kids"]["jwt"]


@pytest.mark.parametrize(
    "bad",
    [
        {"signer": "unpinned"},  # ondertekend met een niet-gepinde sleutel
        {"signer": "policy"},  # jwt-wijziging door een policy-sleutel
        {"tamper": {"purpose": "policy"}},  # doel in de inhoud past niet bij de sleutel
        {"sequence": 2},  # gat in de volgnummers
        {"tamper": {"retire": ["onbekend"]}},
        {"tamper": {"iss": "nep"}},
    ],
)
def test_invalid_key_rotation_is_rejected_and_stops(
    paired_client: Any, make_settings: Any, fake_hub: FakeHub, bad: dict[str, Any]
) -> None:
    sim = fake_hub.sim
    new = SimKey()
    signer = {"unpinned": SimKey(), "policy": sim.policy_keys[0]}.get(bad.get("signer", ""))
    sim.add_key_rotation("jwt", add=[new], signer=signer, sequence=bad.get("sequence"), tamper=bad.get("tamper"))
    w = Worker(make_settings(), transport=fake_hub.transport)
    w.run_once()
    st = w.store.read()
    assert st.pins is not None and st.pins.rotation_sequence == 0 and new.kid not in [p.kid for p in st.pins.jwt]
    assert st.key_rotation_blocked_sequence == 1
    c = paired_client
    r = c.get("/connector/v1/discover", headers={"Authorization": f"Bearer {sim.user_jwt(['admin'], key=new)}"})
    assert r.status_code == 401 and r.json()["details"]["reason"] == "unknown_key"
    health = c.get("/connector/v1/health", headers=fake_hub.service_auth()).json()
    keys = next(x for x in health["checks"] if x["name"] == "hub_sleutels")
    assert keys["status"] == "degraded" and keys["reason_code"] == "sleutelrotatie_geweigerd"
    with w.db.sessions() as s:
        n = s.execute(text("SELECT count(*) FROM outbox_event WHERE event_type='service.key_rotation.rejected'"))
        assert n.scalar() == 1


# ------------------------------------------------------------------ outbox
def test_outbox_push_delivery_dead_letter_and_not_paired(
    paired_client: Any, make_settings: Any, fake_hub: FakeHub, auth: Any
) -> None:
    c, h = paired_client, auth("admin")
    c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "hub_local", "username": "a", "login_kind": "lokaal"},
        headers=idem(h),
    )
    worker = Worker(make_settings(), transport=fake_hub.transport)
    worker.run_once()
    assert fake_hub.inbox and fake_hub.inbox[0]["source_app"] == "home-control-hub"
    assert {e["event_type"] for e in fake_hub.inbox} >= {"service.hub_link.linked"}
    with worker.db.sessions() as s:
        pending = s.execute(text("SELECT count(*) FROM outbox_event WHERE delivery_status <> 'delivered'")).scalar()
    assert pending == 0 and fake_hub.rejected == []
    # Hub weigert → backoff, na MAX_ATTEMPTS dead letter (zichtbaar in health)
    fake_hub.sim.inbox_status = 500
    c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "hub_local", "username": "b", "login_kind": "lokaal"},
        headers=idem(h),
    )
    for _ in range(MAX_ATTEMPTS):
        with worker.db.sessions() as s:
            s.execute(text("UPDATE outbox_event SET next_attempt_at = now() WHERE delivery_status='pending'"))
            s.commit()
        worker.run_once()
    health = c.get("/connector/v1/health", headers=h).json()
    outbox = next(x for x in health["checks"] if x["name"] == "outbox")
    assert outbox["status"] == "degraded" and outbox["detail"]["dead_letter"] >= 1
    assert c.get("/connector/v1/events", headers=h).json()["dead_letter_count"] >= 1


def test_worker_closes_expired_activations(
    paired_client: Any, make_settings: Any, fake_hub: FakeHub, auth: Any
) -> None:
    c, h = paired_client, auth("admin")
    acc = c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "hub_local", "username": "nood", "login_kind": "lokaal", "is_break_glass": True},
        headers=idem(h),
    ).json()
    c.put(
        f"/integrations/v1/sso/recovery/accounts/{acc['id']}/emergency-access",
        json={"network_scopes": [{"cidr": "10.20.0.0/16", "kind": "lan"}]},
        headers=idem(h),
    )
    act = c.post(
        "/integrations/v1/sso/break-glass/activations",
        json={"account_id": acc["id"], "client_ip": "10.20.1.1", "mode": "oefening"},
        headers=idem(h),
    ).json()
    worker = Worker(make_settings(), transport=fake_hub.transport)
    with worker.db.sessions() as s:
        s.execute(
            text("UPDATE sso_break_glass_activation SET activated_at=:a, expires_at=:e WHERE id=:i"),
            {"a": utcnow() - timedelta(hours=2), "e": utcnow() - timedelta(hours=1), "i": act["id"]},
        )
        s.commit()
    worker.run_once()
    assert worker.state.stats["closed_activations"] == 1
    with worker.db.sessions() as s:
        assert s.execute(text("SELECT closed_at IS NOT NULL FROM sso_break_glass_activation")).scalar()
        assert (
            s.execute(text("SELECT count(*) FROM outbox_event WHERE event_type='sso.break_glass.expired'")).scalar()
            == 1
        )


# ------------------------------------------------------------------ overzetten uit de database (§3.5)
def _legacy_rows(w: Worker, fake_hub: FakeHub, token: str, *, policy: bool = True) -> None:
    from integrations.models import ServiceState

    with w.db.sessions() as s:
        s.add(
            ServiceState(
                key="hub_link",
                value={
                    "status": "gekoppeld",
                    "reason": "gekoppeld",
                    "hub_url": HUB_URL,
                    "via": "koppelcode",
                    "service_id": str(uuid.uuid4()),
                    "enrolled_at": "2026-11-09T10:00:00Z",
                    "service_token_sha256": "x",
                    "service_token_last4": token[-4:],
                },
            )
        )
        s.add(ServiceState(key="hub_jwks", value={"jwks": fake_hub.sim.jwks(), "source": "enroll"}))
        if policy:
            s.add(ServiceState(key="hub_policy_key", value={"jwk": fake_hub.sim.policy_jwk()}))
        w.vault.put(s, "vault://hub/service-token", token)
        s.commit()


def test_legacy_link_is_moved_to_the_file_once(make_settings: Any, fake_hub: FakeHub, data_dir: Path) -> None:
    settings = make_settings()
    w = Worker(settings, transport=fake_hub.transport)
    token = "svc_" + "L" * 43
    _legacy_rows(w, fake_hub, token)
    hl = HubLink(settings, w.store, {}, w.hub, w.db, w.vault)
    assert hl.ensure_migrated()
    st = w.store.read()
    assert st.state == "gekoppeld" and st.service_token == token and st.confirmed_at is None
    assert st.pins is not None and {p.source for p in st.pins.jwt} == {"overgezet"}
    assert st.first_linked_at == "2026-11-09T10:00:00Z"
    with w.db.sessions() as s:
        assert s.execute(text("SELECT count(*) FROM service_state WHERE key LIKE 'hub_%'")).scalar() == 0
        assert s.execute(text("SELECT count(*) FROM vault_secret WHERE ref='vault://hub/service-token'")).scalar() == 0
    # een database-herstel brengt de oude rijen terug: het bestand wint en de rijen verdwijnen weer
    _legacy_rows(w, fake_hub, "svc_" + "R" * 43)
    HubLink(settings, w.store, {}, w.hub, w.db, w.vault).ensure_migrated()
    assert w.store.read().service_token == token
    with w.db.sessions() as s:
        assert s.execute(text("SELECT count(*) FROM service_state WHERE key LIKE 'hub_%'")).scalar() == 0
    # het overgezette token is bij de Hub onbekend → services/self 401 → ingetrokken (nooit stil vertrouwd)
    w.run_once()
    assert w.store.read().state == "ingetrokken"


def test_incomplete_legacy_link_becomes_unlinked(make_settings: Any, fake_hub: FakeHub) -> None:
    settings = make_settings()
    w = Worker(settings, transport=fake_hub.transport)
    _legacy_rows(w, fake_hub, "svc-oud-formaat-token", policy=False)
    w.run_once()
    st = w.store.read()
    assert st.state == "ontkoppeld" and st.last_error is not None and st.last_error.code == "overzetten_onvolledig"
    assert st.ever_linked  # het koppelformulier van de statuspagina blijft dicht (§3.7)
