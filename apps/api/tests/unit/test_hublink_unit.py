"""Unit (A5, A7): het enroll-verzoek bevat exact de velden van §3.3, het antwoord wordt volgens §3.3 gecontroleerd,
``hub-link.json`` volgt §3.5 (atomair, 0600, witte lijst, opnieuw lezen bij wijziging, onleesbaar = fail-closed) en
ondertekende sleutelrotaties volgen §4.5. Geen database nodig."""

from __future__ import annotations

import json
import os
import stat
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest

from integrations.config import Settings
from integrations.enrollment import (
    ENROLL_FIELDS,
    HubLink,
    InvalidResponseError,
    _pins_from,
    backoff_delay,
    validate_enroll_response,
    verify_rotation,
)
from integrations.hubclient import HubClient
from integrations.hublink_store import MAX_USED_TOKENS, HubLinkStore, LastError, LinkState, Pending
from integrations.security.hubkeys import validate_hub_jwk
from integrations.security.secrets import enroll_public_jwk, ensure_secrets, load_identity
from integrations.status_page import PairThrottle
from tests.conftest import HubSim, SimKey


@pytest.fixture
def sim() -> Any:
    return HubSim()


def _hublink(tmp_path: Path) -> HubLink:
    ensure_secrets(tmp_path)
    s = Settings(data_dir=tmp_path.parent, public_url=None)
    return HubLink(s, HubLinkStore(tmp_path), enroll_public_jwk(load_identity(tmp_path)), HubClient(s))


def _response(sim: Any) -> dict[str, Any]:
    token = sim.new_enrollment_token()
    body = {
        "app_id": "home-control-hub",
        "enrollment_token": token,
        "version": "0.1.0",
        "base_url": None,
        "public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": SimKey().x},
    }
    reply = sim.enroll(json.dumps(body).encode(), "192.0.2.1")
    assert reply.status == 200, reply.body
    return dict(reply.body)


# ------------------------------------------------------------------ verzoek (§3.3)
@pytest.mark.parametrize("field", ["enrollment_token", "pairing_code"])
def test_enroll_request_has_exactly_the_contract_fields(tmp_path: Path, sim: Any, field: str) -> None:
    hl = _hublink(tmp_path / "secrets")
    secret = sim.new_enrollment_token() if field == "enrollment_token" else sim.new_pairing_code()
    body = hl.enroll_body(field, secret)
    assert set(body) == {*ENROLL_FIELDS, field}
    assert set(body) == {"app_id", field, "version", "base_url", "public_key_jwk"}
    assert body["app_id"] == "home-control-hub"  # vaste app_id uit §2, niet de TrueNAS-appnaam
    assert set(body["public_key_jwk"]) == {"kty", "crv", "x", "kid"}
    for alias in ("kind", "secret", "api_prefix", "connector_prefix", "token", "use", "alg"):
        assert alias not in body and alias not in body["public_key_jwk"]
    # de Hub-simulator volgt §3.3 exact (onbekende velden → 422): dit verzoek wordt geaccepteerd
    reply = sim.enroll(json.dumps(body).encode(), "192.0.2.1")
    assert reply.status == 200 and reply.body["enrollment_replayed"] is False


def test_simulator_follows_3_3_errors(sim: Any) -> None:
    """A5: Hub-simulatoren volgen §3.3 exact, inclusief 401/422/429 en ``enrollment_replayed``."""
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": SimKey().x}
    token = sim.new_enrollment_token()
    ok = {"app_id": "home-control-hub", "enrollment_token": token, "version": "0.1.0", "base_url": None}

    def enroll(body: dict[str, Any], ip: str = "192.0.2.1") -> Any:
        return sim.enroll(json.dumps(body).encode(), ip)

    for bad in (
        {**ok, "public_key_jwk": {**jwk, "use": "sig"}},
        {**ok, "public_key_jwk": {**jwk, "alg": "EdDSA"}},
        {**ok, "public_key_jwk": {**jwk, "kid": "geen-thumbprint"}},
        {**ok, "public_key_jwk": jwk, "kind": "token"},
        {**ok, "public_key_jwk": jwk, "pairing_code": "ABCD-EFGH-JKMN"},
        {k: v for k, v in ok.items() if k != "base_url"} | {"public_key_jwk": jwk},
        {**ok, "enrollment_token": "enr_kort", "public_key_jwk": jwk},
    ):
        r = enroll(bad)
        assert r.status == 422 and r.body["code"] == "validation_error", bad
    r = enroll({**ok, "enrollment_token": "enr_" + "Q" * 43, "public_key_jwk": jwk})
    assert r.status == 401 and r.body["code"] == "invalid_enrollment"
    first = enroll({**ok, "public_key_jwk": jwk})
    again = enroll({**ok, "public_key_jwk": jwk})  # zelfde sleutel, token nooit gebruikt → toegestane herhaling
    assert first.status == again.status == 200 and again.body["enrollment_replayed"] is True
    other = enroll({**ok, "public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": SimKey().x}})
    assert other.status == 401  # andere sleutel: geen herhaling
    for _ in range(9):
        enroll({**ok, "enrollment_token": "enr_" + "Q" * 43, "public_key_jwk": jwk}, ip="192.0.2.9")
    assert enroll({**ok, "enrollment_token": "enr_" + "Q" * 43, "public_key_jwk": jwk}, ip="192.0.2.9").status == 401
    limited = enroll({**ok, "public_key_jwk": jwk}, ip="192.0.2.9")
    assert limited.status == 429 and int(limited.headers["Retry-After"]) > 0
    assert enroll({**ok, "public_key_jwk": jwk}, ip="192.0.2.8").status != 429  # per bron-IP


# ------------------------------------------------------------------ antwoord (§3.3)
def test_valid_response_and_expected_fingerprint(sim: Any) -> None:
    data = _response(sim)
    out = validate_enroll_response({**data, "onbekend_extra_veld": 1}, sim.fingerprint().lower())
    assert out["_fingerprint"] == sim.fingerprint()
    with pytest.raises(InvalidResponseError) as exc:
        validate_enroll_response(data, "0000-0000-0000-0000")
    assert exc.value.code == "hub_vingerafdruk_onjuist"


@pytest.mark.parametrize(
    "field",
    [
        "schema_version",
        "service_id",
        "app_id",
        "service_token",
        "token_type",
        "hub_issuer",
        "jwks",
        "policy_public_key",
        "keyset_fingerprint",
        "jwks_url",
        "events_inbox_url",
        "key_rotation_url",
        "enrollment_replayed",
    ],
)
def test_every_required_response_field(sim: Any, field: str) -> None:
    data = _response(sim)
    data.pop(field)
    with pytest.raises(InvalidResponseError):
        validate_enroll_response(data, None)


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"schema_version": "2.0"}, "hub_antwoord_ongeldig"),
        ({"schema_version": "1.3"}, None),  # zelfde major: geaccepteerd
        ({"token_type": "Basic"}, "hub_antwoord_ongeldig"),
        ({"hub_issuer": "nep"}, "hub_antwoord_ongeldig"),
        ({"service_token": "svc_kort"}, "hub_antwoord_ongeldig"),
        ({"enrollment_replayed": 1}, "hub_antwoord_ongeldig"),
        ({"jwks": {"keys": []}}, "hub_antwoord_ongeldig"),
        ({"keyset_fingerprint": "AAAA-BBBB-CCCC-DDDD"}, "hub_vingerafdruk_onjuist"),
    ],
)
def test_response_rules(sim: Any, change: dict[str, Any], code: str | None) -> None:
    data = {**_response(sim), **change}
    if code is None:
        validate_enroll_response(data, None)
        return
    with pytest.raises(InvalidResponseError) as exc:
        validate_enroll_response(data, None)
    assert exc.value.code == code


# ------------------------------------------------------------------ hub-link.json (§3.5)
def test_store_atomic_0600_reread_by_other_process_and_whitelist(tmp_path: Path) -> None:
    d = tmp_path / "secrets"
    d.mkdir(mode=0o700)
    a, b = HubLinkStore(d), HubLinkStore(d)  # twee processen (API en worker)
    assert a.read().state == "nooit_gekoppeld" and not a.exists()

    def link(st: LinkState) -> LinkState:
        st.state = "gekoppeld"
        st.service_token = "svc_" + "s" * 43
        st.service_token_last4 = "ssss"
        st.pending = Pending(
            kind="token", secret_sha256="f" * 64, hub_url="http://x:1", started_at="2026-11-09T12:00:00Z"
        )
        st.first_linked_at = "2026-11-09T12:00:00Z"
        return st

    a.update(link)
    assert b.read().state == "gekoppeld"  # het andere proces ziet de wijziging direct
    f = d / "hub-link.json"
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert not [p for p in d.iterdir() if p.name.endswith(".tmp")]  # geen halve bestanden
    pub = b.read().public()
    assert set(pub) == {
        "state",
        "koppelen_bezig",
        "hub_url",
        "service_id",
        "via",
        "linked_at",
        "first_linked_at",
        "keyset_fingerprint",
        "service_token_last4",
        "last_error",
    }
    assert pub["koppelen_bezig"] is True and "svc_" not in json.dumps(pub) and "f" * 64 not in json.dumps(pub)
    b.update(lambda st: st.model_copy(update={"state": "ontkoppeld"}))
    assert a.read().state == "ontkoppeld"


def test_store_corrupt_file_is_fail_closed_and_blocks_status_page_pairing(tmp_path: Path) -> None:
    store = HubLinkStore(tmp_path)
    (tmp_path / "hub-link.json").write_text("geen json", encoding="utf-8")
    st = store.read()
    assert st.corrupt and not st.linked and st.ever_linked
    os.chmod(tmp_path / "hub-link.json", 0o000)
    try:
        if os.geteuid() != 0:
            assert store.read().corrupt
    finally:
        os.chmod(tmp_path / "hub-link.json", 0o600)


def test_used_tokens_keep_the_last_20() -> None:
    st = LinkState()
    for i in range(30):
        st.remember_token(f"{i:064d}")
    st.remember_token(f"{29:064d}")
    assert len(st.used_enrollment_token_sha256) == MAX_USED_TOKENS
    assert st.used_enrollment_token_sha256[-1] == f"{29:064d}" and f"{9:064d}" not in st.used_enrollment_token_sha256


def test_store_lock_serialises_read_modify_write(tmp_path: Path) -> None:
    store = HubLinkStore(tmp_path)

    def bump(st: LinkState) -> LinkState:
        st.used_enrollment_token_sha256 = [*st.used_enrollment_token_sha256, uuid.uuid4().hex]
        return st

    threads = [
        threading.Thread(target=lambda: [HubLinkStore(tmp_path).update(bump) for _ in range(3)]) for _ in range(5)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(store.read().used_enrollment_token_sha256) == 15  # 5 × 3 geschreven, geen verloren updates
    with_more = store.read()
    assert len(set(with_more.used_enrollment_token_sha256)) == len(with_more.used_enrollment_token_sha256)


def test_write_over_unreadable_file_keeps_it_and_stays_fail_closed(tmp_path: Path) -> None:
    """Review contract 1.2 (ADR-0013): een gewone schrijfactie (``last_error``, ``pending``, tokenhash) over een onleesbaar
    bestand mag de koppelstatus niet stil terugzetten naar ``nooit_gekoppeld``: dan kwam het koppelformulier terug
    (open bij fout). Het origineel blijft bewaard (0600) en de status blijft 'onbekend' tot een geslaagde koppeling."""
    store = HubLinkStore(tmp_path)
    (tmp_path / "hub-link.json").write_text("geen json", encoding="utf-8")

    def error(st: LinkState) -> LinkState:
        st.last_error = LastError(code="hub_adres_ongeldig", at="2026-11-09T12:00:00Z")
        st.remember_token("a" * 64)
        return st

    after = store.update(error)
    asides = sorted(tmp_path.glob("hub-link.json.onleesbaar-*"))
    assert len(asides) == 1 and asides[0].read_text(encoding="utf-8") == "geen json"
    assert stat.S_IMODE(asides[0].stat().st_mode) == 0o600
    for st in (after, store.read(), HubLinkStore(tmp_path).read()):  # ook een ander proces ziet het
        assert st.corrupt and st.ever_linked and not st.linked and not st.unreadable
        assert st.state == "nooit_gekoppeld" and st.unreadable_replaced_at is not None
        assert st.used_enrollment_token_sha256 == ["a" * 64]  # het env-token wordt niet opnieuw geprobeerd
        assert st.public()["last_error"]["code"] == "koppelstatus_onleesbaar"
    # een volgende schrijfactie zet niets meer apart en houdt de markering
    store.update(lambda st: st.model_copy(update={"last_error": None}))
    assert len(list(tmp_path.glob("hub-link.json.onleesbaar-*"))) == 1 and store.read().corrupt
    # pas een geslaagde koppeling (first_linked_at gevuld) maakt de status weer bekend
    linked = store.update(lambda _st: LinkState(state="ontkoppeld", first_linked_at="2026-11-09T12:00:00Z"))
    assert not linked.corrupt and linked.unreadable_replaced_at is None and not store.read().corrupt


def test_unreadable_file_without_write_is_untouched(tmp_path: Path) -> None:
    store = HubLinkStore(tmp_path)
    (tmp_path / "hub-link.json").write_text("{}x", encoding="utf-8")
    assert store.update(lambda _st: None).corrupt  # 'niets wijzigen' schrijft niets en zet niets apart
    assert (tmp_path / "hub-link.json").read_text(encoding="utf-8") == "{}x"
    assert not list(tmp_path.glob("hub-link.json.onleesbaar-*"))
    pub = store.read().public()
    assert pub["state"] == "nooit_gekoppeld" and pub["last_error"]["code"] == "koppelstatus_onleesbaar"


def test_write_forces_0600_when_the_dataset_widens_the_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Geërfde ACL's van een dataset (bv. NFSv4 op TrueNAS) kunnen een nieuw bestand ruimer maken dan de gevraagde 0600.
    Zo'n bestand leest de dienst zelf als onleesbaar (§3.5, fail-closed); daarom zet de schrijver de modus expliciet op
    0600. Hier nagebootst door elk nieuw bestand direct 0660 te geven (echte ZFS-ACL's: NIET GEVALIDEERD)."""
    import integrations.hublink_store as hs

    echt_open = os.open

    def ruim_open(path: Any, flags: int, mode: int = 0o777, *args: Any, **kwargs: Any) -> int:
        fd = echt_open(path, flags, mode, *args, **kwargs)
        if flags & os.O_CREAT and str(path).endswith(".tmp"):
            os.fchmod(fd, 0o660)  # zoals een geërfde ACE die groep-rechten geeft
        return fd

    monkeypatch.setattr(hs.os, "open", ruim_open)
    store = HubLinkStore(tmp_path)
    store.update(
        lambda st: st.model_copy(update={"last_error": LastError(code="rate_limited", at="2026-11-10T09:00:00Z")})
    )
    assert stat.S_IMODE((tmp_path / "hub-link.json").stat().st_mode) == 0o600
    assert not HubLinkStore(tmp_path).read().corrupt


# ------------------------------------------------------------------ sleutelrotatie (§4.5)
def _pins(sim: Any) -> Any:
    jwks = [validate_hub_jwk(k) for k in sim.jwks()["keys"]]
    return _pins_from(jwks, [validate_hub_jwk(sim.policy_jwk())], "enroll", "2026-11-09T12:00:00Z")


def test_verify_rotation_jwt_and_policy(sim: Any) -> None:
    pins = _pins(sim)
    new = SimKey()
    item = sim.add_key_rotation("jwt", add=[new], retire=[sim.jwt_keys[0].kid])
    after = verify_rotation(item, pins, 1)
    assert [p.kid for p in after.jwt] == [new.kid] and after.rotation_sequence == 1
    assert after.keyset_fingerprint == sim.fingerprint() != pins.keyset_fingerprint
    # policy-rotatie, ondertekend met de gepinde policy-sleutel
    new_policy = SimKey()
    item2 = sim.add_key_rotation("policy", add=[new_policy])
    after2 = verify_rotation(item2, after, 2)
    assert new_policy.kid in [p.kid for p in after2.policy] and after2.rotation_sequence == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {"signer": "unpinned"},
        {"signer": "other_purpose"},
        {"tamper": {"type": "iets"}},
        {"tamper": {"iss": "nep"}},
        {"tamper": {"sequence": 7}},
        {"tamper": {"purpose": "policy"}},
        {"tamper": {"retire": ["bestaat-niet"]}},
        {"tamper": {"add": "geen lijst"}},
        {"tamper": {"issued_at": None}},
        {"retire_all": True},
    ],
)
def test_verify_rotation_rejects(sim: Any, kwargs: dict[str, Any]) -> None:
    pins = _pins(sim)
    signer = {"unpinned": SimKey(), "other_purpose": sim.policy_keys[0]}.get(kwargs.get("signer", ""))
    if kwargs.get("retire_all"):
        item = sim.add_key_rotation("jwt", retire=[sim.jwt_keys[0].kid])
    else:
        item = sim.add_key_rotation("jwt", add=[SimKey()], signer=signer, tamper=kwargs.get("tamper"))
    with pytest.raises(InvalidResponseError):
        verify_rotation(item, pins, 1)


def test_verify_rotation_sequence_must_be_next(sim: Any) -> None:
    pins = _pins(sim)
    item = sim.add_key_rotation("jwt", add=[SimKey()])
    for seq in (0, 2):
        with pytest.raises(InvalidResponseError):
            verify_rotation(item, pins, seq)
    with pytest.raises(InvalidResponseError):
        verify_rotation({"sequence": True, "statement": item["statement"]}, pins, 1)
    with pytest.raises(InvalidResponseError):
        verify_rotation({"sequence": 1, "statement": "geen-jws"}, pins, 1)


# ------------------------------------------------------------------ rest
def test_backoff_starts_at_5s_and_caps_at_15_min() -> None:
    assert 4.0 <= backoff_delay(1) <= 6.0
    assert 8.0 <= backoff_delay(2) <= 12.0
    assert all(backoff_delay(n) <= 900.0 for n in range(1, 40))
    assert backoff_delay(30) >= 720.0


def test_pair_throttle_per_ip_and_total() -> None:
    t = PairThrottle(per_ip=5, total=20, window_s=900)
    assert all(t.allow("a") for _ in range(5)) and not t.allow("a")
    assert all(t.allow(ip) for ip in ("b", "c", "d") for _ in range(5)) is True
    assert not t.allow("e")  # 20 voor de hele dienst
    t2 = PairThrottle(per_ip=1, total=5, window_s=0.01)
    assert t2.allow("a") and not t2.allow("a")
    import time as _t

    _t.sleep(0.02)
    assert t2.allow("a")  # venster voorbij


@pytest.mark.parametrize(
    ("public_url", "expected"),
    [
        (None, None),
        ("http://nas.lan:30420", "http://nas.lan:30420"),
        ("https://nas.lan/hch", "https://nas.lan/hch"),
        ("http://nas.lan:30420/?x=1", None),  # zou de Hub met 422 laten weigeren en het token verbranden
        ("ftp://nas.lan", None),
        ("http://" + "a" * 600, None),
    ],
)
def test_base_url_is_only_sent_when_valid(
    tmp_path: Path, sim: Any, public_url: str | None, expected: str | None
) -> None:
    ensure_secrets(tmp_path)
    s = Settings(data_dir=tmp_path.parent, public_url=public_url)
    hl = HubLink(s, HubLinkStore(tmp_path), enroll_public_jwk(load_identity(tmp_path)), HubClient(s))
    body = hl.enroll_body("enrollment_token", sim.new_enrollment_token())
    assert body["base_url"] == expected
    assert sim.enroll(json.dumps(body).encode(), "192.0.2.1").status == 200
