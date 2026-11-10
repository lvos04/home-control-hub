"""Integratie (PostgreSQL, Hub-simulator): koppelen volgens contract 1.3 §3.3/§3.5/§4.5 (C1.3-HCH-04, C1.3-HCH-05).

- ``rotation_sequence`` uit het enroll-antwoord wordt ``pins.rotation_sequence``; de dienst vraagt daarna alleen
  ``key-rotations?after=<waarde>`` en controleert dus geen statements die met al ingetrokken sleutels zijn ondertekend.
  Een Hub 1.2 stuurt het veld niet: dan 0. Een ongeldige waarde → niets opslaan (``hub_antwoord_ongeldig``).
- ``hub-link.json``: deze dienst schrijft ``schema_version`` ``"1.3"``; een lezer accepteert elke ``1.x`` en negeert
  onbekende velden; een andere major, ontbrekende verplichte velden of te ruime rechten = onleesbaar (fail-closed).
- Vaste ``last_error``-codes met hun HTTP-uitkomst; overige 4xx van de Hub = ``hub_incompatibel``; bij
  ``vingerafdruk_ongeldig``/``hub_adres_ongeldig`` geen verzoek naar de Hub en het token blijft onafgehandeld.

Sim-getest; geen echte Hub of NAS."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any

import pytest

from integrations.enrollment import ENROLL_PATH, KEY_ROTATIONS_PATH, InvalidResponseError, validate_enroll_response
from integrations.hublink_store import ERROR_MESSAGES, SCHEMA_VERSION, HubLinkStore, LinkState
from integrations.security.hubkeys import sha256_hex
from integrations.worker import Worker
from tests.conftest import ENV_TOKEN, HUB_URL, FakeHub, SimKey, sim_hub

pytestmark = pytest.mark.integration

#: §3.5: vaste codes (1.2) en de vaste aanvullingen van 1.3
VASTE_CODES = {
    "hub_onbereikbaar",
    "hub_weigerde",
    "hub_antwoord_ongeldig",
    "hub_vingerafdruk_onjuist",
    "enroll_endpoint_ontbreekt",
    "rate_limited",
    "koppelen_onderbroken",
    "token_verlopen_na_60_min",
    "ingetrokken_door_hub",
    "hub_incompatibel",
    "token_ongeldig",
    "vingerafdruk_ongeldig",
    "hub_adres_ongeldig",
    "overzetten_onvolledig",
    "koppelstatus_onleesbaar",
}


def _worker(make_settings: Any, fake_hub: FakeHub, **over: Any) -> Worker:
    return Worker(make_settings(**{"hub_url": HUB_URL, "enrollment_token": ENV_TOKEN, **over}), fake_hub.transport)


def _rotation_queries(fake_hub: FakeHub) -> list[str]:
    return [str(r.url.params.get("after")) for r in fake_hub.requests if r.url.path == KEY_ROTATIONS_PATH]


# ------------------------------------------------------------------ rotation_sequence (§3.3, §4.5)
def test_rotation_sequence_from_the_enroll_response_starts_the_poll(make_settings: Any, fake_hub: FakeHub) -> None:
    """De Hub roteerde vóór de koppeling (oude jwt-sleutel ingetrokken). Met 1.2-gedrag (beginnen bij 0) zou de dienst
    statement 1 krijgen, ondertekend met een sleutel die hij nooit gepind heeft, en de rotatie weigeren (incident)."""
    oud = fake_hub.sim.jwt_keys[0]
    nieuw = SimKey()
    fake_hub.sim.add_key_rotation("jwt", add=[nieuw], retire=[oud.kid])
    fake_hub.sim.jwt_keys = [k for k in fake_hub.sim.jwt_keys if k.kid != oud.kid]
    fake_hub.sim.signing = nieuw
    w = _worker(make_settings, fake_hub, hub_key_fingerprint=fake_hub.fingerprint())
    w.run_once()
    st = w.store.read()
    assert st.linked and st.pins is not None and st.pins.rotation_sequence == 1
    assert [p.kid for p in st.pins.jwt] == [nieuw.kid]
    assert _rotation_queries(fake_hub) == ["1"]  # nooit after=0
    assert st.key_rotation_blocked_sequence is None  # geen geweigerde rotatie, geen incident
    # een volgende rotatie (2, ondertekend met de gepinde sleutel) wordt gewoon toegepast
    nog = SimKey()
    fake_hub.sim.add_key_rotation("jwt", add=[nog], signer=nieuw)
    assert w.hublink.poll_key_rotations(trace_id=str(uuid.uuid4())) == 1
    assert w.store.read().pins.rotation_sequence == 2  # type: ignore[union-attr]


def test_hub_1_2_without_rotation_sequence_means_zero(make_settings: Any, fake_hub: FakeHub) -> None:
    fake_hub.sim.legacy_12 = True
    w = _worker(make_settings, fake_hub)
    w.run_once()
    st = w.store.read()
    assert st.linked and st.pins is not None and st.pins.rotation_sequence == 0
    assert _rotation_queries(fake_hub) == ["0"]


@pytest.mark.parametrize("waarde", [-1, "1", True, 1.5, None])
def test_invalid_rotation_sequence_stores_nothing(waarde: Any) -> None:
    sim = sim_hub.HubSim()
    token = sim.new_enrollment_token()
    body = {
        "app_id": "home-control-hub",
        "enrollment_token": token,
        "version": "0.1.0",
        "base_url": None,
        "public_key_jwk": {"kty": "OKP", "crv": "Ed25519", "x": SimKey().x},
    }
    data = sim.enroll(json.dumps(body).encode(), "192.0.2.1").body
    assert data["schema_version"] == "1.3" and data["rotation_sequence"] == 0
    with pytest.raises(InvalidResponseError) as exc:
        validate_enroll_response({**data, "rotation_sequence": waarde}, None)
    assert exc.value.code == "hub_antwoord_ongeldig"


# ------------------------------------------------------------------ hub-link.json (§3.5)
def test_file_is_written_as_1_3_and_readers_accept_every_1x(tmp_path: Path) -> None:
    store = HubLinkStore(tmp_path)
    store.update(lambda st: st)
    raw = json.loads((tmp_path / "hub-link.json").read_text(encoding="utf-8"))
    assert raw["schema_version"] == SCHEMA_VERSION == "1.3"
    # een nieuwere 1.x met onbekende velden blijft leesbaar
    nieuw = {**raw, "schema_version": "1.9", "veld_uit_de_toekomst": {"x": 1}}
    (tmp_path / "hub-link.json").write_text(json.dumps(nieuw), encoding="utf-8")
    os.chmod(tmp_path / "hub-link.json", 0o600)
    assert not store.read().corrupt
    store.update(lambda st: st)  # een schrijfactie schrijft weer de eigen versie
    assert json.loads((tmp_path / "hub-link.json").read_text(encoding="utf-8"))["schema_version"] == "1.3"


@pytest.mark.parametrize(
    ("inhoud", "modus"),
    [
        ({"schema_version": "2.0", "state": "gekoppeld"}, 0o600),  # andere major
        ({"state": "nooit_gekoppeld"}, 0o600),  # schema_version ontbreekt
        ({"schema_version": "1.3"}, 0o600),  # state ontbreekt
        ({"schema_version": 1.3, "state": "nooit_gekoppeld"}, 0o600),  # geen tekst
        ({"schema_version": "1.3", "state": "nooit_gekoppeld"}, 0o644),  # rechten ruimer dan 0600
        ({"schema_version": "1.3", "state": "nooit_gekoppeld"}, 0o660),
    ],
)
def test_unreadable_variants_are_fail_closed(tmp_path: Path, inhoud: dict[str, Any], modus: int) -> None:
    pad = tmp_path / "hub-link.json"
    pad.write_text(json.dumps(inhoud), encoding="utf-8")
    os.chmod(pad, modus)
    st = HubLinkStore(tmp_path).read()
    assert st.corrupt and not st.linked and st.ever_linked
    assert st.public()["last_error"]["code"] == "koppelstatus_onleesbaar"


def test_every_fixed_last_error_code_has_a_dutch_message() -> None:
    assert set(ERROR_MESSAGES) >= VASTE_CODES
    assert all(ERROR_MESSAGES[c].strip().endswith(".") for c in VASTE_CODES)


@pytest.mark.parametrize("status", [400, 403, 405, 409, 410])
def test_other_4xx_from_the_hub_is_incompatible_and_final(make_settings: Any, fake_hub: FakeHub, status: int) -> None:
    fake_hub.sim.enroll_override = lambda _b: sim_hub.Reply(status, {"code": "x"})
    w = _worker(make_settings, fake_hub)
    w.run_once()
    w.run_once()
    st = w.store.read()
    assert st.last_error is not None and st.last_error.code == "hub_incompatibel" and st.pending is None
    assert sha256_hex(ENV_TOKEN) in st.used_enrollment_token_sha256  # definitief: nooit opnieuw
    assert len([r for r in fake_hub.requests if r.url.path == ENROLL_PATH]) == 1


@pytest.mark.parametrize(
    ("over", "code"),
    [
        ({"hub_key_fingerprint": "geen-vingerafdruk"}, "vingerafdruk_ongeldig"),
        ({"hub_url": "http://127.1:1"}, "hub_adres_ongeldig"),
    ],
)
def test_bad_form_values_never_reach_the_hub_and_keep_the_token(
    make_settings: Any, fake_hub: FakeHub, over: dict[str, str], code: str
) -> None:
    w = _worker(make_settings, fake_hub, **over)
    w.run_once()
    st = w.store.read()
    assert st.last_error is not None and st.last_error.code == code
    assert not fake_hub.requests and sha256_hex(ENV_TOKEN) not in st.used_enrollment_token_sha256
    # de beheerder verbetert het formulier: hetzelfde token koppelt alsnog
    w2 = _worker(make_settings, fake_hub)
    w2.run_once()
    assert w2.store.read().linked


def test_public_view_of_the_link_is_unchanged_whitelist(make_settings: Any, fake_hub: FakeHub) -> None:
    w = _worker(make_settings, fake_hub)
    w.run_once()
    pub = w.store.read().public()
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
    assert isinstance(LinkState().schema_version, str)
