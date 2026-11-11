"""Controle van het ondertekende ``ExecutionRequest`` (contract 1.3 §8) door de eigenaar-connector.

De ondertekenaar is de Hub-simulator (``tests/e2e/sim_hub.py``): die heeft zijn eigen canonieke JSON, los van de
dienst. Een verschil tussen wat de Hub ondertekent en wat de dienst controleert valt hier dus op. Sim-getest.
"""

from __future__ import annotations

import copy
import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from integrations.security import execreq
from tests.conftest import HubSim, SimKey

NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
ACTION = "automation.flows.restore"
TARGET = {"type": "source", "id": "node_red"}
PARAMS = {"snapshot_id": "0b0e7c9e-2f1d-4a67-9d0e-6f0c1f1f0a01"}
PREVIEW = "sha256:" + "a" * 64
ETAG = "sha256:" + "b" * 64


def make(sim: HubSim, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "action_id": ACTION,
        "target": TARGET,
        "parameters": PARAMS,
        "preview_hash": PREVIEW,
        "resource_etag": ETAG,
        "now": NOW,
    }
    base.update(kw)
    return sim.execution_request(**base)


def keys(sim: HubSim) -> list[Any]:
    return [k.private.public_key() for k in sim.policy_keys]


def refusal(request: Any, sim: HubSim, now: datetime = NOW) -> execreq.Refusal:
    with pytest.raises(execreq.Refusal) as exc:
        execreq.check_envelope(request, keys(sim), now=now)
    return exc.value


def approval_refusal(request: dict[str, Any], now: datetime = NOW, **kw: Any) -> execreq.Refusal:
    args: dict[str, Any] = {"min_risk_class": "R2", "preview_hash": PREVIEW, "requires_backup": False, "now": now}
    args.update(kw)
    with pytest.raises(execreq.Refusal) as exc:
        execreq.check_approval(request, **args)
    return exc.value


# ------------------------------------------------------------------------------------------------ canonieke JSON
def test_canonical_json_is_sorted_compact_utf8() -> None:
    value = {"b": [1, True, None], "a": {"é": "ü", "A": "x"}}
    assert execreq.canonical_json(value) == '{"a":{"A":"x","é":"ü"},"b":[1,true,null]}'.encode()
    assert execreq.canonical_sha256(value) == "sha256:" + hashlib.sha256(execreq.canonical_json(value)).hexdigest()


@pytest.mark.parametrize(
    "value",
    [{"a": 1.5}, {"a": [1, {"b": 0.0}]}, {1: "x"}, {"a": b"bytes"}, {"a": {1, 2}}, {"a": float("nan")}],
)
def test_canonical_json_refuses_what_cannot_be_signed(value: Any) -> None:
    with pytest.raises(execreq.CanonicalError):
        execreq.canonical_json(value)


def test_canonical_json_refuses_too_deep_nesting() -> None:
    value: Any = "x"
    for _ in range(execreq.MAX_DEPTH + 2):
        value = [value]
    with pytest.raises(execreq.CanonicalError):
        execreq.canonical_json(value)


def test_signer_and_verifier_agree_on_canonical_bytes() -> None:
    """De Hub-simulator en de dienst komen zonder gedeelde code op dezelfde bytes uit (ook met niet-ASCII)."""
    sim = HubSim()
    request = make(sim, proposal_overrides={"reason": "Terug naar vóór de wijziging — café"})
    from tests.conftest import sim_hub

    unsigned = {k: v for k, v in request.items() if k != "signature"}
    assert sim_hub.canonical_json(unsigned) == execreq.signing_bytes(request)
    assert execreq.request_sha256(request) == hashlib.sha256(execreq.signing_bytes(request)).hexdigest()
    assert request["approval"]["action_scope"] == execreq.action_scope(ACTION, TARGET, PARAMS)


def test_b64url_is_strict() -> None:
    raw = bytes(range(64))
    text = execreq.b64url(raw)
    assert "=" not in text
    assert execreq.b64url_decode(text) == raw
    with pytest.raises(ValueError):
        execreq.b64url_decode(text + "=")  # opvulling hoort er niet in
    with pytest.raises(ValueError):
        execreq.b64url_decode(text.replace("_", "/").replace("-", "+") + "+/")  # standaard-base64


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("2026-03-01T12:00:00Z", True),
        ("2026-03-01T12:00:00+00:00", False),
        ("2026-03-01T12:00:00.000Z", False),
        ("2026-03-01 12:00:00Z", False),
        ("2026-13-01T12:00:00Z", False),
        (1772366400, False),
        (None, False),
    ],
)
def test_timestamps_only_whole_utc_seconds(value: Any, ok: bool) -> None:
    assert (execreq.parse_ts(value) is not None) is ok


def test_risk_class_ordering() -> None:
    assert execreq.class_at_least("R2", "R2")
    assert execreq.class_at_least("R3", "R2")
    assert not execreq.class_at_least("R1", "R2")
    assert not execreq.class_at_least("R9", "R2")
    assert not execreq.class_at_least("R2", "hoog")


# ------------------------------------------------------------------------------------------------- handtekening
def test_valid_request_passes_envelope_and_approval() -> None:
    sim = HubSim()
    request = make(sim)
    assert execreq.structure_errors(request) == []
    execreq.check_envelope(request, keys(sim), now=NOW)
    approval = execreq.check_approval(
        request, min_risk_class="R2", preview_hash=PREVIEW, requires_backup=False, now=NOW
    )
    assert approval["one_time_nonce"] == request["approval"]["one_time_nonce"]


def test_signature_of_an_unpinned_key_is_refused() -> None:
    sim = HubSim()
    stranger = SimKey()
    request = make(sim, key=stranger)
    r = refusal(request, sim)
    assert (r.status, r.code, r.details["reason"]) == (403, "forbidden", "handtekening_ongeldig")
    assert execreq.verify_signature(request, [stranger.private.public_key()])  # wel geldig voor die andere sleutel


def test_every_pinned_policy_key_is_tried() -> None:
    sim = HubSim()
    old = sim.policy_keys[0]
    sim.policy_keys.append(SimKey())
    execreq.check_envelope(make(sim, key=old), keys(sim), now=NOW)
    execreq.check_envelope(make(sim), keys(sim), now=NOW)
    assert refusal(make(sim), HubSim()).details["reason"] == "handtekening_ongeldig"  # zonder gepinde sleutel: nooit
    with pytest.raises(execreq.Refusal):
        execreq.check_envelope(make(sim), [], now=NOW)


@pytest.mark.parametrize(
    "path",
    [
        ("proposal", "parameters", "snapshot_id"),
        ("proposal", "action_id"),
        ("proposal", "target", "id"),
        ("proposal", "expected_version"),
        ("approval", "approved_by"),
        ("approval", "preview_hash"),
        ("approval", "one_time_nonce"),
        ("policy_decision", "risk_class"),
        ("expires_at",),
        ("nonce",),
    ],
)
def test_any_change_after_signing_breaks_the_signature(path: tuple[str, ...]) -> None:
    sim = HubSim()
    request = copy.deepcopy(make(sim))
    node: Any = request
    for name in path[:-1]:
        node = node[name]
    replacement = {
        "snapshot_id": str(uuid.uuid4()),
        "action_id": "automation.flows.restore",
        "id": "node_red",
        "expected_version": "sha256:" + "c" * 64,
        "approved_by": "iemand-anders",
        "preview_hash": "sha256:" + "d" * 64,
        "one_time_nonce": str(uuid.uuid4()),
        "risk_class": "R3",
        "expires_at": "2026-03-01T12:10:00Z",
        "nonce": str(uuid.uuid4()),
    }[path[-1]]
    if node[path[-1]] == replacement:  # zelfde waarde: maak hem aantoonbaar anders maar nog steeds goed gevormd
        replacement = {"action_id": "automation.flows.snapshot", "id": "node_red_2"}[path[-1]]
    node[path[-1]] = replacement
    assert execreq.structure_errors(request) == []
    assert refusal(request, sim).details["reason"] == "handtekening_ongeldig"


@pytest.mark.parametrize("signature", ["", "AAAA", "niet base64!", "a" * 86, None, 12])
def test_malformed_signatures_never_verify(signature: Any) -> None:
    sim = HubSim()
    request = {**make(sim), "signature": signature}
    assert not execreq.verify_signature(request, keys(sim))
    r = refusal(request, sim)
    if isinstance(signature, str):
        assert r.details["reason"] == "handtekening_ongeldig"
    else:
        assert (r.status, r.code) == (422, "execution_request_ongeldig")


def test_padded_signature_is_refused() -> None:
    sim = HubSim()
    request = make(sim)
    assert refusal({**request, "signature": request["signature"] + "=="}, sim).details["reason"] == (
        "handtekening_ongeldig"
    )


def test_signature_made_with_json_escapes_does_not_verify() -> None:
    """Een ondertekenaar die niet-ASCII als \\u-escape schrijft, tekent andere bytes: geweigerd."""
    import json

    sim = HubSim()
    request = make(sim, proposal_overrides={"reason": "café"})
    body = {k: v for k, v in request.items() if k != "signature"}
    escaped = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    key: Ed25519PrivateKey = sim.policy_keys[-1].private
    forged = {**body, "signature": execreq.b64url(key.sign(escaped))}
    assert refusal(forged, sim).details["reason"] == "handtekening_ongeldig"


# ---------------------------------------------------------------------------------------------------------- vorm
@pytest.mark.parametrize(
    ("overrides", "veld"),
    [
        ({"extra": 1}, "extra"),
        ({"nonce": "geen-uuid"}, "nonce"),
        ({"nonce": str(uuid.uuid4()).upper()}, "nonce"),
        ({"issued_at": "2026-03-01T12:00:00+00:00"}, "issued_at"),
        ({"expires_at": 1772366400}, "expires_at"),
        ({"policy_decision": {"risk_class": "R2", "rule_ids": []}}, "policy_decision"),
        (
            {"policy_decision": {"risk_class": "R7", "rule_ids": [], "policy_hash": PREVIEW}},
            "policy_decision.risk_class",
        ),
        (
            {"policy_decision": {"risk_class": "R2", "rule_ids": "x", "policy_hash": PREVIEW}},
            "policy_decision.rule_ids",
        ),
        (
            {"policy_decision": {"risk_class": "R2", "rule_ids": [], "policy_hash": "abc"}},
            "policy_decision.policy_hash",
        ),
        ({"proposal": "tekst"}, "proposal"),
        ({"approval": "ja"}, "approval"),
    ],
)
def test_structure_is_strict(overrides: dict[str, Any], veld: str) -> None:
    sim = HubSim()
    request = make(sim, overrides=overrides)  # geldig ondertekend, alleen de vorm is fout
    r = refusal(request, sim)
    assert (r.status, r.code) == (422, "execution_request_ongeldig")
    assert veld in {f["veld"] for f in r.details["fouten"]}


@pytest.mark.parametrize(
    ("overrides", "veld"),
    [
        ({"onbekend": True}, "proposal.onbekend"),
        ({"idempotency_key": "x"}, "proposal.idempotency_key"),
        ({"action_id": 5}, "proposal.action_id"),
        ({"target": "node_red"}, "proposal.target"),
        ({"parameters": []}, "proposal.parameters"),
        ({"expected_version": "v1 met spatie"}, "proposal.expected_version"),
        ({"actor": {"type": "user"}}, "proposal.actor"),
        ({"parameters": {"snapshot_id": 1.5}}, ""),
    ],
)
def test_proposal_structure_is_strict(overrides: dict[str, Any], veld: str) -> None:
    sim = HubSim()
    r = refusal(make(sim, proposal_overrides=overrides), sim)
    assert (r.status, r.code) == (422, "execution_request_ongeldig")
    assert veld in {f["veld"] for f in r.details["fouten"]}


@pytest.mark.parametrize(
    ("overrides", "veld"),
    [
        ({"vrij_veld": 1}, "approval.vrij_veld"),
        ({"approval_id": "x"}, "approval.approval_id"),
        ({"one_time_nonce": "x"}, "approval.one_time_nonce"),
        ({"preview_hash": "a" * 64}, "approval.preview_hash"),
        ({"policy_hash": "sha256:kort"}, "approval.policy_hash"),
        ({"risk_class": "hoog"}, "approval.risk_class"),
        ({"approved_at": "gisteren"}, "approval.approved_at"),
        ({"approved_by": ""}, "approval.approved_by"),
        ({"backup_checkpoint_id": 7}, "approval.backup_checkpoint_id"),
        ({"action_scope": "alles"}, "approval.action_scope"),
    ],
)
def test_approval_structure_is_strict(overrides: dict[str, Any], veld: str) -> None:
    sim = HubSim()
    r = refusal(make(sim, approval_overrides=overrides), sim)
    assert (r.status, r.code) == (422, "execution_request_ongeldig")
    assert veld in {f["veld"] for f in r.details["fouten"]}


def test_missing_fields_are_listed() -> None:
    sim = HubSim()
    request = make(sim)
    del request["nonce"]
    del request["proposal"]["actor"]
    del request["approval"]["action_scope"]
    velden = {f["veld"] for f in execreq.structure_errors(request)}
    assert {"nonce", "proposal.actor", "approval.action_scope"} <= velden
    assert execreq.structure_errors("geen object") == [{"veld": "", "fout": "verwacht een object"}]
    assert execreq.structure_errors(None)


def test_structure_error_list_is_capped_and_never_echoes_long_keys() -> None:
    sim = HubSim()
    request = make(sim, overrides={f"veld_{i:03d}" + "x" * 200: i for i in range(40)})
    r = refusal(request, sim)
    assert len(r.details["fouten"]) == 20
    assert all(len(f["veld"]) <= 60 for f in r.details["fouten"])


# ------------------------------------------------------------------------------------------------------- tijden
def test_request_validity_window() -> None:
    sim = HubSim()
    request = make(sim, ttl_s=300)
    execreq.check_envelope(request, keys(sim), now=NOW + timedelta(seconds=299))
    assert refusal(request, sim, NOW + timedelta(seconds=300)).details["reason"] == "verzoek_verlopen"
    assert refusal(request, sim, NOW + timedelta(hours=2)).details["reason"] == "verzoek_verlopen"
    # de klok van de Hub mag hooguit 30 s voorlopen
    execreq.check_envelope(request, keys(sim), now=NOW - timedelta(seconds=execreq.CLOCK_SKEW))
    early = refusal(request, sim, NOW - timedelta(seconds=execreq.CLOCK_SKEW + 1))
    assert early.details["reason"] == "verzoek_nog_niet_geldig"


def test_request_lives_at_most_fifteen_minutes() -> None:
    sim = HubSim()
    execreq.check_envelope(make(sim, ttl_s=900), keys(sim), now=NOW)
    assert refusal(make(sim, ttl_s=901), sim).details["reason"] == "verzoek_geldigheid_ongeldig"
    backwards = make(sim, overrides={"issued_at": "2026-03-01T12:05:00Z", "expires_at": "2026-03-01T12:05:00Z"})
    assert refusal(backwards, sim, NOW + timedelta(minutes=4, seconds=45)).details["reason"] == (
        "verzoek_geldigheid_ongeldig"
    )


# -------------------------------------------------------------------------------------------------- goedkeuring
def test_r2_action_needs_a_human_approval() -> None:
    sim = HubSim()
    request = make(sim, approved_by=None)
    execreq.check_envelope(request, keys(sim), now=NOW)  # vorm en handtekening kloppen
    r = approval_refusal(request)
    assert (r.status, r.code, r.details["reason"]) == (403, "forbidden", "goedkeuring_ontbreekt")


def test_risk_class_below_own_recalculation_is_refused() -> None:
    """De eigen herberekening (R2) wint altijd van wat de Hub of een AI opgeeft (EX18)."""
    sim = HubSim()
    request = make(sim, risk_class="R1")
    r = approval_refusal(request)
    assert r.details == {"reason": "risicoklasse_te_laag", "eigen_risk_class": "R2"}
    assert request["proposal"]["risk_claim"] == "R0"  # de claim in het voorstel doet nergens aan mee
    execreq.check_approval(
        make(sim, risk_class="R3"), min_risk_class="R2", preview_hash=PREVIEW, requires_backup=False, now=NOW
    )


def test_approval_validity_window() -> None:
    sim = HubSim()
    request = make(sim, approval_ttl_s=900)
    assert approval_refusal(request, NOW + timedelta(seconds=900)).details["reason"] == "goedkeuring_verlopen"
    assert approval_refusal(request, NOW - timedelta(seconds=31)).details["reason"] == "goedkeuring_ongeldig"
    assert approval_refusal(make(sim, approval_ttl_s=901)).details["reason"] == "goedkeuring_ongeldig"
    stil = make(sim, approval_overrides={"expires_at": "2026-03-01T11:59:59Z", "approved_at": "2026-03-01T11:59:59Z"})
    assert approval_refusal(stil, NOW - timedelta(seconds=5)).details["reason"] == "goedkeuring_ongeldig"


@pytest.mark.parametrize(
    ("kw", "gewijzigd"),
    [
        ({"approval_overrides": {"preview_hash": "sha256:" + "c" * 64}}, ["preview_hash"]),
        ({"approval_overrides": {"resource_etag": "sha256:" + "c" * 64}}, ["resource_etag"]),
        ({"approval_overrides": {"policy_hash": "sha256:" + "c" * 64}}, ["policy_hash"]),
        ({"approval_overrides": {"risk_class": "R1"}}, ["risk_class"]),
        (
            {"approval_overrides": {"action_scope": execreq.action_scope(ACTION, TARGET, {"snapshot_id": "ander"})}},
            ["action_scope"],
        ),
        (
            {"approval_overrides": {"action_scope": execreq.action_scope("app.restart", TARGET, PARAMS)}},
            ["action_scope"],
        ),
        (
            {
                "approval_overrides": {
                    "action_scope": execreq.action_scope(ACTION, {"type": "source", "id": "x"}, PARAMS)
                }
            },
            ["action_scope"],
        ),
        (
            {"approval_overrides": {"preview_hash": "sha256:" + "c" * 64, "policy_hash": "sha256:" + "d" * 64}},
            ["policy_hash", "preview_hash"],
        ),
    ],
)
def test_approval_is_bound_to_exactly_this_action(kw: dict[str, Any], gewijzigd: list[str]) -> None:
    """EX19: een goedkeuring voor iets anders (andere preview, ETag, beleid, parameters of doel) telt niet."""
    sim = HubSim()
    r = approval_refusal(make(sim, **kw))
    assert (r.status, r.code) == (409, "goedkeuring_past_niet")
    assert r.details == {"gewijzigd": gewijzigd}


def test_approval_bound_to_own_preview_not_the_one_in_the_request() -> None:
    sim = HubSim()
    request = make(sim)
    r = approval_refusal(request, preview_hash="sha256:" + "f" * 64)  # de dienst kent een andere preview
    assert r.details == {"gewijzigd": ["preview_hash"]}


def test_backup_checkpoint_required_when_the_action_asks_for_it() -> None:
    sim = HubSim()
    r = approval_refusal(make(sim), requires_backup=True)
    assert (r.status, r.code) == (409, "backup_checkpoint_ontbreekt")
    with_checkpoint = make(sim, approval_overrides={"backup_checkpoint_id": "chk-1"})
    execreq.check_approval(with_checkpoint, min_risk_class="R2", preview_hash=PREVIEW, requires_backup=True, now=NOW)


def test_refusal_is_readable() -> None:
    r = execreq.Refusal(409, "nonce_al_gebruikt", "Al gebruikt.")
    assert str(r) == "409 nonce_al_gebruikt"
    assert r.details == {}
