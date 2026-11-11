"""Controle van een door de Hub ondertekend ``ExecutionRequest`` door deze eigenaar-connector (contract 1.3 §8).

Het formaat volgt de referentie van de Hub (``ai-server-manager/docs/EXECUTION_REQUEST.md``)::

    {"proposal": ActionProposal, "approval": Approval | null,
     "policy_decision": {"risk_class", "rule_ids", "policy_hash"},
     "issued_at", "expires_at", "nonce": "<uuid>", "signature": "<base64url zonder =>"}

``signature`` = Ed25519 met de policy-sleutel van de Hub over de canonieke JSON van het verzoek **zonder** het veld
``signature`` (sleutels gesorteerd, scheidingstekens ``,`` en ``:``, UTF-8 zonder escapes, geen kommagetallen). Er staat
geen sleutel-ID in het verzoek: elke bij het koppelen **gepinde** policy-sleutel wordt geprobeerd (§4.5). Een sleutel
die via HTTP binnenkomt, voegt nooit vertrouwen toe.

Deze module ondertekent zelf nooit iets: deze dienst kan geen uitvoeringsverzoek maken, alleen controleren. De
actie-specifieke controles (allowlist, parameterschema, eenmalige nonce, precondities via readback) staan bij de actie
zelf (``domains/automation/restore.py``).

Weigeringen hebben dezelfde stabiele codes als bij de executor. Omdat de foutcatalogus (§5) onder 403 alleen
``forbidden`` met ``details.reason`` toestaat, staat de code van een 403-weigering in ``details.reason``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_APPROVAL_SECONDS = 15 * 60
MAX_REQUEST_SECONDS = 15 * 60
CLOCK_SKEW = 30
RISK_CLASSES = ("R0", "R1", "R2", "R3")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ETAG_RE = re.compile(r"^(sha256:[0-9a-f]{64}|absent|dataset:[^\s]{1,200}|snapshot:[^\s]{1,264}|geen|eigenaar)$")
PROPOSAL_KEYS = frozenset(
    {
        "idempotency_key",
        "action_id",
        "target",
        "parameters",
        "reason",
        "actor",
        "expected_version",
        "risk_claim",
        "evidence_ids",
        "expires_in_seconds",
    }
)
PROPOSAL_REQUIRED = ("idempotency_key", "action_id", "target", "parameters", "actor", "expected_version")
APPROVAL_KEYS = frozenset(
    {
        "approval_id",
        "request_id",
        "preview_hash",
        "resource_etag",
        "policy_hash",
        "risk_class",
        "approved_by",
        "approved_at",
        "expires_at",
        "one_time_nonce",
        "backup_checkpoint_id",
        "action_scope",
    }
)
REQUEST_KEYS = frozenset({"proposal", "approval", "policy_decision", "issued_at", "expires_at", "nonce", "signature"})
MAX_DEPTH = 32


class CanonicalError(ValueError):
    """De waarde kan niet canoniek worden weergegeven (bv. een kommagetal of een niet-tekstsleutel)."""


@dataclass(frozen=True)
class Refusal(Exception):
    """Een geweigerd uitvoeringsverzoek; er is niets uitgevoerd."""

    status: int
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.status} {self.code}"


def _check(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError("te diep genest")
    if value is None or isinstance(value, bool | str | int):
        return
    if isinstance(value, float):
        raise CanonicalError("kommagetallen zijn niet toegestaan in ondertekende gegevens")
    if isinstance(value, list | tuple):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError("alleen tekstsleutels")
            _check(item, depth + 1)
        return
    raise CanonicalError(f"type {type(value).__name__} is niet toegestaan")


def canonical_json(value: Any) -> bytes:
    """Canonieke UTF-8-bytes (gelijk aan ``asm_policy.canonical.canonical_json`` van de Hub)."""
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """``"sha256:<64 hex>"`` over de canonieke JSON van ``value``."""
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text: str) -> bytes:
    raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64url(raw) != text:
        raise ValueError("geen canonieke base64url")
    return raw


def parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not TS_RE.fullmatch(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        return None


def action_scope(action_id: str, target: Mapping[str, Any], parameters: Mapping[str, Any]) -> dict[str, Any]:
    return {"action_id": action_id, "target": dict(target), "parameters_sha256": canonical_sha256(dict(parameters))}


def signing_bytes(request: Mapping[str, Any]) -> bytes:
    return canonical_json({k: v for k, v in request.items() if k != "signature"})


def request_sha256(request: Mapping[str, Any]) -> str:
    """Kale hex-hash van het verzoek zonder handtekening (voor het nonce-register en de audit)."""
    return hashlib.sha256(signing_bytes(request)).hexdigest()


def class_at_least(given: str, minimum: str) -> bool:
    return (
        given in RISK_CLASSES and minimum in RISK_CLASSES and RISK_CLASSES.index(given) >= RISK_CLASSES.index(minimum)
    )


def verify_signature(request: Mapping[str, Any], keys: Iterable[Ed25519PublicKey]) -> bool:
    sig = request.get("signature")
    if not isinstance(sig, str) or not sig:
        return False
    try:
        raw = b64url_decode(sig)
        message = signing_bytes(request)
    except (ValueError, TypeError):
        return False
    for key in keys:
        try:
            key.verify(raw, message)
            return True
        except InvalidSignature:
            continue
    return False


def structure_errors(request: Any) -> list[dict[str, str]]:
    """Vormcontrole (strikt: een onbekend veld is een fout)."""
    errs: list[dict[str, str]] = []

    def bad(veld: str, fout: str) -> None:
        errs.append({"veld": veld, "fout": fout})

    if not isinstance(request, Mapping):
        return [{"veld": "", "fout": "verwacht een object"}]
    for k in sorted(set(request) - REQUEST_KEYS):
        bad(str(k)[:60], "onbekend veld")
    for k in sorted(REQUEST_KEYS - set(request)):
        bad(k, "verplicht veld ontbreekt")
    _proposal_errors(request.get("proposal"), bad)
    _approval_errors(request.get("approval"), bad)
    d = request.get("policy_decision")
    if not isinstance(d, Mapping) or set(d) != {"risk_class", "rule_ids", "policy_hash"}:
        bad("policy_decision", "verwacht precies {risk_class, rule_ids, policy_hash}")
    else:
        if d.get("risk_class") not in RISK_CLASSES:
            bad("policy_decision.risk_class", "R0–R3")
        if not (isinstance(d.get("rule_ids"), list) and all(isinstance(r, str) for r in d["rule_ids"])):
            bad("policy_decision.rule_ids", "verwacht een lijst")
        if not (isinstance(d.get("policy_hash"), str) and SHA_RE.fullmatch(d["policy_hash"])):
            bad("policy_decision.policy_hash", "verwacht sha256:<hex>")
    for k in ("issued_at", "expires_at"):
        if parse_ts(request.get(k)) is None:
            bad(k, "verwacht YYYY-MM-DDTHH:MM:SSZ")
    if not (isinstance(request.get("nonce"), str) and UUID_RE.fullmatch(request["nonce"])):
        bad("nonce", "verwacht een UUID")
    if not isinstance(request.get("signature"), str):
        bad("signature", "verwacht tekst")
    try:
        _check(dict(request))
    except CanonicalError as exc:
        bad("", str(exc))
    return errs


def _proposal_errors(p: Any, bad: Any) -> None:
    if not isinstance(p, Mapping):
        bad("proposal", "verwacht een object")
        return
    for k in sorted(set(p) - PROPOSAL_KEYS):
        bad(f"proposal.{str(k)[:60]}", "onbekend veld")
    for k in PROPOSAL_REQUIRED:
        if k not in p:
            bad(f"proposal.{k}", "verplicht veld ontbreekt")
    if not isinstance(p.get("action_id"), str):
        bad("proposal.action_id", "verwacht tekst")
    if not isinstance(p.get("target"), Mapping):
        bad("proposal.target", "verwacht een object")
    if not isinstance(p.get("parameters"), Mapping):
        bad("proposal.parameters", "verwacht een object")
    if not (isinstance(p.get("idempotency_key"), str) and UUID_RE.fullmatch(p["idempotency_key"])):
        bad("proposal.idempotency_key", "verwacht een UUID")
    if not (isinstance(p.get("expected_version"), str) and ETAG_RE.fullmatch(p["expected_version"])):
        bad("proposal.expected_version", "ongeldige versie/ETag")
    actor = p.get("actor")
    if not (isinstance(actor, Mapping) and isinstance(actor.get("type"), str) and isinstance(actor.get("id"), str)):
        bad("proposal.actor", "verwacht {type, id}")


def _approval_errors(a: Any, bad: Any) -> None:
    if a is None:
        return
    if not isinstance(a, Mapping):
        bad("approval", "verwacht een object of null")
        return
    for k in sorted(set(a) - APPROVAL_KEYS):
        bad(f"approval.{str(k)[:60]}", "onbekend veld")
    for k in sorted(APPROVAL_KEYS - set(a)):
        bad(f"approval.{k}", "verplicht veld ontbreekt")
    for k in ("approval_id", "request_id", "one_time_nonce"):
        if not (isinstance(a.get(k), str) and UUID_RE.fullmatch(a[k])):
            bad(f"approval.{k}", "verwacht een UUID")
    for k in ("preview_hash", "policy_hash"):
        if not (isinstance(a.get(k), str) and SHA_RE.fullmatch(a[k])):
            bad(f"approval.{k}", "verwacht sha256:<hex>")
    if a.get("risk_class") not in RISK_CLASSES:
        bad("approval.risk_class", "R0–R3")
    for k in ("approved_at", "expires_at"):
        if parse_ts(a.get(k)) is None:
            bad(f"approval.{k}", "verwacht YYYY-MM-DDTHH:MM:SSZ")
    if not isinstance(a.get("approved_by"), str) or not a.get("approved_by"):
        bad("approval.approved_by", "verwacht tekst")
    if a.get("backup_checkpoint_id") is not None and not isinstance(a.get("backup_checkpoint_id"), str):
        bad("approval.backup_checkpoint_id", "verwacht tekst of null")
    if not isinstance(a.get("action_scope"), Mapping):
        bad("approval.action_scope", "verwacht een object")


def _forbidden(reason: str, message: str, details: dict[str, Any] | None = None) -> Refusal:
    return Refusal(403, "forbidden", message, {"reason": reason, **(details or {})})


def check_envelope(request: Any, keys: Iterable[Ed25519PublicKey], *, now: datetime) -> None:
    """Vorm, handtekening tegen de gepinde policy-sleutels en geldigheidsduur. Gooit :class:`Refusal`."""
    fouten = structure_errors(request)
    if fouten:
        raise Refusal(
            422,
            "execution_request_ongeldig",
            "Het uitvoeringsverzoek heeft niet de juiste vorm; er is niets uitgevoerd.",
            {"fouten": fouten[:20]},
        )
    if not verify_signature(request, keys):
        raise _forbidden(
            "handtekening_ongeldig",
            "De handtekening klopt niet met een gepinde policy-sleutel van de Hub; er is niets uitgevoerd.",
        )
    skew = timedelta(seconds=CLOCK_SKEW)
    issued = parse_ts(request["issued_at"])
    expires = parse_ts(request["expires_at"])
    if issued is None or expires is None:  # pragma: no cover - al gecontroleerd in structure_errors
        raise Refusal(422, "execution_request_ongeldig", "Ongeldige tijd in het uitvoeringsverzoek.")
    if issued > now + skew:
        raise _forbidden("verzoek_nog_niet_geldig", "Het uitvoeringsverzoek is in de toekomst uitgegeven.")
    if expires <= now:
        raise _forbidden("verzoek_verlopen", "Het uitvoeringsverzoek is verlopen; er is niets uitgevoerd.")
    if expires <= issued or (expires - issued).total_seconds() > MAX_REQUEST_SECONDS:
        raise _forbidden("verzoek_geldigheid_ongeldig", "Een uitvoeringsverzoek is hooguit 15 minuten geldig.")


def check_approval(
    request: Mapping[str, Any], *, min_risk_class: str, preview_hash: str, requires_backup: bool, now: datetime
) -> Mapping[str, Any]:
    """Een R2/R3-actie vraagt een goedkeuring die bij precies deze actie, dit doel, deze parameters, deze ETag, deze
    preview en dit beleid hoort (EX19). Geeft de goedkeuring terug of gooit :class:`Refusal`."""
    prop = request["proposal"]
    besluit = request["policy_decision"]
    if not class_at_least(str(besluit["risk_class"]), min_risk_class):
        raise _forbidden(
            "risicoklasse_te_laag",
            "De risicoklasse in het verzoek is lager dan de eigen herberekening; er is niets uitgevoerd.",
            {"eigen_risk_class": min_risk_class},
        )
    approval = request.get("approval")
    if not isinstance(approval, Mapping):
        raise _forbidden("goedkeuring_ontbreekt", "Deze actie vraagt een menselijke goedkeuring.")
    skew = timedelta(seconds=CLOCK_SKEW)
    approved = parse_ts(approval.get("approved_at"))
    expires = parse_ts(approval.get("expires_at"))
    if approved is None or expires is None:  # pragma: no cover - al gecontroleerd in structure_errors
        raise Refusal(422, "execution_request_ongeldig", "Ongeldige tijd in de goedkeuring.")
    if approved > now + skew:
        raise _forbidden("goedkeuring_ongeldig", "De goedkeuring ligt in de toekomst.")
    if expires <= now:
        raise _forbidden("goedkeuring_verlopen", "De goedkeuring is verlopen (hooguit 15 minuten geldig).")
    if expires <= approved or (expires - approved).total_seconds() > MAX_APPROVAL_SECONDS:
        raise _forbidden("goedkeuring_ongeldig", "Een goedkeuring is hooguit 15 minuten geldig.")
    gebonden = {
        "policy_hash": approval.get("policy_hash") == besluit["policy_hash"],
        "resource_etag": approval.get("resource_etag") == prop.get("expected_version"),
        "action_scope": approval.get("action_scope")
        == action_scope(str(prop["action_id"]), prop["target"], prop["parameters"]),
        "risk_class": class_at_least(str(approval.get("risk_class")), min_risk_class),
        "preview_hash": approval.get("preview_hash") == preview_hash,
    }
    anders = sorted(k for k, ok in gebonden.items() if not ok)
    if anders:
        raise Refusal(
            409,
            "goedkeuring_past_niet",
            "De goedkeuring hoort niet (meer) bij deze actie; maak een nieuw voorstel en keur opnieuw goed.",
            {"gewijzigd": anders},
        )
    if requires_backup and not approval.get("backup_checkpoint_id"):
        raise Refusal(
            409, "backup_checkpoint_ontbreekt", "Deze actie vraagt een geverifieerd herstelpunt in de goedkeuring."
        )
    return approval
