"""B11-003 — veilige acties: een flow vráágt een actie aan; deze dienst voert zelf nooit iets uit.

Het pad van een actieverzoek (``POST /integrations/v1/automation/flow-api/actions``, alleen met een flow-token):

1. harde weigerlijst — wordt nooit doorgestuurd: boiler (EX27), shell/sudo/docker/exec, vernietigende acties (een
   dataset verwijderen kan nooit via een flow: EX45), beleid/rollen/aanmelding, betaalde acties;
2. de actie moet binnen de scope van het token vallen;
3. tempolimiet per flow en actie (``429 rate_limited``; wordt niet vastgelegd);
4. ontdubbeling op het trigger-event: hetzelfde event levert voor dezelfde actie precies één verzoek op (EX46);
5. keten van herkomst: geen lus, hooguit acht stappen;
6. een **informatieve** risico-inschatting uit de vaste tabel van contract §8 — de ``risk_claim`` van de flow telt
   nooit (EX18); de Hub bepaalt de risicoklasse en vraagt bij R2/R3 een mens om goedkeuring;
7. het verzoek gaat als event ``flow.action.requested`` (in de vorm van een ActionProposal) naar de Hub.

Een geweigerd verzoek wordt vastgelegd (rij, audit en event ``flow.action.rejected``): de flow blijft auditbaar.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import audit, events
from ...redact import redact
from ...timeutil import iso
from . import inbox, policy
from .models import (
    AutomationActionRequest,
    AutomationDelivery,
    AutomationEvent,
    AutomationFlow,
    AutomationFlowRun,
    AutomationFlowToken,
    AutomationRateLimit,
)

ACTION_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,3}$")
SCOPE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,3}(\.\*)?$")
DEFAULT_MAX_PER_HOUR = 30
ANY_ACTION = "*"
MAX_PARAM_BYTES = 8 * 1024
#: zo lang mag de Hub een verzoek van een flow hooguit in behandeling nemen (ActionProposal.expires_in_seconds)
PROPOSAL_EXPIRES_S = 900

#: informatief: de vaste tabel van contract §8 (allowlist v1 van de executor). De Hub beslist; dit is alleen een
#: inschatting voor de eigenaar van de flow.
RISK_TABLE: dict[str, str] = {
    "notification.send": "R0",
    "app.restart": "R1",
    "app.stop": "R1",
    "app.start": "R1",
    "zfs.snapshot.create": "R1",
    "zfs.snapshot.clone_to_sandbox": "R1",
    "app.install": "R2",
    "app.update": "R2",
    "app.rollback": "R2",
    "app.uninstall": "R2",
}

REFUSALS_NL = {
    "boiler_nooit": "De boiler wordt nooit door een automatisering geschakeld.",
    "shell_verboden": "Shell-, sudo-, exec- en Docker-acties kunnen niet via een flow.",
    "destructief_verboden": "Verwijderen of wissen (bijvoorbeeld een dataset) kan nooit via een flow.",
    "beleid_verboden": "Beleid, rollen en aanmelding kunnen niet door een flow worden gewijzigd.",
    "betaald_verboden": "Betaalde acties kunnen niet via een flow.",
    "buiten_scope": "Deze actie valt buiten wat het token van deze flow mag aanvragen.",
    "lus_gedetecteerd": "Deze flow zit al in de keten van dit event; het verzoek zou een lus maken.",
    "keten_te_lang": "De keten van flows die op elkaar reageren is te lang.",
    "flow_geblokkeerd": "Deze flow is geblokkeerd door het flowbeleid.",
    "flow_niet_actief": "Deze flow is niet actief.",
    "geheim_in_parameters": "De parameters lijken een geheim te bevatten; geheimen horen nooit in een actieverzoek.",
}
#: acties die alleen tekst afleveren en niets schakelen: hun parameters worden niet op "boiler" doorzocht
TEXT_ONLY_ACTIONS = frozenset({"notification.send"})
_BOILER = ("boiler", "warmwater", "hot_water", "water_heater")
_DESTRUCTIVE = frozenset({"delete", "destroy", "remove", "wipe", "purge", "format", "erase", "uninstall_data"})
_SHELL = frozenset({"shell", "sudo", "docker", "exec", "ssh", "bash", "sh"})
_POLICY_DOMAINS = frozenset({"policy", "auth", "role", "roles", "rbac", "sso", "user", "users", "permission"})
_PAID = frozenset({"billing", "payment", "purchase", "overage", "betaling", "betaald"})


def local_refusal(action_id: str, target: dict[str, Any], parameters: dict[str, Any]) -> str | None:
    """De harde weigerlijst. Wat hier geweigerd wordt gaat nooit naar de Hub."""
    scanned: dict[str, Any] = {"t": target}
    if action_id not in TEXT_ONLY_ACTIONS:
        # de tekst van een melding ("de boiler verbruikt veel") schakelt niets; elk ander verzoek wordt volledig bekeken
        scanned["p"] = parameters
    haystack = (action_id + " " + policy.canonical(scanned).decode("utf-8")).lower()
    if any(word in haystack for word in _BOILER):
        return "boiler_nooit"
    parts = action_id.lower().split(".")
    segments = set(parts) | {w for part in parts for w in part.split("_")}
    if segments & _SHELL:
        return "shell_verboden"
    if segments & _DESTRUCTIVE or "uninstall_data" in action_id:
        return "destructief_verboden"
    if parts[0] in _POLICY_DOMAINS or segments & {"policy", "rbac"}:
        return "beleid_verboden"
    if segments & _PAID:
        return "betaald_verboden"
    return None


def scope_problem(action: str) -> str | None:
    """Mag deze actie (of dit patroon ``<prefix>.*``) in de scope van een token staan?"""
    if not SCOPE_RE.fullmatch(action) or len(action) > 80:
        return "geen geldige actie of patroon (<domein>.<object>[.<actie>] of <prefix>.*)"
    probe = action[:-2] + ".x" if action.endswith(".*") else action
    refusal = local_refusal(probe, {}, {})
    return REFUSALS_NL[refusal] if refusal else None


def in_scope(action_id: str, allowed: list[str]) -> bool:
    return any(entry == action_id or (entry.endswith(".*") and action_id.startswith(entry[:-1])) for entry in allowed)


def risk_preview(action_id: str, risk_claim: str | None) -> dict[str, Any]:
    known = RISK_TABLE.get(action_id)
    return {
        "bekend": known is not None,
        "klasse_min": known,
        "goedkeuring_vereist": (known in ("R2", "R3")) if known is not None else None,
        "risk_claim": risk_claim,
        "risk_claim_genegeerd": True,
        "bron": "contract §8 (allowlist v1); de Hub bepaalt de risicoklasse",
    }


def dedupe_key(
    flow_id: uuid.UUID, trigger_event_id: uuid.UUID, action_id: str, target: dict[str, Any], parameters: dict[str, Any]
) -> str:
    raw = b"|".join(
        (
            str(flow_id).encode(),
            str(trigger_event_id).encode(),
            action_id.encode(),
            policy.canonical(target),
            policy.canonical(parameters),
        )
    )
    return hashlib.sha256(raw).hexdigest()


def request_view(row: AutomationActionRequest) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "flow_id": str(row.flow_id),
        "action_id": row.action_id,
        "target": row.target,
        "parameters": row.parameters,
        "reason": row.reason,
        "owner": row.owner,
        "status": row.status,
        "rejected_reason": row.rejected_reason,
        "risk_claim": row.risk_claim,
        "risk_preview": row.risk_preview,
        "hub_risk_class": row.hub_risk_class,
        "hub_proposal_id": row.hub_proposal_id,
        "hub_result": row.hub_result,
        "origin_chain": list(row.origin_chain or []),
        "trigger_event_id": str(row.trigger_event_id) if row.trigger_event_id else None,
        "created_at": iso(row.created_at),
        "updated_at": iso(row.updated_at),
        "uitvoering": "door de Hub (policy, goedkeuring en executor); deze dienst voert niets uit",
    }


class RateLimited(Exception):
    def __init__(self, retry_after: int, limit: dict[str, Any]) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after
        self.limit = limit


def _limits(session: Session, flow_id: uuid.UUID, action_id: str) -> tuple[int, int]:
    rows = {
        r.action_id: r
        for r in session.scalars(
            select(AutomationRateLimit).where(
                AutomationRateLimit.flow_id == flow_id, AutomationRateLimit.action_id.in_((action_id, ANY_ACTION))
            )
        )
    }
    row = rows.get(action_id) or rows.get(ANY_ACTION)
    return (row.max_per_hour, row.cooldown_s) if row is not None else (DEFAULT_MAX_PER_HOUR, 0)


def check_rate(session: Session, flow_id: uuid.UUID, action_id: str, now: datetime) -> None:
    max_per_hour, cooldown_s = _limits(session, flow_id, action_id)
    window = now - timedelta(hours=1)
    count, oldest, newest = session.execute(
        select(
            func.count(), func.min(AutomationActionRequest.created_at), func.max(AutomationActionRequest.created_at)
        ).where(
            AutomationActionRequest.flow_id == flow_id,
            AutomationActionRequest.action_id == action_id,
            AutomationActionRequest.created_at > window,
        )
    ).one()
    limit = {"max_per_uur": max_per_hour, "wachttijd_s": cooldown_s}
    if count >= max_per_hour:
        wait = int((oldest + timedelta(hours=1) - now).total_seconds()) + 1 if oldest else 60
        raise RateLimited(max(1, wait), limit)
    if cooldown_s and newest is not None and (now - newest).total_seconds() < cooldown_s:
        raise RateLimited(max(1, int(cooldown_s - (now - newest).total_seconds()) + 1), limit)


@dataclass
class Outcome:
    status_code: int
    body: dict[str, Any]
    refused_reason: str | None = None


def _trigger(
    session: Session, flow: AutomationFlow, delivery_id: uuid.UUID | None
) -> tuple[AutomationDelivery | None, AutomationEvent | None, str | None]:
    if delivery_id is None:
        return None, None, None
    delivery = session.get(AutomationDelivery, delivery_id)
    if delivery is None or delivery.flow_id != flow.id:
        return None, None, "aflevering_onbekend"
    return delivery, session.get(AutomationEvent, delivery.event_seq), None


def request_action(
    session: Session,
    *,
    flow: AutomationFlow,
    token: AutomationFlowToken,
    key: uuid.UUID,
    action_id: str,
    target: dict[str, Any],
    parameters: dict[str, Any],
    reason: str,
    risk_claim: str | None,
    trigger_delivery_id: uuid.UUID | None,
    trace_id: str,
    now: datetime,
) -> Outcome:
    """Beoordeelt en registreert één actieverzoek. Gooit :class:`RateLimited`; committeert niet."""
    delivery, trigger_event, trigger_error = _trigger(session, flow, trigger_delivery_id)
    chain = list(trigger_event.origin_chain or []) if trigger_event is not None else []
    refusal: str | None = None
    if redact({"p": parameters, "t": target}) != {"p": parameters, "t": target}:
        refusal = "geheim_in_parameters"
    refusal = refusal or local_refusal(action_id, target, parameters)
    if refusal is None and not in_scope(action_id, list(token.allowed_actions or [])):
        refusal = "buiten_scope"
    if refusal is None and inbox.chain_entry(flow.id) in chain:
        refusal = "lus_gedetecteerd"
    if refusal is None and len(chain) >= inbox.MAX_CHAIN:
        refusal = "keten_te_lang"
    preview = risk_preview(action_id, risk_claim)
    stored_parameters = {} if refusal == "geheim_in_parameters" else parameters
    stored_target = {} if refusal == "geheim_in_parameters" else target

    run = inbox.active_dry_run(session, flow.id, now)
    if run is not None:
        return _simulate(run, action_id, stored_target, stored_parameters, refusal, preview, trigger_error, now)
    if flow.status == "geblokkeerd":
        refusal = refusal or "flow_geblokkeerd"
    elif flow.status != "actief":
        refusal = refusal or "flow_niet_actief"
    if trigger_error is not None:
        return Outcome(
            422,
            {
                "code": "trigger_ongeldig",
                "message": "De opgegeven aflevering hoort niet bij deze flow.",
                "details": {"reason": trigger_error},
            },
        )
    check_rate(session, flow.id, action_id, now)
    dkey: str | None = None
    if trigger_event is not None and refusal is None:
        dkey = dedupe_key(flow.id, trigger_event.event_id, action_id, target, parameters)
        earlier = session.scalars(
            select(AutomationActionRequest).where(AutomationActionRequest.dedupe_key == dkey)
        ).first()
        if earlier is not None:
            return Outcome(200, {**request_view(earlier), "ontdubbeld": True})
    row = AutomationActionRequest(
        id=uuid.uuid4(),
        flow_id=flow.id,
        idempotency_key=key,
        action_id=action_id,
        risk_claim=risk_claim,
        origin_chain=chain,
        status="geweigerd" if refusal else "aangevraagd",
        created_at=now,
        updated_at=now,
        token_id=token.id,
        trigger_delivery_id=delivery.id if delivery is not None else None,
        trigger_event_id=trigger_event.event_id if trigger_event is not None else None,
        target=stored_target,
        parameters=stored_parameters,
        reason=reason[:500],
        owner=flow.owner,
        risk_preview=preview,
        dedupe_key=dkey,
        rejected_reason=refusal,
        hub_result={},
    )
    session.add(row)
    session.flush()
    actor = ("flow", inbox.chain_entry(flow.id))
    if refusal is not None:
        audit.record(
            session,
            domain="automation",
            action="automation.action.rejected",
            entity_type="flow",
            entity_id=str(flow.id),
            principal=None,
            actor_override=actor,
            trace_id=trace_id,
            message_nl=f"Actieverzoek van flow '{flow.label}' geweigerd: {REFUSALS_NL[refusal]}",
            details={"action_request_id": str(row.id), "action_id": action_id, "reden": refusal},
        )
        events.emit(
            session,
            event_type="flow.action.rejected",
            entity_type="flow",
            entity_id=str(flow.id),
            actor_type="flow",
            actor_id=actor[1],
            trace_id=trace_id,
            correlation_id=str(row.id),
            payload={
                "ernst": "hoog" if refusal in ("boiler_nooit", "shell_verboden", "destructief_verboden") else "middel",
                "action_request_id": str(row.id),
                "action_id": action_id,
                "reden": refusal,
                "label": flow.label,
                "owner": flow.owner,
            },
        )
        return Outcome(
            403,
            {
                "code": "forbidden",
                "message": REFUSALS_NL[refusal],
                "details": {"reason": refusal, "action_request_id": str(row.id)},
            },
            refused_reason=refusal,
        )
    outbox = events.emit(
        session,
        event_type="flow.action.requested",
        entity_type="flow",
        entity_id=str(flow.id),
        actor_type="flow",
        actor_id=actor[1],
        trace_id=trace_id,
        correlation_id=str(row.id),
        payload={
            "action_request_id": str(row.id),
            "idempotency_key": str(key),
            "action_id": action_id,
            "target": target,
            "parameters": parameters,
            "reason": reason[:500],
            "actor": {"type": "flow", "id": actor[1]},
            "expected_version": None,
            "evidence_ids": [str(trigger_event.event_id)] if trigger_event is not None else [],
            "expires_in_seconds": PROPOSAL_EXPIRES_S,
            "owner": flow.owner,
            "flow": {"id": str(flow.id), "label": flow.label, "version": flow.version},
            "trigger_event_id": str(trigger_event.event_id) if trigger_event is not None else None,
            "origin_chain": [*chain, inbox.chain_entry(flow.id)],
            "risk_claim_genegeerd": True,
        },
    )
    session.flush()
    row.outbox_event_id = outbox.event_id
    audit.record(
        session,
        domain="automation",
        action="automation.action.requested",
        entity_type="flow",
        entity_id=str(flow.id),
        principal=None,
        actor_override=actor,
        trace_id=trace_id,
        message_nl=f"Flow '{flow.label}' vraagt actie {action_id} aan bij de Hub.",
        details={"action_request_id": str(row.id), "action_id": action_id, "risico_inschatting": preview},
    )
    return Outcome(202, {**request_view(row), "ontdubbeld": False})


def _simulate(
    run: AutomationFlowRun,
    action_id: str,
    target: dict[str, Any],
    parameters: dict[str, Any],
    refusal: str | None,
    preview: dict[str, Any],
    trigger_error: str | None,
    now: datetime,
) -> Outcome:
    """Tijdens een proefrun wordt niets aangevraagd: geen rij, geen event naar de Hub, geen echte wijziging."""
    outcome = "zou_worden_geweigerd" if refusal else "zou_worden_aangevraagd"
    entry = {
        "t": iso(now),
        "soort": "actie",
        "action_id": action_id,
        "target": target,
        "parameter_namen": sorted(str(k)[:60] for k in parameters)[:40],
        "uitkomst": outcome,
        "reden": refusal,
        "risico_inschatting": preview,
        "trigger_fout": trigger_error,
    }
    run.runlog = [*list(run.runlog or []), entry][-500:]
    return Outcome(
        200,
        {
            "dry_run": True,
            "run_id": str(run.id),
            "status": "gesimuleerd",
            "uitkomst": outcome,
            "reden": refusal,
            "risk_preview": preview,
            "resultaat": {
                "status": "gesimuleerd",
                "toelichting_nl": "Proefrun: er is niets aangevraagd en niets gewijzigd.",
            },
        },
    )


FINAL_STATUSES = ("uitgevoerd", "geweigerd", "mislukt")
RESULT_STATUSES = ("wacht_op_goedkeuring", *FINAL_STATUSES)


def record_result(
    row: AutomationActionRequest,
    *,
    status: str,
    hub_proposal_id: str | None,
    hub_risk_class: str | None,
    reason: str | None,
    result: dict[str, Any],
    now: datetime,
) -> bool:
    """De Hub meldt wat er met het verzoek gebeurd is. Een afgerond verzoek verandert niet meer."""
    if row.status in FINAL_STATUSES:
        return False
    row.status = status
    row.updated_at = now
    row.hub_proposal_id = hub_proposal_id or row.hub_proposal_id
    row.hub_risk_class = hub_risk_class or row.hub_risk_class
    row.hub_result = redact(result)
    if status == "geweigerd":
        row.rejected_reason = (reason or "hub_beleid")[:80]
    return True
