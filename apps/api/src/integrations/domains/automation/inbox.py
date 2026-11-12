"""B11-002 — inname van events, de wachtrij per bron en de keten van herkomst.

- **Inname** (:func:`intake`): elk event wordt tegen de eventcatalogus gelegd en **altijd bewaard** met zijn status.
  Een event met een onbekende schema-versie, een onbekend type, een ongeldige payload of van een bron buiten haar
  domein wordt niet afgeleverd, maar blijft zichtbaar (lijst, health, event met een probleemwerkwoord): het verdwijnt
  nooit stil. Hetzelfde event nog een keer (zelfde ``event_id`` of ``source_app`` + ``source_event_id``) levert niets
  nieuws op (EX46).
- **Wachtrij per bron** (``automation_delivery``): per flow en per bron wordt alleen het oudste openstaande event
  uitgegeven; een mislukte verwerking blokkeert alleen de events van díe bron en wordt met oplopende wachttijd herhaald.
  Na tien pogingen gaat de aflevering naar ``dead_letter`` (zichtbaar, met event; handmatig opnieuw in te plannen).
- **Keten van herkomst**: een event dat het gevolg is van een actieverzoek van een flow draagt die flow in zijn keten
  (via ``correlation_id`` = het id van het actieverzoek en/of ``payload.origin_chain``). Een flow krijgt nooit een event
  uit een keten waar hij zelf al in zit; de keten is hooguit acht stappen lang.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ... import events
from ...models import OutboxEvent
from ...timeutil import iso, utcnow
from . import eventcatalog
from .models import (
    AutomationActionRequest,
    AutomationDelivery,
    AutomationEvent,
    AutomationExecutionNonce,
    AutomationFlow,
    AutomationFlowRun,
    AutomationTrigger,
)
from .snapshots import SYSTEM_ACTOR, state_get, state_put

MAX_ATTEMPTS = 10
LEASE = timedelta(seconds=120)
MAX_CHAIN = 8
MAX_CLAIM = 20
RETENTION = timedelta(days=30)
WATERMARK_KEY = "automation_outbox_watermark"
OUTBOX_LAG = timedelta(seconds=5)
MAX_RAW_PAYLOAD = 64 * 1024
CHAIN_ENTRY_RE = re.compile(r"^flow:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
ERROR_RE = re.compile(r"^[a-z0-9_.-]{1,80}$")
REJECT_EVENT_WINDOW = timedelta(hours=1)


def chain_entry(flow_id: uuid.UUID) -> str:
    return f"flow:{flow_id}"


def backoff(attempts: int) -> timedelta:
    return timedelta(seconds=min(3600, 30 * 2 ** max(0, attempts - 1)))


def clean_chain(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for entry in value[: MAX_CHAIN * 2]:
        if isinstance(entry, str) and CHAIN_ENTRY_RE.fullmatch(entry) and entry not in out:
            out.append(entry)
    return out


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(value) if isinstance(value, str) else None
    except ValueError:
        return None


def origin_chain_of(session: Session, envelope: dict[str, Any]) -> list[str]:
    """De keten van herkomst van een event: die van het actieverzoek waar het bij hoort, plus wat het event meldt."""
    chain: list[str] = []
    correlation = _as_uuid(envelope.get("correlation_id"))
    if correlation is not None:
        request = session.get(AutomationActionRequest, correlation)
        if request is not None:
            chain.extend(clean_chain(list(request.origin_chain or [])))
            own = chain_entry(request.flow_id)
            if own not in chain:
                chain.append(own)
    payload = envelope.get("payload")
    if isinstance(payload, dict):
        for entry in clean_chain(payload.get("origin_chain")):
            if entry not in chain:
                chain.append(entry)
    return chain


@dataclass
class IntakeResult:
    event: AutomationEvent
    duplicate: bool
    deliveries: int = 0
    skipped: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event.event_id),
            "seq": self.event.seq,
            "catalog_status": self.event.catalog_status,
            "catalog_detail": self.event.catalog_detail,
            "duplicaat": self.duplicate,
            "afleveringen": self.deliveries,
            "niet_afgeleverd": self.skipped[:20],
            "bewaard": True,
        }


def _existing(session: Session, event_id: uuid.UUID, source_app: str, source_event_id: str) -> AutomationEvent | None:
    row = session.scalars(select(AutomationEvent).where(AutomationEvent.event_id == event_id)).first()
    if row is not None:
        return row
    return session.scalars(
        select(AutomationEvent).where(
            AutomationEvent.source_app == source_app, AutomationEvent.source_event_id == source_event_id
        )
    ).first()


def _matches(trigger: AutomationTrigger, envelope: dict[str, Any]) -> bool:
    flt = trigger.filter or {}
    if flt.get("source_app") and flt["source_app"] != envelope.get("source_app"):
        return False
    entity = _as_dict(envelope.get("entity"))
    return not (flt.get("entity_type") and flt["entity_type"] != entity.get("type"))


def _safe_payload(envelope: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        detail["payload_bewaard"] = False
        return {}
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_RAW_PAYLOAD:
        detail["payload_bewaard"] = False
        detail["payload_bytes"] = len(raw)
        detail["payload_sha256"] = hashlib.sha256(raw).hexdigest()
        return {}
    return payload


def intake(
    session: Session,
    envelope: dict[str, Any],
    *,
    received_by: str,
    trace_id: str,
    now: datetime | None = None,
    test_run: AutomationFlowRun | None = None,
) -> IntakeResult:
    """Neemt één event aan. Gooit :class:`eventcatalog.EnvelopeError` als de envelope niet te bewaren is."""
    now = now or utcnow()
    verdict = eventcatalog.classify(envelope)
    event_id = uuid.UUID(str(envelope["event_id"]))
    source_app, source_event_id = str(envelope["source_app"]), str(envelope["source_event_id"])
    existing = _existing(session, event_id, source_app, source_event_id)
    if existing is not None:
        return IntakeResult(event=existing, duplicate=True)
    detail = dict(verdict.detail)
    entity = _as_dict(envelope.get("entity"))
    actor = _as_dict(envelope.get("actor"))
    classification = envelope.get("classification")
    chain = origin_chain_of(session, envelope)
    row = AutomationEvent(
        event_id=event_id,
        source_app=source_app,
        source_event_id=source_event_id,
        envelope_version=str(envelope["schema_version"]),
        event_type=str(envelope["event_type"]),
        entity_type=str(entity.get("type"))[:64] if isinstance(entity.get("type"), str) else None,
        entity_id=str(entity.get("id"))[:200] if isinstance(entity.get("id"), str) else None,
        timestamp_utc=eventcatalog.parse_timestamp(envelope.get("timestamp_utc")),
        trace_id=_as_uuid(envelope.get("trace_id")),
        correlation_id=_as_uuid(envelope.get("correlation_id")),
        actor={"type": str(actor.get("type"))[:20], "id": str(actor.get("id"))[:128]} if actor else {},
        classification=classification if classification in eventcatalog.CLASSIFICATIONS else None,
        payload=_safe_payload(envelope, detail),
        origin_chain=chain,
        catalog_status=verdict.status,
        catalog_detail=detail,
        received_at=now,
        received_by=received_by[:200],
        test_run_id=test_run.id if test_run is not None else None,
    )
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        # een gelijktijdige inname van hetzelfde event was eerder
        winner = _existing(session, event_id, source_app, source_event_id)
        if winner is None:
            raise
        return IntakeResult(event=winner, duplicate=True)
    result = IntakeResult(event=row, duplicate=False)
    if not verdict.deliverable:
        _report_rejected(session, row, trace_id, now)
        return result
    if row.classification == "sensitive":
        row.catalog_detail = {**detail, "niet_afgeleverd_reden": "classificatie_sensitive"}
        return result
    targets: list[AutomationFlow | None]
    if test_run is not None:
        targets = [session.get(AutomationFlow, test_run.flow_id)]
    else:
        triggers = session.scalars(
            select(AutomationTrigger).where(
                AutomationTrigger.event_type == row.event_type,
                AutomationTrigger.schema_version == row.envelope_version,
            )
        ).all()
        targets = [session.get(AutomationFlow, t.flow_id) for t in triggers if _matches(t, envelope)]
    for flow in targets:
        if flow is None:
            continue
        reason: str | None = None
        if test_run is None and flow.status != "actief":
            reason = f"flow_{flow.status}"
        elif chain_entry(flow.id) in chain:
            reason = "lus_gedetecteerd"
        elif len(chain) >= MAX_CHAIN:
            reason = "keten_te_lang"
        if reason is not None:
            result.skipped.append({"flow_id": str(flow.id), "reden": reason})
            continue
        session.add(
            AutomationDelivery(
                id=uuid.uuid4(),
                flow_id=flow.id,
                event_seq=row.seq,
                source_app=row.source_app,
                status="wachtend",
                attempts=0,
                next_attempt_at=now,
                created_at=now,
                run_id=test_run.id if test_run is not None else None,
            )
        )
        result.deliveries += 1
    if result.skipped:
        row.catalog_detail = {**detail, "niet_afgeleverd": result.skipped[:20]}
    session.flush()
    return result


def _report_rejected(session: Session, row: AutomationEvent, trace_id: str, now: datetime) -> None:
    """Eén probleem-event per bron, type en status per uur (de rij zelf blijft altijd zichtbaar)."""
    if row.test_run_id is not None:
        return
    earlier = session.scalar(
        select(func.count())
        .select_from(AutomationEvent)
        .where(
            AutomationEvent.source_app == row.source_app,
            AutomationEvent.event_type == row.event_type,
            AutomationEvent.catalog_status == row.catalog_status,
            AutomationEvent.received_at > now - REJECT_EVENT_WINDOW,
            AutomationEvent.seq != row.seq,
        )
    )
    if earlier:
        return
    events.emit(
        session,
        event_type="automation.event.rejected",
        entity_type="automation_event",
        entity_id=str(row.event_id),
        actor_type="system",
        actor_id=SYSTEM_ACTOR,
        trace_id=trace_id,
        payload={
            "ernst": "middel",
            "catalog_status": row.catalog_status,
            "event_type": row.event_type[:128],
            "source_app": row.source_app,
            "schema_version": row.envelope_version,
            "gevolg_nl": "Het event is bewaard maar niet afgeleverd aan flows.",
        },
    )


# ------------------------------------------------------------------------------------------------------------ uitgifte
def active_dry_run(session: Session, flow_id: uuid.UUID, now: datetime) -> AutomationFlowRun | None:
    return session.scalars(
        select(AutomationFlowRun)
        .where(
            AutomationFlowRun.flow_id == flow_id,
            AutomationFlowRun.mode == "dry_run",
            AutomationFlowRun.status == "bezig",
            AutomationFlowRun.expires_at > now,
        )
        .order_by(AutomationFlowRun.started_at.desc())
        .limit(1)
    ).first()


def dry_run_for(session: Session, flow: AutomationFlow, now: datetime) -> AutomationFlowRun | None:
    """De lopende proefrun die voor deze flow telt: nooit voor een geblokkeerde flow. Een proefrun die al liep vóór de
    blokkade wordt bij het blokkeren afgesloten (``simulate.close_for_block``); deze controle is de tweede laag. De
    flow krijgt dan niets en elk verzoek wordt geweigerd zoals bij elke geblokkeerde flow (ADR-0016 kop 2;
    vervolgpunt R-VEILIG-3 van S-P2-295)."""
    if flow.status == "geblokkeerd":
        return None
    return active_dry_run(session, flow.id, now)


def envelope_of(event: AutomationEvent) -> dict[str, Any]:
    return {
        "schema_version": event.envelope_version,
        "event_id": str(event.event_id),
        "source_app": event.source_app,
        "source_event_id": event.source_event_id,
        "event_type": event.event_type,
        "entity": {"type": event.entity_type, "id": event.entity_id},
        "timestamp_utc": iso(event.timestamp_utc),
        "trace_id": str(event.trace_id) if event.trace_id else None,
        "correlation_id": str(event.correlation_id) if event.correlation_id else None,
        "actor": event.actor,
        "classification": event.classification,
        "payload": event.payload,
        "payload_ref": None,
    }


def delivery_view(d: AutomationDelivery, event: AutomationEvent | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(d.id),
        "flow_id": str(d.flow_id),
        "event_seq": d.event_seq,
        "source_app": d.source_app,
        "status": d.status,
        "attempts": d.attempts,
        "next_attempt_at": iso(d.next_attempt_at),
        "lease_until": iso(d.lease_until),
        "last_error": d.last_error,
        "created_at": iso(d.created_at),
        "finished_at": iso(d.finished_at),
        "dry_run": d.run_id is not None,
        "run_id": str(d.run_id) if d.run_id else None,
    }
    if event is not None:
        out["event"] = envelope_of(event)
        out["origin_chain"] = list(event.origin_chain or [])
    return out


def _dead_letter(session: Session, d: AutomationDelivery, now: datetime, trace_id: str) -> None:
    d.status = "dead_letter"
    d.lease_until = None
    d.finished_at = now
    if d.run_id is not None:
        return
    events.emit(
        session,
        event_type="automation.delivery.failed",
        entity_type="flow",
        entity_id=str(d.flow_id),
        actor_type="system",
        actor_id=SYSTEM_ACTOR,
        trace_id=trace_id,
        payload={
            "ernst": "middel",
            "delivery_id": str(d.id),
            "source_app": d.source_app,
            "pogingen": d.attempts,
            "laatste_fout": d.last_error,
            "vervolg_nl": "De aflevering staat in dead_letter; een beheerder kan hem opnieuw inplannen.",
        },
    )


def release_expired(session: Session, now: datetime, trace_id: str, flow_id: uuid.UUID | None = None) -> int:
    """Een verlopen claim telt als een mislukte poging (de flow heeft niet bevestigd)."""
    stmt = select(AutomationDelivery).where(
        AutomationDelivery.status == "geclaimd", AutomationDelivery.lease_until < now
    )
    if flow_id is not None:
        stmt = stmt.where(AutomationDelivery.flow_id == flow_id)
    rows = session.scalars(stmt.with_for_update(skip_locked=True)).all()
    for d in rows:
        _fail(session, d, "claim_verlopen", now, trace_id)
    return len(rows)


def _fail(session: Session, d: AutomationDelivery, error: str, now: datetime, trace_id: str) -> None:
    d.attempts += 1
    d.last_error = error if ERROR_RE.fullmatch(error) else "onbekend"
    if d.run_id is not None or d.attempts >= MAX_ATTEMPTS:
        # een proefrun herhaalt niet: de uitzondering staat in het runlog
        _dead_letter(session, d, now, trace_id)
        return
    d.status = "wachtend"
    d.lease_until = None
    d.next_attempt_at = now + backoff(d.attempts)


def claim(
    session: Session, flow: AutomationFlow, *, limit: int, now: datetime, trace_id: str
) -> tuple[list[dict[str, Any]], AutomationFlowRun | None]:
    """Geeft per bron hooguit het oudste openstaande event uit. Tijdens een proefrun alleen de events van die run; een
    geblokkeerde flow krijgt niets, ook niet uit een proefrun die al liep vóór de blokkade (:func:`dry_run_for`)."""
    release_expired(session, now, trace_id, flow.id)
    run = dry_run_for(session, flow, now)
    if run is None and flow.status != "actief":
        return [], None
    stmt = select(AutomationDelivery).where(
        AutomationDelivery.flow_id == flow.id, AutomationDelivery.status.in_(("wachtend", "geclaimd"))
    )
    stmt = stmt.where(AutomationDelivery.run_id == run.id if run is not None else AutomationDelivery.run_id.is_(None))
    rows = session.scalars(stmt.order_by(AutomationDelivery.event_seq).limit(1000).with_for_update()).all()
    heads: dict[str, AutomationDelivery] = {}
    for d in rows:
        heads.setdefault(d.source_app, d)
    out: list[dict[str, Any]] = []
    for _source, d in sorted(heads.items(), key=lambda kv: kv[1].event_seq):
        if len(out) >= max(1, min(limit, MAX_CLAIM)):
            break
        if d.status != "wachtend" or d.next_attempt_at > now:
            continue  # deze bron wacht op een bevestiging of op de volgende poging: latere events blijven staan
        d.status = "geclaimd"
        d.lease_until = now + LEASE
        event = session.get(AutomationEvent, d.event_seq)
        view = delivery_view(d, event)
        view["attempt"] = d.attempts + 1
        out.append(view)
    return out, run


def get_delivery(session: Session, flow_id: uuid.UUID, delivery_id: uuid.UUID) -> AutomationDelivery | None:
    d = session.get(AutomationDelivery, delivery_id, with_for_update=True)
    return d if d is not None and d.flow_id == flow_id else None


def ack(session: Session, d: AutomationDelivery, now: datetime) -> bool:
    """``True`` als de aflevering nu (of al eerder) verwerkt is; ``False`` als hij niet geclaimd was."""
    if d.status == "verwerkt":
        return True
    if d.status != "geclaimd":
        return False
    d.status = "verwerkt"
    d.lease_until = None
    d.finished_at = now
    return True


def nack(session: Session, d: AutomationDelivery, error: str, now: datetime, trace_id: str) -> bool:
    if d.status != "geclaimd":
        return False
    _fail(session, d, error, now, trace_id)
    return True


def requeue(session: Session, d: AutomationDelivery, now: datetime) -> bool:
    if d.status != "dead_letter" or d.run_id is not None:
        return False
    d.status = "wachtend"
    d.attempts = 0
    d.finished_at = None
    d.next_attempt_at = now
    d.last_error = None
    return True


# ------------------------------------------------------------------------------------------------ eigen events (worker)
def feed_own_outbox(session: Session, now: datetime, trace_id: str, limit: int = 200) -> int:
    """Biedt de eigen events (Authentik, energie, netwerk, automatisering) aan de flows aan.

    Alleen events waarvoor een trigger bestaat worden overgenomen; de rest blijft alleen in de outbox naar de Hub."""
    state = state_get(session, WATERMARK_KEY)
    if state is None:
        # geen geschiedenis naspelen: begin bij wat er nu is
        latest = session.scalar(select(func.max(OutboxEvent.seq))) or 0
        state_put(session, WATERMARK_KEY, {"seq": int(latest), "sinds": iso(now)})
        return 0
    watermark = int(state.get("seq", 0))
    wanted = set(session.scalars(select(AutomationTrigger.event_type).distinct()).all())
    rows = session.scalars(
        select(OutboxEvent).where(OutboxEvent.seq > watermark).order_by(OutboxEvent.seq).limit(limit)
    ).all()
    taken = 0
    for ev in rows:
        if ev.timestamp_utc > now - OUTBOX_LAG:
            break  # een transactie met een lager volgnummer kan nog onderweg zijn
        watermark = ev.seq
        if ev.event_type not in wanted:
            continue
        try:
            result = intake(session, events.envelope(ev), received_by="worker:outbox", trace_id=trace_id, now=now)
        except eventcatalog.EnvelopeError:
            continue  # kan bij eigen events niet voorkomen; nooit de worker laten vastlopen
        taken += 0 if result.duplicate else 1
    state_put(session, WATERMARK_KEY, {**state, "seq": watermark, "bijgewerkt": iso(now)})
    return taken


def purge(session: Session, now: datetime) -> dict[str, int]:
    """Bewaartermijn: afgehandelde afleveringen en events ouder dan dertig dagen; verlopen nonces na een dag."""
    cutoff = now - RETENTION

    def removed(stmt: Any) -> int:
        result = session.execute(stmt)
        return int(getattr(result, "rowcount", 0) or 0)

    deliveries = removed(
        delete(AutomationDelivery).where(
            AutomationDelivery.status.in_(("verwerkt", "dead_letter")), AutomationDelivery.finished_at < cutoff
        )
    )
    open_events = select(AutomationDelivery.event_seq)
    removed_events = removed(
        delete(AutomationEvent).where(AutomationEvent.received_at < cutoff, AutomationEvent.seq.not_in(open_events))
    )
    nonces = removed(
        delete(AutomationExecutionNonce).where(AutomationExecutionNonce.expires_at < now - timedelta(days=1))
    )
    runs = removed(
        delete(AutomationFlowRun).where(AutomationFlowRun.status != "bezig", AutomationFlowRun.started_at < cutoff)
    )
    return {"afleveringen": deliveries, "events": removed_events, "nonces": nonces, "runs": runs}


def queue_stats(session: Session, now: datetime) -> dict[str, Any]:
    by_status = dict(
        session.execute(
            select(AutomationDelivery.status, func.count())
            .where(AutomationDelivery.run_id.is_(None))
            .group_by(AutomationDelivery.status)
        ).all()
    )
    rejected = dict(
        session.execute(
            select(AutomationEvent.catalog_status, func.count())
            .where(
                AutomationEvent.catalog_status != "geldig",
                AutomationEvent.test_run_id.is_(None),
                AutomationEvent.received_at > now - timedelta(hours=24),
            )
            .group_by(AutomationEvent.catalog_status)
        ).all()
    )
    oldest = session.scalar(
        select(func.min(AutomationDelivery.created_at)).where(
            AutomationDelivery.status.in_(("wachtend", "geclaimd")), AutomationDelivery.run_id.is_(None)
        )
    )
    return {
        "afleveringen": {str(k): int(v) for k, v in by_status.items()},
        "niet_afgeleverd_24u": {str(k): int(v) for k, v in rejected.items()},
        "oudste_wachtende": iso(oldest),
    }
