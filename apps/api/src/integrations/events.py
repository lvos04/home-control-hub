"""Outbox met event-envelope (contract 1.3 §7).

Events worden in dezelfde transactie als de wijziging vastgelegd. De worker pusht ze naar
``POST {HUB_URL}/api/v1/events/inbox`` (service-token) met backoff; na 10 mislukte pogingen → ``dead_letter``
(zichtbaar via de connector en de Hub). De Hub kan ook pollen via ``GET /connector/v1/events?cursor=``.
Geen exact-once-aanname: de Hub dedupliceert op ``event_id``.

Grenzen van de Hub-inbox worden **vóór verzending** gecontroleerd (1.3 §7), zodat een event niet pas als dead-letter
opvalt: precies drie segmenten; eigen domeinen ``sso``, ``energy``, ``network``, ``automation``, ``flow``; gedeeld
alleen ``app.health.changed`` en de vaste ``service.*``-lijst (met ``entity`` = deze dienst); ``payload.ernst``
optioneel met een van de vijf Peil-woorden. Het derde segment is het werkwoord (probleem: ``failed`` …, herstel:
``recovered`` …, de rest informatie); ``entity`` is het stabiele onderwerp (ADR-0014).
"""

from __future__ import annotations

import json
import random
import re
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import APP_ID, SCHEMA_VERSION
from .models import OutboxEvent
from .redact import redact
from .timeutil import iso, utcnow

MAX_ATTEMPTS = 10
CLASSIFICATIONS = ("public", "internal", "sensitive")
# Contract §7: precies <domein>.<object>.<gebeurtenis>. Dezelfde regels als de inbox van de Hub
# (ai-server-manager apps/api/src/hub/events/envelope.py): anders weigert de Hub het event en eindigt het na
# 10 pogingen als dead-letter.
EVENT_TYPE_RE = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$")
ENTITY_TYPE_RE = re.compile(r"^[a-z0-9_.-]{1,60}$")  # kolom 60, Hub 64
MAX_PAYLOAD_BYTES = 16 * 1024
#: 1.3 §7: domeinen van home-control-hub (eerste segment); gedeeld: ``app`` (alleen app.health.changed) en ``service``
DOMAINS = frozenset({"sso", "energy", "network", "automation", "flow"})
SERVICE_EVENTS = frozenset(
    {
        "service.hub_link.linked",
        "service.hub_link.unlinked",
        "service.hub_link.revoked",
        "service.token.rotated",
        "service.key_rotation.applied",
        "service.key_rotation.rejected",
    }
)
#: 1.3 §7: vaste werkwoorden (derde segment) voor probleem en herstel; de rest is informatie
PROBLEM_VERBS = frozenset(
    {"failed", "crashed", "down", "degraded", "stalled", "blocked", "rejected", "saturated", "conflict"}
)
RECOVERY_VERBS = frozenset({"recovered", "succeeded", "resolved", "restored"})
#: 1.3 §7: platformbrede ernst (Peil-woorden) in ``payload.ernst`` (optioneel)
ERNST = ("kritiek", "hoog", "middel", "laag", "info")


def check_event_type(event_type: str, entity_type: str, entity_id: str) -> None:
    """De 1.3-regels van §7 voor deze bron; een afwijking is een programmeerfout (de Hub zou het event weigeren of
    alleen als algemene informatie verwerken)."""
    if len(event_type) > 120 or not EVENT_TYPE_RE.match(event_type):  # kolom 120, Hub 128
        raise ValueError(f"event_type moet precies <domein>.<object>.<gebeurtenis> zijn: {event_type!r}")
    domain = event_type.split(".", 1)[0]
    if domain == "service":
        if event_type not in SERVICE_EVENTS:
            raise ValueError(f"service-event buiten de vaste lijst van §7: {event_type!r}")
        if entity_type != "service" or entity_id != APP_ID:
            raise ValueError("een service-event heeft entity {type: service, id: home-control-hub}")
    elif domain == "app":
        if event_type != "app.health.changed":
            raise ValueError(f"domein 'app' alleen voor app.health.changed: {event_type!r}")
    elif domain not in DOMAINS:
        raise ValueError(f"domein {domain!r} hoort niet bij home-control-hub (§7)")


def event_role(event_type: str) -> str:
    """``probleem`` | ``herstel`` | ``info`` volgens het werkwoord (derde segment, §7)."""
    verb = event_type.rsplit(".", 1)[-1]
    if verb in PROBLEM_VERBS:
        return "probleem"
    if verb in RECOVERY_VERBS:
        return "herstel"
    return "info"


def _fit_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Payload binnen de grens van de Hub houden. Te groot → alleen de enkelvoudige velden plus ``_ingekort``
    (het event komt dan wél aan; de details staan in de audit/het bewijs van deze dienst)."""
    size = len(json.dumps(payload, default=str).encode("utf-8"))
    if size <= MAX_PAYLOAD_BYTES:
        return payload
    small = {k: v for k, v in payload.items() if isinstance(v, str | int | float | bool) or v is None}
    small = {k: (v[:500] if isinstance(v, str) else v) for k, v in small.items()}
    return {**small, "_ingekort": True, "_oorspronkelijke_bytes": size}


def emit(
    session: Session,
    *,
    event_type: str,
    entity_type: str,
    entity_id: str,
    actor_type: str,
    actor_id: str,
    trace_id: str,
    payload: dict[str, Any] | None = None,
    classification: str = "internal",
    correlation_id: str | None = None,
) -> OutboxEvent:
    if classification not in CLASSIFICATIONS:
        raise ValueError("ongeldige classificatie")
    check_event_type(event_type, entity_type, str(entity_id))
    if not ENTITY_TYPE_RE.match(entity_type) or not str(entity_id) or not actor_id:
        raise ValueError("ongeldige entity of actor voor de event-envelope")
    if payload is not None and "ernst" in payload and payload["ernst"] not in ERNST:
        raise ValueError(f"payload.ernst moet een van {', '.join(ERNST)} zijn")
    clean = _fit_payload(redact(payload or {}))
    ev = OutboxEvent(
        event_id=uuid.uuid4(),
        event_type=event_type,
        entity_type=entity_type,
        entity_id=str(entity_id)[:120],  # kolom 120 (Hub: 200); bv. een Authentik-gebruikersnaam tot 150
        trace_id=uuid.UUID(trace_id),
        correlation_id=uuid.UUID(correlation_id) if correlation_id else None,
        actor_type=actor_type if actor_type in ("system", "user", "ai", "flow") else "system",
        actor_id=actor_id[:128],  # Hub: 128
        classification=classification,
        payload=clean,
        timestamp_utc=utcnow(),
        next_attempt_at=utcnow(),
    )
    session.add(ev)
    return ev


def envelope(ev: OutboxEvent) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(ev.event_id),
        "source_app": APP_ID,
        "source_event_id": str(ev.seq),
        "event_type": ev.event_type,
        "entity": {"type": ev.entity_type, "id": ev.entity_id},
        "timestamp_utc": iso(ev.timestamp_utc),
        "trace_id": str(ev.trace_id),
        "correlation_id": str(ev.correlation_id) if ev.correlation_id else None,
        "actor": {"type": ev.actor_type, "id": ev.actor_id},
        "classification": ev.classification,
        "payload": ev.payload,
        "payload_ref": None,
    }


def due_for_push(session: Session, limit: int = 50) -> list[OutboxEvent]:
    stmt = (
        select(OutboxEvent)
        .where(OutboxEvent.delivery_status == "pending", OutboxEvent.next_attempt_at <= utcnow())
        .order_by(OutboxEvent.seq)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    return list(session.scalars(stmt))


def mark_delivered(ev: OutboxEvent) -> None:
    ev.delivery_status = "delivered"
    ev.delivered_at = utcnow()
    ev.last_error = None


def mark_failed(ev: OutboxEvent, error: str) -> None:
    ev.attempts += 1
    ev.last_error = error[:300]
    if ev.attempts >= MAX_ATTEMPTS:
        ev.delivery_status = "dead_letter"
        return
    base = min(3600.0, 5.0 * (2 ** (ev.attempts - 1)))
    ev.next_attempt_at = utcnow() + timedelta(seconds=base * random.uniform(0.8, 1.2))  # noqa: S311 (jitter)
