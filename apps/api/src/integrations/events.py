"""Outbox met event-envelope (contract §7).

Events worden in dezelfde transactie als de wijziging vastgelegd. De worker pusht ze naar
``POST {HUB_URL}/api/v1/events/inbox`` (service-token) met backoff; na 10 mislukte pogingen → ``dead_letter``
(zichtbaar via de connector en de Hub). De Hub kan ook pollen via ``GET /connector/v1/events?cursor=``.
Geen exact-once-aanname: de Hub dedupliceert op ``event_id``.
"""

from __future__ import annotations

import random
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
    if event_type.count(".") < 2:
        raise ValueError("event_type moet <domein>.<object>.<gebeurtenis> zijn")
    ev = OutboxEvent(
        event_id=uuid.uuid4(),
        event_type=event_type,
        entity_type=entity_type,
        entity_id=str(entity_id),
        trace_id=uuid.UUID(trace_id),
        correlation_id=uuid.UUID(correlation_id) if correlation_id else None,
        actor_type=actor_type if actor_type in ("system", "user", "ai", "flow") else "system",
        actor_id=actor_id,
        classification=classification,
        payload=redact(payload or {}),
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
