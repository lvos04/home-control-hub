"""Kerntabellen die voor alle domeinen gelden.

Domeintabellen staan in ``domains/<domein>/models.py``; ``all_models()`` importeert ze zodat Alembic en de
schema-drifttest het volledige model zien.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Identity,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base, Timestamps, new_id, utcnow


class ServiceState(Base):
    """Klein key/value-register voor de eigen toestand (koppeling met de Hub e.d.). Nooit geheimen."""

    __tablename__ = "service_state"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IdempotencyRecord(Base):
    """Opgeslagen resultaat per (principal, Idempotency-Key): herhaling geeft hetzelfde resultaat (contract §5)."""

    __tablename__ = "idempotency_record"
    principal: Mapped[str] = mapped_column(String(200), primary_key=True)
    key: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(500), nullable=False)
    request_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    response_body: Mapped[Any] = mapped_column(JSONB, nullable=True)
    response_headers: Mapped[dict[str, str]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (Index("ix_idempotency_record_created_at", "created_at"),)


class OutboxEvent(Base):
    """Uitgaande events (contract §7). Pollbaar via /connector/v1/events en gepusht naar de Hub-inbox."""

    __tablename__ = "outbox_event"
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True, default=new_id, nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(60), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(120), nullable=False)
    timestamp_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    trace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(200), nullable=False)
    classification: Mapped[str] = mapped_column(String(20), nullable=False, default="internal")
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    delivery_status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("classification IN ('public','internal','sensitive')", name="classification"),
        CheckConstraint("delivery_status IN ('pending','delivered','dead_letter')", name="delivery_status"),
        Index("ix_outbox_event_pending", "delivery_status", "next_attempt_at"),
    )


class VaultSecret(Base):
    """Versleutelde credentials van andere apps (AES-256-GCM, sleutel in secrets/vault.key).

    Tabellen elders bewaren alleen de referentie ``vault://<scope>/<naam>``; de API toont nooit de waarde terug.
    """

    __tablename__ = "vault_secret"
    ref: Mapped[str] = mapped_column(String(200), primary_key=True)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class IntegrationSource(Timestamps, Base):
    """Toestand per geconfigureerde bron (NetAlertX, AdGuard, Node-RED, Authentik, my_house, …).

    De catalogus (welke bronnen er kunnen komen) staat in code per domein; deze rij bestaat pas als een beheerder
    de bron configureert. Geen rij = 'niet geconfigureerd' (nooit 'gezond').
    """

    __tablename__ = "integration_source"
    source_id: Mapped[str] = mapped_column(String(60), primary_key=True)
    domain: Mapped[str] = mapped_column(String(20), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    credential_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_probe_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_probe_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    last_probe_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_probe_detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        CheckConstraint("domain IN ('network','automation','sso','energy')", name="domain"),
        CheckConstraint("last_probe_status IN ('healthy','degraded','down','unknown')", name="probe_status"),
        CheckConstraint("credential_ref IS NULL OR credential_ref LIKE 'vault://%'", name="credential_is_vault_ref"),
    )


class AuditEvent(Base):
    """Auditspoor van elke mutatie in deze dienst (geredigeerd, nooit geheimen)."""

    __tablename__ = "audit_event"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    domain: Mapped[str] = mapped_column(String(20), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(60), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(120), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(200), nullable=False)
    client_scope: Mapped[str | None] = mapped_column(String(20), nullable=True)
    trace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    message_nl: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (Index("ix_audit_event_at", "at"), Index("ix_audit_event_entity", "entity_type", "entity_id"))


def all_models() -> type[Base]:
    """Importeert alle domeinmodellen (voor Alembic en drifttests) en geeft de Base terug."""
    from .domains.automation import models as _automation  # noqa: F401
    from .domains.energy import models as _energy  # noqa: F401
    from .domains.network import models as _network  # noqa: F401
    from .domains.sso import models as _sso  # noqa: F401

    return Base
