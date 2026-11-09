"""B11-datamodel (P0: alleen schema).

Invarianten:
- Flowversies zijn onveranderlijk en hebben een checksum; credentials alleen als vault-referentie.
- Actieverzoeken van flows hebben een idempotency-key (EX46: vijf keer hetzelfde event → één actie) en een
  oorsprongsketen tegen lussen (B11-002).
- ``risk_claim`` van een flow is informatief; de Hub-policy bepaalt ``risk_class`` (EX18).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, Timestamps, new_id


class AutomationFlow(Timestamps, Base):
    __tablename__ = "automation_flow"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    source_flow_id: Mapped[str] = mapped_column(String(120), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="onbekend")
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("source_id", "source_flow_id", name="uq_automation_flow_source"),
        CheckConstraint("status IN ('actief','gepauzeerd','uitgeschakeld','onbekend')", name="status"),
    )


class AutomationFlowVersion(Base):
    __tablename__ = "automation_flow_version"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    export_ref: Mapped[str | None] = mapped_column(String(300), nullable=True)
    credentials_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    node_types: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("flow_id", "seq", name="uq_automation_flow_version_seq"),
        CheckConstraint("credentials_ref IS NULL OR credentials_ref LIKE 'vault://%'", name="credentials_is_vault_ref"),
        CheckConstraint("checksum_sha256 ~ '^[0-9a-f]{64}$'", name="checksum_format"),
    )


class AutomationTrigger(Base):
    __tablename__ = "automation_trigger"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(10), nullable=False)
    filter: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class AutomationFlowRun(Base):
    __tablename__ = "automation_flow_run"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), nullable=False)
    trigger_event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    mode: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(80), nullable=True)

    __table_args__ = (
        CheckConstraint("mode IN ('echt','dry_run')", name="mode"),
        CheckConstraint("status IN ('bezig','klaar','mislukt','geweigerd')", name="status"),
    )


class AutomationActionRequest(Base):
    __tablename__ = "automation_action_request"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("automation_flow_run.id", ondelete="SET NULL"), nullable=True
    )
    idempotency_key: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True)
    action_id: Mapped[str] = mapped_column(String(80), nullable=False)
    risk_claim: Mapped[str | None] = mapped_column(String(2), nullable=True)
    hub_risk_class: Mapped[str | None] = mapped_column(String(2), nullable=True)
    origin_chain: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="aangevraagd")
    hub_proposal_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "status IN ('aangevraagd','wacht_op_goedkeuring','uitgevoerd','geweigerd','mislukt')", name="status"
        ),
        CheckConstraint("jsonb_typeof(origin_chain) = 'array'", name="origin_chain_array"),
    )


class AutomationReplayKey(Base):
    """Dedupe van binnenkomende events per flow (EX46)."""

    __tablename__ = "automation_replay_key"
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AutomationRateLimit(Base):
    __tablename__ = "automation_rate_limit"
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    max_per_hour: Mapped[int] = mapped_column(Integer, nullable=False)
    cooldown_s: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (CheckConstraint("max_per_hour >= 0 AND cooldown_s >= 0", name="limits"),)


class AutomationFlowOwner(Base):
    __tablename__ = "automation_flow_owner"
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), primary_key=True)
    principal: Mapped[str] = mapped_column(String(200), primary_key=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (CheckConstraint("role IN ('eigenaar','bewerker','lezer')", name="role"),)
