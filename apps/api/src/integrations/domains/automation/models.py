"""B11-datamodel (P2: Node-RED-automatisering met Hub-policy; migratie 0005).

Invarianten (in de database afgedwongen waar dat kan):
- Een momentopname van Node-RED (``automation_snapshot``) is onveranderlijk en versleuteld opgeslagen (AES-256-GCM met
  de vault-sleutel). Node-RED geeft via de admin-API nooit credentials terug; alleen als de datamap van Node-RED
  alleen-lezen is gekoppeld (``HCH_NODE_RED_DATA_DIR``) bevat de momentopname ook het door Node-RED zélf versleutelde
  ``flows_cred.json`` (``has_credentials``). Deze dienst kan die credentials niet lezen en logt ze nooit.
- Flowversies (per Node-RED-tabblad) zijn onveranderlijk, hebben een checksum en verwijzen naar hun momentopname.
- Een flow-token wordt alleen als SHA-256 bewaard (het geheim wordt één keer getoond).
- Actieverzoeken van flows hebben een unieke idempotency-key, een ontdubbelsleutel (EX46: vijf keer hetzelfde event →
  één actie) en een oorsprongsketen tegen lussen (B11-002). ``risk_claim`` van een flow is informatief; de Hub-policy
  bepaalt ``risk_class`` (EX18). Deze dienst zet een verzoek nooit zelf op ``uitgevoerd``: dat meldt alleen de Hub.
- Binnenkomende events met een onbekende schema-versie verdwijnen niet: ze blijven met hun status bewaard
  (``catalog_status``) en zijn zichtbaar via de API, de health en een event naar de Hub (B11-002).
- Een simulatie (``automation_flow_run`` met ``mode = dry_run``) maakt nooit een actieverzoek of outbox-event (B11-004).
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
    ForeignKey,
    Identity,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, Timestamps, new_id, utcnow

FLOW_STATUSES = ("actief", "gepauzeerd", "uitgeschakeld", "geblokkeerd", "verwijderd", "onbekend")
SNAPSHOT_REASONS = ("gepland", "handmatig", "voor_herstel", "na_herstel")
CATALOG_STATUSES = ("geldig", "onbekende_schema_versie", "onbekend_type", "ongeldige_payload", "buiten_domein")
DELIVERY_STATUSES = ("wachtend", "geclaimd", "verwerkt", "dead_letter")
REQUEST_STATUSES = ("aangevraagd", "wacht_op_goedkeuring", "uitgevoerd", "geweigerd", "mislukt")
RESTORE_STATUSES = ("voorgesteld", "uitgevoerd", "mislukt", "verlopen")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class AutomationFlow(Timestamps, Base):
    """Eén Node-RED-tabblad (``source_flow_id`` = id van het tabblad)."""

    __tablename__ = "automation_flow"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    source_flow_id: Mapped[str] = mapped_column(String(120), nullable=False)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    #: eigenaarlabel (B11-003 "owner labels"); zonder eigenaar geeft deze dienst geen flow-token uit
    owner: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="onbekend")
    current_version_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    disabled_in_node_red: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    blocked_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    blocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("source_id", "source_flow_id", name="uq_automation_flow_source"),
        CheckConstraint(_in("status", FLOW_STATUSES), name="status"),
        CheckConstraint("status <> 'geblokkeerd' OR blocked_reason IS NOT NULL", name="blocked_has_reason"),
    )


class AutomationSnapshot(Base):
    """Momentopname van de volledige Node-RED-configuratie (``GET /flows``, API v2), versleuteld opgeslagen."""

    __tablename__ = "automation_snapshot"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True, nullable=False)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    node_red_rev: Mapped[str | None] = mapped_column(String(64), nullable=True)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(20), nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, nullable=False)
    flow_count: Mapped[int] = mapped_column(Integer, nullable=False)
    policy_summary: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    node_red_version: Mapped[str | None] = mapped_column(String(40), nullable=True)
    #: True als het door Node-RED versleutelde credentials-bestand is meegenomen (B11-005 "inclusief credentials")
    has_credentials: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: sha256 van dat bestand (alleen om wijzigingen te zien; het bestand zelf zit in de versleutelde momentopname)
    credentials_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    trace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_in("reason", SNAPSHOT_REASONS), name="reason"),
        CheckConstraint("has_credentials = (credentials_sha256 IS NOT NULL)", name="credentials_hash"),
        CheckConstraint("checksum_sha256 ~ '^[0-9a-f]{64}$'", name="checksum_format"),
        Index("ix_automation_snapshot_source_seq", "source_id", "seq"),
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
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("automation_snapshot.id", ondelete="RESTRICT"), nullable=True
    )
    node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    policy_status: Mapped[str] = mapped_column(String(20), nullable=False, default="in_orde")
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)

    __table_args__ = (
        UniqueConstraint("flow_id", "seq", name="uq_automation_flow_version_seq"),
        CheckConstraint("credentials_ref IS NULL OR credentials_ref LIKE 'vault://%'", name="credentials_is_vault_ref"),
        CheckConstraint("checksum_sha256 ~ '^[0-9a-f]{64}$'", name="checksum_format"),
        CheckConstraint("policy_status IN ('in_orde','geblokkeerd')", name="policy_status"),
    )


class AutomationTrigger(Base):
    __tablename__ = "automation_trigger"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(120), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(10), nullable=False)
    filter: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, default=utcnow)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        UniqueConstraint("flow_id", "event_type", "schema_version", name="uq_automation_trigger_flow_type"),
    )


class AutomationFlowToken(Base):
    """Per-flow token (B11-003 "scoped per-flow token"): alleen de SHA-256 en de laatste 4 tekens."""

    __tablename__ = "automation_flow_token"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), nullable=False)
    token_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    last4: Mapped[str] = mapped_column(String(4), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="actief")
    label: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    #: scope: alleen deze action_id's mag de flow AANVRAGEN (uitvoeren kan een flow nooit)
    allowed_actions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("status IN ('actief','ingetrokken')", name="status"),
        CheckConstraint("jsonb_typeof(allowed_actions) = 'array'", name="allowed_actions_array"),
        CheckConstraint("token_sha256 ~ '^[0-9a-f]{64}$'", name="hash_format"),
        CheckConstraint("status <> 'ingetrokken' OR revoked_at IS NOT NULL", name="revoked_has_time"),
        Index("ix_automation_flow_token_flow", "flow_id", "status"),
    )


class AutomationEvent(Base):
    """Binnenkomend event (van de Hub, dienst-JWT) voor de triggers van flows; ook als het niet past (B11-002)."""

    __tablename__ = "automation_event"
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True)
    source_app: Mapped[str] = mapped_column(String(64), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(200), nullable=False)
    envelope_version: Mapped[str] = mapped_column(String(10), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entity_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    timestamp_utc: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    trace_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    classification: Mapped[str | None] = mapped_column(String(20), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    origin_chain: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    catalog_status: Mapped[str] = mapped_column(String(30), nullable=False)
    catalog_detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    received_by: Mapped[str] = mapped_column(String(200), nullable=False)
    #: gezet voor een voorbeeld-event van een simulatie (B11-004); zo'n event bereikt nooit een echte aflevering
    test_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("source_app", "source_event_id", name="uq_automation_event_source"),
        CheckConstraint(_in("catalog_status", CATALOG_STATUSES), name="catalog_status"),
        CheckConstraint("jsonb_typeof(origin_chain) = 'array'", name="origin_chain_array"),
        Index("ix_automation_event_status", "catalog_status", "received_at"),
    )


class AutomationDelivery(Base):
    """Aflevering van één event aan één flow; per bron (``source_app``) een eigen wachtrij met herhaling (B11-002)."""

    __tablename__ = "automation_delivery"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), nullable=False)
    event_seq: Mapped[int] = mapped_column(ForeignKey("automation_event.seq", ondelete="CASCADE"), nullable=False)
    source_app: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="wachtend")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: gezet = aflevering van een simulatie (dry-run): acties hierop worden alleen gelogd, nooit aangevraagd
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("automation_flow_run.id", ondelete="CASCADE"), nullable=True
    )

    __table_args__ = (
        UniqueConstraint("flow_id", "event_seq", name="uq_automation_delivery_flow_event"),
        CheckConstraint(_in("status", DELIVERY_STATUSES), name="status"),
        CheckConstraint("status <> 'geclaimd' OR lease_until IS NOT NULL", name="claim_has_lease"),
        Index("ix_automation_delivery_queue", "flow_id", "source_app", "status", "event_seq"),
    )


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
    version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("automation_flow_version.id", ondelete="SET NULL"), nullable=True
    )
    #: eerdere simulatie waarmee de uitkomst vergeleken wordt (B11 §4: diff met baseline)
    baseline_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    sample_ids: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    runlog: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

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
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=utcnow)
    token_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("automation_flow_token.id", ondelete="SET NULL"), nullable=True
    )
    trigger_delivery_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    trigger_event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    target: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    owner: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    risk_preview: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    dedupe_key: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    outbox_event_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    rejected_reason: Mapped[str | None] = mapped_column(String(80), nullable=True)
    #: wat de Hub terugmeldde (besluit, uitvoering); deze dienst vult dit nooit zelf
    hub_result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        CheckConstraint(_in("status", REQUEST_STATUSES), name="status"),
        CheckConstraint("jsonb_typeof(origin_chain) = 'array'", name="origin_chain_array"),
        CheckConstraint("status <> 'geweigerd' OR rejected_reason IS NOT NULL", name="rejected_has_reason"),
        CheckConstraint("risk_claim IS NULL OR risk_claim IN ('R0','R1','R2','R3')", name="risk_claim"),
        Index("ix_automation_action_request_flow", "flow_id", "action_id", "created_at"),
    )


class AutomationReplayKey(Base):
    """P0-tabel (ongewijzigd). Ontdubbelen gebeurt sinds P2 met ``uq_automation_event_source`` (zelfde bron-event),
    ``uq_automation_delivery_flow_event`` (één aflevering per flow en event) en ``dedupe_key`` op actieverzoeken."""

    __tablename__ = "automation_replay_key"
    flow_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("automation_flow.id", ondelete="CASCADE"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AutomationRateLimit(Base):
    """Per flow en actie: strengere grenzen dan de standaard van de actiecatalogus (nooit ruimer)."""

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


class AutomationRestore(Base):
    """Herstelvoorstel (B11-005): terug naar een momentopname; toepassen alleen met een ondertekend ExecutionRequest."""

    __tablename__ = "automation_restore"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    target_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("automation_snapshot.id", ondelete="RESTRICT"), nullable=False
    )
    base_rev: Mapped[str] = mapped_column(String(64), nullable=False)
    base_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    target_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    preview_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    plan: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="voorgesteld")
    requested_by: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pre_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("automation_snapshot.id", ondelete="RESTRICT"), nullable=True
    )
    post_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("automation_snapshot.id", ondelete="RESTRICT"), nullable=True
    )
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    trace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_in("status", RESTORE_STATUSES), name="status"),
        CheckConstraint("preview_hash ~ '^[0-9a-f]{64}$'", name="preview_hash_format"),
        CheckConstraint(
            "status <> 'uitgevoerd' OR (pre_snapshot_id IS NOT NULL AND post_snapshot_id IS NOT NULL "
            "AND applied_at IS NOT NULL)",
            name="applied_has_snapshots",
        ),
    )


class AutomationExecutionNonce(Base):
    """Eenmalige nonces van ondertekende ExecutionRequests (contract §8, EX20): een tweede keer wordt geweigerd."""

    __tablename__ = "automation_execution_nonce"
    nonce: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(80), nullable=False)
    request_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False, default="aangenomen")
