"""B11 (P2): Node-RED-automatisering — momentopnamen, flow-tokens, events en afleveringen, herstel

Nieuw:
- ``automation_snapshot``: versleutelde momentopnamen van de Node-RED-configuratie (B11-005);
- ``automation_flow_token``: per-flow tokens, alleen als SHA-256 (B11-003);
- ``automation_event`` en ``automation_delivery``: binnenkomende events en de wachtrij per bron en flow (B11-002);
- ``automation_restore``: herstelvoorstellen (B11-005);
- ``automation_execution_nonce``: eenmalige nonces van ondertekende ExecutionRequests (contract §8).

Gewijzigd (P0-tabellen): ``automation_flow`` (status ``geblokkeerd``/``verwijderd`` met reden, laatst gezien),
``automation_flow_version`` (momentopname, policy-uitkomst), ``automation_trigger`` (uniek per flow en type),
``automation_flow_run`` (simulatie: voorbeeld-events, runlog, uitkomst), ``automation_action_request`` (doel,
parameters, reden, eigenaar, risicovoorbeeld, ontdubbelsleutel, weigerreden, terugmelding van de Hub).

Bestaande rijen: een actieverzoek met status ``geweigerd`` zonder reden (van vóór deze revisie, of na
``migrate --down 0004``, waarbij de reden vervalt) krijgt de reden ``reden_onbekend``; zo faalt de nieuwe
CHECK-constraint niet en gaat er niets verloren.

Terugdraaien: de nieuwe tabellen en kolommen vervallen (momentopnamen, tokens, events, afleveringen en
herstelvoorstellen gaan daarbij verloren); flows met status ``geblokkeerd`` of ``verwijderd`` worden ``onbekend``.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-11 10:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FLOW_STATUS_OUD = "status IN ('actief','gepauzeerd','uitgeschakeld','onbekend')"
FLOW_STATUS_NIEUW = "status IN ('actief', 'gepauzeerd', 'uitgeschakeld', 'geblokkeerd', 'verwijderd', 'onbekend')"


def upgrade() -> None:
    op.create_table(
        "automation_event",
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("source_app", sa.String(length=64), nullable=False),
        sa.Column("source_event_id", sa.String(length=200), nullable=False),
        sa.Column("envelope_version", sa.String(length=10), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("entity_type", sa.String(length=64), nullable=True),
        sa.Column("entity_id", sa.String(length=200), nullable=True),
        sa.Column("timestamp_utc", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trace_id", sa.UUID(), nullable=True),
        sa.Column("correlation_id", sa.UUID(), nullable=True),
        sa.Column("actor", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("classification", sa.String(length=20), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("origin_chain", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("catalog_status", sa.String(length=30), nullable=False),
        sa.Column("catalog_detail", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_by", sa.String(length=200), nullable=False),
        sa.Column("test_run_id", sa.UUID(), nullable=True),
        sa.CheckConstraint(
            "catalog_status IN ('geldig', 'onbekende_schema_versie', 'onbekend_type', 'ongeldige_payload', 'buiten_domein')",
            name=op.f(op.f("ck_automation_event_catalog_status")),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(origin_chain) = 'array'", name=op.f(op.f("ck_automation_event_origin_chain_array"))
        ),
        sa.PrimaryKeyConstraint("seq", name=op.f("pk_automation_event")),
        sa.UniqueConstraint("event_id", name=op.f("uq_automation_event_event_id")),
        sa.UniqueConstraint("source_app", "source_event_id", name="uq_automation_event_source"),
    )
    op.create_index("ix_automation_event_status", "automation_event", ["catalog_status", "received_at"], unique=False)
    op.create_table(
        "automation_execution_nonce",
        sa.Column("nonce", sa.UUID(), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("request_sha256", sa.String(length=64), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.PrimaryKeyConstraint("nonce", name=op.f("pk_automation_execution_nonce")),
    )
    op.create_table(
        "automation_snapshot",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("node_red_rev", sa.String(length=64), nullable=True),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=20), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("node_count", sa.Integer(), nullable=False),
        sa.Column("flow_count", sa.Integer(), nullable=False),
        sa.Column("policy_summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("node_red_version", sa.String(length=40), nullable=True),
        sa.Column("has_credentials", sa.Boolean(), nullable=False),
        sa.Column("credentials_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("trace_id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "checksum_sha256 ~ '^[0-9a-f]{64}$'", name=op.f(op.f("ck_automation_snapshot_checksum_format"))
        ),
        sa.CheckConstraint(
            "reason IN ('gepland', 'handmatig', 'voor_herstel', 'na_herstel')",
            name=op.f(op.f("ck_automation_snapshot_reason")),
        ),
        sa.CheckConstraint(
            "has_credentials = (credentials_sha256 IS NOT NULL)",
            name=op.f(op.f("ck_automation_snapshot_credentials_hash")),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_snapshot")),
        sa.UniqueConstraint("seq", name=op.f("uq_automation_snapshot_seq")),
    )
    op.create_index("ix_automation_snapshot_source_seq", "automation_snapshot", ["source_id", "seq"], unique=False)
    op.create_table(
        "automation_flow_token",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("token_sha256", sa.String(length=64), nullable=False),
        sa.Column("last4", sa.String(length=4), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("label", sa.String(length=80), nullable=False),
        sa.Column("allowed_actions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(length=80), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(allowed_actions) = 'array'", name=op.f(op.f("ck_automation_flow_token_allowed_actions_array"))
        ),
        sa.CheckConstraint(
            "status <> 'ingetrokken' OR revoked_at IS NOT NULL",
            name=op.f(op.f("ck_automation_flow_token_revoked_has_time")),
        ),
        sa.CheckConstraint("status IN ('actief','ingetrokken')", name=op.f(op.f("ck_automation_flow_token_status"))),
        sa.CheckConstraint("token_sha256 ~ '^[0-9a-f]{64}$'", name=op.f(op.f("ck_automation_flow_token_hash_format"))),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_flow_token_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_flow_token")),
        sa.UniqueConstraint("token_sha256", name=op.f("uq_automation_flow_token_token_sha256")),
    )
    op.create_index("ix_automation_flow_token_flow", "automation_flow_token", ["flow_id", "status"], unique=False)
    op.create_table(
        "automation_restore",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("target_snapshot_id", sa.UUID(), nullable=False),
        sa.Column("base_rev", sa.String(length=64), nullable=False),
        sa.Column("base_checksum", sa.String(length=64), nullable=False),
        sa.Column("target_checksum", sa.String(length=64), nullable=False),
        sa.Column("preview_hash", sa.String(length=64), nullable=False),
        sa.Column("plan", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("requested_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("pre_snapshot_id", sa.UUID(), nullable=True),
        sa.Column("post_snapshot_id", sa.UUID(), nullable=True),
        sa.Column("result", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("trace_id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "preview_hash ~ '^[0-9a-f]{64}$'", name=op.f(op.f("ck_automation_restore_preview_hash_format"))
        ),
        sa.CheckConstraint(
            "status <> 'uitgevoerd' OR (pre_snapshot_id IS NOT NULL AND post_snapshot_id IS NOT NULL AND applied_at IS NOT NULL)",
            name=op.f(op.f("ck_automation_restore_applied_has_snapshots")),
        ),
        sa.CheckConstraint(
            "status IN ('voorgesteld', 'uitgevoerd', 'mislukt', 'verlopen')",
            name=op.f(op.f("ck_automation_restore_status")),
        ),
        sa.ForeignKeyConstraint(
            ["post_snapshot_id"],
            ["automation_snapshot.id"],
            name=op.f("fk_automation_restore_post_snapshot_id_automation_snapshot"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["pre_snapshot_id"],
            ["automation_snapshot.id"],
            name=op.f("fk_automation_restore_pre_snapshot_id_automation_snapshot"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["target_snapshot_id"],
            ["automation_snapshot.id"],
            name=op.f("fk_automation_restore_target_snapshot_id_automation_snapshot"),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_restore")),
    )
    op.create_table(
        "automation_delivery",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("event_seq", sa.BigInteger(), nullable=False),
        sa.Column("source_app", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("run_id", sa.UUID(), nullable=True),
        sa.CheckConstraint(
            "status <> 'geclaimd' OR lease_until IS NOT NULL", name=op.f(op.f("ck_automation_delivery_claim_has_lease"))
        ),
        sa.CheckConstraint(
            "status IN ('wachtend', 'geclaimd', 'verwerkt', 'dead_letter')",
            name=op.f(op.f("ck_automation_delivery_status")),
        ),
        sa.ForeignKeyConstraint(
            ["event_seq"],
            ["automation_event.seq"],
            name=op.f("fk_automation_delivery_event_seq_automation_event"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_delivery_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["automation_flow_run.id"],
            name=op.f("fk_automation_delivery_run_id_automation_flow_run"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_delivery")),
        sa.UniqueConstraint("flow_id", "event_seq", name="uq_automation_delivery_flow_event"),
    )
    op.create_index(
        "ix_automation_delivery_queue",
        "automation_delivery",
        ["flow_id", "source_app", "status", "event_seq"],
        unique=False,
    )
    op.add_column("automation_action_request", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("automation_action_request", sa.Column("token_id", sa.UUID(), nullable=True))
    op.add_column("automation_action_request", sa.Column("trigger_delivery_id", sa.UUID(), nullable=True))
    op.add_column("automation_action_request", sa.Column("trigger_event_id", sa.UUID(), nullable=True))
    op.add_column(
        "automation_action_request",
        sa.Column(
            "target", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
    )
    op.add_column(
        "automation_action_request",
        sa.Column(
            "parameters", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
    )
    op.add_column(
        "automation_action_request",
        sa.Column("reason", sa.String(length=500), nullable=False, server_default=sa.text("''")),
    )
    op.add_column(
        "automation_action_request",
        sa.Column("owner", sa.String(length=200), nullable=False, server_default=sa.text("''")),
    )
    op.add_column(
        "automation_action_request",
        sa.Column(
            "risk_preview",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.add_column("automation_action_request", sa.Column("dedupe_key", sa.String(length=64), nullable=True))
    op.add_column("automation_action_request", sa.Column("outbox_event_id", sa.UUID(), nullable=True))
    op.add_column("automation_action_request", sa.Column("rejected_reason", sa.String(length=80), nullable=True))
    op.add_column(
        "automation_action_request",
        sa.Column(
            "hub_result", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
    )
    op.create_index(
        "ix_automation_action_request_flow",
        "automation_action_request",
        ["flow_id", "action_id", "created_at"],
        unique=False,
    )
    op.create_unique_constraint(
        op.f("uq_automation_action_request_dedupe_key"), "automation_action_request", ["dedupe_key"]
    )
    op.create_foreign_key(
        op.f("fk_automation_action_request_token_id_automation_flow_token"),
        "automation_action_request",
        "automation_flow_token",
        ["token_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column(
        "automation_flow",
        sa.Column("disabled_in_node_red", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("automation_flow", sa.Column("blocked_reason", sa.String(length=80), nullable=True))
    op.add_column("automation_flow", sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("automation_flow", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("automation_flow_run", sa.Column("version_id", sa.UUID(), nullable=True))
    op.add_column("automation_flow_run", sa.Column("baseline_run_id", sa.UUID(), nullable=True))
    op.add_column("automation_flow_run", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("automation_flow_run", sa.Column("created_by", sa.String(length=200), nullable=True))
    op.add_column(
        "automation_flow_run",
        sa.Column(
            "sample_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
    )
    op.add_column(
        "automation_flow_run",
        sa.Column(
            "runlog", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
    )
    op.add_column(
        "automation_flow_run",
        sa.Column(
            "result", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
    )
    op.create_foreign_key(
        op.f("fk_automation_flow_run_version_id_automation_flow_version"),
        "automation_flow_run",
        "automation_flow_version",
        ["version_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column("automation_flow_version", sa.Column("snapshot_id", sa.UUID(), nullable=True))
    op.add_column(
        "automation_flow_version", sa.Column("node_count", sa.Integer(), nullable=False, server_default=sa.text("0"))
    )
    op.add_column(
        "automation_flow_version",
        sa.Column("policy_status", sa.String(length=20), nullable=False, server_default=sa.text("'in_orde'")),
    )
    op.add_column(
        "automation_flow_version",
        sa.Column(
            "findings", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
    )
    op.create_foreign_key(
        op.f("fk_automation_flow_version_snapshot_id_automation_snapshot"),
        "automation_flow_version",
        "automation_snapshot",
        ["snapshot_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.add_column("automation_trigger", sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("automation_trigger", sa.Column("created_by", sa.String(length=200), nullable=True))
    op.create_unique_constraint(
        "uq_automation_trigger_flow_type", "automation_trigger", ["flow_id", "event_type", "schema_version"]
    )
    # CHECK-constraints (Alembic-autogenerate ziet die niet): met de hand
    op.drop_constraint(op.f("ck_automation_flow_status"), "automation_flow", type_="check")
    op.create_check_constraint(op.f("ck_automation_flow_status"), "automation_flow", FLOW_STATUS_NIEUW)
    op.create_check_constraint(
        op.f("ck_automation_flow_blocked_has_reason"),
        "automation_flow",
        "status <> 'geblokkeerd' OR blocked_reason IS NOT NULL",
    )
    op.create_check_constraint(
        op.f("ck_automation_flow_version_policy_status"),
        "automation_flow_version",
        "policy_status IN ('in_orde','geblokkeerd')",
    )
    # een geweigerd verzoek zonder reden (P0, of terug naar 0004 en weer omhoog): reden invullen, niets weggooien
    op.execute(
        "UPDATE automation_action_request SET rejected_reason = 'reden_onbekend' "
        "WHERE status = 'geweigerd' AND rejected_reason IS NULL"
    )
    op.create_check_constraint(
        op.f("ck_automation_action_request_rejected_has_reason"),
        "automation_action_request",
        "status <> 'geweigerd' OR rejected_reason IS NOT NULL",
    )
    op.create_check_constraint(
        op.f("ck_automation_action_request_risk_claim"),
        "automation_action_request",
        "risk_claim IS NULL OR risk_claim IN ('R0','R1','R2','R3')",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_automation_action_request_risk_claim"), "automation_action_request", type_="check")
    op.drop_constraint(
        op.f("ck_automation_action_request_rejected_has_reason"), "automation_action_request", type_="check"
    )
    op.drop_constraint(op.f("ck_automation_flow_version_policy_status"), "automation_flow_version", type_="check")
    op.drop_constraint(op.f("ck_automation_flow_blocked_has_reason"), "automation_flow", type_="check")
    op.drop_constraint(op.f("ck_automation_flow_status"), "automation_flow", type_="check")
    op.execute("UPDATE automation_flow SET status = 'onbekend' WHERE status IN ('geblokkeerd', 'verwijderd')")
    op.create_check_constraint(op.f("ck_automation_flow_status"), "automation_flow", FLOW_STATUS_OUD)
    # een geweigerd verzoek zonder flow-token-verwijzing blijft staan; alleen de nieuwe kolommen vervallen
    op.drop_constraint("uq_automation_trigger_flow_type", "automation_trigger", type_="unique")
    op.drop_column("automation_trigger", "created_by")
    op.drop_column("automation_trigger", "created_at")
    op.drop_constraint(
        op.f("fk_automation_flow_version_snapshot_id_automation_snapshot"),
        "automation_flow_version",
        type_="foreignkey",
    )
    op.drop_column("automation_flow_version", "findings")
    op.drop_column("automation_flow_version", "policy_status")
    op.drop_column("automation_flow_version", "node_count")
    op.drop_column("automation_flow_version", "snapshot_id")
    op.drop_constraint(
        op.f("fk_automation_flow_run_version_id_automation_flow_version"), "automation_flow_run", type_="foreignkey"
    )
    op.drop_column("automation_flow_run", "result")
    op.drop_column("automation_flow_run", "runlog")
    op.drop_column("automation_flow_run", "sample_ids")
    op.drop_column("automation_flow_run", "created_by")
    op.drop_column("automation_flow_run", "expires_at")
    op.drop_column("automation_flow_run", "baseline_run_id")
    op.drop_column("automation_flow_run", "version_id")
    op.drop_column("automation_flow", "last_seen_at")
    op.drop_column("automation_flow", "blocked_at")
    op.drop_column("automation_flow", "blocked_reason")
    op.drop_column("automation_flow", "disabled_in_node_red")
    op.drop_constraint(
        op.f("fk_automation_action_request_token_id_automation_flow_token"),
        "automation_action_request",
        type_="foreignkey",
    )
    op.drop_constraint(op.f("uq_automation_action_request_dedupe_key"), "automation_action_request", type_="unique")
    op.drop_index("ix_automation_action_request_flow", table_name="automation_action_request")
    op.drop_column("automation_action_request", "hub_result")
    op.drop_column("automation_action_request", "rejected_reason")
    op.drop_column("automation_action_request", "outbox_event_id")
    op.drop_column("automation_action_request", "dedupe_key")
    op.drop_column("automation_action_request", "risk_preview")
    op.drop_column("automation_action_request", "owner")
    op.drop_column("automation_action_request", "reason")
    op.drop_column("automation_action_request", "parameters")
    op.drop_column("automation_action_request", "target")
    op.drop_column("automation_action_request", "trigger_event_id")
    op.drop_column("automation_action_request", "trigger_delivery_id")
    op.drop_column("automation_action_request", "token_id")
    op.drop_column("automation_action_request", "updated_at")
    op.drop_index("ix_automation_delivery_queue", table_name="automation_delivery")
    op.drop_table("automation_delivery")
    op.drop_table("automation_restore")
    op.drop_index("ix_automation_flow_token_flow", table_name="automation_flow_token")
    op.drop_table("automation_flow_token")
    op.drop_index("ix_automation_snapshot_source_seq", table_name="automation_snapshot")
    op.drop_table("automation_snapshot")
    op.drop_table("automation_execution_nonce")
    op.drop_index("ix_automation_event_status", table_name="automation_event")
    op.drop_table("automation_event")
