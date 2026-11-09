"""basisschema: kern, B10, B11, B13-001 en B14

Kern (service_state, idempotency, outbox, vault, bronnen, audit), B13-001-herstelregister en de P0-datamodellen
van B10/B11/B14 (alleen schema, geen data). Referentiedata: de drie kwaliteitslabels voor energie.

Revision ID: 0001
Revises:
Create Date: 2026-11-09 09:24:05.544821
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_event",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("domain", sa.String(length=20), nullable=False),
        sa.Column("action", sa.String(length=80), nullable=False),
        sa.Column("entity_type", sa.String(length=60), nullable=False),
        sa.Column("entity_id", sa.String(length=120), nullable=False),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("actor_id", sa.String(length=200), nullable=False),
        sa.Column("client_scope", sa.String(length=20), nullable=True),
        sa.Column("trace_id", sa.UUID(), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("message_nl", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_event")),
    )
    op.create_index("ix_audit_event_at", "audit_event", ["at"], unique=False)
    op.create_index("ix_audit_event_entity", "audit_event", ["entity_type", "entity_id"], unique=False)
    op.create_table(
        "automation_flow",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("source_flow_id", sa.String(length=120), nullable=False),
        sa.Column("label", sa.String(length=200), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("current_version_id", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('actief','gepauzeerd','uitgeschakeld','onbekend')", name=op.f("ck_automation_flow_status")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_flow")),
        sa.UniqueConstraint("source_id", "source_flow_id", name="uq_automation_flow_source"),
    )
    op.create_table(
        "energy_estimate_provenance",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("method", sa.String(length=30), nullable=False),
        sa.Column("calibration_ref", sa.String(length=200), nullable=True),
        sa.Column("assumptions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=3, scale=2), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "method <> 'cpu_model' OR calibration_ref IS NOT NULL",
            name=op.f("ck_energy_estimate_provenance_cpu_model_requires_calibration"),
        ),
        sa.CheckConstraint(
            "method IN ('interpolatie','cpu_model','vergelijkbare_dag','handmatig')",
            name=op.f("ck_energy_estimate_provenance_method"),
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name=op.f("ck_energy_estimate_provenance_confidence")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_energy_estimate_provenance")),
    )
    op.create_table(
        "energy_meter",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("source_meter_id", sa.String(length=120), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("unit", sa.String(length=10), nullable=False),
        sa.Column("read_only", sa.Boolean(), nullable=False),
        sa.Column("replaced_meter_id", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("unit IN ('kWh','m3','W')", name=op.f("ck_energy_meter_unit")),
        sa.CheckConstraint("read_only", name=op.f("ck_energy_meter_always_read_only")),
        sa.ForeignKeyConstraint(
            ["replaced_meter_id"], ["energy_meter.id"], name=op.f("fk_energy_meter_replaced_meter_id_energy_meter")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_energy_meter")),
        sa.UniqueConstraint("source_id", "source_meter_id", name="uq_energy_meter_source"),
    )
    op.create_table(
        "energy_sample_quality",
        sa.Column("code", sa.String(length=20), nullable=False),
        sa.Column("description_nl", sa.String(length=300), nullable=False),
        sa.CheckConstraint("code IN ('gemeten','geschat','onbekend')", name=op.f("ck_energy_sample_quality_code")),
        sa.PrimaryKeyConstraint("code", name=op.f("pk_energy_sample_quality")),
    )
    op.bulk_insert(
        sa.table("energy_sample_quality", sa.column("code", sa.String), sa.column("description_nl", sa.String)),
        [
            {"code": "gemeten", "description_nl": "Gemeten door een echte meter."},
            {"code": "geschat", "description_nl": "Schatting; herkomst en aannames verplicht."},
            {"code": "onbekend", "description_nl": "Geen bruikbare meting; geen waarde."},
        ],
    )
    op.create_table(
        "energy_tariff",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=10), nullable=False),
        sa.Column("unit", sa.String(length=10), nullable=False),
        sa.Column("price_per_unit", sa.Numeric(precision=10, scale=5), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_ref", sa.String(length=200), nullable=False),
        sa.CheckConstraint("kind IN ('vast','dynamisch')", name=op.f("ck_energy_tariff_kind")),
        sa.CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name=op.f("ck_energy_tariff_validity")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_energy_tariff")),
    )
    op.create_table(
        "energy_workload",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("owner_app", sa.String(length=60), nullable=False),
        sa.Column("workload_key", sa.String(length=120), nullable=False),
        sa.Column("priority_class", sa.String(length=20), nullable=False),
        sa.Column("preemptible", sa.Boolean(), nullable=False),
        sa.Column("needs_safe_checkpoint", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "priority_class IN ('interactief','hoog','normaal','achtergrond')",
            name=op.f("ck_energy_workload_priority_class"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_energy_workload")),
        sa.UniqueConstraint("owner_app", "workload_key", name="uq_energy_workload_owner_key"),
    )
    op.create_table(
        "idempotency_record",
        sa.Column("principal", sa.String(length=200), nullable=False),
        sa.Column("key", sa.UUID(), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path", sa.String(length=500), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("response_body", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("response_headers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("principal", "key", name=op.f("pk_idempotency_record")),
    )
    op.create_index("ix_idempotency_record_created_at", "idempotency_record", ["created_at"], unique=False)
    op.create_table(
        "integration_source",
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("domain", sa.String(length=20), nullable=False),
        sa.Column("base_url", sa.String(length=500), nullable=True),
        sa.Column("credential_ref", sa.String(length=200), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_probe_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_probe_status", sa.String(length=20), nullable=False),
        sa.Column("last_probe_reason", sa.String(length=80), nullable=True),
        sa.Column("last_probe_detail", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "credential_ref IS NULL OR credential_ref LIKE 'vault://%%'",
            name=op.f("ck_integration_source_credential_is_vault_ref"),
        ),
        sa.CheckConstraint(
            "domain IN ('network','automation','sso','energy')", name=op.f("ck_integration_source_domain")
        ),
        sa.CheckConstraint(
            "last_probe_status IN ('healthy','degraded','down','unknown')",
            name=op.f("ck_integration_source_probe_status"),
        ),
        sa.PrimaryKeyConstraint("source_id", name=op.f("pk_integration_source")),
    )
    op.create_table(
        "network_block_rule",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("rule_kind", sa.String(length=20), nullable=False),
        sa.Column("pattern", sa.String(length=253), nullable=False),
        sa.Column("scope", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("rollback_ttl_s", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("rule_kind IN ('blokkeren','toestaan')", name=op.f("ck_network_block_rule_rule_kind")),
        sa.CheckConstraint(
            "scope IN ('pilot','kinderprofiel','netwerkbreed')", name=op.f("ck_network_block_rule_scope")
        ),
        sa.CheckConstraint(
            "status IN ('voorstel','goedgekeurd','actief','teruggedraaid','afgewezen')",
            name=op.f("ck_network_block_rule_status"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_block_rule")),
    )
    op.create_table(
        "network_device",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("mac_normalized", sa.String(length=17), nullable=False),
        sa.Column("mac_is_randomized", sa.Boolean(), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=True),
        sa.Column("vendor", sa.String(length=120), nullable=True),
        sa.Column("vendor_confidence", sa.Numeric(precision=3, scale=2), nullable=True),
        sa.Column("classification", sa.String(length=20), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ref", sa.String(length=200), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "classification IN ('onbekend','bekend','infrastructuur','iot','persoonlijk','gast')",
            name=op.f("ck_network_device_classification"),
        ),
        sa.CheckConstraint(
            "mac_normalized ~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'", name=op.f("ck_network_device_mac_format")
        ),
        sa.CheckConstraint("last_seen >= first_seen", name=op.f("ck_network_device_seen_order")),
        sa.CheckConstraint(
            "vendor_confidence IS NULL OR (vendor_confidence >= 0 AND vendor_confidence <= 1)",
            name=op.f("ck_network_device_conf"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_device")),
        sa.UniqueConstraint("source_id", "mac_normalized", name="uq_network_device_source_mac"),
    )
    op.create_table(
        "network_dns_query_aggregate",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_seconds", sa.Integer(), nullable=False),
        sa.Column("client_key", sa.String(length=120), nullable=True),
        sa.Column("queries_total", sa.Integer(), nullable=False),
        sa.Column("queries_blocked", sa.Integer(), nullable=False),
        sa.Column("top_blocked_categories", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("coverage", sa.String(length=20), nullable=False),
        sa.CheckConstraint(
            "coverage IN ('alleen_dns_via_adguard','onvolledig','onbekend')",
            name=op.f("ck_network_dns_query_aggregate_coverage"),
        ),
        sa.CheckConstraint(
            "queries_blocked >= 0 AND queries_blocked <= queries_total",
            name=op.f("ck_network_dns_query_aggregate_counts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_dns_query_aggregate")),
        sa.UniqueConstraint("source_id", "bucket_start", "bucket_seconds", "client_key", name="uq_network_dns_bucket"),
    )
    op.create_table(
        "network_tunnel_health",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("tunnel_key", sa.String(length=120), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("reason_code", sa.String(length=80), nullable=True),
        sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("exposes_admin", sa.Boolean(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("secret_ref", sa.String(length=200), nullable=True),
        sa.CheckConstraint(
            "secret_ref IS NULL OR secret_ref LIKE 'vault://%%'",
            name=op.f("ck_network_tunnel_health_secret_is_vault_ref"),
        ),
        sa.CheckConstraint(
            "status IN ('healthy','degraded','down','unknown')", name=op.f("ck_network_tunnel_health_status")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_tunnel_health")),
    )
    op.create_index(
        "ix_network_tunnel_health_key_at",
        "network_tunnel_health",
        ["source_id", "tunnel_key", "observed_at"],
        unique=False,
    )
    op.create_table(
        "network_vpn_peer",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("peer_key", sa.String(length=120), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=True),
        sa.Column("online", sa.Boolean(), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_vpn_peer")),
        sa.UniqueConstraint("source_id", "peer_key", name="uq_network_vpn_peer_source_key"),
    )
    op.create_table(
        "outbox_event",
        sa.Column("seq", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("entity_type", sa.String(length=60), nullable=False),
        sa.Column("entity_id", sa.String(length=120), nullable=False),
        sa.Column("timestamp_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trace_id", sa.UUID(), nullable=False),
        sa.Column("correlation_id", sa.UUID(), nullable=True),
        sa.Column("actor_type", sa.String(length=20), nullable=False),
        sa.Column("actor_id", sa.String(length=200), nullable=False),
        sa.Column("classification", sa.String(length=20), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("delivery_status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.String(length=300), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "classification IN ('public','internal','sensitive')", name=op.f("ck_outbox_event_classification")
        ),
        sa.CheckConstraint(
            "delivery_status IN ('pending','delivered','dead_letter')", name=op.f("ck_outbox_event_delivery_status")
        ),
        sa.PrimaryKeyConstraint("seq", name=op.f("pk_outbox_event")),
        sa.UniqueConstraint("event_id", name=op.f("uq_outbox_event_event_id")),
    )
    op.create_index("ix_outbox_event_pending", "outbox_event", ["delivery_status", "next_attempt_at"], unique=False)
    op.create_table(
        "service_state",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_service_state")),
    )
    op.create_table(
        "sso_admin_account",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("system", sa.String(length=20), nullable=False),
        sa.Column("username", sa.String(length=120), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("is_break_glass", sa.Boolean(), nullable=False),
        sa.Column("login_kind", sa.String(length=10), nullable=False),
        sa.Column("mfa_status", sa.String(length=20), nullable=False),
        sa.Column("mfa_methods", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("mfa_attested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mfa_attested_by", sa.String(length=200), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("notes", sa.String(length=500), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "NOT is_break_glass OR login_kind <> 'sso'", name=op.f("ck_sso_admin_account_break_glass_not_sso_only")
        ),
        sa.CheckConstraint("jsonb_typeof(mfa_methods) = 'array'", name=op.f("ck_sso_admin_account_mfa_methods_array")),
        sa.CheckConstraint("login_kind IN ('lokaal','sso','beide')", name=op.f("ck_sso_admin_account_login_kind")),
        sa.CheckConstraint(
            "mfa_status IN ('bevestigd','niet_ingesteld','onbekend')", name=op.f("ck_sso_admin_account_mfa_status")
        ),
        sa.CheckConstraint("status IN ('actief','uitgeschakeld')", name=op.f("ck_sso_admin_account_status")),
        sa.CheckConstraint(
            "system IN ('hub_local','authentik','truenas','node_red','adguard_home','netalertx','overig')",
            name=op.f("ck_sso_admin_account_system"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_admin_account")),
        sa.UniqueConstraint("system", "username", name="uq_sso_admin_account_system_username"),
    )
    op.create_table(
        "sso_recovery_kit_export",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("format", sa.String(length=40), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("register_sha256", sa.String(length=64), nullable=False),
        sa.Column("accounts_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_recovery_kit_export")),
    )
    op.create_table(
        "vault_secret",
        sa.Column("ref", sa.String(length=200), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("last4", sa.String(length=4), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("ref", name=op.f("pk_vault_secret")),
    )
    op.create_table(
        "automation_flow_owner",
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("principal", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.CheckConstraint("role IN ('eigenaar','bewerker','lezer')", name=op.f("ck_automation_flow_owner_role")),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_flow_owner_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("flow_id", "principal", name=op.f("pk_automation_flow_owner")),
    )
    op.create_table(
        "automation_flow_run",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("trigger_event_id", sa.UUID(), nullable=True),
        sa.Column("mode", sa.String(length=10), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=True),
        sa.CheckConstraint("mode IN ('echt','dry_run')", name=op.f("ck_automation_flow_run_mode")),
        sa.CheckConstraint(
            "status IN ('bezig','klaar','mislukt','geweigerd')", name=op.f("ck_automation_flow_run_status")
        ),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_flow_run_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_flow_run")),
    )
    op.create_table(
        "automation_flow_version",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("checksum_sha256", sa.String(length=64), nullable=False),
        sa.Column("export_ref", sa.String(length=300), nullable=True),
        sa.Column("credentials_ref", sa.String(length=200), nullable=True),
        sa.Column("node_types", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.CheckConstraint(
            "checksum_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_automation_flow_version_checksum_format")
        ),
        sa.CheckConstraint(
            "credentials_ref IS NULL OR credentials_ref LIKE 'vault://%%'",
            name=op.f("ck_automation_flow_version_credentials_is_vault_ref"),
        ),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_flow_version_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_flow_version")),
        sa.UniqueConstraint("flow_id", "seq", name="uq_automation_flow_version_seq"),
    )
    op.create_table(
        "automation_rate_limit",
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("max_per_hour", sa.Integer(), nullable=False),
        sa.Column("cooldown_s", sa.Integer(), nullable=False),
        sa.CheckConstraint("max_per_hour >= 0 AND cooldown_s >= 0", name=op.f("ck_automation_rate_limit_limits")),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_rate_limit_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("flow_id", "action_id", name=op.f("pk_automation_rate_limit")),
    )
    op.create_table(
        "automation_replay_key",
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_replay_key_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("flow_id", "event_id", name=op.f("pk_automation_replay_key")),
    )
    op.create_table(
        "automation_trigger",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=120), nullable=False),
        sa.Column("schema_version", sa.String(length=10), nullable=False),
        sa.Column("filter", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_trigger_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_trigger")),
    )
    op.create_table(
        "energy_cost_model",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("tariff_id", sa.UUID(), nullable=False),
        sa.Column("requires_meter", sa.Boolean(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("requires_meter", name=op.f("ck_energy_cost_model_requires_meter")),
        sa.ForeignKeyConstraint(
            ["tariff_id"], ["energy_tariff.id"], name=op.f("fk_energy_cost_model_tariff_id_energy_tariff")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_energy_cost_model")),
    )
    op.create_table(
        "energy_meter_role",
        sa.Column("meter_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("confirmed_by", sa.String(length=200), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "role IN ('p1_net','boiler_socket','airco_outdoor','nas_host','overig')",
            name=op.f("ck_energy_meter_role_role"),
        ),
        sa.ForeignKeyConstraint(
            ["meter_id"],
            ["energy_meter.id"],
            name=op.f("fk_energy_meter_role_meter_id_energy_meter"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("meter_id", "role", name=op.f("pk_energy_meter_role")),
    )
    op.create_table(
        "energy_usage_interval",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("meter_id", sa.UUID(), nullable=False),
        sa.Column("start_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_utc", sa.DateTime(timezone=True), nullable=False),
        sa.Column("counter_start", sa.Numeric(precision=14, scale=3), nullable=True),
        sa.Column("counter_end", sa.Numeric(precision=14, scale=3), nullable=True),
        sa.Column("delta", sa.Numeric(precision=14, scale=3), nullable=True),
        sa.Column("direction", sa.String(length=10), nullable=False),
        sa.Column("quality", sa.String(length=20), nullable=False),
        sa.Column("counter_reset", sa.Boolean(), nullable=False),
        sa.Column("provenance_id", sa.UUID(), nullable=True),
        sa.Column("source_ref", sa.String(length=200), nullable=False),
        sa.CheckConstraint("direction IN ('import','export')", name=op.f("ck_energy_usage_interval_direction")),
        sa.CheckConstraint(
            "quality <> 'geschat' OR provenance_id IS NOT NULL",
            name=op.f("ck_energy_usage_interval_estimate_requires_provenance"),
        ),
        sa.CheckConstraint(
            "quality <> 'onbekend' OR delta IS NULL", name=op.f("ck_energy_usage_interval_unknown_has_no_value")
        ),
        sa.CheckConstraint("delta IS NULL OR delta >= 0", name=op.f("ck_energy_usage_interval_delta_non_negative")),
        sa.CheckConstraint("end_utc > start_utc", name=op.f("ck_energy_usage_interval_interval_order")),
        sa.ForeignKeyConstraint(
            ["meter_id"],
            ["energy_meter.id"],
            name=op.f("fk_energy_usage_interval_meter_id_energy_meter"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["provenance_id"],
            ["energy_estimate_provenance.id"],
            name=op.f("fk_energy_usage_interval_provenance_id_energy_estimate_provenance"),
        ),
        sa.ForeignKeyConstraint(
            ["quality"],
            ["energy_sample_quality.code"],
            name=op.f("fk_energy_usage_interval_quality_energy_sample_quality"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_energy_usage_interval")),
        sa.UniqueConstraint("meter_id", "start_utc", "direction", name="uq_energy_usage_interval_meter_start"),
    )
    op.create_table(
        "energy_workload_reservation",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("workload_id", sa.UUID(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resources", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("wait_reason_nl", sa.String(length=300), nullable=True),
        sa.CheckConstraint(
            "status IN ('voorstel','gepland','actief','wacht','klaar','geannuleerd')",
            name=op.f("ck_energy_workload_reservation_status"),
        ),
        sa.CheckConstraint("window_end > window_start", name=op.f("ck_energy_workload_reservation_window_order")),
        sa.ForeignKeyConstraint(
            ["workload_id"],
            ["energy_workload.id"],
            name=op.f("fk_energy_workload_reservation_workload_id_energy_workload"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_energy_workload_reservation")),
    )
    op.create_table(
        "network_address_observation",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.CheckConstraint("last_seen >= first_seen", name=op.f("ck_network_address_observation_seen_order")),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["network_device.id"],
            name=op.f("fk_network_address_observation_device_id_network_device"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_address_observation")),
        sa.UniqueConstraint("device_id", "ip_address", name="uq_network_address_observation_device_ip"),
    )
    op.create_table(
        "network_discovery_event",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=60), nullable=False),
        sa.Column("source_event_id", sa.String(length=120), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=True),
        sa.Column("kind", sa.String(length=30), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "kind IN ('nieuw_apparaat','ip_gewijzigd','weer_online','offline')",
            name=op.f("ck_network_discovery_event_kind"),
        ),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["network_device.id"],
            name=op.f("fk_network_discovery_event_device_id_network_device"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_discovery_event")),
        sa.UniqueConstraint("source_id", "source_event_id", name="uq_network_discovery_event_source"),
    )
    op.create_table(
        "network_security_finding",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("device_id", sa.UUID(), nullable=True),
        sa.Column("category", sa.String(length=30), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("confidence", sa.Numeric(precision=3, scale=2), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("detected_by", sa.String(length=60), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "category <> 'malware' OR jsonb_array_length(evidence) > 0",
            name=op.f("ck_network_security_finding_malware_requires_evidence"),
        ),
        sa.CheckConstraint(
            "category IN ('nieuw_apparaat','onbekend_apparaat','dns_afwijking','loginpogingen','malware','overig')",
            name=op.f("ck_network_security_finding_category"),
        ),
        sa.CheckConstraint("jsonb_typeof(evidence) = 'array'", name=op.f("ck_network_security_finding_evidence_array")),
        sa.CheckConstraint(
            "severity IN ('info','laag','middel','hoog')", name=op.f("ck_network_security_finding_severity")
        ),
        sa.CheckConstraint(
            "status IN ('open','bevestigd','onterecht','opgelost')", name=op.f("ck_network_security_finding_status")
        ),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name=op.f("ck_network_security_finding_confidence")),
        sa.ForeignKeyConstraint(
            ["device_id"],
            ["network_device.id"],
            name=op.f("fk_network_security_finding_device_id_network_device"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_security_finding")),
    )
    op.create_table(
        "sso_break_glass_activation",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("mode", sa.String(length=10), nullable=False),
        sa.Column("client_ip", sa.String(length=45), nullable=False),
        sa.Column("matched_scope", sa.String(length=50), nullable=True),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reported_by", sa.String(length=200), nullable=False),
        sa.Column("rotation_required", sa.Boolean(), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_by", sa.String(length=200), nullable=True),
        sa.CheckConstraint("mode IN ('oefening','echt')", name=op.f("ck_sso_break_glass_activation_mode")),
        sa.CheckConstraint(
            "rotation_required = (mode = 'echt')", name=op.f("ck_sso_break_glass_activation_rotation_after_real_use")
        ),
        sa.CheckConstraint("expires_at > activated_at", name=op.f("ck_sso_break_glass_activation_expiry")),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["sso_admin_account.id"],
            name=op.f("fk_sso_break_glass_activation_account_id_sso_admin_account"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_break_glass_activation")),
    )
    op.create_index(
        "ix_sso_break_glass_activation_account",
        "sso_break_glass_activation",
        ["account_id", "activated_at"],
        unique=False,
    )
    op.create_table(
        "sso_emergency_access",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("network_scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("session_max_minutes", sa.Integer(), nullable=False),
        sa.Column("review_interval_days", sa.Integer(), nullable=False),
        sa.Column("last_reviewed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_reviewed_by", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("reason", sa.String(length=300), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "jsonb_typeof(network_scopes) = 'array' AND jsonb_array_length(network_scopes) > 0",
            name=op.f("ck_sso_emergency_access_scopes"),
        ),
        sa.CheckConstraint("status IN ('actief','ingetrokken')", name=op.f("ck_sso_emergency_access_status")),
        sa.CheckConstraint(
            "review_interval_days BETWEEN 7 AND 365", name=op.f("ck_sso_emergency_access_review_interval")
        ),
        sa.CheckConstraint("session_max_minutes BETWEEN 5 AND 240", name=op.f("ck_sso_emergency_access_session_max")),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["sso_admin_account.id"],
            name=op.f("fk_sso_emergency_access_account_id_sso_admin_account"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_emergency_access")),
        sa.UniqueConstraint("account_id", name=op.f("uq_sso_emergency_access_account_id")),
    )
    op.create_table(
        "sso_recovery_method",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("method_type", sa.String(length=40), nullable=False),
        sa.Column("storage_hint", sa.String(length=30), nullable=False),
        sa.Column("sso_independent", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "method_type IN ('lokaal_wachtwoord_lan','lokaal_wachtwoord_vpn','herstelcodes_offline','hardwaresleutel','authentik_herstelsleutel','truenas_console','verzegelde_envelop')",
            name=op.f("ck_sso_recovery_method_method_type"),
        ),
        sa.CheckConstraint(
            "sso_independent = (method_type <> 'authentik_herstelsleutel')",
            name=op.f("ck_sso_recovery_method_sso_independent_derived"),
        ),
        sa.CheckConstraint("status IN ('actief','ingetrokken')", name=op.f("ck_sso_recovery_method_status")),
        sa.CheckConstraint(
            "storage_hint IN ('wachtwoordmanager','verzegelde_envelop','kluis','hardwaresleutel','anders','onbekend')",
            name=op.f("ck_sso_recovery_method_storage_hint"),
        ),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["sso_admin_account.id"],
            name=op.f("fk_sso_recovery_method_account_id_sso_admin_account"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_recovery_method")),
    )
    op.create_index("ix_sso_recovery_method_account", "sso_recovery_method", ["account_id"], unique=False)
    op.create_table(
        "automation_action_request",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("flow_id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=True),
        sa.Column("idempotency_key", sa.UUID(), nullable=False),
        sa.Column("action_id", sa.String(length=80), nullable=False),
        sa.Column("risk_claim", sa.String(length=2), nullable=True),
        sa.Column("hub_risk_class", sa.String(length=2), nullable=True),
        sa.Column("origin_chain", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("hub_proposal_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "jsonb_typeof(origin_chain) = 'array'", name=op.f("ck_automation_action_request_origin_chain_array")
        ),
        sa.CheckConstraint(
            "status IN ('aangevraagd','wacht_op_goedkeuring','uitgevoerd','geweigerd','mislukt')",
            name=op.f("ck_automation_action_request_status"),
        ),
        sa.ForeignKeyConstraint(
            ["flow_id"],
            ["automation_flow.id"],
            name=op.f("fk_automation_action_request_flow_id_automation_flow"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["automation_flow_run.id"],
            name=op.f("fk_automation_action_request_run_id_automation_flow_run"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_automation_action_request")),
        sa.UniqueConstraint("idempotency_key", name=op.f("uq_automation_action_request_idempotency_key")),
    )
    op.create_table(
        "network_policy_change",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("finding_id", sa.UUID(), nullable=True),
        sa.Column("action_kind", sa.String(length=30), nullable=False),
        sa.Column("risk_class", sa.String(length=2), nullable=False),
        sa.Column("hub_proposal_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("requires_independent_test", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.CheckConstraint("risk_class IN ('R2','R3')", name=op.f("ck_network_policy_change_risk_class")),
        sa.CheckConstraint(
            "status IN ('voorstel','goedgekeurd','uitgevoerd','teruggedraaid','afgewezen')",
            name=op.f("ck_network_policy_change_status"),
        ),
        sa.CheckConstraint(
            "requires_independent_test", name=op.f("ck_network_policy_change_independent_test_required")
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["network_security_finding.id"],
            name=op.f("fk_network_policy_change_finding_id_network_security_finding"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_policy_change")),
    )
    op.create_table(
        "sso_break_glass_drill",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("account_id", sa.UUID(), nullable=False),
        sa.Column("method_id", sa.UUID(), nullable=True),
        sa.Column("mode", sa.String(length=10), nullable=False),
        sa.Column("outcome", sa.String(length=10), nullable=False),
        sa.Column("authenticator_state", sa.String(length=20), nullable=False),
        sa.Column("client_scope", sa.String(length=10), nullable=False),
        sa.Column("checks", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("notes", sa.String(length=500), nullable=False),
        sa.Column("performed_by", sa.String(length=200), nullable=False),
        sa.Column("performed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trace_id", sa.UUID(), nullable=False),
        sa.CheckConstraint(
            "authenticator_state IN ('online','offline','niet_geconfigureerd','onbekend')",
            name=op.f("ck_sso_break_glass_drill_authenticator_state"),
        ),
        sa.CheckConstraint(
            "client_scope IN ('lan','vpn','onbekend')", name=op.f("ck_sso_break_glass_drill_client_scope")
        ),
        sa.CheckConstraint("mode IN ('zelftest','handmatig')", name=op.f("ck_sso_break_glass_drill_mode")),
        sa.CheckConstraint("outcome IN ('ok','mislukt','onvolledig')", name=op.f("ck_sso_break_glass_drill_outcome")),
        sa.ForeignKeyConstraint(
            ["account_id"],
            ["sso_admin_account.id"],
            name=op.f("fk_sso_break_glass_drill_account_id_sso_admin_account"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["method_id"],
            ["sso_recovery_method.id"],
            name=op.f("fk_sso_break_glass_drill_method_id_sso_recovery_method"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_break_glass_drill")),
    )
    op.create_index(
        "ix_sso_break_glass_drill_account", "sso_break_glass_drill", ["account_id", "performed_at"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_sso_break_glass_drill_account", table_name="sso_break_glass_drill")
    op.drop_table("sso_break_glass_drill")
    op.drop_table("network_policy_change")
    op.drop_table("automation_action_request")
    op.drop_index("ix_sso_recovery_method_account", table_name="sso_recovery_method")
    op.drop_table("sso_recovery_method")
    op.drop_table("sso_emergency_access")
    op.drop_index("ix_sso_break_glass_activation_account", table_name="sso_break_glass_activation")
    op.drop_table("sso_break_glass_activation")
    op.drop_table("network_security_finding")
    op.drop_table("network_discovery_event")
    op.drop_table("network_address_observation")
    op.drop_table("energy_workload_reservation")
    op.drop_table("energy_usage_interval")
    op.drop_table("energy_meter_role")
    op.drop_table("energy_cost_model")
    op.drop_table("automation_trigger")
    op.drop_table("automation_replay_key")
    op.drop_table("automation_rate_limit")
    op.drop_table("automation_flow_version")
    op.drop_table("automation_flow_run")
    op.drop_table("automation_flow_owner")
    op.drop_table("vault_secret")
    op.drop_table("sso_recovery_kit_export")
    op.drop_table("sso_admin_account")
    op.drop_table("service_state")
    op.drop_index("ix_outbox_event_pending", table_name="outbox_event")
    op.drop_table("outbox_event")
    op.drop_table("network_vpn_peer")
    op.drop_index("ix_network_tunnel_health_key_at", table_name="network_tunnel_health")
    op.drop_table("network_tunnel_health")
    op.drop_table("network_dns_query_aggregate")
    op.drop_table("network_device")
    op.drop_table("network_block_rule")
    op.drop_table("integration_source")
    op.drop_index("ix_idempotency_record_created_at", table_name="idempotency_record")
    op.drop_table("idempotency_record")
    op.drop_table("energy_workload")
    op.drop_table("energy_tariff")
    op.drop_table("energy_sample_quality")
    op.drop_table("energy_meter")
    op.drop_table("energy_estimate_provenance")
    op.drop_table("automation_flow")
    op.drop_index("ix_audit_event_entity", table_name="audit_event")
    op.drop_index("ix_audit_event_at", table_name="audit_event")
    op.drop_table("audit_event")
