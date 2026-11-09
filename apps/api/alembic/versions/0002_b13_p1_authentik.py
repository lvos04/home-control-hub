"""B13 P1: Authentik-integratie, SSO-mapping per app, audit/afwijkingen, back-up en upgrade; JWT-replaycache

Nieuwe tabellen (geen wijziging aan bestaande tabellen, dus terugdraaien = alleen deze tabellen weg):
- jwt_jti_use              replaybescherming voor Hub-JWT's bij mutaties (B13-002; contract 1.2-punt)
- sso_app_setting          loginroute per app (native/oidc) + handmatige installatiecontrole (B13-003)
- sso_group_role_mapping   Authentik-groep → rol per app (B13-003)
- sso_proposal             voorstellen met preview/diff/preview_hash; toepassen kan nog niet (B13-002/005)
- sso_authentik_snapshot   geschoonde configuratie-export en rechtenkaart (B13-004/005)
- sso_auth_event           minimale kopie van login-/wijzigingsevents, 30 dagen (B13-004)
- sso_anomaly              ontdubbelde afwijkingen (B13-004)

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-09 12:17:47.069918
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "jwt_jti_use",
        sa.Column("jti", sa.String(length=200), nullable=False),
        sa.Column("subject", sa.String(length=200), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path", sa.String(length=500), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("jti", name=op.f("pk_jwt_jti_use")),
    )
    op.create_index("ix_jwt_jti_use_expires_at", "jwt_jti_use", ["expires_at"], unique=False)
    op.create_table(
        "sso_anomaly",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("rule_id", sa.String(length=40), nullable=False),
        sa.Column("dedupe_key", sa.String(length=200), nullable=False),
        sa.Column("severity", sa.String(length=10), nullable=False),
        sa.Column("subject", sa.String(length=150), nullable=True),
        sa.Column("message_nl", sa.String(length=500), nullable=False),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.CheckConstraint("severity IN ('laag','middel','hoog')", name=op.f("ck_sso_anomaly_severity")),
        sa.CheckConstraint("status IN ('open','afgehandeld')", name=op.f("ck_sso_anomaly_status")),
        sa.CheckConstraint("last_seen >= first_seen AND count >= 1", name=op.f("ck_sso_anomaly_window")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_anomaly")),
        sa.UniqueConstraint("dedupe_key", name=op.f("uq_sso_anomaly_dedupe_key")),
    )
    op.create_index("ix_sso_anomaly_detected_at", "sso_anomaly", ["detected_at"], unique=False)
    op.create_table(
        "sso_app_setting",
        sa.Column("app_id", sa.String(length=60), nullable=False),
        sa.Column("login_mode", sa.String(length=10), nullable=False),
        sa.Column("installation_check", sa.String(length=30), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checked_by", sa.String(length=200), nullable=True),
        sa.Column("notes", sa.String(length=500), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "NOT (login_mode = 'oidc' AND installation_check = 'mislukt')",
            name=op.f("ck_sso_app_setting_no_oidc_after_failed_check"),
        ),
        sa.CheckConstraint(
            "installation_check IN ('niet_getest','handmatig_bevestigd','mislukt')",
            name=op.f("ck_sso_app_setting_installation_check"),
        ),
        sa.CheckConstraint("login_mode IN ('native','oidc')", name=op.f("ck_sso_app_setting_login_mode")),
        sa.PrimaryKeyConstraint("app_id", name=op.f("pk_sso_app_setting")),
    )
    op.create_table(
        "sso_auth_event",
        sa.Column("authentik_pk", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("username", sa.String(length=150), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("created", sa.DateTime(timezone=True), nullable=False),
        sa.Column("model_name", sa.String(length=60), nullable=True),
        sa.Column("model_label", sa.String(length=200), nullable=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("authentik_pk", name=op.f("pk_sso_auth_event")),
    )
    op.create_index("ix_sso_auth_event_created", "sso_auth_event", ["created"], unique=False)
    op.create_index("ix_sso_auth_event_user_action", "sso_auth_event", ["username", "action", "created"], unique=False)
    op.create_table(
        "sso_authentik_snapshot",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.String(length=20), nullable=False),
        sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("taken_by", sa.String(length=200), nullable=False),
        sa.Column("authentik_version", sa.String(length=20), nullable=True),
        sa.Column("complete", sa.Boolean(), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("trace_id", sa.UUID(), nullable=False),
        sa.CheckConstraint("kind IN ('config_export','rechten')", name=op.f("ck_sso_authentik_snapshot_kind")),
        sa.CheckConstraint(
            "size_bytes >= 0 AND size_bytes <= 8388608", name=op.f("ck_sso_authentik_snapshot_size_limit")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_authentik_snapshot")),
    )
    op.create_index(
        "ix_sso_authentik_snapshot_kind_taken_at", "sso_authentik_snapshot", ["kind", "taken_at"], unique=False
    )
    op.create_table(
        "sso_group_role_mapping",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("app_id", sa.String(length=60), nullable=False),
        sa.Column("authentik_group", sa.String(length=150), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(authentik_group) > 0 AND length(role) > 0", name=op.f("ck_sso_group_role_mapping_not_empty")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_group_role_mapping")),
        sa.UniqueConstraint("app_id", "authentik_group", name="uq_sso_group_role_mapping_app_group"),
    )
    op.create_table(
        "sso_proposal",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("action_id", sa.String(length=60), nullable=False),
        sa.Column("target", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("parameters", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("preview", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("preview_hash", sa.String(length=64), nullable=False),
        sa.Column("resource_etag", sa.String(length=64), nullable=False),
        sa.Column("risk_claim", sa.String(length=2), nullable=False),
        sa.Column("authentik_version", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("apply_status", sa.String(length=30), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("trace_id", sa.UUID(), nullable=False),
        sa.CheckConstraint("apply_status = 'nog_niet_toepasbaar'", name=op.f("ck_sso_proposal_apply_not_available")),
        sa.CheckConstraint("risk_claim IN ('R2','R3')", name=op.f("ck_sso_proposal_risk_at_least_r2")),
        sa.CheckConstraint("status IN ('voorstel','verlopen','vervangen')", name=op.f("ck_sso_proposal_status")),
        sa.CheckConstraint("expires_at > created_at", name=op.f("ck_sso_proposal_expiry")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_sso_proposal")),
    )
    op.create_index("ix_sso_proposal_created_at", "sso_proposal", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_sso_proposal_created_at", table_name="sso_proposal")
    op.drop_table("sso_proposal")
    op.drop_table("sso_group_role_mapping")
    op.drop_index("ix_sso_authentik_snapshot_kind_taken_at", table_name="sso_authentik_snapshot")
    op.drop_table("sso_authentik_snapshot")
    op.drop_index("ix_sso_auth_event_user_action", table_name="sso_auth_event")
    op.drop_index("ix_sso_auth_event_created", table_name="sso_auth_event")
    op.drop_table("sso_auth_event")
    op.drop_table("sso_app_setting")
    op.drop_index("ix_sso_anomaly_detected_at", table_name="sso_anomaly")
    op.drop_table("sso_anomaly")
    op.drop_index("ix_jwt_jti_use_expires_at", table_name="jwt_jti_use")
    op.drop_table("jwt_jti_use")
