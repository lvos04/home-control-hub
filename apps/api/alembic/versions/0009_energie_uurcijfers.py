"""Bewaar de vier decimalen van de uur-export en een bronschatting zonder opgegeven zekerheid."""

import sqlalchemy as sa
from alembic import context, op

from integrations.migrations import BackupError

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

PROVENANCE = "energy_estimate_provenance"
INTERVAL = "energy_usage_interval"
OLD_METHODS = "'interpolatie','cpu_model','vergelijkbare_dag','handmatig'"


def change_methods(methods: str) -> None:
    op.drop_constraint(op.f("ck_energy_estimate_provenance_method"), PROVENANCE, type_="check")
    op.create_check_constraint("method", PROVENANCE, f"method IN ({methods})")


def upgrade() -> None:
    op.alter_column(INTERVAL, "delta", type_=sa.Numeric(15, 4))
    op.alter_column(INTERVAL, "meter_id", nullable=True)
    op.create_check_constraint("value_requires_meter", INTERVAL, "meter_id IS NOT NULL OR quality = 'onbekend'")
    op.create_index(
        "uq_energy_usage_interval_gap",
        INTERVAL,
        ["source_ref", "start_utc", "direction"],
        unique=True,
        postgresql_where=sa.text("meter_id IS NULL"),
    )
    op.create_index("ix_energy_usage_interval_source_start", INTERVAL, ["source_ref", "start_utc"])
    change_methods(OLD_METHODS + ",'bronaggregatie'")
    op.alter_column(PROVENANCE, "confidence", nullable=True)
    op.create_check_constraint(
        "confidence_for_local_estimate", PROVENANCE, "confidence IS NOT NULL OR method = 'bronaggregatie'"
    )


def downgrade() -> None:
    if context.is_offline_mode():
        raise BackupError("Verifieer eerst in de database of de uurcijfers in schema 0008 passen.")
    op.execute("LOCK TABLE energy_estimate_provenance, energy_usage_interval IN SHARE MODE")
    if op.get_bind().scalar(
        sa.text(
            "SELECT EXISTS (SELECT 1 FROM energy_usage_interval WHERE delta <> round(delta, 3) OR meter_id IS NULL) "
            "OR EXISTS (SELECT 1 FROM energy_estimate_provenance WHERE method = 'bronaggregatie')"
        )
    ):
        raise BackupError(
            "Schema 0008 kan de uurcijfers niet zonder verlies bewaren. Herstel de voor-upgradeback-up in een afzonderlijke datamap."
        )
    op.drop_constraint(op.f("ck_energy_estimate_provenance_confidence_for_local_estimate"), PROVENANCE, type_="check")
    op.alter_column(PROVENANCE, "confidence", nullable=False)
    change_methods(OLD_METHODS)
    op.drop_constraint(op.f("ck_energy_usage_interval_value_requires_meter"), INTERVAL, type_="check")
    op.alter_column(INTERVAL, "meter_id", nullable=False)
    op.drop_index("uq_energy_usage_interval_gap", table_name=INTERVAL)
    op.drop_index("ix_energy_usage_interval_source_start", table_name=INTERVAL)
    op.alter_column(INTERVAL, "delta", type_=sa.Numeric(14, 3))
