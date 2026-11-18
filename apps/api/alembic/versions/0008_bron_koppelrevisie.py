"""Voeg een koppelrevisie toe aan integration_source en vul die voor bestaande rijen.

Alleen een kolom erbij; er gaat niets verloren. Elke bestaande bron krijgt een eigen willekeurige revisie.

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import context, op

from integrations.migrations import BackupError

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("integration_source", sa.Column("link_revision", sa.String(36), nullable=True))
    op.execute("UPDATE integration_source SET link_revision = gen_random_uuid()::text")
    op.alter_column("integration_source", "link_revision", nullable=False)


def downgrade() -> None:
    if context.is_offline_mode():
        raise BackupError("Terugmigratie van 0008 vereist een databaseverbinding om de koppelrevisies te beschermen")
    # Blokkeer nieuwe of gewijzigde koppelrevisies tot het einde van de migratie. Pg_dump kan de tabel wel lezen.
    op.execute("LOCK TABLE integration_source IN SHARE MODE")
    if op.get_bind().scalar(sa.text("SELECT EXISTS (SELECT 1 FROM integration_source)")):
        backup = context.config.attributes.get("backup_before_downgrade")
        if backup is None:
            raise BackupError("Gebruik 'integrations migrate --down' om de koppelrevisies vooraf te archiveren")
        backup(revision)
    op.drop_column("integration_source", "link_revision")
