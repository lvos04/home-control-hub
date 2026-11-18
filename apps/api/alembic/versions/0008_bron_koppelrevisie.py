"""Voeg een koppelrevisie toe aan integration_source en vul die voor bestaande rijen.

Alleen een kolom erbij; er gaat niets verloren. Elke bestaande bron krijgt een eigen willekeurige revisie.

Revision ID: 0008
Revises: 0007
"""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("integration_source", sa.Column("link_revision", sa.String(36), nullable=True))
    op.execute("UPDATE integration_source SET link_revision = gen_random_uuid()::text")
    op.alter_column("integration_source", "link_revision", nullable=False)


def downgrade() -> None:
    op.drop_column("integration_source", "link_revision")
