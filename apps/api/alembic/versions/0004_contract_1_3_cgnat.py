"""contract 1.3: 100.64.0.0/10 telt standaard niet als privé (noodtoegang)

- ``sso_emergency_access`` krijgt ``cgnat_toegestaan`` (standaard ``false``). Een bestaande registratie met een
  100.64.0.0/10-bereik blijft staan, maar dat bereik geeft geen toegang meer tot een beheerder het bewust toestaat
  (§4.1: verscherpen, nooit stil verruimen); de herstelstatus meldt het als aandachtspunt.

Terugdraaien: de kolom vervalt (een 100.64-bereik telt dan weer als privé, zoals in contract 1.2).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-10 10:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "sso_emergency_access",
        sa.Column("cgnat_toegestaan", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )


def downgrade() -> None:
    op.drop_column("sso_emergency_access", "cgnat_toegestaan")
