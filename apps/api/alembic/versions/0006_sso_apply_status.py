"""Maak de toegestane Authentik-uitvoerstanden expliciet, zonder bestaande rijen te wijzigen.

In het voorbereidende deel is uitsluitend de gesloten stand toegestaan.

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_check_constraint(
        op.f("ck_sso_proposal_apply_status"), "sso_proposal", "apply_status IN ('nog_niet_toepasbaar')"
    )


def downgrade() -> None:
    # Ook rechtstreeks terugzetten van een database met de eerder gepubliceerde 0006 blijft veilig.
    exists = op.get_bind().scalar(
        sa.text(
            "SELECT 1 FROM pg_constraint WHERE conrelid = 'sso_proposal'::regclass "
            "AND conname = 'ck_sso_proposal_apply_not_available'"
        )
    )
    if exists is None:
        op.create_check_constraint(
            op.f("ck_sso_proposal_apply_not_available"), "sso_proposal", "apply_status = 'nog_niet_toepasbaar'"
        )
    op.drop_constraint(op.f("ck_sso_proposal_apply_status"), "sso_proposal", type_="check")
