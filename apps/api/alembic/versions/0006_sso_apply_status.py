"""Maak de toegestane Authentik-uitvoerstanden expliciet, zonder bestaande rijen te wijzigen.

In het voorbereidende deel is uitsluitend de gesloten stand toegestaan.

Revision ID: 0006
Revises: 0005
"""

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_check_constraint(
        op.f("ck_sso_proposal_apply_status"), "sso_proposal", "apply_status IN ('nog_niet_toepasbaar')"
    )
    op.drop_constraint(op.f("ck_sso_proposal_apply_not_available"), "sso_proposal", type_="check")


def downgrade() -> None:
    op.create_check_constraint(
        op.f("ck_sso_proposal_apply_not_available"), "sso_proposal", "apply_status = 'nog_niet_toepasbaar'"
    )
    op.drop_constraint(op.f("ck_sso_proposal_apply_status"), "sso_proposal", type_="check")
