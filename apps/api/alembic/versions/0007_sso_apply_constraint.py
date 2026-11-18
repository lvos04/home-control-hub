"""Herstel de oude SSO-constraint op databases die de eerste versie van 0006 hebben gedraaid.

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
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


def downgrade() -> None:
    # De herstelde voorwaarde hoort al bij 0005 en bij de gecorrigeerde 0006.
    pass
