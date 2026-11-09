"""contract 1.2: replaycache op (iss, jti) voor elke Hub-JWT

- ``jwt_jti_use`` krijgt de kolom ``iss`` (bestaande rijen: ``hub``) en de primaire sleutel ``(iss, jti)`` (§4.6).
- De koppeling met de Hub verhuist naar ``/appdata/secrets/hub-link.json`` (§3.5). Dat overzetten gebeurt bij de
  eerste start door de app zelf (het service-token is versleuteld en alleen met ``vault.key`` te lezen); deze
  migratie wijzigt daarom niets aan ``service_state`` of ``vault_secret``.

Terugdraaien: de kolom ``iss`` vervalt; de cache is kortlevend (≤ 150 s), dus eerst leegmaken is veilig.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-09 17:30:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("jwt_jti_use", sa.Column("iss", sa.String(length=40), nullable=False, server_default="hub"))
    op.alter_column("jwt_jti_use", "iss", server_default=None)
    op.drop_constraint("pk_jwt_jti_use", "jwt_jti_use", type_="primary")
    op.create_primary_key("pk_jwt_jti_use", "jwt_jti_use", ["iss", "jti"])


def downgrade() -> None:
    op.execute("DELETE FROM jwt_jti_use")
    op.drop_constraint("pk_jwt_jti_use", "jwt_jti_use", type_="primary")
    op.drop_column("jwt_jti_use", "iss")
    op.create_primary_key("pk_jwt_jti_use", "jwt_jti_use", ["jti"])
