"""Bewaar het bevestigde adres van een Authentik-aanmelding, ook als de bron tijdelijk uit staat."""

import sqlalchemy as sa
from alembic import context, op

from integrations.migrations import BackupError

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("integration_source", sa.Column("credential_base_url", sa.String(500), nullable=True))
    # Oudere versies bewaarden het token ook bij een adreswissel. Alleen een volledig auditspoor met één
    # bestemming bewijst bij welk adres de beheerder het invoerde. Laat bij twijfel de kluisrij intact.
    op.execute("""
        UPDATE integration_source AS s SET credential_base_url = s.base_url
        FROM (
            SELECT count(*) AS wijzigingen, min(details->>'base_url') AS adres
            FROM audit_event
            WHERE action = 'source.configured' AND entity_type = 'integration_source' AND entity_id = 'authentik'
            HAVING count(*) = count(details->>'base_url') AND count(DISTINCT details->>'base_url') = 1
        ) AS historie
        WHERE s.source_id = 'authentik' AND s.credential_ref = 'vault://source/authentik'
            AND s.version = historie.wijzigingen AND s.base_url = historie.adres
        """)


def downgrade() -> None:
    if context.is_offline_mode():
        raise BackupError("Controleer vóór terugmigratie of er een Authentik-aanmelding is.")
    op.execute("LOCK TABLE integration_source IN SHARE MODE")
    connection = op.get_bind()
    bron = connection.execute(
        sa.text("""
        SELECT base_url, credential_base_url, credential_ref FROM integration_source
        WHERE source_id = 'authentik' AND credential_ref IS NOT NULL
        """)
    ).one_or_none()
    if bron is not None:
        if (
            not bron.base_url
            or bron.base_url != bron.credential_base_url
            or bron.credential_ref != "vault://source/authentik"
        ):
            raise BackupError("Schema 0009 zou een onbevestigde Authentik-aanmelding kunnen activeren.")
        backup = context.config.attributes.get("backup_before_downgrade")
        if backup is None:
            raise BackupError("Gebruik 'integrations migrate --down' om het aanmeldadres vooraf te archiveren.")
        backup(revision, connection)
    op.drop_column("integration_source", "credential_base_url")
