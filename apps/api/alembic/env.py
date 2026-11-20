"""Alembic-omgeving. De URL komt uit de Config (migrations.py) of uit HCH_DATABASE_URL."""

from __future__ import annotations

import os

from alembic import context
from sqlalchemy import engine_from_config, pool

from integrations.models import all_models

config = context.config
target_metadata = all_models().metadata

url = config.get_main_option("sqlalchemy.url") or os.environ.get("HCH_DATABASE_URL")
if not url:
    raise RuntimeError("Geen database-URL: zet HCH_DATABASE_URL of gebruik 'python -m integrations migrate'.")
config.set_main_option("sqlalchemy.url", url.replace("%", "%%") if "%%" not in url else url)


def run_migrations_offline() -> None:
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}), prefix="sqlalchemy.", poolclass=pool.NullPool
    )
    with connectable.connect() as connection:
        # Een terugmigratie kan pg_dump vanuit een tweede verbinding starten. Geef de DDL-sloten
        # van de voorgaande revisie eerst vrij, met haar versie en wijzigingen samen vastgelegd.
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            transaction_per_migration=config.attributes.get("backup_before_downgrade") is not None,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
