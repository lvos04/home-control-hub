"""Alembic-migraties programmatisch (ook in de alles-in-één image, via ``HCH_ALEMBIC_DIR``)."""

from __future__ import annotations

import logging
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from .config import Settings
from .db import Database

log = logging.getLogger("integrations.migrations")


def alembic_dir(settings: Settings) -> Path:
    if settings.alembic_dir is not None:
        return settings.alembic_dir
    return Path(__file__).resolve().parents[2] / "alembic"


def alembic_config(settings: Settings) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(alembic_dir(settings)))
    cfg.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
    return cfg


def head_revision(settings: Settings) -> str | None:
    return ScriptDirectory.from_config(alembic_config(settings)).get_current_head()


def upgrade(settings: Settings, revision: str = "head") -> None:
    command.upgrade(alembic_config(settings), revision)


def downgrade(settings: Settings, revision: str) -> None:
    command.downgrade(alembic_config(settings), revision)


def pending(settings: Settings, db: Database) -> bool:
    return db.current_revision() != head_revision(settings)


def pre_upgrade_backup(settings: Settings, db: Database, backup_dir: Path, keep: int = 3) -> Path | None:
    """``pg_dump -Fc`` vóór openstaande migraties (alleen als er al een schema is). Faalt nooit hard."""
    current = db.current_revision()
    if current is None or current == head_revision(settings):
        return None
    if shutil.which("pg_dump") is None:
        log.warning("pg_dump ontbreekt; geen back-up vóór upgrade")
        return None
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    target = backup_dir / f"voor-upgrade-{current}-{stamp}.dump"
    parts = urlsplit(settings.database_url.replace("postgresql+psycopg://", "postgresql://"))
    host = parse_qs(parts.query).get("host", [parts.hostname or ""])[0]
    cmd = [
        "pg_dump",
        "-Fc",
        "-f",
        str(target),
        "-h",
        host,
        "-U",
        parts.username or "hch",
        (parts.path or "/hch").lstrip("/"),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603 (vaste argumenten)
    if result.returncode != 0:
        log.warning("back-up vóór upgrade mislukt (code %s); migratie gaat door", result.returncode)
        target.unlink(missing_ok=True)
        return None
    dumps = sorted(backup_dir.glob("voor-upgrade-*.dump"))
    for old in dumps[:-keep]:
        old.unlink(missing_ok=True)
    return target
