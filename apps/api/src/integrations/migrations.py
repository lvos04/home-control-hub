"""Alembic-migraties programmatisch (ook in de alles-in-één image, via ``HCH_ALEMBIC_DIR``)."""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
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


def revision_known(settings: Settings, revision: str) -> bool:
    """Kent deze versie van de app de revisie in de database? Zo niet, dan is de database nieuwer (tag-only rollback)."""
    try:
        return ScriptDirectory.from_config(alembic_config(settings)).get_revision(revision) is not None
    except Exception:
        return False


def upgrade(settings: Settings, revision: str = "head") -> None:
    command.upgrade(alembic_config(settings), revision)


def downgrade(settings: Settings, revision: str, backup_dir: Path | None = None) -> Path | None:
    """Geef een gegevensverwijderende revisie toegang tot de gedeelde dumpvoorziening."""
    dump = None

    def backup(current: str) -> None:
        nonlocal dump
        dump = _write_backup(settings, current, backup_dir or settings.data_dir / "backups", "voor-terugmigratie")

    cfg = alembic_config(settings)
    cfg.attributes["backup_before_downgrade"] = backup
    command.downgrade(cfg, revision)
    return dump


def pending(settings: Settings, db: Database) -> bool:
    return db.current_revision() != head_revision(settings)


class BackupError(RuntimeError):
    """De back-up vóór een migratie is mislukt; er wordt dan **niet** gemigreerd (fail-closed, gate-matrix)."""


def pre_upgrade_backup(settings: Settings, db: Database, backup_dir: Path, keep: int = 3) -> Path | None:
    """``pg_dump -Fc`` vóór openstaande migraties op een bestaand schema.

    Geeft ``None`` als er niets te back-uppen is (verse database of al op de nieuwste revisie). Mislukt de back-up,
    dan volgt ``BackupError`` en mag de aanroeper niet migreren: een schemawijziging zonder database-export vooraf is
    volgens de gate-matrix (``06_FASERING_EN_GATES``) niet toegestaan.
    """
    current = db.current_revision()
    if current is None or current == head_revision(settings):
        return None
    return _write_backup(settings, current, backup_dir, "voor-upgrade", keep)


def _write_backup(settings: Settings, current: str, backup_dir: Path, prefix: str, keep: int = 3) -> Path:
    if shutil.which("pg_dump") is None:
        raise BackupError("pg_dump ontbreekt; zonder back-up vooraf wordt niet gemigreerd")
    try:
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(backup_dir, 0o700)  # back-ups bevatten de (versleutelde) vault en de audit: alleen de app zelf
    except OSError as exc:
        raise BackupError(f"de back-upmap {backup_dir} kan niet worden aangemaakt") from exc
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    target = backup_dir / f"{prefix}-{current}-{stamp}.dump"
    checksum = target.with_suffix(".dump.sha256")
    parts = urlsplit(settings.database_url.replace("postgresql+psycopg://", "postgresql://"))
    query = parse_qs(parts.query)
    host = query.get("host", [parts.hostname or ""])[0]
    port = query.get("port", [str(parts.port or "")])[0]
    try:
        with tempfile.TemporaryDirectory(dir=backup_dir) as directory:
            partial = Path(directory) / target.name
            cmd = ["pg_dump", "-Fc", "-f", str(partial), "-h", host, "-U", parts.username or "hch"]
            if port:
                cmd.extend(("-p", port))
            cmd.append((parts.path or "/hch").lstrip("/"))
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603 (vaste argumenten)
            if result.returncode != 0 or not partial.is_file() or partial.stat().st_size == 0:
                raise BackupError(f"pg_dump vóór de migratie mislukte (code {result.returncode})")
            os.chmod(partial, 0o600)
            with partial.open("rb") as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
                os.fsync(handle.fileno())
            with (Path(directory) / checksum.name).open("w", encoding="ascii") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(f"{digest}  {target.name}\n")
                handle.flush()
                os.fsync(handle.fileno())
            (Path(directory) / checksum.name).replace(checksum)
            partial.replace(target)
        # De dump wordt pas zichtbaar nadat zijn checksum beschikbaar is.
        dir_fd = os.open(backup_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        dumps = sorted(backup_dir.glob(f"{prefix}-*.dump"), key=lambda f: (f.stat().st_mtime, f.name))
        for old in dumps[:-keep]:
            if old != target:
                old.unlink(missing_ok=True)
                old.with_suffix(".dump.sha256").unlink(missing_ok=True)
    except OSError as exc:
        raise BackupError("Het dump- of SHA-256-bestand kon niet veilig worden opgeslagen.") from exc
    return target
