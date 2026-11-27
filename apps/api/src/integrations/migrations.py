"""Alembic-migraties programmatisch (ook in de alles-in-één image, via ``HCH_ALEMBIC_DIR``)."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from psycopg import ProgrammingError
from psycopg.conninfo import make_conninfo
from sqlalchemy import Connection, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

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
    destination = backup_dir or settings.data_dir / "backups"

    def backup(current: str, connection: Connection) -> None:
        nonlocal dump
        snapshot = connection.scalar(text("SELECT pg_export_snapshot()"))
        if snapshot is None:
            raise BackupError("De terugmigratie kon geen databasesnapshot voor de dump delen")
        dump = _write_backup(settings, current, destination, "voor-terugmigratie", snapshot=snapshot)

    cfg = alembic_config(settings)
    cfg.attributes["downgrade_target"] = revision
    cfg.attributes["downgrade_backup_dir"] = destination
    cfg.attributes["backup_before_downgrade"] = backup
    command.downgrade(cfg, revision)
    return dump


def preflight_downgrade(cfg: Config, connection: Connection) -> None:
    """Controleer de gegevensvoorwaarden van alle geplande stappen op het beginschema."""
    scripts = ScriptDirectory.from_config(cfg)
    heads = MigrationContext.configure(connection).get_current_heads()
    needs_backup = False
    for step in scripts.iterate_revisions(heads, cfg.attributes["downgrade_target"], select_for_downgrade=True):
        check = getattr(step.module, "check_downgrade", None)
        if check is not None and check(connection):
            needs_backup = True
    if needs_backup:
        backup_dir = cfg.attributes["downgrade_backup_dir"]
        _prepare_backup_dir(backup_dir)
        try:
            # Een bestaande map kan leesbaar zijn terwijl de ACL het maken van een dumplocatie weigert.
            with tempfile.TemporaryDirectory(dir=backup_dir):
                pass
        except OSError as exc:
            raise BackupError("De back-upmap is niet beschrijfbaar") from exc


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


def _prepare_backup_dir(backup_dir: Path) -> None:
    if shutil.which("pg_dump") is None:
        raise BackupError("pg_dump ontbreekt; zonder back-up vooraf wordt niet gemigreerd")
    try:
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with contextlib.suppress(PermissionError):  # NFSv4-ACL met aclmode=restricted weigert chmod
            os.chmod(backup_dir, 0o700)  # back-ups bevatten de (versleutelde) vault en de audit: alleen de app zelf
    except OSError as exc:
        raise BackupError(f"de back-upmap {backup_dir} kan niet worden aangemaakt") from exc


def _write_backup(
    settings: Settings, current: str, backup_dir: Path, prefix: str, keep: int = 3, *, snapshot: str | None = None
) -> Path:
    _prepare_backup_dir(backup_dir)
    try:
        # Dezelfde URL-uitleg als de migratie, inclusief dbname en Unix-sockets in de query.
        url = make_url(settings.database_url)
        args, parameters = url.get_dialect()().create_connect_args(url)
        password = parameters.pop("password", None)
        conninfo = make_conninfo(*args, **parameters)
    except (ArgumentError, ProgrammingError, ValueError):
        raise BackupError("De databaseverbinding voor pg_dump kon niet worden bepaald") from None
    env = os.environ.copy()
    if password is not None:
        env["PGPASSWORD"] = str(password)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    target = backup_dir / f"{prefix}-{current}-{stamp}.dump"
    checksum = target.with_suffix(".dump.sha256")
    try:
        with tempfile.TemporaryDirectory(dir=backup_dir) as directory:
            partial = Path(directory) / target.name
            cmd = ["pg_dump", "-Fc", "--no-password", "-f", str(partial), "--dbname", conninfo]
            if snapshot is not None:
                # PostgreSQL weigert import van de snapshot op een andere database of server.
                cmd.extend(("--snapshot", snapshot))
            result = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)  # noqa: S603
            if result.returncode != 0 or not partial.is_file() or partial.stat().st_size == 0:
                raise BackupError(f"pg_dump vóór de migratie mislukte (code {result.returncode})")
            with contextlib.suppress(PermissionError):  # idem; de ACL van de dataset bepaalt het dan
                os.chmod(partial, 0o600)
            with partial.open("rb") as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
                os.fsync(handle.fileno())
            with (Path(directory) / checksum.name).open("w", encoding="ascii") as handle:
                with contextlib.suppress(PermissionError):
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
