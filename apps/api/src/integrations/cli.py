"""Commando's: ``python -m integrations <init|migrate|api|worker|openapi|enroll>``."""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import threading
from pathlib import Path

from .config import Settings
from .logfilter import install_log_filter, uvicorn_log_config


def _logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    install_log_filter()  # KLEIN-32: vangnet tegen de DETAIL-regel van PostgreSQL
    logging.getLogger("alembic.runtime.plugins").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def cmd_init(settings: Settings) -> int:
    from .security.secrets import ensure_secrets

    created = ensure_secrets(settings.secrets_dir)
    print("geheimen aangemaakt: " + (", ".join(created) if created else "geen (bestonden al)"))
    return 0


def cmd_migrate(settings: Settings, backup_dir: str | None, down: str | None) -> int:
    from .db import Database
    from .migrations import BackupError, downgrade, pre_upgrade_backup, revision_known, upgrade

    if down:
        downgrade(settings, down)
        print(f"teruggezet naar {down}")
        return 0
    db = Database(settings.database_url)
    try:
        current = db.current_revision()
        if current is not None and not revision_known(settings, current):
            print(
                f"FOUT: de database staat op revisie {current}, die deze versie van de app niet kent: de database is "
                "nieuwer dan deze image. Alleen de image-tag terugzetten kan niet; herstel de back-up uit "
                "/appdata/backups of de dataset-snapshot van vóór de update. Er is niets gewijzigd.",
                file=sys.stderr,
            )
            return 4
        if backup_dir:
            try:
                dump = pre_upgrade_backup(settings, db, Path(backup_dir))
            except BackupError as exc:
                print(
                    f"FOUT: back-up vóór de migratie mislukt: {exc}. Er is NIET gemigreerd; de database is ongewijzigd.",
                    file=sys.stderr,
                )
                return 3
            if dump:
                print(f"back-up vóór upgrade: {dump}")
        upgrade(settings)
        print(f"database op revisie {db.current_revision()}")
    finally:
        db.dispose()
    return 0


def cmd_api(settings: Settings, host: str, port: int) -> int:
    import uvicorn

    from .app import create_app

    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
        log_level="info",
        log_config=uvicorn_log_config(),
        proxy_headers=False,
        server_header=False,
    )
    return 0


def cmd_worker(settings: Settings, once: bool) -> int:
    from .worker import Worker

    worker = Worker(settings)
    if once:
        worker.run_once()
        print(json.dumps(worker.state.stats))
        return 0
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    worker.run(stop)
    return 0


def export_openapi(settings: Settings | None = None) -> str:
    """Deterministische export; gebruikt een tijdelijke datamap (raakt /appdata en de database niet aan)."""
    import dataclasses
    import tempfile

    from .app import create_app

    base = settings or Settings()
    with tempfile.TemporaryDirectory(prefix="hch-openapi-") as tmp:
        app = create_app(dataclasses.replace(base, data_dir=Path(tmp)))
        return json.dumps(app.openapi(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def cmd_openapi(settings: Settings, out: str | None) -> int:
    text = export_openapi(settings)
    if out:
        Path(out).write_text(text, encoding="utf-8")
        print(f"OpenAPI geschreven naar {out}")
    else:
        sys.stdout.write(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="integrations", description="Home Control Hub — integratiedienst")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="ontbrekende geheimen aanmaken in <data>/secrets")
    m = sub.add_parser("migrate", help="databasemigraties uitvoeren")
    m.add_argument("--backup-dir", help="pg_dump vóór openstaande migraties naar deze map")
    m.add_argument("--down", help="terug naar deze revisie (bv. base)")
    a = sub.add_parser("api", help="API + statuspagina starten")
    a.add_argument("--host", default="0.0.0.0")  # noqa: S104 - in de container; poort via het formulier
    a.add_argument("--port", type=int, default=None)
    w = sub.add_parser("worker", help="achtergrondtaken")
    w.add_argument("--once", action="store_true")
    o = sub.add_parser("openapi", help="OpenAPI-schema exporteren")
    o.add_argument("--out")
    args = parser.parse_args(argv)
    _logging()
    settings = Settings.from_env()
    if args.cmd == "init":
        return cmd_init(settings)
    if args.cmd == "migrate":
        return cmd_migrate(settings, args.backup_dir, args.down)
    if args.cmd == "api":
        return cmd_api(settings, args.host, args.port or settings.port)
    if args.cmd == "worker":
        return cmd_worker(settings, args.once)
    return cmd_openapi(settings, args.out)
