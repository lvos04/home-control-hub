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


def _logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("alembic.runtime.plugins").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)


def cmd_init(settings: Settings) -> int:
    from .security.secrets import ensure_secrets

    created = ensure_secrets(settings.secrets_dir)
    print("geheimen aangemaakt: " + (", ".join(created) if created else "geen (bestonden al)"))
    return 0


def cmd_migrate(settings: Settings, backup_dir: str | None, down: str | None) -> int:
    from .db import Database
    from .migrations import downgrade, pre_upgrade_backup, upgrade

    if down:
        downgrade(settings, down)
        print(f"teruggezet naar {down}")
        return 0
    db = Database(settings.database_url)
    try:
        if backup_dir:
            dump = pre_upgrade_backup(settings, db, Path(backup_dir))
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

    uvicorn.run(create_app(settings), host=host, port=port, log_level="info", proxy_headers=False, server_header=False)
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


def export_openapi(settings: Settings) -> str:
    from .app import create_app

    return json.dumps(create_app(settings).openapi(), indent=2, ensure_ascii=False, sort_keys=True) + "\n"


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
