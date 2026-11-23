"""Invoer voor de lokale Hub-proef. Dit bestand draait met de Python van het archief van ai-server-manager."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from runpy import run_path
from unittest.mock import patch

from hub import __file__ as hub_file
from hub.__main__ import main
from hub.backup import bronmetingen
from hub.models import Decision, InventoryRun, InventorySnapshot, Service
from hub.onboarding.service import seed
from hub.registry import expected_repository
from hub.timeutil import iso, utcnow
from hub.truenas.client import build_ws_url
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def start_api(port: str) -> int:
    # De app-back-ups komen uit de eigen testfixture van de Hub. Ook de oorspronkelijke gate blijft rekenen
    # met de plaatselijke inventaris, besluiten, executorregistratie en de echte dump van de eigen testdatabase.
    roots = (*Path(hub_file).resolve().parents, Path(sys.prefix).parent)
    fixture = next(p / "tests/backupfixtures.py" for p in roots if (p / "tests/backupfixtures.py").is_file())
    appmetingen = run_path(str(fixture))["groene_appmetingen"]
    with patch.object(bronmetingen, "lees", lambda db, settings: appmetingen(utcnow())):
        return main(["api", "--host", "localhost", "--port", port])


def inventaris(app_id: str, port: int) -> None:
    """Meetgegevens uit de simulator in de eigen Hub-database. Alle dienstverkeer gaat naar de lokale connector."""
    with Session(create_engine(os.environ["HUB_DATABASE_URL"])) as db, db.begin():
        seed(db)
        for key, value in {
            "D03": {"nas_adres": "localhost"},
            "D04": {"methode": "truenas_cloud_sync", "taken": ["interop"]},
            "D05": None,
            "D06": None,
            "D16": {"per_app": [{"app_id": "emby", "rpo_uren": 24, "rto_uren": 4}]},
        }.items():
            decision = db.get(Decision, key)
            decision.status, decision.waarde = "Getest", value
        db.add(Service(app_id="ai-server-manager-executor", enrolled_via="koppelcode"))
        run = InventoryRun(status="ok", target_url=build_ws_url("localhost", None))
        db.add(run)
        db.flush()
        app = {
            "naam": app_id,
            "images": [{"repository": expected_repository(app_id)}],
            "poorten": [{"host_poort": port, "container_poort": 30420, "protocol": "tcp"}],
        }
        sync = {
            "id": 1,
            "omschrijving": "interop",
            "ingeschakeld": True,
            "richting": "PUSH",
            "is_onedrive": True,
            "laatste_job": {"staat": "SUCCESS", "beeindigd": iso(utcnow())},
        }
        for kind, method, data in (
            ("apps", "app.query", [app]),
            ("pools", "pool.query", [{"naam": "testpool", "status": "ONLINE", "gezond": True}]),
            ("cloudsync", "cloudsync.query", [sync]),
        ):
            db.add(InventorySnapshot(run_id=run.id, kind=kind, status="ok", method=method, data=data))


if __name__ == "__main__":
    if sys.argv[1] == "api":
        raise SystemExit(start_api(sys.argv[2]))
    if sys.argv[1] == "inventaris":
        inventaris(sys.argv[2], int(sys.argv[3]))
    else:
        raise SystemExit("Onbekende proefopdracht")
