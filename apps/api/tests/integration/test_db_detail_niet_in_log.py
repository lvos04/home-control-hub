"""KLEIN-32: een onverwachte databasefout zet de DETAIL-regel van PostgreSQL niet in de app-log.

Bij een unique-schending noemt PostgreSQL in DETAIL de sleutelwaarde ("Key (kolom)=(waarde) already exists."), bij een
check- of not-null-schending de hele rij ("Failing row contains (...)"). ``hide_parameters=True`` (V-094) haalt alleen
de parameters weg, niet deze regel. De algemene foutafhandeling (API en worker) logt daarom bij een databasefout alleen
soort, sqlstate, constraint en tabel; een logfilter op de handlers van de app haalt DETAIL ook elders weg (vangnet).
Het HTTP-antwoord blijft de vaste 500 ``internal_error``.
"""

from __future__ import annotations

import io
import logging
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from integrations.db import Database
from integrations.errors import install_handlers

pytestmark = pytest.mark.integration

# Herkenbare testwaarden (geen echte geheimen).
SLEUTELWAARDE = "hch-klein32-sleutel-0123456789"
RIJWAARDE = "hch-klein32-rijgeheim-9876543210"


def _schending(db: Database, soort: str) -> None:
    """Een echte constraint-schending in een tijdelijke tabel met benoemde constraints."""
    with db.sessions() as s:
        s.execute(
            text(
                "CREATE TEMP TABLE k32_proef (sleutel text, geheim text, rol text, "
                "CONSTRAINT uq_k32_sleutel UNIQUE (sleutel), "
                "CONSTRAINT ck_k32_rol CHECK (rol IN ('lezer', 'beheerder')))"
            )
        )
        s.execute(text("INSERT INTO k32_proef VALUES (:s, :g, 'lezer')"), {"s": SLEUTELWAARDE, "g": RIJWAARDE})
        if soort == "unique":
            s.execute(text("INSERT INTO k32_proef VALUES (:s, :g, 'lezer')"), {"s": SLEUTELWAARDE, "g": RIJWAARDE})
        else:
            s.execute(text("INSERT INTO k32_proef VALUES (:s, :g, 'onbekend')"), {"s": "ander", "g": RIJWAARDE})


def _geen_detail(tekst: str) -> None:
    tekst = tekst.replace("[DETAIL weggelaten]", "")  # de vaste aantekening van het filter telt niet
    for verboden in (SLEUTELWAARDE, RIJWAARDE, "DETAIL", "Failing row", "Key ("):
        assert verboden not in tekst, f"{verboden!r} staat in de log"


@pytest.mark.parametrize(
    ("soort", "sqlstate", "constraint"),
    [("unique", "23505", "uq_k32_sleutel"), ("check", "23514", "ck_k32_rol")],
)
def test_api_databasefout_logt_geen_detail(
    clean_db: str, caplog: pytest.LogCaptureFixture, soort: str, sqlstate: str, constraint: str
) -> None:
    db = Database(clean_db)
    app = FastAPI()
    install_handlers(app)

    @app.get("/proef")
    def _proef() -> None:
        _schending(db, soort)

    try:
        with caplog.at_level(logging.DEBUG), TestClient(app, raise_server_exceptions=False) as c:
            r = c.get("/proef")
    finally:
        db.dispose()
    # Het antwoord is precies zoals voorheen: vaste 500 zonder fouttekst.
    assert r.status_code == 500
    body = r.json()
    assert body["code"] == "internal_error"
    assert body["message"] == "Interne fout; zie de app-log met dit trace-id."
    assert body["details"] == {}
    assert r.headers["X-Trace-Id"] == body["trace_id"]
    eigen = [rec for rec in caplog.records if rec.name == "integrations"]
    assert eigen, "de fout is niet gelogd"
    logtekst = "\n".join(caplog.handler.format(rec) for rec in eigen)
    _geen_detail(logtekst)
    assert sqlstate in logtekst and constraint in logtekst and "k32_proef" in logtekst
    assert body["trace_id"] in logtekst


def test_worker_databasefout_logt_geen_detail(clean_db: str, caplog: pytest.LogCaptureFixture) -> None:
    from integrations.worker import Worker

    db = Database(clean_db)

    def stap() -> None:
        _schending(db, "check")

    worker: Any = Worker.__new__(Worker)
    namen = ("start_step", "enroll_step", "link_step", "push_step", "authentik_step", "automation_step")
    for naam in namen:
        setattr(worker, naam, (lambda *_: None))
    worker.start_step = stap
    worker.housekeeping_step = lambda *_: None
    gezien: list[list[str]] = []
    worker.heartbeat = lambda _started, failed: gezien.append(failed)
    try:
        with caplog.at_level(logging.DEBUG, logger="integrations"):
            worker.run_once()
    finally:
        db.dispose()
    assert gezien == [["start"]]
    eigen = [rec for rec in caplog.records if rec.name.startswith("integrations")]
    assert eigen, "de fout is niet gelogd"
    logtekst = "\n".join(caplog.handler.format(rec) for rec in eigen)
    _geen_detail(logtekst)
    assert "23514" in logtekst and "ck_k32_rol" in logtekst and "start" in logtekst


@pytest.mark.parametrize("soort", ["unique", "check"])
def test_logfilter_haalt_detail_uit_bericht_en_traceback(clean_db: str, soort: str) -> None:
    from integrations.logfilter import DETAIL_WEGGELATEN, install_log_filter

    db = Database(clean_db)
    try:
        with pytest.raises(DBAPIError) as info:
            _schending(db, soort)
    finally:
        db.dispose()
    assert "DETAIL" in str(info.value)  # zonder filter staat de regel er echt in
    uit = io.StringIO()
    logger = logging.Logger("k32-proef")
    handler = logging.StreamHandler(uit)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger.addHandler(handler)
    install_log_filter(logger)
    install_log_filter(logger)  # tweemaal aanhaken geeft geen dubbel filter
    assert len(handler.filters) == 1
    try:
        raise info.value
    except DBAPIError as exc:
        logger.exception("ergens anders gelogd: %s", exc)
    tekst = uit.getvalue()
    _geen_detail(tekst)
    assert DETAIL_WEGGELATEN in tekst
    assert "ergens anders gelogd" in tekst and "Traceback" in tekst


def test_logfilter_laat_gewone_berichten_en_argumenten_staan() -> None:
    from integrations.logfilter import scrub_detail

    assert scrub_detail("gewone regel\nnog een") == "gewone regel\nnog een"
    record = logging.LogRecord("x", logging.INFO, __file__, 1, '%s - "%s %s"', ("adres", "GET", "/pad"), None)
    from integrations.logfilter import DbDetailFilter

    assert DbDetailFilter().filter(record)
    assert record.args == ("adres", "GET", "/pad")  # de access-log van uvicorn leest record.args
    assert scrub_detail("fout\nDETAIL:  Key (a)=(geheim) already exists.\n[SQL: x]") == "fout\n[DETAIL weggelaten]"
    assert scrub_detail("x\n  Failing row contains (1, geheim).\ny") == "x\n[DETAIL weggelaten]\ny"


def test_uvicorn_logconfig_heeft_het_filter_op_elke_handler() -> None:
    from integrations.logfilter import uvicorn_log_config

    config = uvicorn_log_config()
    assert config["handlers"], "geen handlers"
    for naam, handler in config["handlers"].items():
        assert "db_detail" in handler.get("filters", []), naam
    assert config["filters"]["db_detail"]["()"] == "integrations.logfilter.DbDetailFilter"
