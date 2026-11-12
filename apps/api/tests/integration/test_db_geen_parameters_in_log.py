"""V-094: een databasefout zet de parameterwaarden niet in de foutmelding of in de app-log.

De productie-engine (integrations.db.Database) staat op hide_parameters=True. Zonder die stand schrijft SQLAlchemy
bij elke databasefout "[parameters: {...}]" met de letterlijke waarden in str(fout); de algemene foutafhandeling
(integrations.errors, log.exception) zet die tekst dan in de app-log. Een parameter kan een geheim of token zijn.
"""

from __future__ import annotations

import logging

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from integrations.db import Database

pytestmark = pytest.mark.integration

# Herkenbare testwaarde (geen echt geheim); te lang voor varchar(8), dus PostgreSQL weigert hem.
TESTWAARDE = "hch-v094-testgeheim-0123456789"


def test_databasefout_zonder_parameterwaarden_in_fout_en_log(clean_db: str, caplog: pytest.LogCaptureFixture) -> None:
    db = Database(clean_db)
    try:
        with db.sessions() as s, pytest.raises(DBAPIError) as info:
            s.execute(text("CREATE TEMP TABLE v094_proef (waarde varchar(8))"))
            s.execute(text("INSERT INTO v094_proef (waarde) VALUES (:waarde)"), {"waarde": TESTWAARDE})
        fout = info.value
        # De fout zelf blijft bruikbaar: de SQL-tekst en de oorzaak staan er nog in.
        assert "INSERT INTO v094_proef" in str(fout)
        assert "parameters hidden" in str(fout)
        assert TESTWAARDE not in str(fout)
        assert TESTWAARDE not in repr(fout)
        # Zoals de algemene foutafhandeling het logt (integrations.errors: log.exception).
        with caplog.at_level(logging.ERROR, logger="integrations"):
            try:
                raise fout
            except DBAPIError:
                logging.getLogger("integrations").exception("onverwachte fout (trace %s)", "v094")
        assert caplog.records, "de fout is niet gelogd"
        assert "INSERT INTO v094_proef" in caplog.text
        assert TESTWAARDE not in caplog.text
    finally:
        db.dispose()
