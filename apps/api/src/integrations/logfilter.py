"""Databasefouten in de log zonder de DETAIL-regel van PostgreSQL (KLEIN-32).

PostgreSQL zet bij een constraint-schending een DETAIL-regel in de fouttekst: de sleutelwaarde
("Key (kolom)=(waarde) already exists.") of de hele rij ("Failing row contains (...)"). ``hide_parameters=True``
(V-094) haalt alleen de parameters weg, niet deze regel; via ``str(fout)`` en de traceback komt hij anders in de log.

- :func:`db_error_text` geeft van een databasefout alleen soort, sqlstate, constraint en tabel (zelfde aanpak als
  ``db_error_text`` in my_house, KLEIN-31). De algemene foutafhandeling van API en worker logt daarmee.
- :class:`DbDetailFilter` is het vangnet op de handlers van de app: in bericht en exceptietekst wordt alles vanaf een
  regel die met ``DETAIL:`` begint, en elke regel met ``Failing row contains``, vervangen door een vaste aantekening.
"""

from __future__ import annotations

import copy
import logging
import re
from typing import Any

DETAIL_WEGGELATEN = "[DETAIL weggelaten]"

# Vanaf het begin van een regel die (na witruimte) met DETAIL: begint, tot het eind van de tekst.
_DETAIL_TOT_EIND = re.compile(r"^[ \t]*DETAIL:.*\Z", re.MULTILINE | re.DOTALL)
_FAILING_ROW = re.compile(r"^.*Failing row contains.*$", re.MULTILINE)


def db_error_text(exc: BaseException) -> str:
    """Een databasefout als tekst zonder DETAIL: alleen soort, sqlstate, constraint en tabel, voor zover de driver
    die geeft (psycopg: ``orig.diag``; asyncpg: ``orig.__cause__``). Nooit ``str(exc)`` of ``str(exc.orig)``."""
    orig = getattr(exc, "orig", None) or exc
    bronnen = [orig, getattr(orig, "__cause__", None), getattr(orig, "diag", None)]

    def veld(*namen: str) -> str | None:
        for bron in bronnen:
            for naam in namen:
                waarde = getattr(bron, naam, None) if bron is not None else None
                if isinstance(waarde, str) and waarde:
                    return waarde
        return None

    soort = type(getattr(orig, "__cause__", None) or orig).__name__
    delen = [f"databasefout {soort}"]
    sqlstate = veld("sqlstate", "pgcode")
    if sqlstate:
        delen.append(f"(sqlstate {sqlstate})")
    constraint = veld("constraint_name")
    if constraint:
        delen.append(f"op constraint {constraint}")
    tabel = veld("table_name")
    if tabel:
        delen.append(f"(tabel {tabel})")
    return " ".join(delen) + "."


def scrub_detail(tekst: str) -> str:
    """Haalt de DETAIL-regel (en alles erna) en regels met 'Failing row contains' uit een tekst."""
    tekst = _DETAIL_TOT_EIND.sub(DETAIL_WEGGELATEN, tekst, count=1)
    return _FAILING_ROW.sub(DETAIL_WEGGELATEN, tekst)


_STANDAARD_FORMATTER = logging.Formatter()


class DbDetailFilter(logging.Filter):
    """Logfilter (vangnet): haalt DETAIL van PostgreSQL uit bericht, exceptie- en stacktekst. Laat elk record door."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            bericht = record.getMessage()
        except Exception:  # een kapot record laten we aan de formatter over
            bericht = None
        if bericht is not None:
            schoon = scrub_detail(bericht)
            if schoon != bericht:  # alleen dan: de access-log van uvicorn leest record.args zelf
                record.msg, record.args = schoon, None
        if record.exc_info and record.exc_info[0] is not None:
            tekst = record.exc_text or _STANDAARD_FORMATTER.formatException(record.exc_info)
            schoon = scrub_detail(tekst)
            if schoon != tekst:
                # de geschoonde tekst als cache; zonder exc_info kan geen handler het origineel opnieuw opmaken
                record.exc_text, record.exc_info = schoon, None
        elif record.exc_text:
            record.exc_text = scrub_detail(record.exc_text)
        if record.stack_info:
            record.stack_info = scrub_detail(record.stack_info)
        return True


def install_log_filter(logger: logging.Logger | None = None) -> None:
    """Hangt het filter aan elke handler van ``logger`` (standaard de root-logger); tweemaal aanhaken mag."""
    for handler in (logger or logging.getLogger()).handlers:
        if not any(isinstance(f, DbDetailFilter) for f in handler.filters):
            handler.addFilter(DbDetailFilter())


def uvicorn_log_config() -> dict[str, Any]:
    """De standaard-logconfiguratie van uvicorn, met het filter op elke handler ("Exception in ASGI application"
    logt uvicorn met de volledige traceback, ook nadat de algemene foutafhandeling het antwoord gaf)."""
    from uvicorn.config import LOGGING_CONFIG

    config = copy.deepcopy(LOGGING_CONFIG)
    config.setdefault("filters", {})["db_detail"] = {"()": "integrations.logfilter.DbDetailFilter"}
    for handler in config["handlers"].values():
        handler["filters"] = [*handler.get("filters", []), "db_detail"]
    return config
