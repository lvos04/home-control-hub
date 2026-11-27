"""Historische CPU-belasting uit het afgeschermde, lokale Hub-eventarchief."""

from collections.abc import Iterator
from datetime import datetime
from decimal import Decimal
from itertools import groupby, islice

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..automation.models import AutomationEvent
from .readings import source_timestamp


def cpu_readings(
    db: Session, linked_at: datetime, start: datetime, end: datetime, *, latest_four: bool = False
) -> Iterator[tuple[datetime, Decimal | None]]:
    # De beveiligde B11-ingang bewaart het Hub-event al. Lees alleen de projectie van het NAS-CPU-kanaal.
    event = AutomationEvent
    query = (
        select(
            event.timestamp_utc,
            event.payload["waarde"],
            event.payload["eenheid"],
            event.payload["status"],
            event.payload["observed_at"],
        )
        .where(
            event.source_app == "ai-server-manager",
            event.received_by == "service:hub",
            event.catalog_status == "geldig",
            event.test_run_id.is_(None),
            event.event_type == "monitoring.metric.recorded",
            event.entity_type == "nas",
            event.entity_id == "nas",
            event.payload["metriek"].astext == "cpu.gebruik",
            event.timestamp_utc >= max(start, linked_at),
            event.timestamp_utc <= end,
            event.received_at >= linked_at,
        )
        .distinct()
    )
    # Voor de leesroute volstaan vier meettijden plus één rij om een conflict op de vierde tijd te zien.
    readings = (
        iter(db.execute(query.order_by(event.timestamp_utc).execution_options(yield_per=256)))
        if not latest_four
        else reversed(db.execute(query.order_by(event.timestamp_utc.desc()).limit(5)).all())
    )
    for at, group in groupby(readings, key=lambda r: r[0]):
        rows = list(islice(group, 2))  # DISTINCT voegt identieke lezingen samen.
        _, value, unit, status, observed = rows[0]
        valid = (
            len(rows) == 1
            and type(value) in (float, int)
            and 0 <= value <= 100
            and unit == "%"
            and status == "ok"
            and source_timestamp(observed) == at
        )
        yield at, Decimal(str(value)) if valid else None
