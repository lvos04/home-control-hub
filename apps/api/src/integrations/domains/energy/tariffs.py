"""Variabele verbruikskosten per richting, uitsluitend bij een prijs voor het hele interval."""

from __future__ import annotations

from bisect import bisect_right
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from .client import EnergyReadError
from .hourly import Direction, midnight, number
from .models import EnergyTariff
from .readings import source_timestamp


def tariff_ref(scope: UUID, direction: Direction) -> str:
    return f"my_house/{scope}/tariffs/{direction}"


def _instant(raw: object, zone: ZoneInfo) -> datetime | None:
    if isinstance(raw, str) and len(raw) == 10:
        try:
            return midnight(date.fromisoformat(raw), zone)
        except (ValueError, OverflowError):
            return None
    return source_timestamp(raw)


def _price(row: dict[str, Any], direction: Direction) -> Decimal | None:
    price = number(row.get(f"{direction}_per_kwh"), magnitude=100_000, scale=5)
    if direction == "import" and any(
        tier is not None and number(tier, magnitude=100_000, scale=5) != price
        for tier in (row.get("import_t1_per_kwh"), row.get("import_t2_per_kwh"))
    ):
        # De hoofdteller splitst deze kWh niet uit naar tariefregister.
        return None
    return price


def store_tariffs(session: Session, scope: UUID, raw: Any, zone: ZoneInfo) -> None:
    if not isinstance(raw, list):
        raise EnergyReadError("De bron leverde geen geldige tarieflijst.")
    by_start: dict[datetime, list[dict[str, Any]]] = {}
    for item in raw:
        start = _instant(item.get("valid_from"), zone) if isinstance(item, dict) else None
        if start is None:
            raise EnergyReadError("Een brontarief heeft geen geldige begindatum.")
        by_start.setdefault(start, []).append(item)
    starts = sorted(by_start)
    directions: tuple[Direction, ...] = ("import", "export")
    for direction in directions:
        ref = tariff_ref(scope, direction)
        previous = {t.id: t for t in session.scalars(select(EnergyTariff).where(EnergyTariff.source_ref == ref))}
        for idx, start in enumerate(starts):
            candidates = by_start[start]
            item = candidates[0]
            end = starts[idx + 1] if idx + 1 < len(starts) else None
            price = _price(item, direction) if len(candidates) == 1 else None
            if item.get("valid_to") is not None:
                until = _instant(item["valid_to"], zone)
                if until is None or until <= start:
                    price = None
                elif end is None or until < end:
                    end = until
            key = uuid5(scope, f"{direction}/{start.isoformat()}")
            tariff = previous.pop(key, None)
            if tariff is None:
                tariff = EnergyTariff(id=key, source_ref=ref, unit="kWh", valid_from=start)
                session.add(tariff)
            tariff.price_per_unit = price
            tariff.kind = "dynamisch" if item.get("source") == "dynamisch" or len(item["valid_from"]) > 10 else "vast"
            tariff.valid_to = end
        # Een latere kostenanalyse kan naar de rij verwijzen. Een ingetrokken prijs vervalt.
        for tariff in previous.values():
            tariff.price_per_unit = None


class Prices:
    def __init__(self, session: Session, scope: UUID, direction: Direction, start: datetime, end: datetime) -> None:
        self.rows = list(
            session.scalars(
                select(EnergyTariff)
                .where(
                    EnergyTariff.source_ref == tariff_ref(scope, direction),
                    EnergyTariff.price_per_unit.is_not(None),
                    EnergyTariff.valid_from < end,
                    (EnergyTariff.valid_to.is_(None) | (EnergyTariff.valid_to > start)),
                )
                .order_by(EnergyTariff.valid_from)
            )
        )
        self.starts = [t.valid_from.astimezone(UTC) for t in self.rows]

    def at(self, start: datetime, end: datetime) -> Decimal | None:
        index = bisect_right(self.starts, start) - 1
        if index < 0:
            return None
        tariff = self.rows[index]
        return tariff.price_per_unit if tariff.valid_to is None or end <= tariff.valid_to.astimezone(UTC) else None
