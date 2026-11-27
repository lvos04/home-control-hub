"""Perioderapport op UTC-intervallen. Alleen een volledig gedekte som heeft een waarde."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Annotated, Literal, cast
from uuid import UUID
from zoneinfo import ZoneInfo

from pydantic import BaseModel, PlainSerializer
from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from .hourly import DAY, METER_CONFIRMATION, Direction, Period, Role, hours, midnight, period_days, series_ref
from .models import EnergyMeterRole, EnergyUsageInterval
from .readings import Quality
from .tariffs import Prices

Number = Annotated[Decimal, PlainSerializer(float, return_type=float, when_used="json")]
Status = Literal["volledig", "onvolledig"]
EXPORT = "my_house:energy/export"
COST = "my_house:energy/export+tariffs"


class Quantity(BaseModel):
    value: Number | None = None
    quality: Quality = "onbekend"
    source: str


class Hour(BaseModel):
    start_utc: datetime
    end_utc: datetime
    meter_id: UUID | None
    counter_reset: bool
    usage: Quantity
    cost: Quantity


class Totals(BaseModel):
    status: Status
    usage: Quantity
    cost: Quantity


class Day(Totals):
    date: date
    hours: list[Hour]


class UsageReport(Totals):
    period: Period
    timezone: str
    role: Role
    direction: Direction
    unit: Literal["kWh"] = "kWh"
    currency: str | None
    days: list[Day]


def total(quantities: Sequence[Quantity], source: str) -> Quantity:
    amount = Decimal(0)
    quality: Quality = "gemeten"
    if not quantities:
        return Quantity(source=source)
    for q in quantities:
        if q.value is None or q.quality == "onbekend":
            return Quantity(source=source)
        amount += q.value
        if q.quality == "geschat":
            quality = "geschat"
    return Quantity(source=source, value=amount, quality=quality)


def totals(parts: Sequence[Hour | Day]) -> Totals:
    usage = total([p.usage for p in parts], EXPORT)
    return Totals(
        status="onvolledig" if usage.value is None else "volledig",
        usage=usage,
        cost=total([p.cost for p in parts], COST),
    )


def usage_report(
    db: Session,
    scope: UUID,
    zone: ZoneInfo,
    currency: str | None,
    period: Period,
    day: date,
    role: Role,
    direction: Direction,
) -> UsageReport:
    first, after = period_days(period, day)
    prices = Prices(db, scope, direction, midnight(first, zone), midnight(after, zone))
    days = usage_days(db, scope, zone, currency, first, after, role, direction, prices)
    return UsageReport(
        **totals(days).model_dump(),
        period=period,
        timezone=zone.key,
        currency=currency,
        role=role,
        direction=direction,
        days=days,
    )


def usage_days(
    db: Session,
    scope: UUID,
    zone: ZoneInfo,
    currency: str | None,
    first: date,
    after: date,
    role: Role,
    direction: Direction,
    prices: Prices,
) -> list[Day]:
    start, end = midnight(first, zone), midnight(after, zone)
    ref = series_ref(scope, role, direction)
    slots: dict[datetime, list[tuple[EnergyUsageInterval, bool]]] = defaultdict(list)
    # Historische, op een weergavenaam gebaseerde intervallen hebben geen bewijs
    # van de onderliggende punten of meter. Herlevering vervangt ze per woningdag.
    for record, confirmation in db.execute(
        select(EnergyUsageInterval, EnergyMeterRole.confirmed_by)
        .outerjoin(
            EnergyMeterRole,
            and_(EnergyMeterRole.meter_id == EnergyUsageInterval.meter_id, EnergyMeterRole.role == role),
        )
        .where(
            EnergyUsageInterval.source_ref == ref,
            EnergyUsageInterval.start_utc >= start,
            EnergyUsageInterval.start_utc < end,
        )
    ):
        slots[record.start_utc.astimezone(UTC)].append((record, confirmation == METER_CONFIRMATION))
    days = []
    while first < after:
        items = []
        for t, following in hours(first, zone):
            rows = slots.get(t, [])
            usage, cost = Quantity(source=EXPORT), Quantity(source=COST)
            meter = None
            if len(rows) == 1 and rows[0][1]:
                r, _ = rows[0]
                meter = r.meter_id
                if (
                    r.delta is not None
                    and r.quality in ("gemeten", "geschat")
                    and r.end_utc.astimezone(UTC) == following
                ):
                    usage = Quantity(source=EXPORT, value=r.delta, quality=cast(Quality, r.quality))
                    price = prices.at(t, following)
                    if price is not None and currency:
                        cost = Quantity(source=COST, value=r.delta * price, quality=usage.quality)
            items.append(
                Hour(
                    start_utc=t,
                    end_utc=following,
                    meter_id=meter,
                    counter_reset=any(r.counter_reset for r, _ in rows),
                    usage=usage,
                    cost=cost,
                )
            )
        days.append(Day(**totals(items).model_dump(), date=first, hours=items))
        first += DAY
    return days
