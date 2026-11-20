"""Uurcijfers uit shc.energy.v2. De woning bepaalt de kalender, de UTC-grenzen bepalen de duur."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .client import EnergyReadError
from .readings import SOURCE_ROLES, Quality, source_timestamp

Direction = Literal["import", "export"]
Period = Literal["day", "week", "month"]
Role = Literal["p1_net", "boiler_socket", "airco_outdoor"]
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
METRICS: dict[str, Direction] = {"energy_import_kwh": "import", "energy_export_kwh": "export"}


def home_zone(value: object) -> ZoneInfo:
    if isinstance(value, str):
        try:
            return ZoneInfo(value)
        except (ValueError, ZoneInfoNotFoundError):
            pass
    raise EnergyReadError("De geldige tijdzone van de woning ontbreekt.")


def midnight(day: date, zone: ZoneInfo) -> datetime:
    return datetime.combine(day, time.min, zone).astimezone(UTC)


def hours(day: date, zone: ZoneInfo) -> Iterator[tuple[datetime, datetime]]:
    start, end = midnight(day, zone), midnight(day + DAY, zone)
    while start < end:
        following = min(start + HOUR, end)
        yield start, following
        start = following


def period_days(period: Period, day: date) -> tuple[date, date]:
    if period == "week":
        first = day - timedelta(days=day.weekday())
        return first, first + 7 * DAY
    if period == "month":
        first = day.replace(day=1)
        return first, (first + 32 * DAY).replace(day=1)
    return day, day + DAY


def number(raw: object, *, magnitude: int, scale: int) -> Decimal | None:
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    n = Decimal(str(raw))
    if not n.is_finite() or abs(n) >= magnitude or n != n.quantize(Decimal(1).scaleb(-scale)):
        return None
    return n


@dataclass(frozen=True)
class Sample:
    value: Decimal | None = None
    quality: Quality = "onbekend"
    reset: bool = False


def sample(row: dict[str, Any]) -> Sample:
    notes = row.get("notes", "")
    if not isinstance(notes, str):
        return Sample()
    skipped = "tellerreset; interval overgeslagen" in notes
    reset = skipped or "tellerreset gedetecteerd" in notes.split("; ")
    n = number(row.get("value"), magnitude=10**11, scale=4)
    if (
        n is None
        or n < 0
        or (reset and n == 0)
        or skipped
        or "ontbrekende metingen" in notes
        or "verdachte meterstand overgeslagen" in notes
    ):
        return Sample(reset=reset)
    quality = row.get("quality")
    if quality == "estimated" or (quality == "measured" and "deels geschat" in notes.split("; ")):
        return Sample(n, "geschat", reset)
    if quality == "measured":
        return Sample(n, "gemeten", reset)
    return Sample(reset=reset)


# Alleen een apparaat dat de bron bij een rol noemt krijgt een fysieke meter-ID.
Channel = tuple[str, Direction]
Series = dict[Channel, dict[datetime, dict[UUID | None, Sample]]]


def parse_export(raw: Any, scope: UUID, day: date, zone: ZoneInfo) -> Series:
    if (
        not isinstance(raw, dict)
        or raw.get("schema") != "shc.energy.v2"
        or raw.get("resolution") != "hour"
        or raw.get("timezone") != zone.key
        or not isinstance(raw.get("rows"), list)
        or source_timestamp(raw.get("from")) != midnight(day, zone)
        or source_timestamp(raw.get("to")) != midnight(day + DAY, zone)
    ):
        raise EnergyReadError("De uur-export past niet bij de gevraagde woningdag.")
    starts = {start for start, _ in hours(day, zone)}
    result: Series = {}
    for item in raw["rows"]:
        if not isinstance(item, dict) or item.get("unit") != "kWh":
            continue
        role = SOURCE_ROLES.get(str(item.get("role")))
        direction = METRICS.get(str(item.get("metric")))
        if role is None or direction is None or (direction == "export" and role != "p1_net"):
            continue
        at = source_timestamp(item.get("at"))
        if at is None or at not in starts:
            continue
        name = item.get("device")
        meter = (
            uuid5(scope, f"{role}/{name}")
            if isinstance(name, str) and name.strip() and len(name) <= 250 and name.isprintable()
            else None
        )
        slot = result.setdefault((role, direction), {}).setdefault(at, {})
        observation = sample(item) if meter is not None else Sample()
        # Een onherkenbare meter maakt de toewijzing van dit uur onzeker.
        old = slot.get(meter)
        if old is not None and old != observation:
            observation = Sample(reset=old.reset or observation.reset)
        slot[meter] = observation
    return result


def series_ref(scope: UUID, role: str, direction: Direction) -> str:
    return f"my_house/{scope}/{role}/{direction}"
