"""B14-004. Kosten van één verplaatsbaar werkuur op vergelijkbare woningdagen."""

from __future__ import annotations

from collections.abc import Collection
from datetime import UTC, date, datetime
from decimal import Decimal
from itertools import groupby
from typing import Literal
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...hublink_store import LinkState
from ...models import IntegrationSource
from ...timeutil import utcnow
from .hourly import DAY, HOUR, midnight
from .load_history import cpu_readings
from .models import EnergyEstimateProvenance
from .readings import source_timestamp
from .tariffs import Prices
from .usage import Day, Number, usage_days

LOOKBACK = 28
MIN_DAYS = 3
BUSY_MIN = 60
QUIET_MAX = 30
CONFIDENCE_CAP = Decimal("0.80")
NO_METER = "geen meter, geen bedrag"
TOO_FEW = "Te weinig vergelijkbare dagen met gemeten afname en vergelijkbare werklast."
DISCLAIMER = "De besparing is niet gegarandeerd."
ASSUMPTIONS = (
    f"De vergelijking omvat de laatste {LOOKBACK} woningdagen tot en met de gekozen datum. "
    "Werkdagen worden met werkdagen vergeleken en weekenddagen met weekenddagen.",
    f"In elk kwartier van het drukke uur is de CPU-belasting minstens {BUSY_MIN}% en in het rustige uur "
    f"hoogstens {QUIET_MAX}% bij alle beschikbare metingen. De uren hebben dezelfde lokale begintijd op iedere dag.",
    "Dezelfde fysieke P1-meter meet beide uren. Het scenario veronderstelt dat het verschil in netafname "
    "door verplaatsbaar werk komt en dat het overige woningverbruik gelijk blijft.",
    "Verplaats het werk alleen bij een lager afnametarief. Vaste kosten blijven buiten de berekening.",
    "De zekerheid weegt het aandeel dagen met hogere afname in het drukke uur en de steekproefomvang. "
    "Het maximum voor deze methode is 0,80.",
)
SOURCES = ("my_house:energy/export", "my_house:tariffs", "monitoring.metric.recorded/cpu.gebruik")


def method_id(scope: UUID) -> UUID:
    return uuid5(scope, "B14-004:vergelijkbare_dag:v1")


def register_advice_method(db: Session, scope: UUID) -> None:
    """Eén herkomst per woning en rekenmethode. De worker houdt de bronrij al vergrendeld."""
    key = method_id(scope)
    if db.get(EnergyEstimateProvenance, key) is None:
        db.add(
            EnergyEstimateProvenance(
                id=key,
                method="vergelijkbare_dag",
                assumptions={"bronnen": SOURCES, "aannames_nl": ASSUMPTIONS, "minimum_dagen": MIN_DAYS},
                confidence=CONFIDENCE_CAP,
                created_at=utcnow(),
            )
        )


class Comparison(BaseModel):
    date: date
    busy_kwh: Number
    quiet_kwh: Number
    busy_price_per_kwh: Number
    quiet_price_per_kwh: Number

    def saving(self) -> Decimal:
        shift = max(Decimal(0), self.busy_kwh - self.quiet_kwh)
        return shift * max(Decimal(0), self.busy_price_per_kwh - self.quiet_price_per_kwh)


class SavingsRange(BaseModel):
    low: Number
    high: Number
    currency: str
    unit_nl: Literal["per verplaatst werkuur"] = "per verplaatst werkuur"
    measurement_quality: Literal["geschat"] = "geschat"


class CostAdvice(BaseModel):
    advice_nl: str
    assumptions_nl: list[str]
    method: Literal["vergelijkbare_dag"]
    provenance_id: UUID
    sources: list[str]
    meter_id: UUID
    role: Literal["p1_net"] = "p1_net"
    timezone: str
    period_start: date
    period_end: date
    busy_hour: int
    quiet_hour: int
    days: list[Comparison]
    confidence: Number = Field(ge=0, le=1, description="Indicatie op basis van aantal dagen en overeenstemming.")
    savings: SavingsRange
    disclaimer_nl: str = DISCLAIMER


class AdviceReport(BaseModel):
    items: list[CostAdvice] = Field(default_factory=list)
    comparable_days: int = 0
    reason_nl: str | None = None


def _matching_hours(
    db: Session, link: LinkState, zone: ZoneInfo, start: datetime, end: datetime, busy: int, quiet: int
) -> set[datetime]:
    since = source_timestamp(link.linked_at)
    source = db.get(IntegrationSource, "truenas_metrics")
    if not link.linked or link.corrupt or since is None or (source is not None and not source.enabled):
        return set()

    def hour_start(reading: tuple[datetime, Decimal | None]) -> datetime:
        return reading[0].astimezone(zone).replace(minute=0, second=0, microsecond=0).astimezone(UTC)

    result = set()
    for stamp, readings in groupby(cpu_readings(db, since, start, end), key=hour_start):
        local_hour = stamp.astimezone(zone).hour
        if local_hour not in (busy, quiet):
            continue
        quarters = set()
        for at, value in readings:
            if value is None or (value < BUSY_MIN if local_hour == busy else value > QUIET_MAX):
                break
            quarters.add(at.astimezone(zone).minute // 15)
        else:
            if len(quarters) == 4:
                result.add(stamp)
    return result


def _measured_pair(
    day: Day, meter: UUID, zone: ZoneInfo, busy: int, quiet: int, matching: Collection[datetime]
) -> tuple[datetime, Decimal, datetime, Decimal] | None:
    pair = {}
    for hour in day.hours:
        local = hour.start_utc.astimezone(zone)
        if local.hour not in (busy, quiet):
            continue
        # Een dubbel of gebroken lokaal klokuur heeft geen eenduidige tegenhanger.
        if (
            local.hour in pair
            or local.minute != 0
            or hour.end_utc - hour.start_utc != HOUR
            or hour.start_utc not in matching
            or hour.meter_id != meter
            or hour.counter_reset
            or hour.usage.quality != "gemeten"
            or hour.usage.value is None
        ):
            return None
        pair[local.hour] = (hour.start_utc, hour.usage.value)
    if busy not in pair or quiet not in pair:
        return None
    return *pair[busy], *pair[quiet]


def cost_advice(
    db: Session,
    scope: UUID,
    link: LinkState,
    zone: ZoneInfo,
    currency: str | None,
    day: date,
    busy: int,
    quiet: int,
    meter: UUID | None,
) -> AdviceReport:
    first, after = day - (LOOKBACK - 1) * DAY, day + DAY
    start, end = midnight(first, zone), midnight(after, zone)
    prices = Prices(db, scope, "import", start, end)
    history = usage_days(db, scope, zone, currency, first, after, "p1_net", "import", prices)
    if meter is None:
        meter = next((h.meter_id for d in reversed(history) for h in reversed(d.hours) if h.meter_id), None)
    if meter is None or not any(h.meter_id == meter and h.usage.quality == "gemeten" for d in history for h in d.hours):
        return AdviceReport(reason_nl=NO_METER)

    matching = _matching_hours(db, link, zone, start, end, busy, quiet)
    days = []
    comparable = 0
    for d in history:
        if (d.date.weekday() < 5) != (day.weekday() < 5):
            continue
        pair = _measured_pair(d, meter, zone, busy, quiet, matching)
        if pair is None:
            continue
        comparable += 1
        busy_at, busy_kwh, quiet_at, quiet_kwh = pair
        busy_price, quiet_price = prices.at(busy_at, busy_at + HOUR), prices.at(quiet_at, quiet_at + HOUR)
        if busy_price is not None and quiet_price is not None:
            days.append(
                Comparison(
                    date=d.date,
                    busy_kwh=busy_kwh,
                    quiet_kwh=quiet_kwh,
                    busy_price_per_kwh=busy_price,
                    quiet_price_per_kwh=quiet_price,
                )
            )
    if comparable < MIN_DAYS:
        return AdviceReport(comparable_days=comparable, reason_nl=TOO_FEW)
    if not currency or len(days) != comparable:
        return AdviceReport(
            comparable_days=comparable, reason_nl="De valuta of een afnametarief voor de gebruikte uren ontbreekt."
        )

    supporting = sum(d.busy_kwh > d.quiet_kwh for d in days)
    amounts = [d.saving() for d in days]
    if supporting * 2 <= comparable or max(amounts) == 0:
        return AdviceReport(comparable_days=comparable, reason_nl="Geen onderbouwd kostenvoordeel bij deze werklast.")
    method = db.get(EnergyEstimateProvenance, method_id(scope))
    if method is None or method.method != "vergelijkbare_dag" or method.confidence is None:
        return AdviceReport(comparable_days=comparable, reason_nl="De herkomst van de adviesmethode ontbreekt.")
    # Aandeel dagen met meer afname in het drukke uur, gewogen naar de steekproefomvang n/(n+3).
    confidence = (method.confidence * supporting / (comparable + MIN_DAYS)).quantize(Decimal("0.01"))
    advice = CostAdvice(
        advice_nl="Overweeg om verplaatsbaar achtergrondwerk, zoals indexeren of AV1-encodering, in het rustige uur te plannen.",
        assumptions_nl=list(ASSUMPTIONS),
        sources=list(SOURCES),
        method="vergelijkbare_dag",
        provenance_id=method.id,
        meter_id=meter,
        timezone=zone.key,
        period_start=first,
        period_end=day,
        busy_hour=busy,
        quiet_hour=quiet,
        confidence=confidence,
        days=days,
        savings=SavingsRange(low=min(amounts), high=max(amounts), currency=currency),
    )
    return AdviceReport(items=[advice], comparable_days=comparable)
