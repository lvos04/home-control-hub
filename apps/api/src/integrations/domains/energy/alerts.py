"""B14-005. Beoordeel de eigen meetreeksen en bewaar een overgang samen met zijn uitgaande gebeurtenis."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from itertools import chain, groupby, islice
from typing import Any, Literal
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import events
from ...hublink_store import LinkState
from ...models import IntegrationSource, ServiceState
from ..automation.models import AutomationEvent
from .hourly import DAY, HOUR, Role, home_zone
from .meters import SOURCE
from .readings import source_timestamp
from .usage import Hour, usage_report
from .usage_sync import STATE_KEY

SETTINGS_KEY = "energy_alert_thresholds"
ROLES: tuple[Role, ...] = ("p1_net", "boiler_socket", "airco_outdoor")
NAS_FRESH = timedelta(minutes=15)
Rule = Literal["meter_offline", "boiler_usage", "nas_load", "daily_budget"]


class AlertThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)
    offline_after_minutes: int = Field(ge=60, le=1440, description="Maximale leeftijd van een gemeten uurinterval.")
    boiler_increase_kwh: float = Field(
        ge=0.001, le=100, description="Toegestane toename per uur boven de drie voorafgaande gemeten boileruren."
    )
    nas_increase_points: float = Field(
        gt=0, lt=100, description="Toegestane CPU-toename in procentpunten boven drie voorafgaande NAS-metingen."
    )
    daily_budget_eur: float = Field(
        ge=0.01, le=100000, description="Budget voor variabele netafnamekosten per lokale woningdag in euro."
    )


class AlertStatus(BaseModel):
    rule: Rule
    role: str
    source: str
    status: Literal["onbekend", "afwijkend", "normaal"]
    observed_at: datetime | None


@dataclass
class Check:
    rule: Rule
    role: str
    scope: UUID | None
    observed_at: datetime | None = None
    breached: bool | None = None
    baseline: Decimal | None = None
    meter: UUID | None = None

    @property
    def source(self) -> str:
        return "truenas_metrics" if self.rule == "nas_load" else SOURCE

    @property
    def subject(self) -> str | None:
        return str(uuid5(self.scope, f"{self.rule}/{self.role}")) if self.scope else None

    def status(self) -> AlertStatus:
        return AlertStatus(
            rule=self.rule,
            role=self.role,
            source=self.source,
            status="onbekend" if self.breached is None else ("afwijkend" if self.breached else "normaal"),
            observed_at=self.observed_at,
        )

    def compare_growth(
        self, current: Decimal | None, previous: Sequence[Decimal | None], increase: float, opened: dict[str, Any]
    ) -> None:
        if current is None:
            return
        incident = opened.get(self.subject or "")
        if incident and incident["meter"] == (str(self.meter) if self.meter else None):
            # Een aanhoudende piek mag zichzelf niet tot de nieuwe normale waarde maken.
            self.baseline = Decimal(incident["baseline"])
        else:
            samples = [n for n in previous if n is not None]
            if len(samples) != 3:
                return
            self.baseline = sum(samples, Decimal(0)) / len(samples)
        self.breached = current > self.baseline + Decimal(str(increase))


def _house_checks(db: Session, now: datetime, limits: AlertThresholds | None, opened: dict[str, Any]) -> list[Check]:
    source = db.get(IntegrationSource, SOURCE, with_for_update={"read": True})
    archive = db.get(ServiceState, STATE_KEY)
    meta = (
        archive.value
        if archive and source and source.enabled and archive.value.get("revision") == source.link_revision
        else {}
    )
    scope = UUID(meta["scope"]) if meta.get("scope") else None
    offline = {r: Check("meter_offline", r, scope) for r in ROLES}
    boiler, budget = Check("boiler_usage", "boiler_socket", scope), Check("daily_budget", "p1_net", scope)
    checks = [*offline.values(), boiler, budget]
    if not limits or not scope or not meta.get("timezone"):
        return checks

    zone = home_zone(meta["timezone"])
    today = now.astimezone(zone).date()
    max_age = timedelta(minutes=limits.offline_after_minutes)
    # Rond de overgang naar zomertijd kan een terugblik van 24 uur drie woningdagen raken.
    first = min(today - DAY, (now - max_age - HOUR).astimezone(zone).date())
    days = [first + offset * DAY for offset in range((today - first).days + 1)]
    for role in ROLES:
        since = source_timestamp(meta.get("watch_since", {}).get(role))
        if since is None:
            continue
        # Gebruik de eindtijd van het bronuur, ook voor de uren vóór lokale middernacht.
        slots = [
            hour
            for day in days
            for hour in usage_report(db, scope, zone, meta.get("currency"), "day", day, role, "import").days[0].hours
            if hour.end_utc <= now
        ]
        latest = next((h.end_utc for h in reversed(slots) if h.usage.quality == "gemeten"), None)
        offline[role].observed_at = latest
        expired = now - (latest or since) > max_age
        if expired or (latest and not meta.get("reason_nl")):
            offline[role].breached = expired
        if expired or meta.get("reason_nl") or not slots:
            continue
        last = slots[-1]
        if last.usage.quality != "gemeten":
            continue
        if role == "boiler_socket":
            boiler.observed_at, boiler.meter = last.end_utc, last.meter_id
            previous = [
                h.usage.value if h.meter_id == last.meter_id and h.usage.quality == "gemeten" else None
                for h in slots[-4:-1]
            ]
            boiler.compare_growth(last.usage.value, previous, limits.boiler_increase_kwh, opened)
        elif role == "p1_net" and meta.get("currency") == "EUR":
            # Basisbedrag is de som sinds lokale middernacht. Elk verstreken uur vereist een meting én een tarief.
            day_hours = [h for h in slots if h.start_utc.astimezone(zone).date() == today]
            _budget(budget, day_hours, limits.daily_budget_eur)
    return checks


def _budget(check: Check, day_hours: Sequence[Hour], limit: float) -> None:
    costs = [h.cost.value for h in day_hours if h.cost.quality == "gemeten" and h.cost.value is not None]
    if day_hours and len(costs) == len(day_hours):
        check.observed_at = day_hours[-1].end_utc
        check.breached = sum(costs, Decimal(0)) > Decimal(str(limit))


def _nas_checks(
    db: Session,
    now: datetime,
    limits: AlertThresholds | None,
    opened: dict[str, Any],
    link: LinkState,
    *,
    history: bool = False,
    after: datetime | None = None,
) -> Iterator[Check]:
    since = source_timestamp(link.linked_at)
    scope = UUID(link.service_id) if link.linked and link.service_id else None
    if not limits or not scope or not since:
        yield Check("nas_load", "nas", scope)
        return
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
            event.timestamp_utc >= max(since, now - 2 * NAS_FRESH),
            event.timestamp_utc <= now,
            event.received_at >= since,
        )
        .distinct()
    )
    # Voor de leesroute volstaan vier meettijden plus één rij om een conflict op de vierde tijd te zien.
    readings = (
        iter(db.execute(query.order_by(event.timestamp_utc).execution_options(yield_per=256)))
        if history
        else reversed(db.execute(query.order_by(event.timestamp_utc.desc()).limit(5)).all())
    )
    previous: deque[tuple[datetime, Decimal | None]] = deque(maxlen=3)
    latest = Check("nas_load", "nas", scope)
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
        current = Decimal(str(value)) if valid else None
        fresh = now - at <= NAS_FRESH
        if not history or (fresh and (after is None or at > after)):
            latest = Check("nas_load", "nas", scope, observed_at=at)
            if fresh:
                baseline = [v for t, v in previous if at - t <= NAS_FRESH]
                latest.compare_growth(current, baseline, limits.nas_increase_points, opened)
            if history:
                yield latest
        previous.append((at, current))
    if not history:
        yield latest


def assess(db: Session, state: ServiceState | None, now: datetime, link: LinkState) -> list[Check]:
    data = state.value if state else {}
    limits = AlertThresholds(**data["thresholds"]) if "thresholds" in data else None
    opened = data.get("open", {})
    return [*_house_checks(db, now, limits, opened), *_nas_checks(db, now, limits, opened, link)]


def notify_changes(db: Session, now: datetime, link: LinkState) -> None:
    state = db.get(ServiceState, SETTINGS_KEY, with_for_update=True)
    if state is None:
        return
    last = source_timestamp(state.value.get("evaluated_at"))
    if last and last > now:
        return
    opened = dict(state.value.get("open", {}))
    limits = AlertThresholds(**state.value["thresholds"]) if "thresholds" in state.value else None
    # Oudere workers bewaarden alleen de beoordelingstijd. Speel hun al beoordeelde periode niet opnieuw af.
    nas_at = source_timestamp(state.value.get("nas_observed_at", state.value.get("evaluated_at")))
    house = _house_checks(db, now, limits, opened)
    nas = _nas_checks(db, now, limits, opened, link, history=True, after=nas_at)
    for check in chain(house, nas):
        if check.rule == "nas_load" and check.observed_at is not None:
            nas_at = check.observed_at
        subject = check.subject
        if subject is None or check.breached is None:
            continue  # onbekend sluit een lopende afwijking nooit
        active = subject in opened
        if check.breached:
            opened[subject] = {
                "baseline": str(check.baseline) if check.baseline is not None else None,
                "meter": str(check.meter) if check.meter else None,
            }
            if active:
                continue
            verb = "down" if check.rule == "meter_offline" else "degraded"
        elif active:
            del opened[subject]
            verb = "recovered"
        else:
            continue
        events.emit(
            db,
            event_type=f"energy.{check.rule}.{verb}",
            entity_type="energy_alert",
            entity_id=subject,
            actor_type="system",
            actor_id="home-control-hub:worker",
            trace_id=str(uuid4()),
            payload={
                "regel": check.rule,
                "rol": check.role,
                "bron": check.source,
                "ernst": "middel" if check.breached else "info",
            },
        )
    state.value = {
        **state.value,
        "open": opened,
        "evaluated_at": now.isoformat(),
        "nas_observed_at": nas_at.isoformat() if nas_at is not None else None,
    }
    db.commit()
