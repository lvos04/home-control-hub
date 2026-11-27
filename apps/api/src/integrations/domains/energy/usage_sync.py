"""Verwerk de gevalideerde uur-export per woning in één transactie met de bronconfiguratie."""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from uuid import UUID, uuid5
from zoneinfo import ZoneInfo

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...config import Settings
from ...models import ServiceState
from ...security.vault import Vault
from ...timeutil import utcnow
from .client import EnergyReadError, EnergyRoute, ViewerDenied
from .hourly import (
    DAY,
    METER_CONFIRMATION,
    Channel,
    Sample,
    Series,
    home_zone,
    hours,
    midnight,
    parse_export,
    series_ref,
)
from .meters import SOURCE, SourceInactive, configured_client
from .models import EnergyEstimateProvenance, EnergyMeter, EnergyMeterRole, EnergyUsageInterval
from .readings import SOURCE_ROLES, declared_roles
from .tariffs import store_tariffs

STATE_KEY = "energy_usage"
HISTORY_DAYS = 31


class Archive:
    def __init__(self, db: Session, scope: UUID) -> None:
        self.db = db
        self.scope = scope
        self.meters: dict[UUID, EnergyMeter] = {}
        self.roles: set[str] = set()
        for meter, role, confirmation in db.execute(
            select(EnergyMeter, EnergyMeterRole.role, EnergyMeterRole.confirmed_by)
            .join(EnergyMeterRole)
            .where(
                EnergyMeter.source_id == SOURCE,
                EnergyMeter.unit == "kWh",
                EnergyMeter.source_meter_id.startswith(f"{scope}/"),
            )
        ):
            if confirmation == METER_CONFIRMATION:
                self.meters[meter.id] = meter
            self.roles.add(role)
        self.estimate_id = uuid5(scope, "uuraggregatie")
        self.provenance = db.get(EnergyEstimateProvenance, self.estimate_id)

    def meter(self, key: UUID, role: str) -> None:
        if key not in self.meters:
            m = EnergyMeter(
                id=key,
                source_id=SOURCE,
                source_meter_id=f"{self.scope}/{role}/{key}",
                unit="kWh",
                display_name=f"my_house {role}",
            )
            self.meters[key] = m
            self.db.add(m)
            self.db.flush()
            self.db.add(EnergyMeterRole(meter_id=key, role=role, confirmed_by=METER_CONFIRMATION))
        self.roles.add(role)

    def estimate(self) -> UUID:
        if self.provenance is None:
            self.provenance = EnergyEstimateProvenance(
                id=self.estimate_id,
                method="bronaggregatie",
                confidence=None,
                created_at=utcnow(),
                assumptions={"bron": "my_house:energy/export", "resolutie": "uur", "bronkwaliteit": "estimated"},
            )
            self.db.add(self.provenance)
            self.db.flush()
        return self.estimate_id

    def day(self, day: date, zone: ZoneInfo, now: datetime, series: Series, declared: set[str]) -> None:
        roles = self.roles | declared | {role for role, _ in series}
        channels: set[Channel] = {(role, "import") for role in roles}
        if "p1_net" in roles:
            channels.add(("p1_net", "export"))
        for role, direction in sorted(channels):
            ref = series_ref(self.scope, role, direction)
            saved = {
                (r.start_utc.astimezone(UTC), r.meter_id): r
                for r in self.db.scalars(
                    select(EnergyUsageInterval).where(
                        EnergyUsageInterval.source_ref == ref,
                        EnergyUsageInterval.end_utc <= now,
                        EnergyUsageInterval.start_utc >= midnight(day, zone),
                        EnergyUsageInterval.start_utc < midnight(day + DAY, zone),
                    )
                )
            }
            slots = series.get((role, direction), {})
            for start, end in hours(day, zone):
                if end > now:
                    break
                observations = slots.get(start) or {None: Sample()}
                for key, s in observations.items():
                    if key is not None:
                        self.meter(key, role)
                    provenance_id = self.estimate() if s.quality == "geschat" else None
                    interval = saved.pop((start, key), None)
                    if interval is None:
                        interval = EnergyUsageInterval(
                            meter_id=key, start_utc=start, direction=direction, source_ref=ref
                        )
                        self.db.add(interval)
                    interval.end_utc = end
                    interval.delta, interval.quality, interval.counter_reset = s.value, s.quality, s.reset
                    interval.provenance_id = provenance_id
            # Een herleverde woningdag is gezaghebbend, ook als een oude meter of waarde wegvalt.
            for obsolete in saved.values():
                self.db.delete(obsolete)
        self.db.flush()

    def replacements(self) -> None:
        spans = self.db.execute(
            select(
                EnergyMeterRole.role,
                EnergyMeterRole.meter_id,
                func.min(EnergyUsageInterval.start_utc),
                func.max(EnergyUsageInterval.start_utc),
            )
            .select_from(EnergyUsageInterval)
            .join(EnergyMeterRole, EnergyMeterRole.meter_id == EnergyUsageInterval.meter_id)
            .where(
                EnergyUsageInterval.source_ref.startswith(f"my_house/{self.scope}/"),
                EnergyMeterRole.confirmed_by == METER_CONFIRMATION,
            )
            .group_by(EnergyMeterRole.role, EnergyMeterRole.meter_id)
            .order_by(EnergyMeterRole.role, func.min(EnergyUsageInterval.start_utc), EnergyMeterRole.meter_id)
        )
        predecessors: dict[UUID, UUID] = {}
        last: dict[str, tuple[UUID, datetime, datetime]] = {}
        for role, meter, first, end in spans:
            first, end = first.astimezone(UTC), end.astimezone(UTC)
            previous = last.get(role)
            if previous and previous[1] < first and previous[2] <= first:
                predecessors[meter] = previous[0]
            if previous is None or end >= previous[2]:
                last[role] = (meter, first, end)
        for registered in self.meters.values():
            registered.replaced_meter_id = predecessors.get(registered.id)


def sync_usage(
    db: Session, settings: Settings, vault: Vault, transport: httpx.BaseTransport | None, now: datetime
) -> bool:
    try:
        client, scope, revision = configured_client(db, settings, vault, transport)
    except SourceInactive:
        return True
    except EnergyReadError as exc:
        state = db.get(ServiceState, STATE_KEY)
        if state is not None:
            state.value = {**state.value, "reason_nl": str(exc)}
            db.commit()
        return False
    state = db.get(ServiceState, STATE_KEY)
    previous = state.value if state and state.value.get("revision") == revision else {}
    metadata = {**previous, "revision": revision, "scope": str(scope)}
    watch_since = dict(previous.get("watch_since", {}))
    try:
        summary = client.read(EnergyRoute.SUMMARY)
        declared = {SOURCE_ROLES[r] for r in declared_roles(summary)}
        zone = home_zone(summary.get("timezone"))
        metadata["timezone"] = zone.key
        for role in declared:
            watch_since.setdefault(role, now.isoformat())
        currency = summary.get("currency")
        today = now.astimezone(zone).date()
        yesterday = today - DAY
        # Per ronde twee actuele dagen en één oudere dag. De terugblik hervat na een herstart.
        backfill = date.fromisoformat(previous["backfill"]) if previous.get("backfill") else yesterday - DAY
        if backfill >= yesterday or backfill < today - HISTORY_DAYS * DAY:
            backfill = yesterday - DAY
        days = (backfill, yesterday, today)
        exports = [parse_export(client.read(EnergyRoute.EXPORT, day=d), scope, d, zone) for d in days]
        try:
            store_tariffs(db, scope, client.read(EnergyRoute.TARIFFS), zone)
        except ViewerDenied:
            raise
        except EnergyReadError:
            store_tariffs(db, scope, [], zone)
        archive = Archive(db, scope)
        for d, series in zip(days, exports, strict=True):
            archive.day(d, zone, now, series, declared)
        archive.replacements()
        for role in archive.roles:
            watch_since.setdefault(role, now.isoformat())
        metadata.pop("reason_nl", None)
        metadata["currency"] = currency if isinstance(currency, str) and re.fullmatch("[A-Z]{3}", currency) else None
        metadata["backfill"] = (backfill - DAY).isoformat()
    except EnergyReadError as exc:
        # Bewaar de bewaakte rollen van deze koppeling om ook tijdens bronuitval meteruitval te kunnen melden.
        metadata["reason_nl"] = str(exc)
    metadata["watch_since"] = watch_since
    if state is None:
        db.add(ServiceState(key=STATE_KEY, value=metadata))
    else:
        state.value = metadata
    db.commit()
    return "reason_nl" not in metadata
