"""Dagplanner B14-003. De plantoestand en de gemeten encodeerbanen hebben ieder hun eigen herkomst."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field
from sqlalchemy import and_, false, select
from sqlalchemy.orm import Session

from .hourly import hours
from .models import EnergyWorkload, EnergyWorkloadReservation
from .workload_sources import Encoding, WorkloadSources

Priority = Literal["interactief", "hoog", "normaal", "achtergrond"]
Status = Literal["voorstel", "gepland", "actief", "wacht", "klaar", "geannuleerd"]
WaitReason = Literal["interactieve_werklast", "eigenaar_gepauzeerd", "veilig_stoppunt", "onbekend"]
WAIT_REASONS: dict[str, WaitReason] = {
    "interactieve_werklast": "interactieve_werklast",
    "eigenaar_gepauzeerd": "eigenaar_gepauzeerd",
    "veilig_stoppunt": "veilig_stoppunt",
}


class Workload(BaseModel):
    id: UUID
    owner_app: str
    workload_key: str
    priority_class: Priority
    preemptible: bool
    needs_safe_checkpoint: bool


def _kind(owner: str, key: str, priority: Priority, preemptible: bool, checkpoint: bool) -> Workload:
    return Workload(
        id=uuid5(NAMESPACE_URL, f"urn:home-control-hub:energy:{owner}:{key}"),
        owner_app=owner,
        workload_key=key,
        priority_class=priority,
        preemptible=preemptible,
        needs_safe_checkpoint=checkpoint,
    )


# Dit zijn plantypen uit B14, geen waarnemingen. De lokale rij heeft voorrang als deze al bestaat.
WORKLOAD_TYPES = (
    _kind("jelly-leon", "transcode", "interactief", False, False),
    _kind("truenas", "backup", "hoog", False, True),
    _kind("truenas", "scrub", "normaal", True, True),
    _kind("zoeken-en-persoonlijke-ai", "zoekindex", "achtergrond", True, True),
    _kind("media-guard-ultimate", "av1", "achtergrond", True, True),
)


class Reservation(BaseModel):
    id: UUID
    workload_id: UUID
    window_start: datetime
    window_end: datetime
    status: Status
    wait_reason: WaitReason | None = None

    @classmethod
    def from_row(cls, row: EnergyWorkloadReservation) -> Reservation:
        # Een oude rij kan een vrije wachtreden of brongegevens in resources bevatten.
        reason = WAIT_REASONS.get(row.wait_reason_nl or "", "onbekend") if row.status == "wacht" else None
        return cls.model_validate(
            {
                "id": row.id,
                "workload_id": row.workload_id,
                "window_start": row.window_start.astimezone(UTC),
                "window_end": row.window_end.astimezone(UTC),
                "status": row.status,
                "wait_reason": reason,
            }
        )


class PlanSlot(BaseModel):
    reservation_id: UUID
    start: datetime
    end: datetime
    status: Status
    wait_reason: WaitReason | None


class PlanHour(BaseModel):
    start: datetime
    end: datetime
    slots: list[PlanSlot] = Field(default_factory=list)
    encoding: Encoding = Field(default_factory=Encoding)


class WorkloadPlan(BaseModel):
    date: date
    timezone: str
    items: list[Workload]
    reservations: list[Reservation]
    hours: list[PlanHour]
    sources: WorkloadSources


def _slots(r: Reservation, start: datetime, end: datetime, interactive: list[Reservation]) -> list[PlanSlot]:
    """Snijd alleen de echte doorsnede met een actieve interactieve reservering uit het achtergrondvenster."""
    overlaps = sorted(
        (max(start, i.window_start), min(end, i.window_end))
        for i in interactive
        if start < i.window_end and i.window_start < end
    )
    result = []
    cursor = start
    for left, right in overlaps:
        if cursor < left:
            result.append(
                PlanSlot(reservation_id=r.id, start=cursor, end=left, status=r.status, wait_reason=r.wait_reason)
            )
        if right > cursor:
            result.append(
                PlanSlot(
                    reservation_id=r.id,
                    start=max(cursor, left),
                    end=right,
                    status="wacht",
                    wait_reason="interactieve_werklast",
                )
            )
        cursor = max(cursor, right)
    if cursor < end:
        result.append(PlanSlot(reservation_id=r.id, start=cursor, end=end, status=r.status, wait_reason=r.wait_reason))
    return result


def day_plan(session: Session, day: date, zone: ZoneInfo, sources: WorkloadSources) -> WorkloadPlan:
    plan = [PlanHour(start=start, end=end) for start, end in hours(day, zone)]
    known = {(w.owner_app, w.workload_key): w for w in WORKLOAD_TYPES}
    reservations = []
    # De werklast en haar vensters komen uit dezelfde databaselezing, ook tijdens een gelijktijdig voorstel.
    overlaps_day = (
        and_(
            EnergyWorkloadReservation.window_start < plan[-1].end, EnergyWorkloadReservation.window_end > plan[0].start
        )
        if plan
        else false()
    )
    q = (
        select(EnergyWorkload, EnergyWorkloadReservation)
        .outerjoin(
            EnergyWorkloadReservation, and_(EnergyWorkloadReservation.workload_id == EnergyWorkload.id, overlaps_day)
        )
        .order_by(EnergyWorkloadReservation.window_start, EnergyWorkloadReservation.id)
    )
    for row, reservation in session.execute(q):
        known[row.owner_app, row.workload_key] = Workload.model_validate(row, from_attributes=True)
        if reservation is not None:
            reservations.append(Reservation.from_row(reservation))
    catalog = sorted(known.values(), key=lambda w: (w.owner_app, w.workload_key))
    priority = {w.id: w.priority_class for w in catalog}
    interactive = [r for r in reservations if r.status == "actief" and priority[r.workload_id] == "interactief"]
    for hour in plan:
        encoding = sources.mediaguard_encoding
        if encoding.observed_at is not None and hour.start <= encoding.observed_at < hour.end:
            hour.encoding = encoding
        for r in reservations:
            start, end = max(r.window_start, hour.start), min(r.window_end, hour.end)
            if start < end:
                must_yield = priority[r.workload_id] == "achtergrond" and r.status in ("gepland", "actief")
                hour.slots.extend(_slots(r, start, end, interactive if must_yield else []))
    return WorkloadPlan(
        date=day, timezone=zone.key, items=catalog, reservations=reservations, hours=plan, sources=sources
    )
