"""B14: meters en dekkingsmatrix uit de eigen viewer-koppeling met my_house."""

from __future__ import annotations

from datetime import date, datetime

from fastapi import Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...deps import get_session
from ...errors import ApiError
from ...models import ServiceState
from ...security.auth import Principal, require_reader
from ...timeutil import utcnow
from ..common import domain_router
from .catalog import EXPECTED_METER_ROLES, QUALITY_LABELS, SOURCES
from .client import EnergyReadError
from .hourly import Direction, Period, Role, home_zone
from .meters import ABSENT, NAS_ABSENT, Inventory, MeterItem, configured_client, meter_inventory
from .readings import LIVE_MAX_AGE, Quality
from .usage import UsageReport, usage_report
from .usage_sync import STATE_KEY

router = domain_router(
    "energy",
    SOURCES,
    {
        "/workloads": ("energy.workload.read", ("B14-003",)),
        "/advice": ("energy.advice.read", ("B14-004",)),
    },
)


class MeterList(BaseModel):
    items: list[MeterItem]
    reason_nl: str | None
    next_cursor: None = None


class CoverageItem(BaseModel):
    role: str
    title_nl: str
    decision: str
    read_only: bool
    notes_nl: str
    measurement_status: Quality
    measurement_quality: Quality
    quality: Quality
    source: str | None
    last_updated: datetime | None
    observed_at: datetime | None
    reason_code: str | None
    reason_nl: str
    why_unknown_nl: str | None


class Coverage(BaseModel):
    items: list[CoverageItem]
    quality_labels: list[str]
    rules_nl: list[str]
    evaluated_at: datetime
    max_age_s: int
    next_cursor: None = None


def coverage_payload(inventory: Inventory) -> Coverage:
    items = []
    now = utcnow()
    for spec in EXPECTED_METER_ROLES:
        meter = inventory.meters.get(spec.role)
        quality: Quality = meter.measurement_quality if meter else "onbekend"
        reason = meter.reason_nl if meter else inventory.reason
        at = meter.last_updated if meter else None
        reason_code = meter.reason_code if meter else None
        if at is not None and now - at > LIVE_MAX_AGE:
            quality, reason_code, reason = "onbekend", "meting_verouderd", "De vermogensmeting is verouderd."
        if spec.role == "nas_host" and reason == ABSENT:
            reason = NAS_ABSENT
        items.append(
            CoverageItem(
                **spec.to_dict(),
                measurement_status=quality,
                measurement_quality=quality,
                quality=quality,
                source=meter.source if meter else None,
                last_updated=at,
                observed_at=at,
                reason_code=reason_code,
                reason_nl=reason,
                why_unknown_nl=reason if quality == "onbekend" else None,
            )
        )
    return Coverage(
        items=items,
        quality_labels=list(QUALITY_LABELS),
        rules_nl=[
            "Een losse meter is vereist voor gemeten NAS-vermogen.",
            "Wattage uit CPU-belasting vereist kalibratie.",
            "De aircometer meet de gedeelde buitenunit.",
            "De boiler wordt uitsluitend gemeten.",
        ],
        evaluated_at=now,
        max_age_s=int(LIVE_MAX_AGE.total_seconds()),
    )


@router.get("/meters", summary="Logische meters van my_house met de laatste vermogensmeting en meetkwaliteit")
def meters(
    request: Request, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> MeterList:
    inventory = meter_inventory(request, session)
    return MeterList(items=list(inventory.meters.values()), reason_nl=None if inventory.meters else inventory.reason)


@router.get("/coverage", summary="Dekking en bronmeettijd per verwachte meterrol (B14-001)")
def coverage(
    request: Request, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> Coverage:
    return coverage_payload(meter_inventory(request, session))


@router.get(
    "/usage",
    summary="Verbruik en variabele kosten per lokale woningdag (B14-002)",
    responses={
        501: {"description": "Bron of eerste uur-export ontbreekt"},
        503: {"description": "De bron of de viewer-koppeling is niet beschikbaar"},
    },
)
def usage(
    request: Request,
    period: Period = "day",
    day: date | None = Query(None, alias="date", description="Een datum binnen de gewenste periode in de woning."),
    role: Role = "p1_net",
    direction: Direction = "import",
    timezone: str | None = Query(None, description="Optioneel ter controle van de door de woning gemelde tijdzone."),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> UsageReport:
    state = request.app.state
    try:
        client, scope, revision = configured_client(session, state.settings, state.vault, state.http_transport)
    except EnergyReadError as exc:
        raise ApiError(501, "capability_unavailable", str(exc), {"reason": "bron_niet_beschikbaar"}) from None
    try:
        client.verify()
        archive = session.get(ServiceState, STATE_KEY)
        if archive is None or archive.value.get("revision") != revision:
            raise ApiError(501, "capability_unavailable", "De eerste uur-export voor deze koppeling ontbreekt.")
        if reason := archive.value.get("reason_nl"):
            raise EnergyReadError(reason)
        zone = home_zone(archive.value.get("timezone"))
    except EnergyReadError as exc:
        raise ApiError(503, "dependency_unavailable", str(exc), headers={"Retry-After": "300"}) from None
    if timezone is not None and timezone != zone.key:
        raise ApiError(422, "validation_error", "De gevraagde tijdzone wijkt af van de tijdzone van de woning.")
    day = day or utcnow().astimezone(zone).date()
    if not 1 < day.year < 9999:
        raise ApiError(422, "validation_error", "De periode valt buiten het ondersteunde datumbereik.")
    return usage_report(session, scope, zone, archive.value.get("currency"), period, day, role, direction)
