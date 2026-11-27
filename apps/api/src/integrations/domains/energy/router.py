"""B14: meters en dekkingsmatrix uit de eigen viewer-koppeling met my_house."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import date, datetime
from uuid import UUID
from zoneinfo import ZoneInfo

from fastapi import Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeout
from sqlalchemy.orm import Session

from ... import audit
from ...deps import check_if_match, etag, get_session, if_match, trace_id
from ...errors import ApiError, ApiErrorBody
from ...idempotency import Result, idempotency_key, run_idempotent
from ...models import ServiceState
from ...security.auth import Principal, require_admin, require_reader
from ...timeutil import utcnow
from ..common import domain_router
from .advice import NO_METER, AdviceReport, cost_advice
from .alerts import SETTINGS_KEY, AlertStatus, AlertThresholds, assess
from .catalog import EXPECTED_METER_ROLES, QUALITY_LABELS, SOURCES
from .client import EnergyReadError
from .hourly import DAY, Direction, Period, Role, home_zone
from .meters import ABSENT, NAS_ABSENT, Inventory, MeterItem, SourceInactive, configured_client, meter_inventory
from .readings import LIVE_MAX_AGE, Quality
from .usage import UsageReport, usage_report
from .usage_sync import STATE_KEY
from .workload_sources import workload_sources
from .workloads import WorkloadPlan, day_plan

router = domain_router("energy", SOURCES, {})


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


def archive_session(request: Request) -> Iterator[Session]:
    try:
        yield from get_session(request)
    except (InterfaceError, OperationalError, PoolTimeout):
        raise ApiError(
            503,
            "dependency_unavailable",
            "Het energiearchief is tijdelijk onbereikbaar.",
            headers={"Retry-After": "300"},
        ) from None


class MissingMeterArchive(ApiError):
    """Er is geen actieve bron of nog geen export van deze koppeling."""


def verified_archive(request: Request, session: Session) -> tuple[UUID, ZoneInfo, str | None]:
    state = request.app.state
    try:
        client, scope, revision = configured_client(session, state.settings, state.vault, state.http_transport)
    except EnergyReadError as exc:
        error = MissingMeterArchive if isinstance(exc, SourceInactive) else ApiError
        raise error(501, "capability_unavailable", str(exc), {"reason": "bron_niet_beschikbaar"}) from None
    try:
        client.verify()
        archive = session.get(ServiceState, STATE_KEY)
        if archive is None or archive.value.get("revision") != revision:
            raise MissingMeterArchive(
                501, "capability_unavailable", "De eerste uur-export voor deze koppeling ontbreekt."
            )
        if reason := archive.value.get("reason_nl"):
            raise EnergyReadError(reason)
        zone = home_zone(archive.value.get("timezone"))
    except EnergyReadError as exc:
        raise ApiError(503, "dependency_unavailable", str(exc), headers={"Retry-After": "300"}) from None
    return scope, zone, archive.value.get("currency")


@router.get(
    "/usage",
    summary="Verbruik en variabele kosten per lokale woningdag (B14-002)",
    responses={
        501: {"description": "Bron of eerste uur-export ontbreekt"},
        503: {
            "description": "De bron, de viewer-koppeling of het energiearchief is tijdelijk onbereikbaar",
            "headers": {"Retry-After": {"description": "Wachttijd in seconden", "schema": {"type": "integer"}}},
        },
    },
)
def usage(
    request: Request,
    period: Period = "day",
    day: date | None = Query(None, alias="date", description="Een datum binnen de gewenste periode in de woning."),
    role: Role = "p1_net",
    direction: Direction = "import",
    timezone: str | None = Query(None, description="Optioneel ter controle van de door de woning gemelde tijdzone."),
    session: Session = Depends(archive_session),
    _p: Principal = Depends(require_reader),
) -> UsageReport:
    if request.query_params.keys() - {"period", "date", "role", "direction", "timezone"}:
        raise ApiError(422, "validation_error", "Onbekend queryveld voor het verbruiksrapport.")
    scope, zone, currency = verified_archive(request, session)
    if timezone is not None and timezone != zone.key:
        raise ApiError(422, "validation_error", "De gevraagde tijdzone wijkt af van de tijdzone van de woning.")
    day = day or utcnow().astimezone(zone).date()
    if not 1 < day.year < 9999:
        raise ApiError(422, "validation_error", "De periode valt buiten het ondersteunde datumbereik.")
    return usage_report(session, scope, zone, currency, period, day, role, direction)


@router.get(
    "/advice",
    summary="Kostenadvies voor een werkuur op vergelijkbare woningdagen (B14-004)",
    description="Leest gemeten P1-netafname, afnametarieven en historische werklast. "
    "Bij onvoldoende gegevens bevat de lijst een reden en nul adviezen.",
    openapi_extra={"security": [{"HubJWT": []}], "x-required-roles": ["viewer", "operator", "admin"]},
    responses={
        401: {"description": "Een geldige aanmelding is vereist.", "model": ApiErrorBody},
        403: {"description": "Een leesrol is vereist.", "model": ApiErrorBody},
        422: {"description": "Ongeldige datum, meter of uurkeuze.", "model": ApiErrorBody},
        501: {"description": "De ingestelde bron heeft geen bruikbare viewer-koppeling.", "model": ApiErrorBody},
        503: {
            "description": "De viewer-koppeling, de bron of het archief is tijdelijk onbereikbaar.",
            "model": ApiErrorBody,
            "headers": {"Retry-After": {"description": "Wachttijd in seconden", "schema": {"type": "integer"}}},
        },
    },
)
def advice(
    request: Request,
    day: date | None = Query(
        None, alias="date", description="Laatste afgesloten woningdag van de terugblik. Standaard gisteren."
    ),
    meter_id: UUID | None = Query(
        None, description="Fysieke P1-meter. Standaard de laatst herkende P1-meter in het tijdvak."
    ),
    busy_hour: int = Query(18, ge=0, le=23, description="Lokaal beginuur van het drukke werkuur."),
    quiet_hour: int = Query(23, ge=0, le=23, description="Lokaal beginuur van het rustige alternatief."),
    session: Session = Depends(archive_session),
    _p: Principal = Depends(require_reader),
) -> AdviceReport:
    if (
        busy_hour == quiet_hour
        or (day and not 1 < day.year < 9999)
        or any(
            k not in {"date", "meter_id", "busy_hour", "quiet_hour"} or len(request.query_params.getlist(k)) != 1
            for k in request.query_params
        )
    ):
        raise ApiError(422, "validation_error", "Kies twee verschillende uren en geldige queryparameters.")
    try:
        scope, zone, currency = verified_archive(request, session)
    except MissingMeterArchive:
        return AdviceReport(reason_nl=NO_METER)
    today = utcnow().astimezone(zone).date()
    if day is not None and day >= today:
        raise ApiError(422, "validation_error", "De laatste woningdag moet afgesloten zijn.")
    return cost_advice(
        session,
        scope,
        request.app.state.hublink_store.read(),
        zone,
        currency,
        day or today - DAY,
        busy_hour,
        quiet_hour,
        meter_id,
    )


@router.get("/alert-thresholds", summary="Ingestelde meldingsdrempels (leeg tot een beheerder ze vastlegt)")
def alert_thresholds(
    response: Response, session: Session = Depends(archive_session), _p: Principal = Depends(require_admin)
) -> AlertThresholds | None:
    state = session.get(ServiceState, SETTINGS_KEY)
    if state is None:
        return None
    response.headers["ETag"] = etag(state.value["version"])
    return AlertThresholds(**state.value["thresholds"])


@router.put(
    "/alert-thresholds",
    response_model=AlertThresholds,
    summary="Energiedrempels voor meldingen instellen",
    description="Vereist een Hub-JWT met de rol admin. Bij een bestaande instelling is If-Match verplicht.",
    openapi_extra={"security": [{"HubJWT": []}], "x-required-roles": ["admin"]},
    responses={
        200: {"headers": {"ETag": {"description": "Versie van de opgeslagen drempels", "schema": {"type": "string"}}}},
        **{
            status: {"description": description, "model": ApiErrorBody}
            for status, description in {
                400: "Idempotency-Key ontbreekt of is geen UUID",
                401: "Aanmelding ontbreekt, is ongeldig of is verlopen",
                403: "De rol admin is vereist",
                412: "If-Match verwijst naar een verouderde versie",
                413: "Verzoek te groot",
                422: "Ongeldige drempels of dezelfde Idempotency-Key bij een ander verzoek",
                428: "If-Match ontbreekt bij een bestaande instelling",
                503: "Het energiearchief of de controle op tokenhergebruik is tijdelijk onbereikbaar",
            }.items()
        },
    },
)
def set_alert_thresholds(
    body: AlertThresholds,
    request: Request,
    session: Session = Depends(archive_session),
    principal: Principal = Depends(require_admin),
    key: UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> JSONResponse:
    # Ook gelijktijdige eerste PUTs moeten de opgeslagen Idempotency-Key zien vóór de ETag-controle.
    session.execute(insert(ServiceState).values(key=SETTINGS_KEY, value={}).on_conflict_do_nothing())
    row = session.get_one(ServiceState, SETTINGS_KEY, with_for_update=True)

    def action() -> Result:
        version = row.value.get("version", 0)
        if version or match not in (None, "*"):
            check_if_match(version, match)
        row.value = {**row.value, "thresholds": body.model_dump(), "version": version + 1}
        audit.record(
            session,
            domain="energy",
            action="thresholds.updated",
            entity_type="energy_thresholds",
            entity_id="energy",
            principal=principal,
            trace_id=tid,
            message_nl="De beheerder heeft de energiedrempels ingesteld.",
        )
        return 200, body, {"ETag": etag(version + 1)}

    return run_idempotent(request, session, principal, key, body, action)


class AlertList(BaseModel):
    items: list[AlertStatus]
    next_cursor: None = None


@router.get("/alerts", summary="Actuele beoordeling per energieregel en bron")
def energy_alerts(
    request: Request, session: Session = Depends(archive_session), _p: Principal = Depends(require_reader)
) -> AlertList:
    checks = assess(session, session.get(ServiceState, SETTINGS_KEY), utcnow(), request.app.state.hublink_store.read())
    return AlertList(items=[check.status() for check in checks])


@router.get("/workloads", summary="Werklasten, reserveringen per uur en actuele bronmetingen (B14-003)")
def workloads(
    request: Request,
    day: date | None = Query(None, alias="date", description="Kalenderdatum in de gevraagde tijdzone."),
    timezone: str = Query("UTC", max_length=128, description="IANA-tijdzone voor de daggrenzen."),
    session: Session = Depends(archive_session),
    _p: Principal = Depends(require_reader),
    tid: str = Depends(trace_id),
) -> WorkloadPlan:
    try:
        zone = home_zone(timezone)
    except EnergyReadError:
        raise ApiError(422, "validation_error", "De tijdzone voor de dagplanner is ongeldig.") from None
    day = day or utcnow().astimezone(zone).date()
    if not 1 < day.year < 9999 or any(
        k not in {"date", "timezone"} or len(request.query_params.getlist(k)) != 1 for k in request.query_params
    ):
        raise ApiError(422, "validation_error", "Ongeldige datum of queryparameters voor de dagplanner.")
    state = request.app.state
    sources = workload_sources(session, state.hub, state.hublink_store.read(), tid)
    return day_plan(session, day, zone, sources)
