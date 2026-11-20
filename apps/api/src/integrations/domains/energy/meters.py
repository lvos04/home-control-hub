"""Lees de actuele dekking en bewaar de herkende logische meetkanalen in de eigen database."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import NAMESPACE_URL, UUID, uuid5

from cryptography.exceptions import InvalidTag
from fastapi import Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import IntegrationSource
from ...sources import source_ref
from ...timeutil import utcnow
from .catalog import EXPECTED_METER_ROLES
from .client import EnergyClient, EnergyReadError, EnergyRoute, ViewerDenied, stored_viewer
from .models import EnergyMeter, EnergyMeterRole
from .readings import SOURCE_ROLES, Quality, Reading, declared_roles, live_readings

SOURCE = "my_house"
ABSENT = "my_house meldt deze meterrol niet."
NAS_ABSENT = "my_house meldt geen losse vermogensmeter voor de NAS."


class MeterItem(BaseModel):
    id: UUID
    role: str
    unit: Literal["W"] = "W"
    source: Literal["my_house"] = "my_house"
    read_only: Literal[True] = True
    last_measurement: float | None
    last_updated: datetime | None
    measurement_quality: Quality
    reason_code: str | None
    reason_nl: str


@dataclass
class Inventory:
    meters: dict[str, MeterItem]
    reason: str = ABSENT


def _read(client: EnergyClient) -> tuple[dict[str, Reading], str]:
    live = client.read(EnergyRoute.LIVE)
    try:
        declared = declared_roles(client.read(EnergyRoute.SUMMARY))
    except ViewerDenied:
        raise
    except EnergyReadError as exc:
        # Het dagoverzicht identificeert P1. De deelmeters dragen zelf rol, meettijd en kwaliteit in /live.
        return live_readings(live, set(), utcnow()), str(exc)
    return live_readings(live, declared, utcnow()), ABSENT


def meter_inventory(request: Request, session: Session) -> Inventory:
    # Eén transactie per koppeling houdt het doeladres, het token en de meterregistratie bij dezelfde lezing.
    source = session.scalar(select(IntegrationSource).where(IntegrationSource.source_id == SOURCE).with_for_update())
    if source is None or not source.base_url:
        return Inventory({}, "De bron my_house is niet ingesteld.")
    if not source.enabled:
        return Inventory({}, "De bron my_house staat uit.")
    if source.credential_ref != source_ref(SOURCE):
        return Inventory({}, "De eigen viewer-koppeling voor my_house ontbreekt.")
    try:
        stored = request.app.state.vault.get(session, source.credential_ref)
        viewer = stored_viewer(stored)
        client = EnergyClient(source.base_url, viewer, request.app.state.settings, request.app.state.http_transport)
    except EnergyReadError as exc:
        return Inventory({}, str(exc))
    except (InvalidTag, ValueError):
        return Inventory({}, "De viewer-koppeling in de kluis is onleesbaar.")

    try:
        readings, reason = _read(client)
    except EnergyReadError as exc:
        readings = {}
        reason = str(exc)

    scope = uuid5(NAMESPACE_URL, f"{viewer.pairing.server_id}/{viewer.pairing.home_id}")
    inventory = _register(session, scope, source.link_revision, readings, reason)
    session.commit()
    return inventory


def _register(session: Session, scope: UUID, revision: str, readings: dict[str, Reading], reason: str) -> Inventory:
    # De bron benoemt vermogenskanalen per woning en rol, zonder serienummer. Houd adressen uit de meter-ID.
    keys = {role: f"{scope}/{role}" for role in SOURCE_ROLES.values()}
    stored = {
        meter.source_meter_id: meter
        for meter in session.scalars(
            select(EnergyMeter).where(EnergyMeter.source_id == SOURCE, EnergyMeter.source_meter_id.in_(keys.values()))
        )
    }
    confirmed_by = f"{SOURCE}:{revision}"
    meters = {}
    for spec in EXPECTED_METER_ROLES:
        role = spec.role
        if role not in keys:
            continue
        meter = stored.get(keys[role])
        binding = session.get(EnergyMeterRole, (meter.id, role)) if meter else None
        previous = binding is not None and binding.confirmed_by == confirmed_by
        reading = readings.get(role)
        if reading is None and not previous:
            continue
        if meter is None:
            meter = EnergyMeter(source_id=SOURCE, source_meter_id=keys[role], display_name=spec.title_nl, unit="W")
            session.add(meter)
            session.flush()
        if binding is None:
            binding = EnergyMeterRole(meter_id=meter.id, role=role)
            session.add(binding)
        last_at = binding.confirmed_at if previous else None
        if reading is None:
            reading = Reading.unknown(reason, last_at)
        elif last_at and reading.at and reading.at < last_at:
            reading = Reading.unknown("Het bronantwoord is ouder dan de vorige meting.", last_at)
        binding.confirmed_by = confirmed_by
        binding.confirmed_at = reading.at or last_at
        meters[role] = MeterItem(
            id=meter.id,
            role=role,
            last_measurement=reading.value,
            last_updated=binding.confirmed_at,
            measurement_quality=reading.quality,
            reason_nl=reading.reason,
            reason_code=reading.reason_code,
        )
    return Inventory(meters, reason)
