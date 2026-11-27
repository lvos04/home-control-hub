"""Lees de lokale meterstand en open meldingen voor het openbare energieblok."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from .domains.energy import alerts
from .domains.energy.catalog import EXPECTED_METER_ROLES, MeterRoleSpec
from .domains.energy.meters import NAS_ABSENT, SOURCE, STATUS_KEY
from .domains.energy.models import EnergyMeter, EnergyMeterRole
from .domains.energy.readings import LIVE_MAX_AGE, source_timestamp
from .domains.energy.usage_sync import STATE_KEY
from .hublink_store import LinkState
from .models import IntegrationSource, ServiceState
from .sources import PROBE_MAX_AGE
from .timeutil import nl_datumtijd

_METERNAAM = {
    "p1_net": "Slimme meter (P1)",
    "boiler_socket": "Boilermeter",
    "airco_outdoor": "Airco (gedeelde buitenunit)",
    "nas_host": "Losse NAS-meter",
}


def _rij(naam: str, toon: str, label: str, reden: str) -> dict[str, str]:
    return {"naam": naam, "toon": toon, "label": label, "reden": reden}


def onleesbaar() -> list[dict[str, str]]:
    return [_rij("Meterdekking en afwijkingen", "storing", "Storing", "De lokale energiestand is niet leesbaar.")]


def _meter(spec: MeterRoleSpec, meting: dict[str, Any], nu: datetime) -> dict[str, str]:
    naam = _METERNAAM.get(spec.role, spec.title_nl)
    at = source_timestamp(meting.get("at"))
    tijd = f" Laatste meting van my_house op {nl_datumtijd(at.astimezone(nu.tzinfo))}." if at and at <= nu else ""
    if at and at <= nu and (nu - at > LIVE_MAX_AGE or meting.get("stale")):
        return _rij(naam, "verouderd", "Verouderd", "Huidig vermogen onbekend." + tijd)
    kwaliteit, watt = meting.get("quality"), meting.get("watts")
    if tijd and kwaliteit in ("gemeten", "geschat") and type(watt) in (int, float):
        waarde = f"{watt:g}".replace(".", ",")
        return _rij(naam, "feit", kwaliteit.capitalize(), f"{waarde} W." + tijd)
    reden = NAS_ABSENT if spec.role == "nas_host" else "my_house levert geen bevestigd vermogen voor deze rol."
    return _rij(naam, "onbekend", "Onbekend", reden + tijd)


def _afwijkingen(staat: dict[str, Any], woning: str | None, link: LinkState, nu: datetime) -> dict[str, str]:
    naam = "Openstaande afwijkingen"
    if not staat.get("thresholds"):
        return _rij(naam, "gate", "Niet ingesteld", "Drempels voor energiemeldingen kun je instellen in de Hub.")
    at = source_timestamp(staat.get("evaluated_at"))
    if at is None or at > nu:
        return _rij(naam, "nog-niet", "Bezig", "De eerste beoordeling van de drempels volgt.")
    geopend = staat.get("open", {})
    meldingen = []
    regels: list[tuple[alerts.Rule, str, str | None, str]] = [
        ("meter_offline", spec.role, woning, f"Meteruitval bij {_METERNAAM.get(spec.role, spec.title_nl)}")
        for spec in EXPECTED_METER_ROLES
        if spec.role in alerts.ROLES
    ]
    regels.extend(
        [
            ("boiler_usage", "boiler_socket", woning, "Afwijkend boilerverbruik"),
            ("daily_budget", "p1_net", woning, "Dagbudget overschreden"),
            ("nas_load", "nas", link.service_id if link.linked else None, "Verhoogde NAS-belasting"),
        ]
    )
    for regel, rol, scope, tekst in regels:
        if scope and alerts.Check(regel, rol, UUID(scope)).subject in geopend:
            meldingen.append(tekst)
    reden = ". ".join(meldingen) + "." if meldingen else "Geen openstaande afwijkingen geregistreerd."
    reden += f" Laatst beoordeeld op {nl_datumtijd(at.astimezone(nu.tzinfo))}."
    if nu - at > PROBE_MAX_AGE:
        return _rij(naam, "verouderd", "Verouderd", reden)
    if meldingen:
        return _rij(naam, "beperkt", "Beperkt", reden)
    return _rij(naam, "feit", "Geen", reden)


def lees_energie(db: Session, bron: IntegrationSource | None, link: LinkState, nu: datetime) -> list[dict[str, str]]:
    sleutels = (STATUS_KEY, STATE_KEY, alerts.SETTINGS_KEY)
    standen = {rij.key: rij.value for rij in db.scalars(select(ServiceState).where(ServiceState.key.in_(sleutels)))}
    regels = standen.get(alerts.SETTINGS_KEY, {})
    actief = bron is not None and bron.enabled and bool(bron.base_url)
    revisie = bron.link_revision if bron and actief else None
    archief = standen.get(STATE_KEY, {})
    woning = archief.get("scope") if revisie and archief.get("revision") == revisie else None
    if not actief:
        rijen = [
            _rij(
                "Meterdekking",
                "gate",
                "Niet ingesteld",
                "Er is geen actieve woningbron. Stel my_house in via de Hub om de meters te zien.",
            )
        ]
        if regels.get("thresholds"):
            rijen.append(_afwijkingen(regels, woning, link, nu))
        return rijen
    stand = standen.get(STATUS_KEY, {})
    if stand.get("revision") != revisie:
        stand = {}
    rijen = []
    meters = stand.get("meters", {})
    if not stand:
        # Vóór het energieblok bewaarde de inventaris alleen de bronmeettijd. Die bewijst geen vermogen of kwaliteit.
        tijden = db.execute(
            select(EnergyMeterRole.role, EnergyMeterRole.confirmed_at)
            .join(EnergyMeter)
            .where(
                EnergyMeter.source_id == SOURCE,
                EnergyMeter.unit == "W",
                EnergyMeterRole.confirmed_by == f"{SOURCE}:{revisie}",
            )
        )
        meters = {rol: {"at": tijd.isoformat()} for rol, tijd in tijden if tijd is not None}
        reden = "De dienst wacht op een nieuwe vermogensmeting." if meters else "De dienst wacht op de eerste meting."
        rijen.append(_rij("Meterdekking", "nog-niet", "Bezig", "De woningbron is ingesteld. " + reden))
    elif stand.get("failed"):
        rijen.append(_rij("Meterdekking", "storing", "Storing", "De laatste leespoging bij de woningbron is mislukt."))
    rijen.extend(_meter(spec, meters.get(spec.role, {}), nu) for spec in EXPECTED_METER_ROLES)
    rijen.append(_afwijkingen(regels, woning, link, nu))
    return rijen
