"""Vertaling van my_house-livevermogen. Elke meting houdt haar eigen tijd en geldigheid."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from .client import EnergyReadError

LIVE_MAX_AGE = timedelta(minutes=5)  # my_house/views/energy.py: LIVE_STALE
Quality = Literal["gemeten", "geschat", "onbekend"]
SOURCE_ROLES = {"grid": "p1_net", "boiler": "boiler_socket", "airco": "airco_outdoor"}
NO_READING = "my_house levert geen actuele vermogensmeting voor deze meterrol."


@dataclass(frozen=True)
class Reading:
    value: float | None
    at: datetime | None
    quality: Quality
    reason: str
    reason_code: str | None = None

    @classmethod
    def unknown(cls, reason: str, at: datetime | None = None) -> Reading:
        return cls(None, at, "onbekend", reason)


def source_timestamp(raw: object) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
        return parsed.astimezone(UTC) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def read_part(part: dict[str, Any], now: datetime) -> Reading:
    at = source_timestamp(part.get("at"))
    if at is None or at > now:
        return Reading.unknown("Een geldige eigen meettijd ontbreekt.")
    if now - at > LIVE_MAX_AGE or part.get("stale") is True:
        return Reading(None, at, "onbekend", "De vermogensmeting is verouderd.", "meting_verouderd")
    value = part.get("watts")
    if part.get("stale") is not False or isinstance(value, bool) or not isinstance(value, int | float):
        return Reading.unknown(NO_READING, at)
    try:
        if not math.isfinite(value):
            return Reading.unknown(NO_READING, at)
    except OverflowError:
        return Reading.unknown(NO_READING, at)
    if part.get("source_quality") == "measured":
        return Reading(value, at, "gemeten", "my_house levert een gemeten vermogen voor deze rol.")
    if part.get("source_quality") == "estimated":
        return Reading(value, at, "geschat", "my_house markeert deze vermogensmeting als schatting.")
    return Reading.unknown("Een bruikbaar kwaliteitslabel ontbreekt.", at)


def declared_roles(summary: Any) -> set[str]:
    # Het dagoverzicht identificeert rollen. kWh en de kwaliteit van een hele dag zeggen niets over het huidige vermogen.
    if not isinstance(summary, dict) or not isinstance(summary.get("meters"), list):
        raise EnergyReadError("De meterinventaris van my_house heeft een ongeldig formaat.")
    return {
        row["role"]
        for row in summary["meters"]
        if isinstance(row, dict)
        and isinstance(row.get("role"), str)
        and row["role"] in SOURCE_ROLES
        and row.get("unit") == "kWh"
    }


def live_readings(live: Any, declared: set[str], now: datetime) -> dict[str, Reading]:
    result = {SOURCE_ROLES[role]: Reading.unknown(NO_READING) for role in declared}
    if live is None:
        return result
    if not isinstance(live, dict) or not isinstance(live.get("parts"), list):
        raise EnergyReadError("Het liveantwoord van my_house heeft een ongeldig formaat.")
    # Alleen de eigen P1-rij levert bronbewijs. Het oude veld 'at' kan ook van een deelmeter zijn.
    if "grid" in declared:
        result["p1_net"] = read_part(
            {
                "watts": live.get("total_w"),
                "at": live.get("total_observed_at"),
                "stale": False,
                "source_quality": live.get("total_source_quality"),
            },
            now,
        )
    seen: set[str] = set()
    for part in live["parts"]:
        if not isinstance(part, dict) or part.get("role") not in ("airco", "boiler"):
            continue
        role = SOURCE_ROLES[part["role"]]
        result[role] = (
            Reading.unknown("my_house levert meerdere livevermogens voor dezelfde rol.")
            if role in seen
            else read_part(part, now)
        )
        seen.add(role)
    return result
