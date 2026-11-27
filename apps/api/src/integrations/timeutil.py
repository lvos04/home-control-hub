"""Tijdhulpmiddelen: alles in UTC, ISO-8601 met ``Z`` (contract §5)."""

from __future__ import annotations

from datetime import UTC, datetime

_MAANDEN = ("jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec")


def nl_datumtijd(dt: datetime) -> str:
    """Datum en tijd met tijdzone voor de statuspagina (Peil §11.2)."""
    zone = dt.tzname() or dt.strftime("%z")
    return f"{dt.day} {_MAANDEN[dt.month - 1]} {dt.year}, {dt:%H:%M}" + (f" {zone}" if zone else "")


def utcnow() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
