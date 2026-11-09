"""Gedeelde FastAPI-afhankelijkheden."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Header, Request
from sqlalchemy.orm import Session

from .errors import ApiError, trace_id_for


def get_session(request: Request) -> Iterator[Session]:
    yield from request.app.state.db.session()


def trace_id(request: Request) -> str:
    return trace_id_for(request)


def etag(version: int) -> str:
    return f'W/"{version}"'


def if_match(if_match: str | None = Header(default=None, alias="If-Match")) -> str | None:
    return if_match.strip() if if_match else None


def check_if_match(current_version: int, given: str | None, *, required: bool = True) -> None:
    """Optimistische vergrendeling: bij wijzigen van een bestaand object is ``If-Match`` met de ETag verplicht."""
    if given is None:
        if required:
            raise ApiError(
                428,
                "precondition_required",
                "Header 'If-Match' met de ETag is verplicht bij het wijzigen van een bestaand object.",
            )
        return
    if given != "*" and given != etag(current_version):
        raise ApiError(
            412,
            "precondition_failed",
            "Het object is intussen gewijzigd; haal het opnieuw op en probeer het nog eens.",
            {"current_etag": etag(current_version)},
        )
