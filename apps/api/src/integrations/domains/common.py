"""Gedeelde routerbouw voor domeinen die in P0 alleen inventaris/capabilities hebben (B10, B11, B14)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import API_PREFIX
from ..deps import get_session
from ..errors import ApiError
from ..security.auth import AuthFirstRoute, Principal, require_reader
from . import DOMAIN_TITLES_NL, Domain, SourceSpec


def unavailable(capability_id: str, task_ids: tuple[str, ...]) -> ApiError:
    return ApiError(
        501,
        "capability_unavailable",
        "Deze functie is nog niet gebouwd; er wordt bewust geen (lege of gesimuleerde) data getoond.",
        {"capability": capability_id, "task_ids": list(task_ids), "status": "niet_gebouwd"},
    )


def domain_router(
    domain: Domain, sources: tuple[SourceSpec, ...], data_routes: dict[str, tuple[str, tuple[str, ...]]]
) -> APIRouter:
    """Maakt ``GET /<domein>/capabilities`` en per niet-gebouwde capability een route die 501 geeft."""
    router = APIRouter(prefix=f"{API_PREFIX}/{domain}", tags=[domain], route_class=AuthFirstRoute)

    @router.get("/capabilities", summary=f"Capabilities en bronnen — {DOMAIN_TITLES_NL[domain]}")
    def capabilities(
        session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
    ) -> dict[str, Any]:
        from ..sources import source_view

        return {
            "domain": domain,
            "title_nl": DOMAIN_TITLES_NL[domain],
            "sources": [source_view(session, s) for s in sources],
            "unavailable_routes": {path: cap_id for path, (cap_id, _t) in data_routes.items()},
        }

    for path, (cap_id, task_ids) in data_routes.items():

        def _make(cap_id: str = cap_id, task_ids: tuple[str, ...] = task_ids) -> Any:
            def endpoint(_p: Principal = Depends(require_reader)) -> dict[str, Any]:
                raise unavailable(cap_id, task_ids)

            return endpoint

        router.add_api_route(
            path,
            _make(),
            methods=["GET"],
            summary=f"{cap_id} (nog niet gebouwd → 501 capability_unavailable)",
            responses={501: {"description": "capability_unavailable"}},
        )
    return router
