"""B14-routes (P0): capabilities, dekkingsmatrix-structuur en eerlijke 501 voor nog niet gebouwde data."""

from __future__ import annotations

from typing import Any

from fastapi import Depends

from ...security.auth import Principal, require_reader
from ...timeutil import iso, utcnow
from ..common import domain_router
from .catalog import EXPECTED_METER_ROLES, QUALITY_LABELS, SOURCES

router = domain_router(
    "energy",
    SOURCES,
    {
        "/meters": ("energy.meters.read", ("B14-001",)),
        "/usage": ("energy.usage.read", ("B14-002",)),
        "/workloads": ("energy.workload.read", ("B14-003",)),
        "/advice": ("energy.advice.read", ("B14-004",)),
    },
)


def coverage_payload() -> dict[str, Any]:
    return {
        "items": [
            {
                **role.to_dict(),
                "measurement_status": "onbekend",
                "quality": "onbekend",
                "source": None,
                "last_updated": None,
                "why_unknown_nl": f"Nog niet vastgelegd: besluit {role.decision} (wizard) of readback van my_house ontbreekt.",
            }
            for role in EXPECTED_METER_ROLES
        ],
        "quality_labels": list(QUALITY_LABELS),
        "rules_nl": [
            "NAS-energie is alleen 'gemeten' met een losse meter; anders 'geschat' (met herkomst) of 'onbekend'.",
            "Geen wattage afleiden uit CPU% zonder kalibratie.",
            "Boiler: alleen meten, nooit schakelen.",
        ],
        "evaluated_at": iso(utcnow()),
        "next_cursor": None,
    }


@router.get("/coverage", summary="Dekkingsmatrix (B14-001): verwachte meterrollen, status onbekend tot gemeten")
def coverage(_p: Principal = Depends(require_reader)) -> dict[str, Any]:
    return coverage_payload()
