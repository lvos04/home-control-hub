"""B11-routes (P0): capabilities, verboden node-typen en eerlijke 501 voor nog niet gebouwde data."""

from __future__ import annotations

from typing import Any

from fastapi import Depends

from ...security.auth import Principal, require_reader
from ..common import domain_router
from .catalog import FORBIDDEN_NODE_TYPES, FORBIDDEN_NODE_TYPES_VERIFICATION, SOURCES

router = domain_router(
    "automation",
    SOURCES,
    {
        "/flows": ("automation.flows.read", ("B11-005",)),
        "/event-types": ("automation.event_types.read", ("B11-002",)),
        "/runs": ("automation.runs.read", ("B11-004",)),
    },
)


@router.get("/policy", summary="Vaste veiligheidsregels voor flows (B11-001/B11-003)")
def automation_policy(_p: Principal = Depends(require_reader)) -> dict[str, Any]:
    return {
        "forbidden_node_types": list(FORBIDDEN_NODE_TYPES),
        "forbidden_node_types_verification": FORBIDDEN_NODE_TYPES_VERIFICATION,
        "actions_via": "Hub-actieverzoek (policy bepaalt de risicoklasse; risk_claim van een flow telt niet)",
        "never_nl": [
            "Geen shell-/exec-uitvoering vanuit flows.",
            "Geen R3-actie (bv. dataset verwijderen) zonder admin-goedkeuring.",
            "Boiler schakelen is via elke route verboden.",
        ],
    }
