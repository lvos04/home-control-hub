"""B10-routes (P0): capabilities + eerlijke 501 voor nog niet gebouwde data."""

from __future__ import annotations

from ..common import domain_router
from .catalog import SOURCES

router = domain_router(
    "network",
    SOURCES,
    {
        "/devices": ("network.devices.read", ("B10-001", "B10-002")),
        "/dns/summary": ("network.dns.summary.read", ("B10-003",)),
        "/vpn/peers": ("network.vpn.status.read", ("B10-005",)),
        "/tunnels": ("network.tunnel.health.read", ("B10-005",)),
        "/findings": ("network.findings.read", ("B10-006",)),
    },
)
