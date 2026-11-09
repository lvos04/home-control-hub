"""Inventaris B14 en de structuur van de dekkingsmatrix (B14-001).

De dekkingsmatrix bevat alleen **verwachte meterrollen** uit D14; of een meter echt bestaat en wat hij meet is
``onbekend`` tot de wizard (D14) of een gemeten readback van my_house het vastlegt. Geen voorbeeldwaarden.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .. import SourceSpec, cap

SOURCES: tuple[SourceSpec, ...] = (
    SourceSpec(
        source_id="my_house",
        domain="energy",
        display_name="my_house (energie)",
        role_nl="Eigenaar van woning-, energie- en apparaatdata; alleen lezen (GET).",
        owner_nl="my_house; welke bestaande energieroutes bruikbaar zijn is te verifiëren in die repo (delta-matrix).",
        install_doc="B14/B06",
        install_method="bestaand",
        upstream="https://github.com/lvos04/my_house",
        required_decisions=("D14",),
        api_verification="te_verifieren",
        capabilities=(
            cap("energy.meters.read", "Meters en meterrollen (P1, boiler-socket, airco-kWh)", "read", ("B14-001",)),
            cap("energy.usage.read", "Verbruiksintervallen met kwaliteitslabel", "read", ("B14-002",)),
        ),
        forbidden_nl=(
            "Boiler blijft in alle gevallen alleen meten; geen schakelroute (EX27, B14-005).",
            "Geen directe writes in de database van my_house.",
        ),
    ),
    SourceSpec(
        source_id="truenas_metrics",
        domain="energy",
        display_name="TrueNAS-metrics (alleen-lezen)",
        role_nl="CPU/RAM/GPU-belasting van de NAS via de read-only Hub-adapter.",
        owner_nl="TrueNAS-middleware via de Hub (read-only key); deze dienst krijgt de data van de Hub.",
        install_doc="B14",
        install_method="n.v.t.",
        upstream="https://www.truenas.com/docs/",
        required_decisions=("D01",),
        api_verification="te_verifieren",
        capabilities=(cap("energy.workload.read", "Werkloadbelasting per app", "read", ("B14-003",)),),
        notes_nl="Geen wattage afleiden uit CPU% zonder kalibratie tegen een echte meter (B14-001).",
    ),
    SourceSpec(
        source_id="mediaguard_encoding",
        domain="energy",
        display_name="MediaGuard (encodingstatus)",
        role_nl="AV1-/encodewachtrij als werkload; alleen status lezen.",
        owner_nl="MediaGuard; acties alleen via MediaGuard-routes en -audit.",
        install_doc="B14",
        install_method="bestaand",
        upstream="https://github.com/lvos04/media-guard-ultimate",
        required_decisions=("D07",),
        api_verification="te_verifieren",
        capabilities=(
            cap("energy.reservations.propose", "Werkloadreservering/pauzevoorstel", "propose", ("B14-003",), "R1"),
        ),
    ),
)


@dataclass(frozen=True)
class MeterRoleSpec:
    role: str
    title_nl: str
    decision: str
    read_only: bool
    notes_nl: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


EXPECTED_METER_ROLES: tuple[MeterRoleSpec, ...] = (
    MeterRoleSpec("p1_net", "Slimme meter (P1) — netafname/-teruglevering", "D14", True, ""),
    MeterRoleSpec(
        "boiler_socket",
        "Energy Socket boiler",
        "D14",
        True,
        "Alleen meten; schakelen is via elke route verboden (EX27).",
    ),
    MeterRoleSpec(
        "airco_outdoor",
        "Airco 1-fase kWh-meter (gedeelde buitenunit)",
        "D14",
        True,
        "Meet de gedeelde buitenunit, niet de afzonderlijke binnenunits (B14 §5).",
    ),
    MeterRoleSpec(
        "nas_host",
        "NAS-host (optioneel, losse meter)",
        "D14",
        True,
        "Zonder losse meter is NAS-energie 'onbekend' of een expliciete schatting; nooit uit CPU% zonder kalibratie.",
    ),
)

QUALITY_LABELS = ("gemeten", "geschat", "onbekend")
