"""Domeinmodules met duidelijke grenzen.

Elk domein heeft:
- ``models.py``  eigen tabellen (prefix ``<domein>_``); nooit tabellen van een ander domein muteren;
- ``catalog.py`` de inventaris: welke bronnen er komen en welke capabilities ze (later) leveren;
- ``router.py``  eigen routes onder ``/integrations/v1/<domein>/…``.

Afspraken (contract §6, ``02_DATA_EIGENAARSCHAP``):
- Een capability die nog niet gebouwd is geeft ``501 capability_unavailable``, nooit een lege lijst of gesimuleerd
  succes (een lege lijst zou "geen apparaten"/"geen verbruik" suggereren).
- Wat een externe app kan (API, OIDC, health-endpoint) is ``te_verifieren`` tot iemand het tegen de officiële
  documentatie én een echte installatie heeft gecontroleerd.
- Een bron zonder configuratie is ``niet_geconfigureerd`` met health ``unknown`` — nooit gezond.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Domain = Literal["network", "automation", "sso", "energy"]
DOMAINS: tuple[Domain, ...] = ("network", "automation", "sso", "energy")
DOMAIN_TITLES_NL = {
    "network": "Netwerk en privacy (B10)",
    "automation": "Node-RED-automatisering (B11)",
    "sso": "Authentik en toegangsbeheer (B13)",
    "energy": "Energie en resources (B14)",
}

CapabilityKind = Literal["read", "propose", "apply", "rollback", "stream"]
BuildStatus = Literal["gebouwd", "niet_gebouwd", "geblokkeerd"]
Verification = Literal["te_verifieren", "geverifieerd_docs", "geverifieerd_installatie", "n.v.t."]


@dataclass(frozen=True)
class CapabilitySpec:
    capability_id: str
    title_nl: str
    kind: CapabilityKind
    build_status: BuildStatus
    risk_class: Literal["R0", "R1", "R2", "R3"]
    task_ids: tuple[str, ...]
    notes_nl: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["task_ids"] = list(self.task_ids)
        return d


@dataclass(frozen=True)
class SourceSpec:
    """Een (toekomstige) bron in de inventaris. Geen runtime-toestand; die staat in ``integration_source``."""

    source_id: str
    domain: Domain
    display_name: str
    role_nl: str
    owner_nl: str
    install_doc: str
    install_method: Literal["catalog_app", "custom_app", "bestaand", "extern", "n.v.t."]
    upstream: str
    required_decisions: tuple[str, ...]
    api_verification: Verification
    capabilities: tuple[CapabilitySpec, ...]
    probe_path: str | None = None  # alleen als er een gezondheids-endpoint bekend is (te verifiëren)
    notes_nl: str = ""
    forbidden_nl: tuple[str, ...] = field(default_factory=tuple)
    api_verification_ref: str | None = None  # waar de verificatie staat (alleen bij geverifieerd_*)
    probe_path_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "domain": self.domain,
            "display_name": self.display_name,
            "role_nl": self.role_nl,
            "owner_nl": self.owner_nl,
            "install_doc": self.install_doc,
            "install_method": self.install_method,
            "upstream": self.upstream,
            "required_decisions": list(self.required_decisions),
            "api_verification": self.api_verification,
            "api_verification_ref": self.api_verification_ref,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "probe_path": self.probe_path,
            "probe_path_verification": (
                ("geverifieerd_docs" if self.probe_path_verified else "te_verifieren") if self.probe_path else None
            ),
            "notes_nl": self.notes_nl,
            "forbidden_nl": list(self.forbidden_nl),
        }


def cap(
    capability_id: str,
    title_nl: str,
    kind: CapabilityKind,
    task_ids: tuple[str, ...],
    risk_class: Literal["R0", "R1", "R2", "R3"] = "R0",
    build_status: BuildStatus = "niet_gebouwd",
    notes_nl: str = "",
) -> CapabilitySpec:
    return CapabilitySpec(capability_id, title_nl, kind, build_status, risk_class, task_ids, notes_nl)
