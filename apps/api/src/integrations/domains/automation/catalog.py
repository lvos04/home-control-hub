"""Inventaris B11. Node-RED-API-gedrag en node-namen zijn ``te_verifieren`` tegen de officiële Node-RED-docs."""

from __future__ import annotations

from .. import SourceSpec, cap

# Node-typen die nooit in een flow mogen (B11-001: "custom exec-node is geblokkeerd"). De exacte typenamen en of er
# meer zijn (bv. via contrib-pakketten) zijn TE VERIFIËREN tegen de Node-RED-documentatie van de gepinde versie.
FORBIDDEN_NODE_TYPES: tuple[str, ...] = ("exec",)
FORBIDDEN_NODE_TYPES_VERIFICATION = "te_verifieren"

SOURCES: tuple[SourceSpec, ...] = (
    SourceSpec(
        source_id="node_red",
        domain="automation",
        display_name="Node-RED",
        role_nl="Visuele automatiseringen; alle muterende acties via Hub-actieverzoeken (policy + audit).",
        owner_nl="Node-RED is eigenaar van flows; deze dienst bewaart versies/metadata en run-historie.",
        install_doc="I10",
        install_method="custom_app",
        upstream="https://github.com/node-red/node-red",
        required_decisions=("D03",),
        api_verification="te_verifieren",
        capabilities=(
            cap("automation.flows.read", "Flowoverzicht en versies", "read", ("B11-005",)),
            cap("automation.event_types.read", "Eventtypen-catalogus met schema-versie", "read", ("B11-002",)),
            cap(
                "automation.action.propose",
                "Actieverzoek van een flow naar de Hub (policy bepaalt risico)",
                "propose",
                ("B11-003",),
                "R1",
            ),
            cap("automation.flows.rollback", "Oude flowversie terugzetten", "rollback", ("B11-005",), "R2"),
        ),
        notes_nl="Editor alleen achter SSO/eigen auth op LAN; geen Docker-socket; geen onbeheerde contrib-pakketten.",
        forbidden_nl=(
            "Geen exec-node of andere shell-uitvoering in flows (B11-001).",
            "Geen dataset-delete of andere R3-actie vanuit een flow zonder admin-goedkeuring (B11-003, EX45).",
            "Boiler schakelen is via elke route verboden (EX27).",
        ),
    ),
)
