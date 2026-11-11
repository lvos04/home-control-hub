"""Inventaris B11.

Het gedrag van de admin-API van Node-RED is gecontroleerd tegen een **lokale container van de gepinde image** (zie
``docs/b11/node-red-verificatie.json`` en ``tools/node_red_verify.py``). Een Node-RED op de echte NAS is daarmee niet
getest: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

from .. import SourceSpec, cap

# De gepinde Node-RED voor de standaard TrueNAS Custom App (formulier). De digest is die van de multi-arch-index.
NODE_RED_IMAGE = "docker.io/nodered/node-red"
NODE_RED_TAG = "5.0.9"
NODE_RED_DIGEST = "sha256:2ccd38b4066648bd5e17430c50a2f8102c566a82fd4f2fc5c342e61664d6896f"
NODE_RED_PORT = 1880
NODE_RED_UID = 1000  # gebruiker node-red in de officiële image (gemeten)

# Node-typen die nooit in een flow mogen (B11-001: "custom exec-node is geblokkeerd"). In de gepinde image zit de
# exec-node in het kernbestand 90-exec.js; met ``nodesExcludes`` wordt dat bestand niet geladen (gemeten).
FORBIDDEN_NODE_TYPES: tuple[str, ...] = ("exec",)
FORBIDDEN_NODE_FILES: tuple[str, ...] = ("90-exec.js",)
FORBIDDEN_NODE_TYPES_VERIFICATION = "geverifieerd_installatie"

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
        api_verification="geverifieerd_installatie",
        api_verification_ref=(
            "admin-API van de gepinde image in een lokale container (docs/b11/node-red-verificatie.json); "
            "echte NAS: NIET GEVALIDEERD"
        ),
        capabilities=(
            cap(
                "automation.isolation.check",
                "Isolatie van Node-RED meten (aanmelding, exec-node, modules, credentials)",
                "read",
                ("B11-001",),
                build_status="gebouwd",
                notes_nl="Wat alleen op de NAS te zien is (root, Docker-socket, netwerk) is 'niet_meetbaar'.",
            ),
            cap(
                "automation.flows.read",
                "Flowoverzicht, eigenaar, beleid en versies",
                "read",
                ("B11-001", "B11-005"),
                build_status="gebouwd",
            ),
            cap(
                "automation.event_types.read",
                "Eventtypen-catalogus met schema-versie",
                "read",
                ("B11-002",),
                build_status="gebouwd",
            ),
            cap(
                "automation.events.deliver",
                "Events per bron in volgorde afleveren aan flows (wachtrij met herhaling)",
                "stream",
                ("B11-002",),
                build_status="gebouwd",
                notes_nl="Het contract kent nog geen pad waarlangs de Hub events van andere apps doorstuurt.",
            ),
            cap(
                "automation.action.propose",
                "Actieverzoek van een flow naar de Hub (policy bepaalt risico)",
                "propose",
                ("B11-003",),
                "R1",
                build_status="gebouwd",
                notes_nl="Alleen het verzoek (flow.action.requested); deze dienst voert zelf nooit iets uit.",
            ),
            cap(
                "automation.simulation.run",
                "Proefrun van een flow met vaste voorbeeld-events",
                "read",
                ("B11-004",),
                build_status="gebouwd",
            ),
            cap(
                "automation.flows.snapshot",
                "Versleutelde momentopnamen en versies van flows",
                "read",
                ("B11-005",),
                build_status="gebouwd",
            ),
            cap(
                "automation.flows.restore.propose",
                "Herstelvoorstel voor een oude momentopname (diff, hash, precondities)",
                "propose",
                ("B11-005",),
                "R2",
                build_status="gebouwd",
            ),
            cap(
                "automation.flows.rollback",
                "Oude momentopname terugzetten met een ondertekend ExecutionRequest van de Hub",
                "rollback",
                ("B11-005",),
                "R2",
                build_status="gebouwd",
                notes_nl="De Hub geeft voor deze actie nog geen ExecutionRequest uit; zonder geldig verzoek gebeurt "
                "er niets.",
            ),
        ),
        notes_nl="Editor alleen achter eigen aanmelding op het LAN; geen Docker-socket; geen onbeheerde modules.",
        forbidden_nl=(
            "Geen exec-node of andere shell-uitvoering in flows (B11-001).",
            "Geen dataset-delete of andere R3-actie vanuit een flow zonder admin-goedkeuring (B11-003, EX45).",
            "Boiler schakelen is via elke route verboden (EX27).",
        ),
    ),
)
