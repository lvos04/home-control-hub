"""B11-001 — beleid voor flows, isolatiecontrole en het beveiligingsprofiel van Node-RED.

Drie onderdelen, alle drie fail-closed:

1. **Flowscan** (:func:`scan`): elke node in de configuratie van Node-RED wordt gecontroleerd tegen de verboden typen
   (``exec``: shell-uitvoering), de toegestane modules (standaard alleen de kern ``node-red``) en de geïnstalleerde
   typen. Een bevinding blokkeert de flow (tabblad): geen afleveringen, geen actieverzoeken, geen token. Bevindingen in
   een subflow of een configuratienode gelden voor elke flow die hem gebruikt. Let op: Node-RED 5 **accepteert** een
   flow met een uitgesloten ``exec``-node gewoon (de node draait dan niet); daarom is deze eigen scan nodig.
2. **Isolatiecontrole** (:func:`check_isolation`): meet via de admin-API of de editor een aanmelding vraagt, of een
   anonieme lezer 401 krijgt, of de ``exec``-node ontbreekt, of het installeren van modules uit staat, of credentials
   met een eigen ``credentialSecret`` versleuteld zijn en of het dienstaccount alleen zijn minimale rechten heeft.
   Wat alleen op de NAS zelf te zien is (niet als root, geen Docker-socket, privé-netwerk) is ``niet_meetbaar`` en
   wordt **nooit** als in orde gemeld; dat staat in de checklist van ``deploy/truenas/NODE_RED_CUSTOM_APP.md``.
3. **Beveiligingsprofiel** (:func:`build_profile`): de formuliervelden voor de standaard TrueNAS Custom App van
   Node-RED (image + digest, poort, opslag, gebruiker, argumenten). De image neemt instellingen alleen aan als
   argument ``--define=<sleutel>=<JSON>`` (gecontroleerd tegen de gepinde image; een omgevingsvariabele voor de
   ``credentialSecret`` bestaat niet). Wachtwoorden staan er alleen als bcrypt-hash in.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

import bcrypt
from sqlalchemy.orm import Session

from ...security.vault import Vault
from ...timeutil import iso, utcnow
from .catalog import (
    FORBIDDEN_NODE_FILES,
    FORBIDDEN_NODE_TYPES,
    NODE_RED_DIGEST,
    NODE_RED_IMAGE,
    NODE_RED_PORT,
    NODE_RED_TAG,
    NODE_RED_UID,
)
from .nodered import NodeRedClient, NodeRedError

#: typen die bij de opbouw van Node-RED zelf horen en geen node van een module zijn
STRUCTURAL_TYPES = frozenset({"tab", "subflow", "group", "junction", "comment", "global-config", "unknown"})
#: kernnodes die iets buiten Node-RED kunnen bereiken of code bevatten: toegestaan, maar zichtbaar als waarschuwing
RISKY_TYPES = frozenset(
    {
        "function",
        "http request",
        "tcp out",
        "tcp request",
        "udp out",
        "mqtt out",
        "websocket out",
        "file",
        "http in",
        "tcp in",
        "udp in",
        "websocket in",
    }
)
#: nodes die een flow gebruikt om zelf iets naar buiten te sturen; een simulatie kan die niet afschermen (B11-004)
OUTBOUND_TYPES = frozenset(
    {"http request", "tcp out", "tcp request", "udp out", "mqtt out", "websocket out", "file", "function"}
)
SERVICE_USER = "hub-dienst"
ADMIN_USER = "beheerder"
#: precies wat deze dienst nodig heeft: flows lezen en (alleen bij herstel) zetten, nodes/instellingen/diagnose lezen
SERVICE_PERMISSIONS = ("flows.read", "flows.write", "nodes.read", "settings.read", "diagnostics.read")
PROFILE_REF = "vault://automation/node-red-profiel"
BCRYPT_ROUNDS = 10
MAX_FINDINGS = 50


def canonical(value: Any) -> bytes:
    """Stabiele JSON voor checksums van flows (kommagetallen mogen: Node-RED gebruikt ze voor posities)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def flows_checksum(flows: list[dict[str, Any]]) -> str:
    return sha256_hex(canonical(flows))


# ---------------------------------------------------------------------------------------------------------- flowscan
def type_modules(node_sets: list[dict[str, Any]]) -> dict[str, str]:
    """``type → module`` voor alle **ingeschakelde** node-sets uit ``GET /nodes``."""
    out: dict[str, str] = {}
    for entry in node_sets:
        if entry.get("enabled") is False:
            continue
        for node_type in entry.get("types") or []:
            out.setdefault(str(node_type), str(entry.get("module")))
    return out


@dataclass
class TabScan:
    tab_id: str
    label: str
    disabled: bool
    node_count: int
    node_types: list[str]
    checksum: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.findings)

    @property
    def blocked_reason(self) -> str | None:
        return str(self.findings[0]["code"]) if self.findings else None


@dataclass
class ScanResult:
    tabs: list[TabScan]
    global_findings: list[dict[str, Any]]
    node_count: int

    def summary(self) -> dict[str, Any]:
        return {
            "flows": len(self.tabs),
            "geblokkeerd": sum(1 for t in self.tabs if t.blocked),
            "bevindingen": sum(len(t.findings) for t in self.tabs),
            "waarschuwingen": sum(len(t.warnings) for t in self.tabs),
            "ongebruikte_bevindingen": self.global_findings[:MAX_FINDINGS],
        }


def _finding(code: str, node: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"code": code, "node_id": str(node.get("id"))[:64], "node_type": str(node.get("type"))[:80], **extra}


def _node_findings(node: dict[str, Any], modules: dict[str, str], allowed: tuple[str, ...]) -> list[dict[str, Any]]:
    node_type = str(node.get("type"))
    if node_type in STRUCTURAL_TYPES or node_type.startswith("subflow:"):
        return []
    if node_type in FORBIDDEN_NODE_TYPES:
        return [_finding("verboden_node", node)]
    module = modules.get(node_type)
    if module is None:
        return [_finding("onbekend_type", node)]
    if module not in allowed:
        return [_finding("module_niet_toegestaan", node, module=module[:80])]
    return []


def _references(node: dict[str, Any]) -> set[str]:
    """Alle tekstwaarden op het eerste niveau van een node (verwijzingen naar configuratienodes zijn zulke waarden)."""
    return {v for k, v in node.items() if isinstance(v, str) and k not in ("id", "type", "z", "name", "info")}


def scan(flows: list[dict[str, Any]], modules: dict[str, str], allowed_modules: tuple[str, ...]) -> ScanResult:
    """Controleert de volledige configuratie; geeft per tabblad bevindingen (blokkerend) en waarschuwingen."""
    tabs = [n for n in flows if n.get("type") == "tab"]
    subflows = {str(n["id"]) for n in flows if n.get("type") == "subflow"}
    containers = {str(t["id"]) for t in tabs} | subflows
    members: dict[str, list[dict[str, Any]]] = {c: [] for c in containers}
    config_nodes: dict[str, dict[str, Any]] = {}
    for node in flows:
        if node.get("type") in ("tab", "subflow"):
            continue
        z = node.get("z")
        if isinstance(z, str) and z in members:
            members[z].append(node)
        else:
            config_nodes[str(node["id"])] = node  # configuratienode (geen of onbekende z): geldt voor wie hem gebruikt
    own: dict[str, list[dict[str, Any]]] = {
        c: [f for node in nodes for f in _node_findings(node, modules, allowed_modules)] for c, nodes in members.items()
    }
    config_findings = {cid: _node_findings(node, modules, allowed_modules) for cid, node in config_nodes.items()}
    uses_subflow: dict[str, set[str]] = {
        c: {
            str(node["type"]).split(":", 1)[1]
            for node in nodes
            if str(node.get("type")).startswith("subflow:") and str(node["type"]).split(":", 1)[1] in subflows
        }
        for c, nodes in members.items()
    }
    uses_config: dict[str, set[str]] = {
        c: {ref for node in nodes for ref in _references(node) if ref in config_nodes} for c, nodes in members.items()
    }

    def closure(container: str) -> set[str]:
        seen: set[str] = set()
        todo = [container]
        while todo:
            current = todo.pop()
            if current in seen:
                continue
            seen.add(current)
            todo.extend(uses_subflow.get(current, ()))
        return seen

    used_config: set[str] = set()
    result: list[TabScan] = []
    for tab in sorted(tabs, key=lambda t: str(t["id"])):
        tab_id = str(tab["id"])
        reach = closure(tab_id)
        findings: list[dict[str, Any]] = []
        nodes: list[dict[str, Any]] = []
        configs: set[str] = set()
        for container in sorted(reach):
            via = None if container == tab_id else container
            findings.extend({**f, "via_subflow": via} if via else f for f in own[container])
            nodes.extend(members[container])
            configs |= uses_config[container]
        for cid in sorted(configs):
            findings.extend({**f, "via_config": True} for f in config_findings[cid])
        used_config |= configs
        unknown_subflows = sorted(
            {
                str(node["type"])
                for container in reach
                for node in members[container]
                if str(node.get("type")).startswith("subflow:") and str(node["type"]).split(":", 1)[1] not in subflows
            }
        )
        findings.extend({"code": "onbekend_type", "node_id": "", "node_type": t[:80]} for t in unknown_subflows)
        own_nodes = members[tab_id]
        warnings = [_finding("risicovolle_node", n) for n in nodes if str(n.get("type")) in RISKY_TYPES]
        closure_doc = {
            "tab": tab,
            "nodes": sorted(own_nodes, key=lambda n: str(n["id"])),
            "subflows": [
                [n for n in flows if n.get("type") == "subflow" and str(n["id"]) == s]
                + sorted(members[s], key=lambda n: str(n["id"]))
                for s in sorted(reach - {tab_id})
            ],
            "config": [config_nodes[c] for c in sorted(configs)],
        }
        result.append(
            TabScan(
                tab_id=tab_id,
                label=str(tab.get("label") or tab_id)[:200],
                disabled=bool(tab.get("disabled")),
                node_count=len(own_nodes),
                node_types=sorted({str(n.get("type")) for n in nodes}),
                checksum=sha256_hex(canonical(closure_doc)),
                findings=findings[:MAX_FINDINGS],
                warnings=warnings[:MAX_FINDINGS],
            )
        )
    unused = [f for cid, fs in sorted(config_findings.items()) if cid not in used_config for f in fs]
    return ScanResult(tabs=result, global_findings=unused, node_count=len(flows))


# ---------------------------------------------------------------------------------------------------- isolatiecontrole
CHECK_TITLES_NL = {
    "editor_aanmelding": "De editor en de admin-API vragen een aanmelding",
    "anoniem_geweigerd": "Een lezer zonder aanmelding krijgt geen flows, nodes of instellingen",
    "beheer_aanmelding_gezet": "Node-RED meldt zelf dat adminAuth is ingesteld",
    "exec_node_afwezig": "De exec-node (shell-uitvoering) is niet geladen",
    "modules_toegestaan": "Alleen nodes uit toegestane modules zijn geladen",
    "palette_installatie_uit": "Modules installeren, bijwerken of uploaden via de editor staat uit",
    "function_modules_uit": "Function-nodes kunnen geen externe modules laden",
    "credentials_versleuteld": "Credentials zijn versleuteld met een eigen credentialSecret",
    "dienstaccount_minimaal": "Het dienstaccount heeft alleen zijn minimale rechten",
    "niet_root": "De container draait niet als root",
    "geen_docker_socket": "Er is geen Docker-socket gekoppeld",
    "prive_netwerk": "Node-RED is alleen op het LAN bereikbaar",
}
#: niet via de admin-API te meten; alleen op de NAS zelf te zien (checklist in deploy/truenas/NODE_RED_CUSTOM_APP.md)
NOT_MEASURABLE = ("niet_root", "geen_docker_socket", "prive_netwerk")
MEASURED = tuple(c for c in CHECK_TITLES_NL if c not in NOT_MEASURABLE)
ANONYMOUS_PATHS = ("/flows", "/nodes", "/settings")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _row(check_id: str, status: str, detail: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": check_id, "title_nl": CHECK_TITLES_NL[check_id], "status": status, "detail": detail or {}}


def _palette_closed(settings: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    ext = _as_dict(settings.get("externalModules"))
    palette = _as_dict(ext.get("palette"))
    modules = _as_dict(ext.get("modules"))
    seen = {
        "autoInstall": ext.get("autoInstall"),
        "palette.allowInstall": palette.get("allowInstall"),
        "palette.allowUpdate": palette.get("allowUpdate"),
        "palette.allowUpload": palette.get("allowUpload"),
        "modules.allowInstall": modules.get("allowInstall"),
    }
    return all(v is False for v in seen.values()), {"gemeten": seen}


def check_isolation(client: NodeRedClient, allowed_modules: tuple[str, ...]) -> dict[str, Any]:
    """Meet de isolatie van Node-RED. Elke niet-gemeten controle is ``onbekend``; nooit stilzwijgend in orde."""
    rows: dict[str, dict[str, Any]] = {}
    version: str | None = None
    error: dict[str, Any] | None = None

    def unknown_rest(reason: str) -> None:
        for check_id in MEASURED:
            rows.setdefault(check_id, _row(check_id, "onbekend", {"reden": reason}))

    try:
        scheme = client.login_scheme()
        secured = scheme.get("type") == "credentials"
        rows["editor_aanmelding"] = _row(
            "editor_aanmelding", "ok" if secured else "afwijking", {"type": str(scheme.get("type") or "geen")[:40]}
        )
        statuses = {path: client.anonymous_status(path) for path in ANONYMOUS_PATHS}
        rows["anoniem_geweigerd"] = _row(
            "anoniem_geweigerd", "ok" if all(s == 401 for s in statuses.values()) else "afwijking", {"http": statuses}
        )
        if not secured:
            # zonder aanmelding leest deze dienst bewust niets uit: de rest is dan niet gemeten
            unknown_rest("niet_beveiligd")
        else:
            settings = client.get_settings()
            version = str(settings.get("version"))[:40] if settings.get("version") else None
            node_sets = client.get_nodes()
            modules = type_modules(node_sets)
            loaded_forbidden = sorted(t for t in FORBIDDEN_NODE_TYPES if t in modules)
            rows["exec_node_afwezig"] = _row(
                "exec_node_afwezig", "afwijking" if loaded_forbidden else "ok", {"geladen": loaded_forbidden}
            )
            foreign = sorted({m for m in modules.values() if m not in allowed_modules})
            rows["modules_toegestaan"] = _row(
                "modules_toegestaan",
                "afwijking" if foreign else "ok",
                {"niet_toegestaan": foreign[:20], "toegestaan": list(allowed_modules)},
            )
            closed, detail = _palette_closed(settings)
            rows["palette_installatie_uit"] = _row("palette_installatie_uit", "ok" if closed else "afwijking", detail)
            fn_ext = settings.get("functionExternalModules")
            rows["function_modules_uit"] = _row(
                "function_modules_uit", "ok" if fn_ext is False else "afwijking", {"functionExternalModules": fn_ext}
            )
            enc = settings.get("flowEncryptionType")
            rows["credentials_versleuteld"] = _row(
                "credentials_versleuteld", "ok" if enc == "user" else "afwijking", {"flowEncryptionType": enc}
            )
            user = _as_dict(settings.get("user"))
            perms = user.get("permissions")
            minimal = isinstance(perms, list) and set(perms) <= set(SERVICE_PERMISSIONS)
            rows["dienstaccount_minimaal"] = _row(
                "dienstaccount_minimaal",
                "ok" if minimal else "afwijking",
                {"rechten": perms if isinstance(perms, list) else str(perms)[:20], "verwacht": SERVICE_PERMISSIONS},
            )
            try:
                diag = client.get_diagnostics()
            except NodeRedError as exc:
                rows["beheer_aanmelding_gezet"] = _row("beheer_aanmelding_gezet", "onbekend", {"reden": exc.reason})
            else:
                runtime = _as_dict(diag.get("runtime"))
                rt_settings = _as_dict(runtime.get("settings"))
                admin_auth = rt_settings.get("adminAuth")
                rows["beheer_aanmelding_gezet"] = _row(
                    "beheer_aanmelding_gezet", "ok" if admin_auth == "SET" else "afwijking", {"adminAuth": admin_auth}
                )
    except NodeRedError as exc:
        error = exc.to_dict()
        unknown_rest(exc.reason)
    for check_id in NOT_MEASURABLE:
        rows[check_id] = _row(
            check_id,
            "niet_meetbaar",
            {"reden": "alleen op de NAS te controleren (formulier van de Custom App); zie de checklist"},
        )
    ordered = [rows[c] for c in CHECK_TITLES_NL]
    measured = [r for r in ordered if r["id"] in MEASURED]
    if any(r["status"] == "afwijking" for r in measured):
        status = "afwijking"
    elif any(r["status"] != "ok" for r in measured):
        status = "onbekend"
    else:
        status = "gemeten_in_orde"
    return {
        "status": status,
        "measured_at": iso(utcnow()),
        "node_red_version": version,
        "checks": ordered,
        "afwijkingen": [r["id"] for r in ordered if r["status"] == "afwijking"],
        "niet_meetbaar": list(NOT_MEASURABLE),
        "fout": error,
        "validatie": "Gemeten via de admin-API; een Node-RED op de echte NAS is NIET GEVALIDEERD (echte NAS).",
    }


# ------------------------------------------------------------------------------------------------ beveiligingsprofiel
def hash_password(password: str) -> str:
    """bcrypt-hash zoals Node-RED (bcryptjs) hem voor ``adminAuth`` verwacht."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def define_arguments(service_hash: str, admin_hash: str, credential_secret: str) -> list[str]:
    """De argumenten voor de container van Node-RED: één instelling per argument, zonder shell."""
    admin_auth = {
        "type": "credentials",
        "sessionExpiryTime": 3600,
        "users": [
            {"username": SERVICE_USER, "password": service_hash, "permissions": list(SERVICE_PERMISSIONS)},
            {"username": ADMIN_USER, "password": admin_hash, "permissions": "*"},
        ],
    }
    external = {
        "autoInstall": False,
        "palette": {"allowInstall": False, "allowUpdate": False, "allowUpload": False},
        "modules": {"allowInstall": False},
    }

    def define(key: str, value: Any) -> str:
        text = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"))
        return f"--define={key}={text}"

    return [
        define("adminAuth", admin_auth),
        define("nodesExcludes", list(FORBIDDEN_NODE_FILES)),
        define("functionExternalModules", False),
        define("externalModules", external),
        define("credentialSecret", credential_secret),
        "--no-telemetry",
    ]


@dataclass
class Profile:
    created: bool
    admin_password_rotated: bool
    arguments: list[str]
    admin_password: str | None  # alleen direct na het (opnieuw) maken; daarna bestaat alleen de hash
    stored: dict[str, Any]

    def form(self) -> dict[str, Any]:
        """Formuliervelden zonder geheimen (de argumenten met de hashes en de credentialSecret komen er apart bij)."""
        return {
            "installatie": "TrueNAS → Apps → Discover Apps → Custom App (formulier; geen YAML)",
            "image": {"repository": NODE_RED_IMAGE, "tag": NODE_RED_TAG, "digest": NODE_RED_DIGEST},
            "poort": {"container": NODE_RED_PORT, "protocol": "tcp", "host": "keuze uit de onboarding (alleen LAN)"},
            "opslag": {"mount_path": "/data", "soort": "eigen dataset voor Node-RED (keuze uit de onboarding)"},
            "gebruiker": {"uid": NODE_RED_UID, "gid": NODE_RED_UID, "root": False},
            "nooit": [
                "geen Docker-socket koppelen",
                "geen privileged-modus of extra capabilities",
                "geen host-netwerk",
                "poort niet buiten het LAN openzetten",
            ],
            "accounts": {
                "dienst": {"gebruiker": SERVICE_USER, "rechten": list(SERVICE_PERMISSIONS)},
                "beheer": {"gebruiker": ADMIN_USER, "rechten": "*"},
            },
            "gemaakt_op": self.stored.get("gemaakt_op"),
            "beheerwachtwoord_gewijzigd_op": self.stored.get("beheer_gewijzigd_op"),
            "validatie": "De argumenten zijn gecontroleerd tegen de gepinde image in een lokale container; "
            "de installatie op de echte NAS is NIET GEVALIDEERD (echte NAS).",
        }


def _store(vault: Vault, session: Session, data: dict[str, Any]) -> None:
    # de laatste sleutel is bewust geen geheim: de vault bewaart de laatste 4 tekens als herkenning
    vault.put(session, PROFILE_REF, json.dumps({**data, "v": 1}, separators=(",", ":")))


def load_profile(vault: Vault, session: Session) -> dict[str, Any] | None:
    raw = vault.get(session, PROFILE_REF)
    if not raw:
        return None
    data = json.loads(raw)
    return data if isinstance(data, dict) else None


def build_profile(vault: Vault, session: Session, *, new_admin_password: bool = False) -> tuple[Profile, str | None]:
    """Maakt het profiel (één keer) of geeft het bestaande terug. Geeft ook het wachtwoord van het dienstaccount terug
    als dat net gemaakt is, zodat de aanroeper het als credential van de bron kan opslaan (het wordt nooit getoond).

    De ``credentialSecret`` wordt hier nooit vervangen: Node-RED kan bestaande credentials dan niet meer lezen."""
    stored = load_profile(vault, session)
    created = stored is None
    service_password: str | None = None
    admin_password: str | None = None
    now = iso(utcnow())
    if stored is None:
        service_password = secrets.token_urlsafe(32)
        admin_password = secrets.token_urlsafe(18)
        stored = {
            "dienst_hash": hash_password(service_password),
            "beheer_hash": hash_password(admin_password),
            "credential_secret": secrets.token_urlsafe(48),
            "gemaakt_op": now,
            "beheer_gewijzigd_op": now,
        }
        _store(vault, session, stored)
    elif new_admin_password:
        admin_password = secrets.token_urlsafe(18)
        stored = {**stored, "beheer_hash": hash_password(admin_password), "beheer_gewijzigd_op": now}
        stored.pop("v", None)
        _store(vault, session, stored)
    arguments = define_arguments(
        str(stored["dienst_hash"]), str(stored["beheer_hash"]), str(stored["credential_secret"])
    )
    profile = Profile(
        created=created,
        admin_password_rotated=bool(new_admin_password and not created),
        arguments=arguments,
        admin_password=admin_password,
        stored={k: v for k, v in stored.items() if k in ("gemaakt_op", "beheer_gewijzigd_op")},
    )
    return profile, service_password
