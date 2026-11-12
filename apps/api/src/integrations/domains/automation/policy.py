"""B11-001 — beleid voor flows, isolatiecontrole en het beveiligingsprofiel van Node-RED.

Drie onderdelen, alle drie fail-closed:

1. **Flowscan** (:func:`scan`): elke node in de configuratie van Node-RED wordt gecontroleerd tegen de verboden typen
   (``exec``: shell-uitvoering), de toegestane modules (standaard alleen de kern ``node-red``) en de geïnstalleerde
   typen, en de scan controleert of hij elke node kan plaatsen (vorm, ook lengte van id en ``z`` en tekens die niet op
   te slaan zijn, dubbele id, tabblad, draden en links). **Grof blokkeren** (besluit van de gebruiker, 2026-11-11):
   staat er ergens in de configuratie iets verbodens of iets wat de dienst niet kan plaatsen, dan zijn **alle** flows
   (tabbladen) van de bron geblokkeerd tot het weg is: geen afleveringen, geen actieverzoeken, geen token. De precieze
   uitkomst per tabblad blijft voor de melding: het tabblad met de oorzaak (of dat er via een subflow,
   configuratienode, draad, link of eigenschap mee verbonden is) krijgt die bevinding zelf, elk ander tabblad
   ``bron_geblokkeerd`` met de oorzaak en de plaats ervan. De scan bootst Node-RED niet na om een uitzondering te
   maken. Let op: Node-RED 5 **accepteert** een flow met een uitgesloten
   ``exec``-node gewoon (de node draait dan niet); daarom is deze eigen scan nodig. Wat tabbladen tijdens het draaien
   delen zonder dat het in de configuratie staat (global context, een ``http in`` die ``http request`` naar Node-RED
   zelf doet, mqtt via een broker) kan geen scan zien; zie ADR-0016 kop 2.
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
from collections.abc import Callable, Collection
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
    NODE_RED_INSTALL_UID,
    NODE_RED_PORT,
    NODE_RED_TAG,
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
#: kernnodes die berichten naar een ander tabblad sturen (veld ``links``: de id's van de link-nodes aan de andere kant)
LINK_TYPES = frozenset({"link out", "link in", "link call"})
SERVICE_USER = "hub-dienst"
ADMIN_USER = "beheerder"
#: precies wat deze dienst nodig heeft: flows lezen en (alleen bij herstel) zetten, nodes/instellingen/diagnose lezen
SERVICE_PERMISSIONS = ("flows.read", "flows.write", "nodes.read", "settings.read", "diagnostics.read")
PROFILE_REF = "vault://automation/node-red-profiel"
BCRYPT_ROUNDS = 10
MAX_FINDINGS = 50
#: langste ``id`` en ``z`` die de dienst kan plaatsen (``automation_flow.source_flow_id`` is String(120)); langer is
#: ``vorm_ongeldig`` (R-VEILIG-8: de echte Node-RED neemt een langere id aan)
MAX_ID_LENGTH = 120
#: reden van een tabblad zonder eigen bevinding dat meegeblokkeerd is omdat elders in de configuratie iets staat
SOURCE_BLOCKED = "bron_geblokkeerd"
#: plaats van een oorzaak buiten elk tabblad en elke subflow (een configuratienode of een niet te plaatsen element)
CONFIG_PLACE = "configuratie"
#: elke reden waarmee de scan een flow blokkeert; is de oorzaak weg, dan wordt zo'n flow gepauzeerd (snapshots)
BLOCK_REASONS = (
    "verboden_node",
    "module_niet_toegestaan",
    "onbekend_type",
    "verwijzing_onbekend",
    "niet_plaatsbaar",
    "tabblad_onbekend",
    "vorm_ongeldig",
    "dubbele_id",
    SOURCE_BLOCKED,
)


def canonical(value: Any) -> bytes:
    """Stabiele JSON voor checksums van flows (kommagetallen mogen: Node-RED gebruikt ze voor posities).

    Een losse surrogaat (Node-RED neemt hem aan en geeft hem terug als ``\\ud800``) kent UTF-8 niet; met
    ``surrogatepass`` wordt hij toch gecodeerd in plaats van dat de synchronisatie crasht (de flowscan maakt er
    ``vorm_ongeldig`` van). ``json.loads`` leest die bytes weer terug. Voor geldige tekst zijn de bytes gelijk aan
    gewone UTF-8, zodat bestaande checksums en momentopnamen blijven kloppen."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def flows_checksum(flows: list[Any]) -> str:
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


def _plain(value: Any, limit: int) -> str:
    """Tekst voor een bevinding: ingekort, met een NUL of een losse surrogaat als U+FFFD. Zo is een bevinding over een
    node met zo'n tekst (``vorm_ongeldig``) zelf altijd op te slaan; PostgreSQL weigert beide tekens."""
    text = str(value)[:limit]
    return "".join("\ufffd" if ch == "\x00" or "\ud800" <= ch <= "\udfff" else ch for ch in text)


def _finding(code: str, node: Any, **extra: Any) -> dict[str, Any]:
    if not isinstance(node, dict):
        return {"code": code, "node_id": "", "node_type": "", **extra}
    return {"code": code, "node_id": _plain(node.get("id"), 64), "node_type": _plain(node.get("type"), 80), **extra}


def _node_findings(
    node: dict[str, Any], modules: dict[str, str], allowed: tuple[str, ...], subflows: Collection[str]
) -> list[dict[str, Any]]:
    node_type = str(node.get("type"))
    if node_type.startswith("subflow:"):
        return [] if node_type.split(":", 1)[1] in subflows else [_finding("onbekend_type", node)]
    if node_type in STRUCTURAL_TYPES:
        return []
    if node_type in FORBIDDEN_NODE_TYPES:
        return [_finding("verboden_node", node)]
    module = modules.get(node_type)
    if module is None:
        return [_finding("onbekend_type", node)]
    if module not in allowed:
        return [_finding("module_niet_toegestaan", node, module=_plain(module, 80))]
    return []


def _storable(text: str) -> bool:
    """Geen NUL en geen losse surrogaat: PostgreSQL slaat een NUL niet op en UTF-8 kent geen losse surrogaat."""
    if "\x00" in text:
        return False
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _has_unstorable_text(element: Any) -> bool:
    """Ergens in het element (sleutels en tekstwaarden, op elke diepte) een tekst die niet op te slaan is. Zonder
    recursie, zodat ook een diep geneste waarde geen RecursionError geeft."""
    todo = [element]
    while todo:
        value = todo.pop()
        if isinstance(value, str):
            if not _storable(value):
                return True
        elif isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str) and not _storable(key):
                    return True
                todo.append(item)
        elif isinstance(value, list):
            todo.extend(value)
    return False


def _shape_problems(node: Any) -> list[str]:
    """De velden die niet de vorm hebben die deze dienst kan plaatsen (leeg: in orde): een object met ``id`` en
    ``type`` als niet-lege tekst, ``id`` en ``z`` hooguit :data:`MAX_ID_LENGTH` tekens (``z`` tekst of afwezig),
    ``wires`` een lijst van lijsten met teksten, ``links`` een lijst met teksten, en nergens in het element (ook niet
    in een label, een sleutel of diep in een eigenschap) een NUL of een losse surrogaat (``tekst``). Wat Node-RED met
    een andere vorm doet, wordt niet nagebootst; de echte Node-RED 5.0.9 neemt een lange id, een NUL en een losse
    surrogaat aan (R-VEILIG-8)."""
    if not isinstance(node, dict):
        return ["node"]
    bad = [key for key in ("id", "type") if not (isinstance(node.get(key), str) and node.get(key))]
    if "id" not in bad and len(node["id"]) > MAX_ID_LENGTH:
        bad.append("id")
    z = node.get("z")
    if z is not None and not (isinstance(z, str) and len(z) <= MAX_ID_LENGTH):
        bad.append("z")
    wires = node.get("wires", [])
    if not (isinstance(wires, list) and all(isinstance(p, list) and all(isinstance(t, str) for t in p) for p in wires)):
        bad.append("wires")
    links = node.get("links", [])
    if not (isinstance(links, list) and all(isinstance(t, str) for t in links)):
        bad.append("links")
    if _has_unstorable_text(node):
        bad.append("tekst")
    return bad


def _references(node: dict[str, Any]) -> set[str]:
    """Alle tekstwaarden op het eerste niveau van een node (verwijzingen naar configuratienodes zijn zulke waarden)."""
    return {v for k, v in node.items() if isinstance(v, str) and k not in ("id", "type", "z", "name", "info")}


def _targets(node: dict[str, Any]) -> set[str]:
    """Elke id waar een node (met een geldige vorm) een bericht naartoe stuurt: ``wires`` (alle uitgangen, ook van een
    junction) en bij een link-node ``links``. Node-RED zoekt zo'n id over **alle** flows heen (``Flow.getNode`` vraagt
    een onbekende id aan de bovenliggende flow); een draad is dus net zo goed een verbinding tussen tabbladen."""
    out = {t for port in node.get("wires") or [] for t in port}
    if node.get("type") in LINK_TYPES:
        out |= set(node.get("links") or [])
    return out


def scan(flows: list[Any], modules: dict[str, str], allowed_modules: tuple[str, ...]) -> ScanResult:
    """Controleert de volledige configuratie; geeft per tabblad bevindingen (blokkerend) en waarschuwingen.

    **Grof blokkeren** (besluit van de gebruiker, 2026-11-11): staat er **ergens** in de configuratie iets verbodens
    (een verboden node, een onbekend type, een module buiten de allowlist; in een tabblad, een subflow of een
    configuratienode, gebruikt of niet) of iets wat de dienst niet kan plaatsen, dan is **elk** tabblad van de bron
    geblokkeerd tot het weg is. Niet te plaatsen is: een element met een andere vorm dan :func:`_shape_problems`
    toestaat, ook een ``id`` of ``z`` langer dan 120 tekens en een NUL of een losse surrogaat in een tekst (ook in een
    label of een sleutel) (``vorm_ongeldig``), een dubbele id (``dubbele_id``), een node met een ``z`` die geen
    tabblad of subflow is (``tabblad_onbekend``), een draad of link naar een id die nergens staat
    (``verwijzing_onbekend``) en een draad of link van of naar iets wat geen node in een tabblad of subflow is, zoals
    een configuratienode zonder ``z`` of een tabblad zelf (``niet_plaatsbaar``). De scan bootst Node-RED niet na om een
    uitzondering te maken. Wat de dienst opslaat (tabblad-id, label, bevindingen) bevat daardoor nooit zo'n tekst. Loopt
    de synchronisatie tóch vast (een uitzondering bij het lezen, in de scan, het flowregister of de opslag), dan
    blokkeert ``snapshots.sync`` in een eigen transactie alle flows met ``synchronisatie_mislukt`` (vorm A, R-VEILIG-8):
    nooit de oude stand.

    De precieze uitkomst blijft voor de melding (welk tabblad de oorzaak is): een tabblad met de oorzaak zelf, of dat
    er via een subflow, een configuratienode, een draad, een link of een eigenschap mee verbonden is, krijgt die
    bevinding (``via_subflow``, ``via_config``, ``via_link``); elk ander tabblad krijgt ``bron_geblokkeerd`` met de
    oorzaak en de plaats ervan (tabblad, subflow of ``configuratie``). Een niet te plaatsen node met de ``z`` van een
    bekend tabblad of subflow telt voor dat tabblad (bevinding en checksum). Bevindingen buiten elk tabblad
    (ongebruikte configuratienode of subflow, niet te plaatsen element zonder bekende ``z``) staan ook in
    ``global_findings``. De uitkomst hangt alleen af van de configuratie zelf (volgorde van het document,
    gesorteerde id's), niet van de volgorde van een set.
    """
    unplaced_nodes: list[tuple[Any, dict[str, Any]]] = []
    placeable: list[dict[str, Any]] = []
    seen: set[str] = set()
    for node in flows:
        problems = _shape_problems(node)
        if problems:
            unplaced_nodes.append((node, _finding("vorm_ongeldig", node, velden=problems)))
        elif node["id"] in seen:
            unplaced_nodes.append((node, _finding("dubbele_id", node)))
        else:
            seen.add(node["id"])
            placeable.append(node)
    real_tabs = [n for n in placeable if n["type"] == "tab"]
    subflow_ids = [str(n["id"]) for n in placeable if n["type"] == "subflow"]
    subflows = set(subflow_ids)
    members: dict[str, list[dict[str, Any]]] = {c: [] for c in [*(str(t["id"]) for t in real_tabs), *subflow_ids]}
    config_nodes: dict[str, dict[str, Any]] = {}
    ghost_tabs: dict[str, dict[str, Any]] = {}
    for node in placeable:
        if node["type"] in ("tab", "subflow"):
            continue
        z = node.get("z") or ""
        if not z:
            config_nodes[node["id"]] = node  # configuratienode zonder z: geldt voor wie hem gebruikt
            continue
        if z not in members:  # node zonder plaatsbaar tabblad: eigen (spook)tabblad voor de melding
            members[z] = []
            ghost_tabs[z] = {"id": z, "type": "tab", "label": z, "disabled": False}
        members[z].append(node)
    tabs = [*real_tabs, *ghost_tabs.values()]
    own: dict[str, list[dict[str, Any]]] = {}
    for c, placed in members.items():
        own[c] = []
        for node in placed:
            own[c].extend(_node_findings(node, modules, allowed_modules, subflows))
            if c in ghost_tabs:
                own[c].append(_finding("tabblad_onbekend", node))
    # niet te plaatsen (vorm of dubbele id): met een bekende z telt de bevinding voor dat tabblad (en zijn checksum)
    # voor de melding, anders buiten elk tabblad; blokkeren doet hij hoe dan ook alles
    unplaced: list[dict[str, Any]] = []
    strays: dict[str, list[Any]] = {}
    for node, shape in unplaced_nodes:
        found = [shape, *(_node_findings(node, modules, allowed_modules, subflows) if isinstance(node, dict) else [])]
        z = node.get("z") if isinstance(node, dict) else None
        if isinstance(z, str) and z in members:
            own[z].extend(found)
            strays.setdefault(z, []).append(node)
        else:
            unplaced.extend(found)
    config_findings = {
        cid: [
            *_node_findings(node, modules, allowed_modules, subflows),
            *(_finding("niet_plaatsbaar", node, ref=ref[:64]) for ref in sorted(_targets(node))),
        ]
        for cid, node in config_nodes.items()
    }
    container_of = {node["id"]: c for c, nodes in members.items() for node in nodes}
    edges: dict[str, set[str]] = {c: set() for c in members}
    link_in = {c for c, nodes in members.items() if any(n["type"] == "link in" for n in nodes)}
    for c, c_nodes in members.items():
        for node in c_nodes:
            others: set[str] = set()
            for ref in sorted(_targets(node)):
                if ref in container_of:
                    others.add(container_of[ref])
                elif ref in config_nodes or ref in members:
                    own[c].append(_finding("niet_plaatsbaar", node, ref=ref[:64]))
                else:
                    own[c].append(_finding("verwijzing_onbekend", node, ref=ref[:64]))
            others |= {container_of[ref] for ref in _references(node) if ref in container_of}
            if node["type"] == "link call" and node.get("linkType") == "dynamic":
                others |= link_in  # kiest pas tijdens het draaien welk ``link in`` hij aanroept: elk telt
            for other in others - {c}:
                edges[c].add(other)
                edges[other].add(c)
    uses_subflow: dict[str, set[str]] = {
        c: {
            str(node["type"]).split(":", 1)[1]
            for node in nodes
            if str(node["type"]).startswith("subflow:") and str(node["type"]).split(":", 1)[1] in subflows
        }
        for c, nodes in members.items()
    }
    uses_config: dict[str, set[str]] = {
        c: {ref for node in nodes for ref in _references(node) | _targets(node) if ref in config_nodes}
        for c, nodes in members.items()
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

    linked = _linked_tabs(sorted(str(t["id"]) for t in tabs), closure, edges)
    used_config: set[str] = set()
    reached: set[str] = set()
    result: list[TabScan] = []
    for tab in sorted(tabs, key=lambda t: str(t["id"])):
        tab_id = str(tab["id"])
        reach = closure(tab_id)
        reached |= reach
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
        own_nodes = members[tab_id]
        warnings = [_finding("risicovolle_node", n) for n in nodes if str(n.get("type")) in RISKY_TYPES]
        closure_doc = {
            "tab": tab,
            "nodes": sorted(own_nodes, key=lambda n: str(n["id"])),
            "subflows": [
                [n for n in placeable if n["type"] == "subflow" and str(n["id"]) == s]
                + sorted(members[s], key=lambda n: str(n["id"]))
                for s in sorted(reach - {tab_id})
            ],
            "config": [config_nodes[c] for c in sorted(configs)],
        }
        if any(c in strays for c in reach):
            closure_doc["niet_te_plaatsen"] = [[c, strays[c]] for c in sorted(reach) if c in strays]
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
    _share_linked_findings(result, linked)
    causes = [(c, f) for c in sorted(members) for f in own[c]]
    causes += [(CONFIG_PLACE, f) for cid in sorted(config_findings) for f in config_findings[cid]]
    causes += [(CONFIG_PLACE, f) for f in unplaced]
    _block_the_whole_source(result, causes)
    unused = [f for cid, fs in sorted(config_findings.items()) if cid not in used_config for f in fs]
    unused += [{**f, "via_subflow": s} for s in subflow_ids if s not in reached for f in own[s]]
    return ScanResult(tabs=result, global_findings=[*unused, *unplaced], node_count=len(flows))


def _linked_tabs(
    tab_ids: list[str], closure: Callable[[str], set[str]], edges: dict[str, set[str]]
) -> dict[str, set[str]]:
    """Per tabblad de andere tabbladen waarmee het verbonden is: via een draad, een link-node of een eigenschap naar
    een node in een ander tabblad (``edges``, per container in beide richtingen), ook via een subflow, en transitief.
    Een verbinding van of naar een subflow geldt voor elk tabblad dat die subflow gebruikt."""
    reach = {t: closure(t) for t in tab_ids}
    tabs_with: dict[str, set[str]] = {}
    for t, containers in reach.items():
        for c in containers:
            tabs_with.setdefault(c, set()).add(t)
    neighbours = {
        t: {u for c in reach[t] for other in edges.get(c, ()) for u in tabs_with.get(other, ())} - {t} for t in tab_ids
    }
    out: dict[str, set[str]] = {}
    for t in tab_ids:
        seen, todo = {t}, [t]
        while todo:
            for u in neighbours[todo.pop()]:
                if u not in seen:
                    seen.add(u)
                    todo.append(u)
        out[t] = seen - {t}
    return out


def _share_linked_findings(result: list[TabScan], linked: dict[str, set[str]]) -> None:
    """Verbonden tabbladen delen hun eigen bevindingen (met ``via_link``). De checksum van een verbonden tabblad hangt
    dan ook af van de tabbladen waarmee het verbonden is, zodat een nieuwe bevinding daar een nieuwe versie geeft."""
    own = {t.tab_id: (list(t.findings), t.checksum) for t in result}
    for t in result:
        others = sorted(linked.get(t.tab_id, ()))
        if not others:
            continue
        shared = [{**f, "via_link": o} for o in others for f in own[o][0]]
        t.findings = [*own[t.tab_id][0], *shared][:MAX_FINDINGS]
        t.checksum = sha256_hex(canonical({"tabblad": own[t.tab_id][1], "verbonden": [[o, own[o][1]] for o in others]}))


def _block_the_whole_source(result: list[TabScan], causes: list[tuple[str, dict[str, Any]]]) -> None:
    """Grof blokkeren: is er ergens een oorzaak, dan krijgt elk tabblad zonder eigen bevinding ``bron_geblokkeerd``
    met per oorzaak de code, de node en de plaats. Zijn checksum volgt die oorzaken (een nieuwe oorzaak of het
    weghalen ervan geeft een nieuwe versie); zonder oorzaak is hij precies die van het tabblad zelf."""
    if not causes:
        return
    for t in result:
        if t.findings:
            continue
        t.findings = [
            {
                "code": SOURCE_BLOCKED,
                "oorzaak": f["code"],
                "plaats": place,
                "node_id": f["node_id"],
                "node_type": f["node_type"],
            }
            for place, f in causes
        ][:MAX_FINDINGS]
        t.checksum = sha256_hex(canonical({"tabblad": t.checksum, "bron": t.findings}))


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
            # de installatiegebruiker van het manifest van jelly-leon-platform (S-P2-310); los van besluit C-12
            "gebruiker": {"uid": NODE_RED_INSTALL_UID, "gid": NODE_RED_INSTALL_UID, "root": False},
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
