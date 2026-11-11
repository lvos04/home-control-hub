"""B11-002 — getypeerde eventcatalogus volgens platformcontract 1.3 §7.

De catalogus verzint niets: hij bevat precies wat het contract vastlegt.

- **Envelope** ``schema_version "1.0"`` met de grenzen van §7 (onbekende velden zijn een fout).
- **Domeinen per eigenaar**: het paar (``source_app``, eerste segment van ``event_type``) bepaalt wie een event mag
  sturen. Een event buiten het eigen domein is alleen algemene informatie en wordt nooit aan een flow afgeleverd.
- **Vaste typen** waarvoor het contract een payload of entiteit voorschrijft (``app.health.changed``, de zes
  ``service.*``-events, ``sso.access.revoked``/``sso.access.changed``) en de in §7 genoemde voorbeeldnamen.

Een event met een **onbekende schema-versie** wordt nooit weggegooid en nooit afgeleverd: het krijgt de status
``onbekende_schema_versie`` en blijft zichtbaar (zie ``inbox.py``). MSO en my_house hebben in het contract (nog) geen
eigen eventdomein; hun events zouden hier ``onbekend_type`` krijgen (gemeld als contractpunt in ADR-0016).
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ... import APP_ID
from ...events import CLASSIFICATIONS, EVENT_TYPE_RE, PROBLEM_VERBS, RECOVERY_VERBS

ENVELOPE_VERSIONS: tuple[str, ...] = ("1.0",)
ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "event_id",
        "source_app",
        "source_event_id",
        "event_type",
        "entity",
        "timestamp_utc",
        "trace_id",
        "correlation_id",
        "actor",
        "classification",
        "payload",
        "payload_ref",
    }
)
ENVELOPE_REQUIRED = (
    "schema_version",
    "event_id",
    "source_app",
    "source_event_id",
    "event_type",
    "entity",
    "timestamp_utc",
    "trace_id",
    "actor",
    "classification",
    "payload",
)
ACTOR_TYPES = ("system", "user", "ai", "flow")
ERNST = ("kritiek", "hoog", "middel", "laag", "info")
MAX_PAYLOAD_BYTES = 16 * 1024
APP_ID_RE = re.compile(r"^[a-z]([-a-z0-9]*[a-z0-9])?$")
ENTITY_TYPE_RE = re.compile(r"^[a-z0-9_.-]{1,64}$")

#: §7 "Domeinen per eigenaar" (eerste segment van ``event_type``)
OWNER_DOMAINS: dict[str, tuple[str, ...]] = {
    "ai-server-manager": (
        "auth",
        "alert",
        "audit",
        "backup",
        "inventory",
        "monitoring",
        "notification",
        "onboarding",
        "action",
    ),
    "home-control-hub": ("sso", "energy", "network", "automation", "flow"),
    "appstore-en-fork": ("catalog",),
    "jelly-leon-platform": ("lifecycle",),
    "zoeken-en-persoonlijke-ai": ("search", "voice"),
    "jelly-leon": ("media",),
    "mediaguard": ("media",),
}
#: gedeelde domeinen: alleen de vaste typen hieronder, en alleen over de eigen app/dienst
SHARED_DOMAINS: tuple[str, ...] = ("app", "service")
SERVICE_EVENTS: tuple[str, ...] = (
    "service.hub_link.linked",
    "service.hub_link.unlinked",
    "service.hub_link.revoked",
    "service.token.rotated",
    "service.key_rotation.applied",
    "service.key_rotation.rejected",
)
HEALTH_STATUSES = ("healthy", "degraded", "down", "unknown")


@dataclass(frozen=True)
class EventTypeSpec:
    """Eén vast eventtype uit het contract. ``sources`` leeg = elke eigenaar van het domein."""

    event_type: str
    title_nl: str
    contract_ref: str
    sources: tuple[str, ...] = ()
    entity_type: str | None = None
    entity_id_is_source: bool = False
    payload_required: tuple[str, ...] = ()
    payload_enums: dict[str, tuple[str, ...]] = field(default_factory=dict)
    schema_versions: tuple[str, ...] = ENVELOPE_VERSIONS

    def to_dict(self) -> dict[str, Any]:
        domain, _obj, verb = self.event_type.split(".")
        return {
            "event_type": self.event_type,
            "title_nl": self.title_nl,
            "domain": domain,
            "soort": verb_kind(verb),
            "schema_versions": list(self.schema_versions),
            "sources": list(self.sources) or owners_of(domain),
            "entity_type": self.entity_type,
            "entity_id_is_source": self.entity_id_is_source,
            "payload_schema": {
                "required": list(self.payload_required),
                "enums": {k: list(v) for k, v in self.payload_enums.items()},
            },
            "contract_ref": self.contract_ref,
        }


def _service_events() -> list[EventTypeSpec]:
    titles = {
        "service.hub_link.linked": "Dienst gekoppeld aan de Hub",
        "service.hub_link.unlinked": "Dienst ontkoppeld",
        "service.hub_link.revoked": "Koppeling ingetrokken door de Hub",
        "service.token.rotated": "Service-token vervangen",
        "service.key_rotation.applied": "Sleutelrotatie van de Hub toegepast",
        "service.key_rotation.rejected": "Sleutelrotatie van de Hub geweigerd",
    }
    out = []
    for name in SERVICE_EVENTS:
        linked = name == "service.hub_link.linked"
        out.append(
            EventTypeSpec(
                name,
                titles[name],
                "§7 vaste service.*-events",
                entity_type="service",
                entity_id_is_source=True,
                payload_required=("via",) if linked else (),
                payload_enums={"via": ("token", "koppelcode")} if linked else {},
            )
        )
    return out


def _sso_access(event_type: str, title_nl: str) -> EventTypeSpec:
    return EventTypeSpec(
        event_type,
        title_nl,
        "§7 sso.access.*",
        (APP_ID,),
        entity_type="authentik_user",
        payload_required=("issuer", "sub", "preferred_username"),
    )


EVENT_TYPES: tuple[EventTypeSpec, ...] = (
    EventTypeSpec(
        "app.health.changed",
        "Gezondheid van een app is gewijzigd",
        "§7 event_type-namen; gedeeld domein app: alleen over de eigen app",
        entity_id_is_source=True,
        payload_required=("status",),
        payload_enums={"status": HEALTH_STATUSES},
    ),
    *_service_events(),
    _sso_access("sso.access.revoked", "Toegang ingetrokken (Authentik)"),
    _sso_access("sso.access.changed", "Toegang gewijzigd (Authentik)"),
    EventTypeSpec("backup.run.failed", "Back-up mislukt", "§7 event_type-namen (voorbeeld)"),
    EventTypeSpec("action.run.executed", "Actie uitgevoerd", "§7 event_type-namen (voorbeeld)"),
    EventTypeSpec("energy.reading.recorded", "Energiemeting vastgelegd", "§7 event_type-namen (voorbeeld)"),
    EventTypeSpec("network.device.discovered", "Nieuw apparaat op het netwerk", "§7 event_type-namen (voorbeeld)"),
    EventTypeSpec("flow.action.requested", "Flow vraagt een actie aan", "§7 event_type-namen (voorbeeld)"),
    EventTypeSpec("auth.break_glass.used", "Noodtoegang gebruikt", "§7 event_type-namen (voorbeeld)"),
    EventTypeSpec("media.download.failed", "Download mislukt", "§7 envelope-voorbeeld", ("mediaguard",)),
)
_BY_TYPE = {spec.event_type: spec for spec in EVENT_TYPES}


def verb_kind(verb: str) -> str:
    if verb in PROBLEM_VERBS:
        return "probleem"
    if verb in RECOVERY_VERBS:
        return "herstel"
    return "informatie"


def owners_of(domain: str) -> list[str]:
    if domain in SHARED_DOMAINS:
        return sorted(OWNER_DOMAINS)
    return sorted(app for app, domains in OWNER_DOMAINS.items() if domain in domains)


def known_domains() -> list[str]:
    return sorted({d for domains in OWNER_DOMAINS.values() for d in domains} | set(SHARED_DOMAINS))


def lookup(event_type: str) -> EventTypeSpec | None:
    return _BY_TYPE.get(event_type)


def catalog_view() -> dict[str, Any]:
    return {
        "envelope": {
            "schema_versions": list(ENVELOPE_VERSIONS),
            "required": list(ENVELOPE_REQUIRED),
            "optional": sorted(ENVELOPE_FIELDS - set(ENVELOPE_REQUIRED)),
            "event_type_pattern": EVENT_TYPE_RE.pattern,
            "actor_types": list(ACTOR_TYPES),
            "classifications": list(CLASSIFICATIONS),
            "max_payload_bytes": MAX_PAYLOAD_BYTES,
            "ernst": list(ERNST),
        },
        "owners": {app: list(domains) for app, domains in sorted(OWNER_DOMAINS.items())},
        "shared_domains": {"app": ["app.health.changed"], "service": list(SERVICE_EVENTS)},
        "verbs": {"probleem": sorted(PROBLEM_VERBS), "herstel": sorted(RECOVERY_VERBS)},
        "items": [spec.to_dict() for spec in EVENT_TYPES],
        "notes_nl": [
            "Een flow kan op elk eventtype uit een bekend domein reageren; alleen de typen in 'items' hebben een vast "
            "payload-schema uit het contract.",
            "Events met classificatie 'sensitive' worden nooit aan een flow afgeleverd.",
            "MSO en my_house hebben in contract 1.3 geen eigen eventdomein; hun events zijn hier 'onbekend_type'.",
        ],
        "contract": "platformcontract 1.3 §7",
    }


def trigger_problem(event_type: str, schema_version: str) -> str | None:
    """Mag een trigger naar dit type verwijzen? Geeft een Nederlandse reden of ``None`` als het mag."""
    if len(event_type) > 128 or not EVENT_TYPE_RE.fullmatch(event_type):
        return "geen geldig eventtype (<domein>.<object>.<gebeurtenis>)"
    if schema_version not in ENVELOPE_VERSIONS:
        return f"onbekende schema-versie (ondersteund: {', '.join(ENVELOPE_VERSIONS)})"
    domain = event_type.split(".")[0]
    if domain not in known_domains():
        return "dit domein staat niet in de eventcatalogus"
    if domain in SHARED_DOMAINS and event_type not in _BY_TYPE:
        return "in dit gedeelde domein bestaan alleen de vaste typen uit de catalogus"
    return None


@dataclass(frozen=True)
class Verdict:
    """Uitkomst van de cataloguscontrole. ``status`` is één van ``models.CATALOG_STATUSES``."""

    status: str
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def deliverable(self) -> bool:
        return self.status == "geldig"


class EnvelopeError(ValueError):
    """De envelope zelf is ongeldig (422): er is niets betrouwbaars om te bewaren."""

    def __init__(self, fouten: list[dict[str, str]]) -> None:
        super().__init__("ongeldige envelope")
        self.fouten = fouten


def _uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else None


def identity_errors(env: Any) -> list[dict[str, str]]:
    """De minimale velden die nodig zijn om een event te kunnen bewaren, ook bij een onbekende schema-versie."""
    if not isinstance(env, dict):
        return [{"veld": "", "probleem": "verwacht een object"}]
    errs: list[dict[str, str]] = []

    def bad(veld: str, probleem: str) -> None:
        errs.append({"veld": veld, "probleem": probleem})

    version = env.get("schema_version")
    if not isinstance(version, str) or not 1 <= len(version) <= 10:
        bad("schema_version", "verplicht, tekst van 1–10 tekens")
    if not _uuid(env.get("event_id")):
        bad("event_id", "verplicht, een UUID")
    source = env.get("source_app")
    if not isinstance(source, str) or len(source) > 40 or not APP_ID_RE.fullmatch(source):
        bad("source_app", "verplicht, een app_id")
    seid = env.get("source_event_id")
    if not isinstance(seid, str) or not 1 <= len(seid) <= 200:
        bad("source_event_id", "verplicht, 1–200 tekens")
    etype = env.get("event_type")
    if not isinstance(etype, str) or not 1 <= len(etype) <= 128:
        bad("event_type", "verplicht, 1–128 tekens")
    return errs


def envelope_errors(env: dict[str, Any]) -> list[dict[str, str]]:
    """Volledige controle tegen de grenzen van §7 voor een envelope met een **bekende** schema-versie."""
    errs = identity_errors(env)

    def bad(veld: str, probleem: str) -> None:
        errs.append({"veld": veld, "probleem": probleem})

    for key in sorted(set(env) - ENVELOPE_FIELDS):
        bad(str(key)[:60], "onbekend veld")
    for key in ENVELOPE_REQUIRED:
        if key not in env:
            bad(key, "verplicht veld ontbreekt")
    etype = env.get("event_type")
    if isinstance(etype, str) and not EVENT_TYPE_RE.fullmatch(etype):
        bad("event_type", "verwacht <domein>.<object>.<gebeurtenis> in kleine letters")
    entity = env.get("entity")
    if not isinstance(entity, dict) or set(entity) != {"type", "id"}:
        bad("entity", "verwacht precies {type, id}")
    else:
        if not isinstance(entity["type"], str) or not ENTITY_TYPE_RE.fullmatch(entity["type"]):
            bad("entity.type", "verwacht ^[a-z0-9_.-]{1,64}$")
        if not isinstance(entity["id"], str) or not 1 <= len(entity["id"]) <= 200:
            bad("entity.id", "1–200 tekens")
    if "timestamp_utc" in env and parse_timestamp(env["timestamp_utc"]) is None:
        bad("timestamp_utc", "verwacht ISO-8601 met tijdzone")
    if "trace_id" in env and not _uuid(env["trace_id"]):
        bad("trace_id", "verwacht een UUID")
    if env.get("correlation_id") is not None and not _uuid(env["correlation_id"]):
        bad("correlation_id", "verwacht een UUID of null")
    actor = env.get("actor")
    if not isinstance(actor, dict) or set(actor) != {"type", "id"}:
        bad("actor", "verwacht precies {type, id}")
    else:
        if actor["type"] not in ACTOR_TYPES:
            bad("actor.type", "system, user, ai of flow")
        if not isinstance(actor["id"], str) or not 1 <= len(actor["id"]) <= 128:
            bad("actor.id", "1–128 tekens")
    if "classification" in env and env["classification"] not in CLASSIFICATIONS:
        bad("classification", "public, internal of sensitive")
    payload = env.get("payload")
    if "payload" in env:
        if not isinstance(payload, dict):
            bad("payload", "verwacht een object")
        elif len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_PAYLOAD_BYTES:
            bad("payload", "groter dan 16 KiB")
    ref = env.get("payload_ref")
    if ref is not None and (not isinstance(ref, str) or len(ref) > 512):
        bad("payload_ref", "tekst van hooguit 512 tekens of null")
    return errs


def classify(env: dict[str, Any]) -> Verdict:
    """Bepaalt de catalogusstatus van een envelope. Gooit :class:`EnvelopeError` als hij niet te bewaren is."""
    errs = identity_errors(env)
    if errs:
        raise EnvelopeError(errs)
    version = str(env["schema_version"])
    if version not in ENVELOPE_VERSIONS:
        # bewust geen verdere controle: de vorm van een onbekende versie kennen we niet
        return Verdict("onbekende_schema_versie", {"schema_version": version, "ondersteund": list(ENVELOPE_VERSIONS)})
    errs = envelope_errors(env)
    if errs:
        raise EnvelopeError(errs)
    etype, source = str(env["event_type"]), str(env["source_app"])
    domain = etype.split(".")[0]
    spec = lookup(etype)
    if domain in SHARED_DOMAINS:
        if spec is None:
            return Verdict("onbekend_type", {"reden": "geen_vast_type_in_gedeeld_domein", "domein": domain})
        if source not in OWNER_DOMAINS:
            return Verdict("buiten_domein", {"reden": "bron_onbekend", "domein": domain})
        if spec.entity_id_is_source and env["entity"]["id"] != source:
            # §7: in een gedeeld domein meldt een app alleen iets over zichzelf (de Hub rekent zo'n event ook niet
            # tot het eigen domein); anders zou app A een flow kunnen laten reageren op "app B is down"
            return Verdict("buiten_domein", {"reden": "niet_over_de_eigen_app", "domein": domain})
    elif domain not in known_domains():
        return Verdict("onbekend_type", {"reden": "domein_onbekend", "domein": domain})
    elif domain not in OWNER_DOMAINS.get(source, ()) or (
        spec is not None and spec.sources and source not in spec.sources
    ):
        return Verdict(
            "buiten_domein", {"reden": "bron_is_geen_eigenaar", "domein": domain, "eigenaars": owners_of(domain)}
        )
    payload: dict[str, Any] = env["payload"]
    fouten: list[str] = []
    ernst = payload.get("ernst")
    if ernst is not None and ernst not in ERNST:
        fouten.append("ernst: kritiek, hoog, middel, laag of info")
    if spec is not None:
        entity = env["entity"]
        if spec.entity_type is not None and entity["type"] != spec.entity_type:
            fouten.append(f"entity.type: verwacht {spec.entity_type}")
        if spec.entity_id_is_source and entity["id"] != source:
            fouten.append("entity.id: verwacht de app_id van de bron")
        for key in spec.payload_required:
            value = payload.get(key)
            if not isinstance(value, str) or not value:
                fouten.append(f"payload.{key}: verplicht")
        for key, allowed in spec.payload_enums.items():
            if key in payload and payload[key] not in allowed:
                fouten.append(f"payload.{key}: {', '.join(allowed)}")
    if fouten:
        return Verdict("ongeldige_payload", {"fouten": fouten[:20], "getypeerd": spec is not None})
    return Verdict("geldig", {"getypeerd": spec is not None})
