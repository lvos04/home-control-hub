"""B13-005 — back-up en upgrade van Authentik: configuratie-export, pre-upgrade-gate en herstelcheck.

Wat dit **wel** is: een geschoonde export van de configuratie via de API (providers, applicaties, groepen met leden,
gebruikers met groepen, flows + flow-blueprints, scopes, sleutel-vingerafdrukken, brands, blueprints, outposts) en
de MFA-apparaten (alleen type/naam) van beheerders. Daarmee kan na een herstel of upgrade gecontroleerd worden dat
rechten, 2FA en clients weer kloppen (acceptatie B13-005).

Wat dit **niet** is: de echte back-up. Volgens de officiële docs (``compat.BACKUP_DOCS``) is de PostgreSQL-database van
Authentik het belangrijkste; die zit in de datasets van de TrueNAS-catalogusapp en wordt via snapshots/back-ups van het
platform gemaakt (Hub/executor). Deze dienst kan die back-up niet zelf controleren: de gate vraagt een door de Hub
bevestigd back-upcheckpoint en is anders ``onbekend``. Een gate is nooit "groen" op aannames.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...timeutil import iso, utcnow
from . import service as recovery_service
from .authaudit import ADMIN_ROLES, Actor, latest_snapshot, store_snapshot
from .authentik import compat
from .authentik.client import AuthentikClient, AuthentikError
from .authentik.reader import ALL_PARTS, read_devices, read_flow_export, read_state, read_version
from .models import SsoAuthentikSnapshot, SsoGroupRoleMapping

EXPORT_MAX_AGE = timedelta(hours=24)
MAX_EXPORT_BYTES = 6 * 1024 * 1024
MAX_MFA_USERS = 50


def _admin_usernames(state_users: list[dict[str, Any]], groups: list[dict[str, Any]], session: Session) -> list[str]:
    admin_groups = {
        m.authentik_group
        for m in session.scalars(select(SsoGroupRoleMapping))
        if m.role in ADMIN_ROLES.get(m.app_id, set())
    }
    superuser_groups = {g["name"] for g in groups if g.get("is_superuser")}
    names = set()
    for u in state_users:
        ugroups = set(u.get("groups") or [])
        if u.get("is_superuser") or ugroups & (admin_groups | superuser_groups):
            names.add(str(u.get("username")))
    return sorted(names)


def build_export(client: AuthentikClient, session: Session) -> tuple[dict[str, Any], bool, str | None]:
    caps = read_version(client)
    state = read_state(client, ALL_PARTS, caps=caps)
    content: dict[str, Any] = {
        "format": "hch-authentik-config-export/1",
        "authentik_version": state.version,
        "compat": caps.to_dict(),
        "parts": dict(state.parts),
        "missing": list(state.missing),
        "role_mappings": [
            {"app_id": m.app_id, "authentik_group": m.authentik_group, "role": m.role}
            for m in session.scalars(
                select(SsoGroupRoleMapping).order_by(SsoGroupRoleMapping.app_id, SsoGroupRoleMapping.authentik_group)
            )
        ],
        "mfa": {},
        "flow_exports": {},
        "note_nl": "Geschoonde export via de API (geen geheimen). Geen vervanging van de database-back-up van Authentik.",
    }
    if not caps.readable:
        return content, False, state.version
    users = state.get("users") or []
    groups = state.get("groups") or []
    by_name = {str(u.get("username")): u for u in users}
    admins = (
        _admin_usernames(users, groups, session)
        if state.get("users") is not None and state.get("groups") is not None
        else []
    )
    if len(admins) > MAX_MFA_USERS:
        content["missing"].append({"part": "mfa", "reason": "te_veel_beheerders"})
        admins = admins[:MAX_MFA_USERS]
    for name in admins:
        try:
            content["mfa"][name] = sorted(
                read_devices(client, by_name[name].get("pk")), key=lambda d: (str(d.get("type")), str(d.get("name")))
            )
        except AuthentikError as exc:
            content["missing"].append({"part": "mfa", "user": name, "reason": exc.reason})
    flows = {str(f.get("pk")): f.get("slug") for f in state.get("flows") or []}
    wanted: set[str] = set()
    for p in state.get("providers") or []:
        for k in ("authorization_flow", "invalidation_flow"):
            if p.get(k) and str(p[k]) in flows:
                wanted.add(str(flows[str(p[k])]))
    for b in state.get("brands") or []:
        for k in ("flow_authentication", "flow_invalidation", "flow_recovery"):
            if b.get(k) and str(b[k]) in flows:
                wanted.add(str(flows[str(b[k])]))
    total = 0
    for slug in sorted(wanted):
        try:
            exp = read_flow_export(client, slug)
        except AuthentikError as exc:
            content["missing"].append({"part": "flow_export", "flow": slug, "reason": exc.reason})
            continue
        total += exp["bytes"]
        if total > MAX_EXPORT_BYTES:
            content["missing"].append({"part": "flow_export", "flow": slug, "reason": "export_te_groot"})
            continue
        content["flow_exports"][slug] = exp
    return content, not content["missing"], state.version


def export_meta(row: SsoAuthentikSnapshot) -> dict[str, Any]:
    c = row.content or {}
    parts = c.get("parts", {})
    return {
        "id": str(row.id),
        "taken_at": iso(row.taken_at),
        "taken_by": row.taken_by,
        "authentik_version": row.authentik_version,
        "complete": row.complete,
        "content_sha256": row.content_sha256,
        "size_bytes": row.size_bytes,
        "counts": {k: len(v) for k, v in parts.items() if isinstance(v, list)},
        "mfa_users": len(c.get("mfa", {})),
        "flow_exports": sorted(c.get("flow_exports", {})),
        "missing": c.get("missing", []),
    }


def create_export(session: Session, client: AuthentikClient, actor: Actor, tid: str) -> SsoAuthentikSnapshot:
    content, complete, version = build_export(client, session)
    return store_snapshot(session, "config_export", content, complete, version, actor, tid)


# ------------------------------------------------------------------ pre-upgrade-gate
def _check(name: str, status: str, message_nl: str, **detail: Any) -> dict[str, Any]:
    return {"name": name, "status": status, "message_nl": message_nl, "detail": detail}


def upgrade_gate(
    session: Session,
    client: AuthentikClient,
    target_raw: str,
    backup_checkpoint: dict[str, Any] | None,
    backup_confirmed_by_hub: bool,
    break_glass_max_age_days: int,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    target = compat.parse_version(target_raw)
    checks.append(
        _check(
            "doelversie",
            "ok" if target else "fout",
            "Exacte stabiele versie (JJJJ.M.P)."
            if target
            else "Geen exacte stabiele versie; 'latest' of een rc mag niet.",
            target=target_raw,
        )
    )
    current = None
    try:
        caps = read_version(client)
        current = compat.parse_version(caps.version)
        checks.append(
            _check(
                "huidige_versie",
                "ok" if current else "onbekend",
                f"Authentik draait {caps.version}." if current else "Huidige versie onleesbaar.",
                support=caps.support,
            )
        )
    except AuthentikError as exc:
        checks.append(_check("huidige_versie", "onbekend", exc.message_nl, reason=exc.reason))
    if target and current:
        path = compat.check_upgrade_path(current, target)
        checks.append(
            _check(
                "upgradepad",
                path.status,
                path.message_nl,
                code=path.code,
                next_step=path.next_step,
                bron=compat.UPGRADE_DOCS,
            )
        )
        tcaps = compat.capabilities_for(str(target))
        checks.append(
            _check(
                "doelversie_api_gecontroleerd",
                "ok" if tcaps.support == "geverifieerd" else "onbekend",
                "API-schema van de doelversie is gecontroleerd."
                if tcaps.support == "geverifieerd"
                else "API-schema van de doelversie is (nog) niet gecontroleerd; deze dienst kan daarna mogelijk niet lezen.",
                support=tcaps.support,
            )
        )
    else:
        checks.append(_check("upgradepad", "onbekend", "Upgradepad niet te beoordelen zonder huidige en doelversie."))
    ready = client.health("ready")
    checks.append(
        _check(
            "authentik_gereed",
            "ok" if ready == 200 else "fout",
            "Authentik meldt zich gereed."
            if ready == 200
            else "Authentik is niet gereed; eerst herstellen, dan upgraden.",
            http_status=ready,
        )
    )
    export = latest_snapshot(session, "config_export")
    fresh = export is not None and export.taken_at >= utcnow() - EXPORT_MAX_AGE
    same_version = export is not None and current is not None and export.authentik_version == str(current)
    checks.append(
        _check(
            "configuratie_export",
            "ok" if fresh and same_version else "fout",
            "Volledige export van < 24 uur van de huidige versie."
            if fresh and same_version
            else "Maak eerst een volledige configuratie-export van de huidige versie (< 24 uur).",
            export_id=str(export.id) if export else None,
            taken_at=iso(export.taken_at) if export else None,
        )
    )
    if backup_checkpoint and backup_confirmed_by_hub:
        checks.append(
            _check(
                "database_backup",
                "ok",
                "Back-upcheckpoint van de Authentik-database door de Hub bevestigd.",
                checkpoint=backup_checkpoint,
            )
        )
    elif backup_checkpoint:
        checks.append(
            _check(
                "database_backup",
                "onbekend",
                "Een checkpoint opgeven is geen bewijs; de Hub moet de back-up bevestigen (backup-gate).",
                checkpoint=backup_checkpoint,
            )
        )
    else:
        checks.append(
            _check(
                "database_backup",
                "onbekend",
                "Geen bevestigde back-up van de Authentik-database (officiële docs: verplicht vóór upgraden).",
                bron=compat.BACKUP_DOCS,
            )
        )
    readiness = recovery_service.overall(session, break_glass_max_age_days)
    level = readiness.get("level")
    checks.append(
        _check(
            "noodtoegang",
            "ok" if level == "ok" else "fout",
            "Noodtoegang zonder Authentik is gereed (B13-001)."
            if level == "ok"
            else "Noodtoegang is niet gereed; een mislukte upgrade kan dan tot lock-out leiden.",
            level=level,
        )
    )
    try:
        outposts = read_state(client, ("outposts",)).get("outposts")
    except AuthentikError:
        outposts = None
    if outposts is None:
        checks.append(_check("outposts", "onbekend", "Outposts konden niet gelezen worden."))
    else:
        external = [o for o in outposts if o.get("managed") != compat.EMBEDDED_OUTPOST_MANAGED]
        checks.append(
            _check(
                "outposts",
                "onbekend" if external else "ok",
                "Alleen de ingebouwde outpost."
                if not external
                else "Externe outposts moeten tegelijk mee-upgraden (officiële docs).",
                external=[o.get("name") for o in external],
            )
        )
    checks.append(
        _check(
            "catalogusversie",
            "onbekend",
            "Of de doelversie in de TrueNAS-catalogus (trein community) beschikbaar is, controleert de Hub/executor; "
            "treinen houden vaak alleen de nieuwste versie.",
        )
    )
    statuses = {c["status"] for c in checks}
    outcome = "rood" if "fout" in statuses else ("onbekend" if "onbekend" in statuses else "ok_lokaal")
    return {
        "target_version": target_raw,
        "current_version": str(current) if current else None,
        "outcome": outcome,
        "outcome_nl": {
            "rood": "Niet upgraden: minstens één controle faalt.",
            "onbekend": "Niet upgraden zolang niet alles bevestigd is.",
            "ok_lokaal": "Alle controles van deze dienst zijn in orde; de eindbeslissing ligt bij de Hub (policy en back-upgate).",
        }[outcome],
        "checks": checks,
        "observed_at": iso(utcnow()),
    }


# ------------------------------------------------------------------ herstelcheck
def _names(rows: list[dict[str, Any]] | None, key: str) -> set[str]:
    return {str(r.get(key)) for r in rows or []}


def restore_check(snapshot: SsoAuthentikSnapshot, client: AuthentikClient, session: Session) -> dict[str, Any]:
    """Vergelijkt een export (van vóór herstel/upgrade) met de huidige toestand: rechten, 2FA, clients, sleutels."""
    before = snapshot.content or {}
    bparts: dict[str, Any] = before.get("parts", {})
    checks: list[dict[str, Any]] = []
    try:
        after_content, _complete, version = build_export(client, session)
    except AuthentikError as exc:
        return {
            "export_id": str(snapshot.id),
            "outcome": "onbekend",
            "checks": [_check("authentik", "onbekend", exc.message_nl, reason=exc.reason)],
            "observed_at": iso(utcnow()),
        }
    aparts: dict[str, Any] = after_content.get("parts", {})
    bv, av = compat.parse_version(before.get("authentik_version")), compat.parse_version(version)
    if bv and av:
        checks.append(
            _check(
                "versie",
                "fout" if av < bv else "ok",
                "Geen downgrade."
                if av >= bv
                else "Nieuwere export dan de huidige versie: downgrade wordt niet ondersteund.",
                before=str(bv),
                after=str(av),
            )
        )
    else:
        checks.append(_check("versie", "onbekend", "Versie onleesbaar."))

    def compare(name: str, part: str, key: str, fields: tuple[str, ...], message_ok: str) -> None:
        b, a = bparts.get(part), aparts.get(part)
        if b is None or a is None:
            checks.append(_check(name, "onbekend", f"Onderdeel '{part}' ontbreekt in de export of nu.", part=part))
            return
        amap = {str(x.get(key)): x for x in a}
        missing, changed = [], []
        for x in b:
            y = amap.get(str(x.get(key)))
            if y is None:
                missing.append(x.get(key))
            elif any(x.get(f) != y.get(f) for f in fields):
                changed.append({"key": x.get(key), "fields": [f for f in fields if x.get(f) != y.get(f)]})
        status = "afwijking" if missing or changed else "ok"
        checks.append(
            _check(
                name,
                status,
                message_ok if status == "ok" else f"{len(missing)} ontbreken, {len(changed)} gewijzigd.",
                missing=missing,
                changed=changed,
            )
        )

    compare(
        "providers",
        "providers",
        "name",
        ("client_id", "client_type", "redirect_uris", "signing_key", "issuer_mode", "sub_mode"),
        "OAuth2/OIDC-providers ongewijzigd.",
    )
    compare("applicaties", "applications", "slug", ("provider", "policy_engine_mode"), "Applicaties ongewijzigd.")
    compare("groepen", "groups", "name", ("is_superuser", "members"), "Groepen, superuservlag en leden ongewijzigd.")
    compare(
        "gebruikers",
        "users",
        "username",
        ("is_active", "is_superuser", "groups"),
        "Gebruikers, status en groepen ongewijzigd.",
    )
    compare(
        "ondertekeningssleutels",
        "signing_keys",
        "name",
        ("fingerprint_sha256",),
        "Sleutelparen (vingerafdrukken) aanwezig.",
    )
    compare("flows", "flows", "slug", ("designation",), "Flows aanwezig.")
    compare(
        "brands",
        "brands",
        "domain",
        ("flow_authentication", "flow_invalidation", "flow_recovery"),
        "Brand-flows ongewijzigd.",
    )
    bmfa, amfa = before.get("mfa", {}), after_content.get("mfa", {})
    if not bmfa:
        checks.append(
            _check("mfa_beheerders", "onbekend", "De export bevat geen MFA-gegevens (geen beheerders of geen rechten).")
        )
    else:
        lost: list[dict[str, Any]] = []
        for user, devs in bmfa.items():
            if user not in amfa:
                lost.append({"user": user, "reason": "niet_gelezen_of_verdwenen"})
                continue
            bc = Counter(d.get("type") for d in devs if d.get("confirmed"))
            ac = Counter(d.get("type") for d in amfa[user] if d.get("confirmed"))
            short = {t: n - ac.get(t, 0) for t, n in bc.items() if ac.get(t, 0) < n}
            if short:
                lost.append({"user": user, "missing_types": short})
        checks.append(
            _check(
                "mfa_beheerders",
                "afwijking" if lost else "ok",
                "2FA van beheerders intact." if not lost else "2FA ontbreekt na herstel bij beheerders.",
                lost=lost,
            )
        )
    statuses = {c["status"] for c in checks}
    outcome = "afwijking" if statuses & {"afwijking", "fout"} else ("onbekend" if "onbekend" in statuses else "ok")
    return {
        "export_id": str(snapshot.id),
        "export_taken_at": iso(snapshot.taken_at),
        "current_version": version,
        "outcome": outcome,
        "checks": checks,
        "observed_at": iso(utcnow()),
        "next_step_nl": (
            "Overweeg oude sessies in te trekken (voorstel sso.sessions.revoke) na herstel of een vermoed lek."
            if outcome != "onbekend"
            else "Eerst Authentik volledig leesbaar maken (rechten van het token, bereikbaarheid)."
        ),
    }
