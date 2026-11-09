"""B13-004 — audit en rechten: Authentik-events lezen, rechtenkaart met verschillen, afwijkingen als events (§7).

- Events (logins, mislukte logins, wijzigingen, impersonatie, ingezien geheim, verdacht verzoek) worden met een
  watermerk opgehaald; alleen minimale velden worden bewaard (30 dagen).
- De rechtenkaart (gebruiker → groepen → rol per app, via de koppeling van B13-003) wordt vergeleken met de vorige.
  **Alleen een volledig gelezen toestand** wordt vergeleken: een half gelezen lijst mag nooit "toegang ingetrokken"
  opleveren (fail-safe). Ingetrokken toegang → ``sso.access.revoked`` zodat de Hub sessies kan beëindigen.
- Afwijkingen zijn regelgebaseerd en ontdubbeld (``sso_anomaly.dedupe_key``); elke nieuwe afwijking → audit +
  ``sso.anomaly.detected`` (classificatie *sensitive*). Regels zijn een startpunt; de grenzen (5 mislukte logins in
  10 min) staan in ADR-0007 en zijn niet op een echte installatie geijkt.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ... import audit, events
from ...models import ServiceState
from ...timeutil import ensure_aware, iso, utcnow
from .authentik import compat
from .authentik.client import AuthentikClient, AuthentikError
from .authentik.reader import read_state, read_version
from .catalog import APP_BY_ID
from .models import SsoAdminAccount, SsoAnomaly, SsoAuthentikSnapshot, SsoAuthEvent, SsoGroupRoleMapping
from .oidc_hub import canonical

EVENT_ACTIONS = (
    "login",
    "login_failed",
    "logout",
    "model_created",
    "model_updated",
    "model_deleted",
    "impersonation_started",
    "secret_view",
    "suspicious_request",
    "password_set",
)
WATERMARK_KEY = "authentik_events_watermark"
SYNC_KEY = "authentik_sync"
INITIAL_LOOKBACK = timedelta(hours=24)
RETENTION = timedelta(days=30)
BURST_WINDOW = timedelta(minutes=10)
BURST_THRESHOLD = 5
MAX_PAGES = 5
MAX_CHANGE_EVENTS = 50
# Rollen die als "beheer" tellen (voor afwijkingen bij toekenning)
ADMIN_ROLES = {"ai-server-manager": {"admin"}, "immich": {"admin"}, "node-red": {"*"}}

Actor = tuple[str, str]


def _parse_dt(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        return ensure_aware(datetime.fromisoformat(raw.replace("Z", "+00:00")))
    except ValueError:
        return None


def _state_get(session: Session, key: str) -> dict[str, Any] | None:
    row = session.get(ServiceState, key)
    return dict(row.value) if row is not None else None


def _state_put(session: Session, key: str, value: dict[str, Any]) -> None:
    row = session.get(ServiceState, key)
    if row is None:
        session.add(ServiceState(key=key, value=value))
    else:
        row.value = value


# ------------------------------------------------------------------ events ophalen
def fetch_new_events(
    client: AuthentikClient, caps: compat.ApiCapabilities, watermark: dict[str, Any] | None
) -> tuple[list[dict[str, Any]], bool, dict[str, Any]]:
    """Nieuwe events sinds het watermerk (nieuwste eerst opgehaald). Geeft (events, volledig, nieuw watermerk)."""
    wm_at = _parse_dt((watermark or {}).get("created")) or (utcnow() - INITIAL_LOOKBACK)
    wm_pks = set((watermark or {}).get("pks_at") or [])
    queries: list[dict[str, Any]]
    if caps.events_multi_action_filter:
        queries = [{"actions": list(EVENT_ACTIONS)}]
    else:  # oudere versies negeren ?actions= en zouden dan álles teruggeven
        queries = [{"action": a} for a in EVENT_ACTIONS]
    found: dict[str, dict[str, Any]] = {}
    complete = True
    for q in queries:
        reached = False
        for page in range(1, MAX_PAGES + 1):
            data = client.get_json("/events/events/", {**q, "ordering": "-created", "page": page, "page_size": 100})
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise AuthentikError("antwoord_ongeldig", 200, "/api/v3/events/events/")
            for ev in data["results"]:
                created = _parse_dt(ev.get("created")) if isinstance(ev, dict) else None
                if created is None or not ev.get("pk"):
                    continue
                if created < wm_at or (created == wm_at and str(ev["pk"]) in wm_pks):
                    reached = True
                    continue
                if ev.get("action") in EVENT_ACTIONS:
                    found[str(ev["pk"])] = ev
            if reached or not (data.get("pagination") or {}).get("next"):
                reached = True
                break
        if not reached:
            complete = False
    evs = sorted(found.values(), key=lambda e: (e.get("created"), str(e.get("pk"))))
    if evs:
        top = max(d for d in (_parse_dt(e["created"]) for e in evs) if d is not None)
        new_wm: dict[str, Any] = {
            "created": iso_full(top),
            "pks_at": sorted(str(e["pk"]) for e in evs if _parse_dt(e["created"]) == top),
        }
        if top == wm_at:
            new_wm["pks_at"] = sorted(set(new_wm["pks_at"]) | wm_pks)
    else:
        new_wm = {"created": iso_full(wm_at), "pks_at": sorted(wm_pks)}
    return evs, complete, new_wm


def iso_full(dt: datetime | None) -> str | None:
    return None if dt is None else dt.isoformat()


def _event_username(action: str, user: dict[str, Any], ctx: dict[str, Any]) -> str | None:
    """Bij ``login_failed`` staat de geprobeerde naam in ``context.username`` (authentik/events/signals.py); de
    ``user`` is dan de echte gebruiker of AnonymousUser (onbekende naam)."""
    if action == "login_failed" and isinstance(ctx.get("username"), str) and ctx["username"]:
        return str(ctx["username"])[:150]
    name = user.get("username")
    return str(name)[:150] if name and name != "AnonymousUser" else None


def ingest(session: Session, raw_events: list[dict[str, Any]]) -> list[SsoAuthEvent]:
    """Bewaart alleen minimale velden; ontdubbelt op het Authentik-pk."""
    new: list[SsoAuthEvent] = []
    now = utcnow()
    for ev in raw_events:
        user: dict[str, Any] = ev["user"] if isinstance(ev.get("user"), dict) else {}
        ctx: dict[str, Any] = ev["context"] if isinstance(ev.get("context"), dict) else {}
        model: dict[str, Any] = ctx["model"] if isinstance(ctx.get("model"), dict) else {}
        created = _parse_dt(ev.get("created"))
        if created is None:
            continue
        values = {
            "authentik_pk": str(ev["pk"])[:64],
            "action": str(ev.get("action"))[:40],
            "username": _event_username(str(ev.get("action")), user, ctx),
            "client_ip": str(ev.get("client_ip"))[:45] if ev.get("client_ip") else None,
            "created": created,
            "model_name": str(model.get("model_name"))[:60] if model.get("model_name") else None,
            "model_label": str(model.get("name"))[:200] if model.get("name") else None,
            "ingested_at": now,
        }
        won = session.execute(
            insert(SsoAuthEvent)
            .values(**values)
            .on_conflict_do_nothing(index_elements=["authentik_pk"])
            .returning(SsoAuthEvent.authentik_pk)
        ).first()
        if won is not None:
            new.append(SsoAuthEvent(**values))
    return new


KEEP_SNAPSHOTS = {"rechten": 100, "config_export": 30}


def purge_old_events(session: Session) -> int:
    """Bewaartermijnen: events 30 dagen; van elke momentopname-soort alleen de nieuwste N (altijd ≥ 1 volledige)."""
    from sqlalchemy import delete

    res = session.execute(delete(SsoAuthEvent).where(SsoAuthEvent.created < utcnow() - RETENTION))
    removed = int(getattr(res, "rowcount", 0) or 0)
    for kind, keep in KEEP_SNAPSHOTS.items():
        keep_ids = (
            select(SsoAuthentikSnapshot.id)
            .where(SsoAuthentikSnapshot.kind == kind)
            .order_by(SsoAuthentikSnapshot.taken_at.desc())
            .limit(keep)
        )
        newest_complete = latest_snapshot(session, kind)
        stmt = delete(SsoAuthentikSnapshot).where(
            SsoAuthentikSnapshot.kind == kind, SsoAuthentikSnapshot.id.not_in(keep_ids)
        )
        if newest_complete is not None:
            stmt = stmt.where(SsoAuthentikSnapshot.id != newest_complete.id)
        removed += int(getattr(session.execute(stmt), "rowcount", 0) or 0)
    return removed


# ------------------------------------------------------------------ afwijkingen
def _record_anomaly(
    session: Session,
    *,
    rule_id: str,
    dedupe_key: str,
    severity: str,
    subject: str | None,
    message_nl: str,
    details: dict[str, Any],
    first_seen: datetime,
    last_seen: datetime,
    count: int,
    actor: Actor,
    tid: str,
) -> SsoAnomaly | None:
    """Nieuwe afwijking → rij + audit + event. Bestaande (zelfde sleutel) → alleen teller/laatst gezien bijwerken."""
    key = dedupe_key if len(dedupe_key) <= 200 else rule_id + ":" + hashlib.sha256(dedupe_key.encode()).hexdigest()
    existing = session.scalar(select(SsoAnomaly).where(SsoAnomaly.dedupe_key == key))
    if existing is not None:
        existing.count = max(existing.count, count)
        existing.last_seen = max(existing.last_seen, last_seen)
        return None
    row = SsoAnomaly(
        id=uuid.uuid4(),
        rule_id=rule_id,
        dedupe_key=key,
        severity=severity,
        subject=subject[:150] if subject else None,
        message_nl=message_nl[:500],
        details=details,
        first_seen=first_seen,
        last_seen=max(last_seen, first_seen),
        count=max(1, count),
        detected_at=utcnow(),
        status="open",
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        domain="sso",
        action="anomaly.detected",
        entity_type="sso_anomaly",
        entity_id=str(row.id),
        principal=None,
        trace_id=tid,
        message_nl=message_nl,
        details={"rule_id": rule_id, "severity": severity, "subject": subject, "count": row.count},
        actor_override=actor,
    )
    events.emit(
        session,
        event_type="sso.anomaly.detected",
        entity_type="sso_anomaly",
        entity_id=str(row.id),
        actor_type=actor[0],
        actor_id=actor[1],
        trace_id=tid,
        classification="sensitive",
        payload={
            "rule_id": rule_id,
            "severity": severity,
            "subject": subject,
            "count": row.count,
            "first_seen": iso(row.first_seen),
            "last_seen": iso(row.last_seen),
            "message_nl": message_nl,
        },
    )
    return row


def mapped_groups(session: Session) -> set[str]:
    return {m.authentik_group for m in session.scalars(select(SsoGroupRoleMapping))}


def break_glass_usernames(session: Session) -> set[str]:
    rows = session.scalars(
        select(SsoAdminAccount).where(SsoAdminAccount.system == "authentik", SsoAdminAccount.is_break_glass)
    )
    return {r.username for r in rows}


def detect_anomalies(session: Session, new_events: list[SsoAuthEvent], actor: Actor, tid: str) -> list[SsoAnomaly]:
    found: list[SsoAnomaly] = []
    groups = mapped_groups(session)
    break_glass = break_glass_usernames(session)

    def rec(**kw: Any) -> None:
        row = _record_anomaly(session, actor=actor, tid=tid, **kw)
        if row is not None:
            found.append(row)

    for ev in new_events:
        pk_key = f"{ev.action}:{ev.authentik_pk}"
        if ev.action == "impersonation_started":
            rec(
                rule_id="impersonatie",
                dedupe_key=pk_key,
                severity="hoog",
                subject=ev.username,
                message_nl=f"Impersonatie gestart door {ev.username or 'onbekend'} in Authentik.",
                details={"client_ip": ev.client_ip},
                first_seen=ev.created,
                last_seen=ev.created,
                count=1,
            )
        elif ev.action == "secret_view":
            rec(
                rule_id="geheim_ingezien",
                dedupe_key=pk_key,
                severity="middel",
                subject=ev.username,
                message_nl=f"{ev.username or 'Onbekend'} heeft in Authentik een token of geheim ingezien.",
                details={"model": ev.model_name, "label": ev.model_label},
                first_seen=ev.created,
                last_seen=ev.created,
                count=1,
            )
        elif ev.action == "suspicious_request":
            rec(
                rule_id="verdacht_verzoek",
                dedupe_key=pk_key,
                severity="middel",
                subject=ev.username,
                message_nl="Authentik meldt een verdacht verzoek.",
                details={"client_ip": ev.client_ip},
                first_seen=ev.created,
                last_seen=ev.created,
                count=1,
            )
        elif ev.action == "login" and ev.username and ev.username in break_glass:
            rec(
                rule_id="noodaccount_login",
                dedupe_key=pk_key,
                severity="hoog",
                subject=ev.username,
                message_nl=f"Het noodaccount {ev.username} heeft in Authentik ingelogd; meld de activatie en roteer het "
                "wachtwoord (B13-001).",
                details={"client_ip": ev.client_ip},
                first_seen=ev.created,
                last_seen=ev.created,
                count=1,
            )
        elif ev.action.startswith("model_") and ev.model_name == "group" and ev.model_label in groups:
            rec(
                rule_id="gekoppelde_groep_gewijzigd",
                dedupe_key=pk_key,
                severity="hoog",
                subject=ev.username,
                message_nl=f"Groep '{ev.model_label}' (gekoppeld aan een rol) is gewijzigd door {ev.username or 'onbekend'}.",
                details={"action": ev.action, "group": ev.model_label},
                first_seen=ev.created,
                last_seen=ev.created,
                count=1,
            )
    # mislukte logins in een venster (per gebruikersnaam)
    failed_users = {e.username for e in new_events if e.action == "login_failed" and e.username}
    for username in sorted(failed_users):
        latest = max(e.created for e in new_events if e.action == "login_failed" and e.username == username)
        since = latest - BURST_WINDOW
        count = (
            session.scalar(
                select(func.count()).where(
                    SsoAuthEvent.username == username,
                    SsoAuthEvent.action == "login_failed",
                    SsoAuthEvent.created >= since,
                    SsoAuthEvent.created <= latest,
                )
            )
            or 0
        )
        if count >= BURST_THRESHOLD:
            first = (
                session.scalar(
                    select(func.min(SsoAuthEvent.created)).where(
                        SsoAuthEvent.username == username,
                        SsoAuthEvent.action == "login_failed",
                        SsoAuthEvent.created >= since,
                    )
                )
                or since
            )
            bucket = int(first.timestamp() // BURST_WINDOW.total_seconds())
            rec(
                rule_id="mislukte_logins_reeks",
                dedupe_key=f"burst:{username}:{bucket}",
                severity="middel",
                subject=username,
                message_nl=f"{count} mislukte inlogpogingen voor {username} binnen 10 minuten.",
                details={"window_minutes": 10, "threshold": BURST_THRESHOLD},
                first_seen=first,
                last_seen=latest,
                count=int(count),
            )
    return found


# ------------------------------------------------------------------ rechtenkaart
def roles_by_group(session: Session) -> dict[str, dict[str, list[str]]]:
    out: dict[str, dict[str, list[str]]] = {}
    for m in session.scalars(select(SsoGroupRoleMapping)):
        out.setdefault(m.authentik_group, {}).setdefault(m.app_id, []).append(m.role)
    return out


def build_rights(
    users: list[dict[str, Any]], groups: list[dict[str, Any]], role_map: dict[str, dict[str, list[str]]]
) -> dict[str, Any]:
    superuser_groups = {g["name"] for g in groups if g.get("is_superuser")}
    rights: dict[str, Any] = {}
    for u in users:
        name = str(u.get("username"))
        ugroups = sorted(u.get("groups") or [])
        roles: dict[str, set[str]] = {}
        for g in ugroups:
            for app_id, rs in role_map.get(g, {}).items():
                roles.setdefault(app_id, set()).update(rs)
        rights[name] = {
            "active": bool(u.get("is_active")),
            "type": u.get("type"),
            "superuser": bool(u.get("is_superuser")) or bool(superuser_groups & set(ugroups)),
            "groups": ugroups,
            "roles": {k: sorted(v) for k, v in sorted(roles.items())},
        }
    return rights


def diff_rights(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        if b == a:
            continue
        ch: dict[str, Any] = {"username": name}
        if b is None:
            ch["change"] = "nieuw"
        elif a is None:
            ch["change"] = "verwijderd"
        else:
            ch["change"] = "gewijzigd"
        b_roles = (b or {}).get("roles", {}) if (b or {}).get("active", False) else {}
        a_roles = (a or {}).get("roles", {}) if (a or {}).get("active", False) else {}
        gained = {app: sorted(set(rs) - set(b_roles.get(app, []))) for app, rs in a_roles.items()}
        lost = {app: sorted(set(rs) - set(a_roles.get(app, []))) for app, rs in b_roles.items()}
        ch["roles_gained"] = {k: v for k, v in gained.items() if v}
        ch["roles_lost"] = {k: v for k, v in lost.items() if v}
        ch["superuser_before"] = bool((b or {}).get("superuser"))
        ch["superuser_after"] = bool((a or {}).get("superuser"))
        ch["active_before"] = (b or {}).get("active")
        ch["active_after"] = (a or {}).get("active")
        ch["groups_added"] = sorted(set((a or {}).get("groups", [])) - set((b or {}).get("groups", [])))
        ch["groups_removed"] = sorted(set((b or {}).get("groups", [])) - set((a or {}).get("groups", [])))
        changes.append(ch)
    return changes


def latest_snapshot(session: Session, kind: str, complete_only: bool = True) -> SsoAuthentikSnapshot | None:
    stmt = select(SsoAuthentikSnapshot).where(SsoAuthentikSnapshot.kind == kind)
    if complete_only:
        stmt = stmt.where(SsoAuthentikSnapshot.complete)
    return session.scalar(stmt.order_by(SsoAuthentikSnapshot.taken_at.desc()).limit(1))


def store_snapshot(
    session: Session, kind: str, content: dict[str, Any], complete: bool, version: str | None, actor: Actor, tid: str
) -> SsoAuthentikSnapshot:
    raw = canonical(content)
    row = SsoAuthentikSnapshot(
        id=uuid.uuid4(),
        kind=kind,
        taken_at=utcnow(),
        taken_by=actor[1],
        authentik_version=version,
        complete=complete,
        content=content,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        trace_id=uuid.UUID(tid),
    )
    session.add(row)
    session.flush()
    return row


def refresh_rights(
    session: Session, client: AuthentikClient, caps: compat.ApiCapabilities, actor: Actor, tid: str
) -> dict[str, Any]:
    state = read_state(client, ("users", "groups"), caps=caps)
    if not state.complete or state.get("users") is None or state.get("groups") is None:
        return {"status": "onvolledig", "missing": state.missing, "changes": [], "snapshot_id": None}
    role_map = roles_by_group(session)
    rights = build_rights(state.parts["users"], state.parts["groups"], role_map)
    content = {"rights": rights, "role_map": role_map, "version": state.version}
    previous = latest_snapshot(session, "rechten")
    if (
        previous is not None
        and previous.content.get("rights") == rights
        and previous.content.get("role_map") == role_map
    ):
        # niets veranderd: geen nieuwe momentopname (de worker draait elke paar minuten)
        return {"status": "ongewijzigd", "changes": [], "snapshot_id": str(previous.id), "previous_id": None}
    snap = store_snapshot(session, "rechten", content, True, state.version, actor, tid)
    if previous is None:
        return {"status": "basislijn", "changes": [], "snapshot_id": str(snap.id), "previous_id": None}
    changes = diff_rights(previous.content.get("rights", {}), rights)
    emitted = 0
    for ch in changes:
        if emitted >= MAX_CHANGE_EVENTS:
            break
        revoked = (
            bool(ch["roles_lost"])
            or (ch["active_before"] and ch["active_after"] is False)
            or ch["change"] == "verwijderd"
        )
        if revoked:
            events.emit(
                session,
                event_type="sso.access.revoked",
                entity_type="authentik_user",
                entity_id=ch["username"],
                actor_type=actor[0],
                actor_id=actor[1],
                trace_id=tid,
                classification="sensitive",
                payload={k: ch[k] for k in ("change", "roles_lost", "active_before", "active_after", "groups_removed")},
            )
            emitted += 1
        if ch["roles_gained"] or ch["superuser_after"] != ch["superuser_before"] or ch["groups_added"]:
            events.emit(
                session,
                event_type="sso.access.changed",
                entity_type="authentik_user",
                entity_id=ch["username"],
                actor_type=actor[0],
                actor_id=actor[1],
                trace_id=tid,
                classification="sensitive",
                payload={
                    k: ch[k] for k in ("change", "roles_gained", "superuser_before", "superuser_after", "groups_added")
                },
            )
            emitted += 1
        admin_gain = any(set(rs) & ADMIN_ROLES.get(app, set()) for app, rs in ch["roles_gained"].items())
        if admin_gain or (ch["superuser_after"] and not ch["superuser_before"]):
            _record_anomaly(
                session,
                rule_id="beheerrecht_toegekend",
                dedupe_key=f"beheer:{ch['username']}:{snap.id}",
                severity="hoog",
                subject=ch["username"],
                message_nl=f"{ch['username']} kreeg beheerrechten (superuser of beheerrol via een groep).",
                details={"roles_gained": ch["roles_gained"], "superuser_after": ch["superuser_after"]},
                first_seen=snap.taken_at,
                last_seen=snap.taken_at,
                count=1,
                actor=actor,
                tid=tid,
            )
    return {
        "status": "vergeleken",
        "changes": changes,
        "truncated_events": len(changes) > MAX_CHANGE_EVENTS,
        "snapshot_id": str(snap.id),
        "previous_id": str(previous.id),
    }


def rights_view(session: Session) -> dict[str, Any]:
    latest = latest_snapshot(session, "rechten")
    if latest is None:
        return {"status": "onbekend", "message_nl": "Nog geen volledige rechtenkaart gelezen.", "rights": None}
    prev = session.scalar(
        select(SsoAuthentikSnapshot)
        .where(
            SsoAuthentikSnapshot.kind == "rechten",
            SsoAuthentikSnapshot.complete,
            SsoAuthentikSnapshot.taken_at < latest.taken_at,
        )
        .order_by(SsoAuthentikSnapshot.taken_at.desc())
        .limit(1)
    )
    rights = latest.content.get("rights", {})
    return {
        "status": "ok",
        "observed_at": iso(latest.taken_at),
        "authentik_version": latest.authentik_version,
        "snapshot_id": str(latest.id),
        "rights": rights,
        "role_map": latest.content.get("role_map", {}),
        "apps": {
            a: APP_BY_ID[a].display_name
            for a in sorted({x for m in latest.content.get("role_map", {}).values() for x in m})
            if a in APP_BY_ID
        },
        "differences": diff_rights(prev.content.get("rights", {}), rights) if prev is not None else [],
        "compared_with": str(prev.id) if prev is not None else None,
        "compared_with_at": iso(prev.taken_at) if prev is not None else None,
    }


# ------------------------------------------------------------------ synchronisatie (worker of API)
def sync(session: Session, client: AuthentikClient, actor: Actor, tid: str) -> dict[str, Any]:
    started = utcnow()
    previous = _state_get(session, SYNC_KEY) or {}
    result: dict[str, Any] = {"started_at": iso(started), "status": "ok", "reason": None}
    try:
        caps = read_version(client)
        result["authentik_version"] = caps.version
        if not caps.readable:
            raise AuthentikError(f"versie_{caps.support}")
        wm = _state_get(session, WATERMARK_KEY)
        raw, complete, new_wm = fetch_new_events(client, caps, wm)
        new = ingest(session, raw)
        _state_put(session, WATERMARK_KEY, new_wm)
        anomalies = detect_anomalies(session, new, actor, tid)
        result["events"] = {"new": len(new), "complete": complete}
        if not complete:
            result["status"] = "onvolledig"
            result["reason"] = "events_niet_volledig_gelezen"
        rights = refresh_rights(session, client, caps, actor, tid)
        result["rights"] = {k: v for k, v in rights.items() if k != "changes"} | {
            "changes": len(rights.get("changes", []))
        }
        if rights["status"] == "onvolledig":
            result["status"], result["reason"] = "onvolledig", "rechten_niet_volledig_gelezen"
        result["anomalies_new"] = int(
            session.scalar(select(func.count()).where(SsoAnomaly.detected_at >= started)) or 0
        )
        result["anomalies_from_events"] = len(anomalies)
    except AuthentikError as exc:
        result["status"] = "fout"
        result["reason"] = exc.reason
    result["finished_at"] = iso(utcnow())
    _state_put(session, SYNC_KEY, result)
    if result["status"] == "fout" and previous.get("status") != "fout":
        events.emit(
            session,
            event_type="sso.authentik.sync.failed",
            entity_type="integration_source",
            entity_id="authentik",
            actor_type=actor[0],
            actor_id=actor[1],
            trace_id=tid,
            payload={"reason": result["reason"]},
        )
    return result


def sync_state(session: Session) -> dict[str, Any] | None:
    return _state_get(session, SYNC_KEY)
