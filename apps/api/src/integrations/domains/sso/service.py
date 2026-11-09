"""B13-001 — databasekant: views, zelftest, herstelregister en gereedheid."""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import APP_ID, __version__, events
from ...deps import etag
from ...models import IntegrationSource, ServiceState
from ...sources import probe_source
from ...timeutil import iso, utcnow
from . import recovery
from .kit import PROCEDURE_NL, canonical
from .models import (
    SsoAdminAccount,
    SsoBreakGlassActivation,
    SsoBreakGlassDrill,
    SsoEmergencyAccess,
    SsoRecoveryMethod,
)

READINESS_STATE_KEY = "sso_readiness_level"


def account_dict(a: SsoAdminAccount) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "system": a.system,
        "username": a.username,
        "display_name": a.display_name,
        "is_break_glass": a.is_break_glass,
        "login_kind": a.login_kind,
        "mfa_status": a.mfa_status,
        "mfa_methods": list(a.mfa_methods or []),
        "mfa_attested_at": iso(a.mfa_attested_at),
        "mfa_attested_by": a.mfa_attested_by,
        "status": a.status,
        "notes": a.notes,
        "version": a.version,
        "etag": etag(a.version),
        "created_at": iso(a.created_at),
        "created_by": a.created_by,
        "updated_at": iso(a.updated_at),
        "updated_by": a.updated_by,
    }


def method_dict(m: SsoRecoveryMethod) -> dict[str, Any]:
    return {
        "id": str(m.id),
        "account_id": str(m.account_id),
        "method_type": m.method_type,
        "storage_hint": m.storage_hint,
        "sso_independent": m.sso_independent,
        "status": m.status,
        "last_verified_at": iso(m.last_verified_at),
        "version": m.version,
        "created_at": iso(m.created_at),
        "created_by": m.created_by,
    }


def emergency_dict(e: SsoEmergencyAccess) -> dict[str, Any]:
    due = e.last_reviewed_at + timedelta(days=e.review_interval_days)
    return {
        "id": str(e.id),
        "account_id": str(e.account_id),
        "network_scopes": e.network_scopes,
        "session_max_minutes": e.session_max_minutes,
        "review_interval_days": e.review_interval_days,
        "last_reviewed_at": iso(e.last_reviewed_at),
        "last_reviewed_by": e.last_reviewed_by,
        "review_due_at": iso(due),
        "status": e.status,
        "reason": e.reason,
        "version": e.version,
        "etag": etag(e.version),
    }


def drill_dict(d: SsoBreakGlassDrill) -> dict[str, Any]:
    return {
        "id": str(d.id),
        "account_id": str(d.account_id),
        "method_id": str(d.method_id) if d.method_id else None,
        "mode": d.mode,
        "outcome": d.outcome,
        "authenticator_state": d.authenticator_state,
        "client_scope": d.client_scope,
        "checks": d.checks,
        "notes": d.notes,
        "performed_by": d.performed_by,
        "performed_at": iso(d.performed_at),
        "trace_id": str(d.trace_id),
        "validation_nl": (
            "Zelftest van configuratie en beleid (geen echte login)."
            if d.mode == "zelftest"
            else "Handmatig bevestigd door een beheerder (attestatie)."
        ),
    }


def activation_dict(a: SsoBreakGlassActivation) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "account_id": str(a.account_id),
        "mode": a.mode,
        "client_ip": a.client_ip,
        "matched_scope": a.matched_scope,
        "activated_at": iso(a.activated_at),
        "expires_at": iso(a.expires_at),
        "closed_at": iso(a.closed_at),
        "reported_by": a.reported_by,
        "rotation_required": a.rotation_required,
        "rotated_at": iso(a.rotated_at),
        "rotated_by": a.rotated_by,
    }


def load_views(session: Session) -> list[recovery.AccountView]:
    accounts = list(session.scalars(select(SsoAdminAccount).order_by(SsoAdminAccount.created_at)))
    methods = list(session.scalars(select(SsoRecoveryMethod)))
    emergencies = {e.account_id: e for e in session.scalars(select(SsoEmergencyAccess))}
    drills = list(
        session.scalars(select(SsoBreakGlassDrill).order_by(SsoBreakGlassDrill.performed_at.desc()).limit(1000))
    )
    rotations = dict(
        session.execute(
            select(SsoBreakGlassActivation.account_id, func.count())
            .where(SsoBreakGlassActivation.rotation_required, SsoBreakGlassActivation.rotated_at.is_(None))
            .group_by(SsoBreakGlassActivation.account_id)
        ).all()
    )
    views: list[recovery.AccountView] = []
    for a in accounts:
        em = emergencies.get(a.id)
        views.append(
            recovery.AccountView(
                id=str(a.id),
                system=a.system,
                username=a.username,
                status=a.status,
                is_break_glass=a.is_break_glass,
                login_kind=a.login_kind,
                mfa_status=a.mfa_status,
                methods=[{"method_type": m.method_type, "status": m.status} for m in methods if m.account_id == a.id],
                emergency=(
                    {
                        "status": em.status,
                        "scopes": em.network_scopes,
                        "last_reviewed_at": em.last_reviewed_at,
                        "review_interval_days": em.review_interval_days,
                    }
                    if em
                    else None
                ),
                drills=[
                    {"mode": d.mode, "outcome": d.outcome, "performed_at": d.performed_at}
                    for d in drills
                    if d.account_id == a.id
                ],
                open_rotations=int(rotations.get(a.id, 0)),
            )
        )
    return views


def overall(session: Session, drill_max_age_days: int) -> dict[str, Any]:
    result = recovery.evaluate_overall(load_views(session), utcnow(), drill_max_age_days)
    result["health"] = recovery.LEVEL_TO_HEALTH[result["level"]]
    result["evaluated_at"] = iso(utcnow())
    result["authenticator_required"] = False
    return result


def emit_readiness_change(session: Session, drill_max_age_days: int, trace_id: str, actor: tuple[str, str]) -> None:
    """Emit ``sso.recovery.readiness_changed`` als het totaalniveau wijzigt (Hub kan het cachen)."""
    session.flush()
    level = recovery.evaluate_overall(load_views(session), utcnow(), drill_max_age_days)["level"]
    row = session.get(ServiceState, READINESS_STATE_KEY)
    previous = row.value.get("level") if row is not None else None
    if previous == level:
        return
    if row is None:
        session.add(ServiceState(key=READINESS_STATE_KEY, value={"level": level, "at": iso(utcnow())}))
    else:
        row.value = {"level": level, "at": iso(utcnow())}
    events.emit(
        session,
        event_type="sso.recovery.readiness_changed",
        entity_type="sso_recovery_register",
        entity_id=APP_ID,
        actor_type=actor[0],
        actor_id=actor[1],
        trace_id=trace_id,
        payload={"previous": previous, "level": level, "health": recovery.LEVEL_TO_HEALTH[level]},
    )


def authenticator_state(request: Request, session: Session) -> tuple[str, dict[str, Any]]:
    """Bereikbaarheid van Authentik voor de oefening; faalt nooit (is alleen informatie)."""
    row = session.get(IntegrationSource, "authentik")
    if row is None or not row.base_url or not row.enabled:
        return "niet_geconfigureerd", {}
    try:
        status, reason, detail = probe_source(request, session, "authentik")
    except Exception:  # pragma: no cover - een probe mag een oefening nooit laten crashen
        return "onbekend", {"reason": "probe_fout"}
    state = {"healthy": "online", "down": "offline"}.get(status, "onbekend")
    return state, {"reason": reason, **detail}


def run_selftest(
    request: Request, session: Session, account: SsoAdminAccount, method: SsoRecoveryMethod | None
) -> tuple[str, str, list[dict[str, Any]]]:
    """Zelftest van configuratie en beleid. Raadpleegt Authentik alleen ter informatie."""
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail_nl: str, informational: bool = False) -> None:
        checks.append(
            {"name": name, "status": "info" if informational else ("ok" if ok else "mislukt"), "detail_nl": detail_nl}
        )

    check("account_actief", account.status == "actief", f"Accountstatus: {account.status}.")
    check(
        "lokale_login",
        account.login_kind != "sso",
        "Inloggen kan zonder SSO." if account.login_kind != "sso" else "Account kan alleen via SSO inloggen.",
    )
    methods = list(session.scalars(select(SsoRecoveryMethod).where(SsoRecoveryMethod.account_id == account.id)))
    active = [m for m in methods if m.status == "actief"]
    independent = [m for m in active if m.sso_independent]
    check(
        "herstelmethodes",
        len(active) >= 2 and bool(independent),
        f"{len(active)} actieve herstelmethode(s), waarvan {len(independent)} zonder SSO.",
    )
    if method is not None:
        check(
            "methode_actief",
            method.status == "actief" and method.account_id == account.id,
            f"Geoefende methode: {method.method_type} ({method.status}).",
        )
    if account.is_break_glass:
        em = session.scalar(select(SsoEmergencyAccess).where(SsoEmergencyAccess.account_id == account.id))
        has_policy = em is not None and em.status == "actief" and bool(em.network_scopes)
        check(
            "noodtoegang_geregistreerd",
            has_policy,
            "Actieve LAN/VPN-noodtoegang." if has_policy else "Geen actieve noodtoegang.",
        )
        if em is not None and has_policy:
            inside, outside = recovery.probe_addresses(em.network_scopes)

            def _eval(ip: str) -> recovery.Evaluation:
                return recovery.evaluate_access(
                    account_status=account.status,
                    is_break_glass=account.is_break_glass,
                    login_kind=account.login_kind,
                    policy_status=em.status if em else None,
                    scopes=em.network_scopes if em else None,
                    session_max_minutes=em.session_max_minutes if em else None,
                    client_ip=ip,
                )

            ev_in, ev_out = _eval(inside), _eval(outside)
            check("beleid_binnen_bereik", ev_in.allowed, f"Testadres {inside} binnen het bereik wordt toegelaten.")
            check(
                "beleid_buiten_bereik_geweigerd",
                not ev_out.allowed,
                f"Documentatie-adres {outside} (internet) wordt geweigerd.",
            )
    state, detail = authenticator_state(request, session)
    check(
        "authenticator",
        True,
        f"Authentik: {state}. De beoordeling hierboven gebruikte Authentik niet.",
        informational=True,
    )
    checks[-1]["detail"] = detail
    failed = [c for c in checks if c["status"] == "mislukt"]
    return ("mislukt" if failed else "ok"), state, checks


def build_register(session: Session, drill_max_age_days: int, created_by: str) -> dict[str, Any]:
    accounts = list(session.scalars(select(SsoAdminAccount).order_by(SsoAdminAccount.system, SsoAdminAccount.username)))
    out_accounts = []
    for a in accounts:
        methods = session.scalars(select(SsoRecoveryMethod).where(SsoRecoveryMethod.account_id == a.id))
        em = session.scalar(select(SsoEmergencyAccess).where(SsoEmergencyAccess.account_id == a.id))
        drills = session.scalars(
            select(SsoBreakGlassDrill)
            .where(SsoBreakGlassDrill.account_id == a.id)
            .order_by(SsoBreakGlassDrill.performed_at.desc())
            .limit(3)
        )
        out_accounts.append(
            {
                "system": a.system,
                "username": a.username,
                "display_name": a.display_name,
                "is_break_glass": a.is_break_glass,
                "login_kind": a.login_kind,
                "mfa_status": a.mfa_status,
                "mfa_methods": list(a.mfa_methods or []),
                "status": a.status,
                "recovery_methods": [
                    {
                        "method_type": m.method_type,
                        "storage_hint": m.storage_hint,
                        "sso_independent": m.sso_independent,
                        "status": m.status,
                        "last_verified_at": iso(m.last_verified_at),
                    }
                    for m in methods
                ],
                "emergency_access": (
                    {
                        "network_scopes": em.network_scopes,
                        "session_max_minutes": em.session_max_minutes,
                        "review_interval_days": em.review_interval_days,
                        "last_reviewed_at": iso(em.last_reviewed_at),
                        "status": em.status,
                    }
                    if em
                    else None
                ),
                "recent_drills": [
                    {
                        "mode": d.mode,
                        "outcome": d.outcome,
                        "authenticator_state": d.authenticator_state,
                        "performed_at": iso(d.performed_at),
                    }
                    for d in drills
                ],
            }
        )
    register = {"accounts": out_accounts}
    readiness = overall(session, drill_max_age_days)
    return {
        "service": {"app_id": APP_ID, "version": __version__},
        "created_at": iso(utcnow()),
        "created_by": created_by,
        "register": register,
        "register_sha256": hashlib.sha256(canonical(register)).hexdigest(),
        "readiness": {"level": readiness["level"], "reasons": readiness["reasons"], "counts": readiness["counts"]},
        "procedure_nl": list(PROCEDURE_NL),
        "contains_secrets": False,
    }


def close_expired_activations(session: Session) -> int:
    now = utcnow()
    rows = list(
        session.scalars(
            select(SsoBreakGlassActivation).where(
                SsoBreakGlassActivation.closed_at.is_(None), SsoBreakGlassActivation.expires_at <= now
            )
        )
    )
    for a in rows:
        a.closed_at = a.expires_at
        events.emit(
            session,
            event_type="sso.break_glass.expired",
            entity_type="sso_break_glass_activation",
            entity_id=str(a.id),
            actor_type="system",
            actor_id=APP_ID,
            trace_id=str(uuid.uuid4()),
            classification="sensitive",
            payload={"account_id": str(a.account_id), "mode": a.mode},
        )
    return len(rows)
