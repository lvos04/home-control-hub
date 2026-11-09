"""Voorstellen voor wijzigingen in Authentik (connectorcontract §6 ``propose``; risicobeleid §8).

Stroom: Hub/admin → ``POST /connector/v1/propose`` → deze dienst leest Authentik (alleen GET), bouwt een plan met
diff, exacte verzoeken, ``resource_etag`` en ``preview_hash`` en bewaart het als ``sso_proposal``.

**Toepassen kan in deze versie niet.** Contract §8 eist een door de Hub ondertekend ``ExecutionRequest`` (policy-engine,
gebonden goedkeuring, nonce); die keten bestaat pas in fase P2. Daarom: ``apply_status = nog_niet_toepasbaar`` (in de
database afgedwongen) en ``/connector/v1/apply`` geeft eerlijk ``501``. Er wordt nooit iets naar Authentik geschreven.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ... import audit, events
from ...errors import ApiError
from ...security.auth import Principal
from ...timeutil import iso, utcnow
from .authentik.client import AuthentikClient, AuthentikError, client_from_source
from .authentik.reader import read_bindings, read_state, read_version
from .models import SsoGroupRoleMapping, SsoProposal
from .oidc_hub import ACTION_ID as HUB_OIDC_ACTION
from .oidc_hub import HUB_APP_ID, HubOidcParams, Plan, build_hub_oidc_plan, sha256_obj

PROPOSAL_TTL = timedelta(minutes=60)
SESSIONS_ACTION = "sso.sessions.revoke"
MAX_SESSIONS = 200


@dataclass(frozen=True)
class ActionSpec:
    action_id: str
    title_nl: str
    task_id: str
    risk_class: str
    apply_status: str = "nog_niet_toepasbaar"


ACTIONS: dict[str, ActionSpec] = {
    HUB_OIDC_ACTION: ActionSpec(
        HUB_OIDC_ACTION, "OIDC-provider en -applicatie voor de Hub in Authentik", "B13-002", "R2"
    ),
    SESSIONS_ACTION: ActionSpec(
        SESSIONS_ACTION, "Authentik-sessies intrekken (na herstel/upgrade of lek)", "B13-005", "R2"
    ),
}

APPLY_UNAVAILABLE_NL = (
    "Toepassen is in deze versie niet beschikbaar: het vereist een door de Hub ondertekend ExecutionRequest "
    "(contract §8) en die keten komt in fase P2. Er is niets in Authentik gewijzigd."
)


def authentik_api_error(exc: AuthentikError) -> ApiError:
    """Vertaalt een Authentik-fout naar het contractfoutformaat; nooit een gesimuleerd resultaat."""
    if exc.reason in ("niet_geconfigureerd", "uitgeschakeld", "geen_token", "ongeldig_adres"):
        return ApiError(409, "authentik_niet_ingesteld", exc.message_nl, exc.to_dict())
    if exc.reason in ("onbereikbaar", "timeout", "http_5xx"):
        return ApiError(503, "authentik_onbereikbaar", exc.message_nl, exc.to_dict())
    if exc.reason == "token_ongeldig":
        return ApiError(502, "authentik_token_geweigerd", exc.message_nl, exc.to_dict())
    if exc.reason == "geen_rechten":
        return ApiError(502, "authentik_geen_rechten", exc.message_nl, exc.to_dict())
    return ApiError(502, "authentik_antwoord_ongeldig", exc.message_nl, exc.to_dict())


def authentik_client(request: Request, session: Session) -> AuthentikClient:
    state = request.app.state
    try:
        return client_from_source(session, state.settings, state.vault, state.http_transport)
    except AuthentikError as exc:
        raise authentik_api_error(exc) from exc


def hub_role_groups(session: Session) -> list[tuple[str, str]]:
    rows = session.scalars(
        select(SsoGroupRoleMapping)
        .where(SsoGroupRoleMapping.app_id == HUB_APP_ID)
        .order_by(SsoGroupRoleMapping.authentik_group)
    )
    return [(r.authentik_group, r.role) for r in rows]


# ------------------------------------------------------------------ plannen per actie
def _plan_hub_oidc(client: AuthentikClient, session: Session, parameters: dict[str, Any]) -> Plan:
    params = HubOidcParams(**parameters)
    caps = read_version(client)
    _require_verified(caps)
    state = read_state(
        client, ("flows", "scope_mappings", "signing_keys", "providers", "applications", "groups"), caps=caps
    )
    app = next((a for a in state.get("applications") or [] if a.get("slug") == params.application_slug), None)
    bindings = read_bindings(client, str(app["pk"])) if app is not None else None
    return build_hub_oidc_plan(state, params, hub_role_groups(session), bindings)


def _plan_sessions(client: AuthentikClient, _session: Session, parameters: dict[str, Any]) -> Plan:
    usernames: list[str] = list(parameters.get("usernames") or [])
    everyone = bool(parameters.get("all_users"))
    caps = read_version(client)
    _require_verified(caps)
    plan = Plan(
        action_id=SESSIONS_ACTION,
        target={
            "system": "authentik",
            "scope": "alle_gebruikers" if everyone else "gebruikers",
            "usernames": sorted(usernames),
        },
        parameters={"usernames": sorted(usernames), "all_users": everyone},
        authentik_version=str(caps.version),
    )
    rows: list[dict[str, Any]] = []
    if everyone:
        rows, complete = client.list_all("/core/authenticated_sessions/")
        if not complete:
            plan.blockers.append(
                {"code": "te_veel_sessies", "message_nl": "Te veel sessies om in één voorstel te tonen."}
            )
    else:
        for name in usernames:
            part, complete = client.list_all("/core/authenticated_sessions/", {"user__username": name})
            if not complete:
                plan.blockers.append({"code": "te_veel_sessies", "message_nl": f"Te veel sessies voor {name}."})
            rows.extend(part)
    sessions = sorted(
        (
            {"uuid": str(r.get("uuid")), "user": r.get("user"), "last_used": r.get("last_used")}
            for r in rows
            if r.get("uuid")
        ),
        key=lambda x: str(x["uuid"]),
    )
    if len(sessions) > MAX_SESSIONS:
        plan.blockers.append(
            {"code": "te_veel_sessies", "message_nl": f"Meer dan {MAX_SESSIONS} sessies; beperk tot gebruikers."}
        )
    plan.resource_basis = {"version": str(caps.version), "sessions": [s["uuid"] for s in sessions]}
    if plan.blockers:
        return plan
    per_user: dict[str, int] = {}
    for s in sessions:
        per_user[str(s["user"])] = per_user.get(str(s["user"]), 0) + 1
    plan.diff = [
        {
            "object": "authenticated_session",
            "key": s["uuid"],
            "operation": "intrekken",
            "changes": [{"field": "user", "before": s["user"], "after": None}],
        }
        for s in sessions
    ]
    plan.requests = [
        {"method": "DELETE", "path": f"/api/v3/core/authenticated_sessions/{s['uuid']}/"} for s in sessions
    ]
    plan.rollback_recipe = [
        {
            "toelichting_nl": "Niet terug te draaien: ingetrokken sessies moeten opnieuw inloggen (bedoeld na herstel of lek)."
        }
    ]
    plan.blast_radius = {
        "apps": ["authentik"],
        "sessions": len(sessions),
        "users": len(per_user),
        "local_login_unchanged": True,
        "toelichting_nl": "Gebruikers moeten opnieuw inloggen bij Authentik; lokale accounts en noodtoegang blijven werken.",
    }
    plan.notes_nl.append("Na intrekken moet iedereen in de lijst opnieuw inloggen (met MFA waar ingesteld).")
    if not sessions:
        plan.notes_nl.append("Er zijn geen actieve sessies gevonden; het voorstel wijzigt niets.")
    return plan


PLANNERS = {HUB_OIDC_ACTION: _plan_hub_oidc, SESSIONS_ACTION: _plan_sessions}


def _require_verified(caps: Any) -> None:
    if not caps.proposals_allowed:
        raise ApiError(
            409,
            "authentik_versie_niet_geverifieerd",
            "Voor deze Authentik-versie zijn voorstellen niet toegestaan (API-schema niet gecontroleerd).",
            caps.to_dict(),
        )


# ------------------------------------------------------------------ opslag en weergave
def proposal_view(p: SsoProposal) -> dict[str, Any]:
    preview = p.preview or {}
    return {
        "proposal_id": str(p.id),
        "action_id": p.action_id,
        "target": p.target,
        "parameters": p.parameters,
        "preview_hash": p.preview_hash,
        "resource_etag": p.resource_etag,
        "diff": preview.get("diff", []),
        "requests": preview.get("requests", []),
        "blast_radius": preview.get("blast_radius", {}),
        "risk_claim": p.risk_claim,
        "rollback_recipe": preview.get("rollback_recipe", []),
        "requires_backup": True,
        "changes": preview.get("changes", 0),
        "warnings": preview.get("warnings", []),
        "notes_nl": preview.get("notes_nl", []),
        "authentik_version": p.authentik_version,
        "status": "verlopen" if p.status == "voorstel" and p.expires_at <= utcnow() else p.status,
        "apply_status": p.apply_status,
        "apply_status_nl": APPLY_UNAVAILABLE_NL,
        "created_at": iso(p.created_at),
        "created_by": p.created_by,
        "expires_at": iso(p.expires_at),
    }


def create_proposal(
    request: Request, session: Session, principal: Principal, tid: str, action_id: str, parameters: dict[str, Any]
) -> dict[str, Any]:
    spec = ACTIONS.get(action_id)
    if spec is None:
        raise ApiError(
            422, "onbekende_actie", "Onbekende action_id; zie /connector/v1/discover.", {"action_id": action_id}
        )
    client = authentik_client(request, session)
    try:
        plan = PLANNERS[action_id](client, session, parameters)
    except AuthentikError as exc:
        raise authentik_api_error(exc) from exc
    if plan.blockers:
        raise ApiError(
            422,
            "voorstel_geblokkeerd",
            "Er kan (nog) geen voorstel gemaakt worden; los eerst de blokkades op.",
            {"blockers": plan.blockers, "resource_etag": plan.resource_etag},
        )
    now = utcnow()
    row = SsoProposal(
        id=uuid.uuid4(),
        action_id=action_id,
        target=plan.target,
        parameters=plan.parameters,
        preview=plan.preview(),
        preview_hash=plan.preview_hash,
        resource_etag=plan.resource_etag,
        risk_claim=spec.risk_class,
        authentik_version=plan.authentik_version,
        status="voorstel",
        apply_status="nog_niet_toepasbaar",
        created_by=principal.audit_id,
        created_at=now,
        expires_at=now + PROPOSAL_TTL,
        trace_id=uuid.UUID(tid),
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        domain="sso",
        action="proposal.created",
        entity_type="sso_proposal",
        entity_id=str(row.id),
        principal=principal,
        trace_id=tid,
        message_nl=f"Voorstel '{spec.title_nl}' gemaakt (alleen preview; niet toegepast).",
        details={"action_id": action_id, "preview_hash": row.preview_hash, "changes": plan.changes},
    )
    events.emit(
        session,
        event_type="sso.proposal.created",
        entity_type="sso_proposal",
        entity_id=str(row.id),
        actor_type=principal.actor_type,
        actor_id=principal.audit_id,
        trace_id=tid,
        payload={
            "action_id": action_id,
            "risk_claim": spec.risk_class,
            "preview_hash": row.preview_hash,
            "changes": plan.changes,
        },
    )
    return proposal_view(row)


def preview_fingerprint(plan: Plan) -> str:
    return sha256_obj({"preview_hash": plan.preview_hash, "resource_etag": plan.resource_etag})
