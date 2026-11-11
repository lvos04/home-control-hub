"""Connectorcontract ``/connector/v1/*`` (contract §6).

- ``read`` en ``stream`` (polling-outbox via ``/events``).
- ``propose`` (P1, B13): voorstellen voor Authentik met preview/diff/``preview_hash`` (R2). Alleen lezen in Authentik.
  P2 (B11-005): ook ``automation.flows.restore`` — flows van Node-RED terugzetten naar een momentopname (R2).
- ``apply`` (P2, B11-005): alleen ``automation.flows.restore`` en alleen met een door de Hub **ondertekend**
  ``ExecutionRequest`` (contract §8) met een menselijke goedkeuring; deze dienst controleert alles zelf opnieuw
  (``domains/automation/restore.py``). Voor de Authentik-acties blijft ``apply`` eerlijk
  ``501 capability_unavailable``. Er wordt nooit iets gesimuleerd of stil uitgevoerd.
- ``rollback`` geeft ``501 capability_unavailable``: terugdraaien van een herstel is een nieuw voorstel naar de
  momentopname ``voor_herstel`` (met een nieuwe goedkeuring), geen aparte route.
- Nieuw in contract 1.2 (§6, §3.8): ``GET /connector/v1/hub-link`` (koppelstatus: witte lijst van §3.5 + gepinde
  ``kid``'s en ``rotation_sequence``; dienst-JWT of gebruiker ``viewer``+) en ``POST /connector/v1/hub-link/unlink``
  (ontkoppelen door de Hub met een dienst-JWT of door een beheerder; ``Idempotency-Key``).
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Body, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import APP_ID, CONNECTOR_PREFIX, SCHEMA_VERSION, __version__
from .deps import get_session, trace_id
from .domains.automation import actions as automation_actions
from .domains.automation import restore as automation_restore
from .domains.automation import snapshots as automation_snapshots
from .domains.automation.models import (
    AutomationActionRequest,
    AutomationFlow,
    AutomationRestore,
    AutomationSnapshot,
)
from .domains.energy.router import coverage_payload as energy_coverage
from .domains.sso import proposals as sso_proposals
from .domains.sso import service as sso_service
from .domains.sso.authentik_router import ProposeIn, anomaly_dict, validate_parameters
from .domains.sso.backup import export_meta
from .domains.sso.mapping import coverage as sso_coverage
from .domains.sso.mapping import mapping_dict
from .domains.sso.models import (
    SsoAdminAccount,
    SsoAnomaly,
    SsoAuthentikSnapshot,
    SsoBreakGlassDrill,
    SsoGroupRoleMapping,
    SsoProposal,
)
from .errors import ApiError, capability_unavailable, forbidden, not_found
from .events import envelope
from .health import connector_health
from .idempotency import idempotency_key, run_idempotent
from .models import AuditEvent, OutboxEvent
from .pagination import MAX_LIMIT, decode_cursor, encode_cursor
from .redact import redact
from .security import hubkeys
from .security.auth import AuthFirstRoute, Principal, require_admin_or_service, require_connector_reader
from .sources import ALL_SOURCES, PROBE_MAX_AGE, source_view
from .timeutil import iso, utcnow

router = APIRouter(prefix=CONNECTOR_PREFIX, tags=["connector"], route_class=AuthFirstRoute)

ITEM_TYPES: dict[str, dict[str, Any]] = {
    "source": {"roles": {"admin", "operator", "viewer", "service"}, "title_nl": "Bronnen (catalogus + toestand)"},
    "sso.app_coverage": {"roles": {"admin", "operator", "viewer", "service"}, "title_nl": "SSO-dekkingsmatrix"},
    "sso.recovery_status": {"roles": {"admin", "operator", "service"}, "title_nl": "Herstelstatus (totaal)"},
    "sso.admin_account": {"roles": {"admin"}, "title_nl": "Beheeraccounts (herstelregister)"},
    "energy.coverage": {"roles": {"admin", "operator", "viewer", "service"}, "title_nl": "Energie-dekkingsmatrix"},
    "sso.role_mapping": {
        "roles": {"admin", "operator", "viewer", "service"},
        "title_nl": "Authentik-groep → rol per app",
    },
    "sso.proposal": {"roles": {"admin", "operator", "service"}, "title_nl": "Voorstellen (preview, niet toepasbaar)"},
    "sso.anomaly": {"roles": {"admin", "operator", "service"}, "title_nl": "Afwijkingen uit Authentik"},
    "automation.flow": {
        "roles": {"admin", "operator", "viewer", "service"},
        "title_nl": "Flows van Node-RED (eigenaar, status, versie)",
    },
    "automation.action_request": {
        "roles": {"admin", "operator", "service"},
        "title_nl": "Actieverzoeken van flows (aangevraagd, nooit hier uitgevoerd)",
    },
    "automation.restore": {
        "roles": {"admin", "operator", "service"},
        "title_nl": "Herstelvoorstellen voor flows (preview en uitkomst)",
    },
}
#: §6.2: standaard max_age 900 s; de bronmetingen van deze dienst gebruiken dezelfde grens (sources.PROBE_MAX_AGE)
MAX_AGE_S = int(PROBE_MAX_AGE.total_seconds())
UNBUILT_ITEM_TYPES = {
    "network.device": "network.devices.read",
    "network.dns_summary": "network.dns.summary.read",
    "energy.usage": "energy.usage.read",
}


@router.get("/discover", summary="Wat deze dienst kan (contract §6)")
def discover(_p: Principal = Depends(require_connector_reader)) -> dict[str, Any]:
    domains: dict[str, list[dict[str, Any]]] = {}
    for spec in ALL_SOURCES.values():
        domains.setdefault(spec.domain, []).extend(c.to_dict() for c in spec.capabilities)
    return {
        "app_id": APP_ID,
        "source_version": __version__,
        "schema_version": SCHEMA_VERSION,
        # apply bestaat alleen voor acties met apply_status 'vereist_execution_request' (zie actions hieronder)
        "capabilities": ["read", "propose", "apply", "stream"],
        "unavailable_capabilities": ["rollback"],
        "stream_mode": "polling via /connector/v1/events en push naar de Hub-inbox",
        "actions": [
            {
                "action_id": a.action_id,
                "title_nl": a.title_nl,
                "task_id": a.task_id,
                "risk_class_min": a.risk_class,
                "apply_status": a.apply_status,
            }
            for a in sso_proposals.ACTIONS.values()
        ]
        + [
            {
                "action_id": automation_restore.ACTION_ID,
                "title_nl": automation_restore.TITLE_NL,
                "task_id": automation_restore.TASK_ID,
                "risk_class_min": automation_restore.MIN_RISK_CLASS,
                "apply_status": automation_restore.APPLY_STATUS,
            }
        ],
        "apply_status_nl": sso_proposals.APPLY_UNAVAILABLE_NL,
        "apply_status_per_actie_nl": {
            "nog_niet_toepasbaar": sso_proposals.APPLY_UNAVAILABLE_NL,
            automation_restore.APPLY_STATUS: automation_restore.APPLY_STATUS_NL,
        },
        "permissions": [
            "read:sources",
            "read:sso.app_coverage",
            "read:sso.recovery_status",
            "read:sso.admin_account (alleen admin)",
            "read:energy.coverage",
            "read:sso.role_mapping",
            "read:sso.proposal",
            "read:sso.anomaly",
            "propose:sso.oidc.hub.register (admin of Hub)",
            "propose:sso.sessions.revoke (admin of Hub)",
            "read:automation.flow",
            "read:automation.action_request",
            "read:automation.restore",
            "propose:automation.flows.restore (admin of Hub)",
            "apply:automation.flows.restore (alleen met ondertekend ExecutionRequest van de Hub)",
            "read:events",
            "read:evidence",
            "read:hub_link",
            "unlink:hub_link (Hub of admin)",
        ],
        "item_types": {k: v["title_nl"] for k, v in ITEM_TYPES.items()},
        "unbuilt_item_types": UNBUILT_ITEM_TYPES,
        "limits": {
            "max_page_size": MAX_LIMIT,
            "outbound_timeout_s": {"connect": 5, "read": 15},
            "max_retries": 3,
            # contract 1.3 §6.2: na deze leeftijd is een meting 'unknown' (meting_verouderd); een afnemer mag strenger
            "max_age_s": {"source": MAX_AGE_S, "health": MAX_AGE_S},
        },
        "domains": domains,
        "timestamp_utc": iso(utcnow()),
    }


@router.get("/health", summary="Gezondheid volgens het connectorcontract")
def health(
    request: Request, session: Session = Depends(get_session), _p: Principal = Depends(require_connector_reader)
) -> dict[str, Any]:
    return connector_health(request, session)


def _offset_page(items: list[Any], cursor: str | None, limit: int) -> dict[str, Any]:
    start = decode_cursor(cursor) or 0
    if not isinstance(start, int) or start < 0:
        raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.")
    chunk = items[start : start + limit]
    nxt = encode_cursor(start + limit) if start + limit < len(items) else None
    return {"items": chunk, "next_cursor": nxt}


@router.get("/items", summary="Eigen data, gepagineerd, met rolcontrole per type")
def items(
    request: Request,
    type: str = Query(..., description="Itemtype, zie /discover"),
    cursor: str | None = None,
    limit: int = Query(default=50, ge=1, le=MAX_LIMIT),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_connector_reader),
) -> dict[str, Any]:
    if type in UNBUILT_ITEM_TYPES:
        raise capability_unavailable(
            UNBUILT_ITEM_TYPES[type], "Dit itemtype is nog niet gebouwd; er wordt geen data verzonnen."
        )
    spec = ITEM_TYPES.get(type)
    if spec is None:
        raise ApiError(400, "invalid_type", "Onbekend itemtype; zie /connector/v1/discover.", {"type": type})
    if not principal.has_any(spec["roles"]):
        raise forbidden("rol_ontbreekt", "Geen toestemming voor dit itemtype.")
    data: list[Any]
    if type == "source":
        data = [source_view(session, s) for s in ALL_SOURCES.values()]
    elif type == "sso.app_coverage":
        data = sso_coverage(session)
    elif type == "sso.role_mapping":
        data = [
            mapping_dict(m)
            for m in session.scalars(
                select(SsoGroupRoleMapping).order_by(SsoGroupRoleMapping.app_id, SsoGroupRoleMapping.authentik_group)
            )
        ]
    elif type == "sso.proposal":
        data = [
            sso_proposals.proposal_view(p)
            for p in session.scalars(select(SsoProposal).order_by(SsoProposal.created_at.desc()).limit(MAX_LIMIT * 5))
        ]
    elif type == "sso.anomaly":
        data = [
            anomaly_dict(a)
            for a in session.scalars(select(SsoAnomaly).order_by(SsoAnomaly.detected_at.desc()).limit(MAX_LIMIT * 5))
        ]
    elif type == "sso.recovery_status":
        st = sso_service.overall(session, request.app.state.settings.break_glass_test_max_age_days)
        st.pop("accounts", None)
        data = [st]
    elif type == "energy.coverage":
        data = energy_coverage()["items"]
    elif type == "automation.flow":
        data = [
            {
                "id": str(f.id),
                "source_flow_id": f.source_flow_id,
                "label": f.label,
                "owner": f.owner,
                "status": f.status,
                "blocked_reason": f.blocked_reason,
                "version": f.version,
                "last_seen_at": iso(f.last_seen_at),
            }
            for f in session.scalars(
                select(AutomationFlow).order_by(AutomationFlow.label, AutomationFlow.id).limit(MAX_LIMIT * 5)
            )
        ]
    elif type == "automation.action_request":
        data = [
            automation_actions.request_view(r)
            for r in session.scalars(
                select(AutomationActionRequest)
                .order_by(AutomationActionRequest.created_at.desc(), AutomationActionRequest.id.desc())
                .limit(MAX_LIMIT * 5)
            )
        ]
    elif type == "automation.restore":
        data = [
            automation_restore.restore_view(r)
            for r in session.scalars(
                select(AutomationRestore)
                .order_by(AutomationRestore.created_at.desc(), AutomationRestore.id.desc())
                .limit(MAX_LIMIT * 5)
            )
        ]
    else:  # sso.admin_account
        data = [
            sso_service.account_dict(a)
            for a in session.scalars(select(SsoAdminAccount).order_by(SsoAdminAccount.created_at))
        ]
    result = _offset_page(data, cursor, limit)
    return {"type": type, **result, "timestamp_utc": iso(utcnow())}


@router.post(
    "/propose",
    status_code=201,
    summary="Voorstel maken: preview, diff, preview_hash en resource_etag (R2; alleen lezen in de bron)",
    responses={
        409: {
            "description": "authentik_niet_ingesteld, authentik_versie_niet_geverifieerd, resource_gewijzigd, "
            "node_red_niet_ingesteld, momentopname_onleesbaar of niets_te_herstellen"
        },
        422: {
            "description": "onbekende_actie, validation_error, voorstel_geblokkeerd, parameters_ongeldig of "
            "momentopname_niet_toegestaan"
        },
        502: {"description": "De bron weigerde de aanmelding, mist rechten of gaf een ongeldig antwoord"},
        503: {"description": "De bron (Authentik of Node-RED) is onbereikbaar"},
    },
)
def propose(
    body: ProposeIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    if body.action_id == automation_restore.ACTION_ID:
        return _propose_restore(body, request, session, principal, key, tid)
    params = validate_parameters(body.action_id, body.parameters)

    def action() -> tuple[int, Any, dict[str, str]]:
        view = sso_proposals.create_proposal(request, session, principal, tid, body.action_id, params)
        if body.expected_version and body.expected_version != view["resource_etag"]:
            raise ApiError(
                409,
                "resource_gewijzigd",
                "De toestand in Authentik is gewijzigd sinds de vorige preview; bekijk het nieuwe voorstel.",
                {"expected_version": body.expected_version, "resource_etag": view["resource_etag"]},
            )
        return 201, view, {"ETag": f'"{view["preview_hash"]}"'}

    return run_idempotent(request, session, principal, key, body.model_dump(mode="json"), action)


def _propose_restore(
    body: ProposeIn, request: Request, session: Session, principal: Principal, key: uuid.UUID, tid: str
) -> Any:
    """B11-005: voorstel om de flows van Node-RED terug te zetten. Leest alleen; ``risk_claim`` telt niet (EX18)."""
    if body.target is not None and body.target != automation_restore.TARGET:
        raise ApiError(
            422,
            "parameters_ongeldig",
            "Het doel van dit voorstel is altijd de bron 'node_red'.",
            {"verwacht": {"target": automation_restore.TARGET}},
        )

    def action() -> tuple[int, Any, dict[str, str]]:
        state = request.app.state
        view = automation_restore.propose(
            session,
            state.settings,
            state.vault,
            state.http_transport,
            parameters=body.parameters,
            principal=principal,
            trace_id=tid,
            now=utcnow(),
        )
        if body.expected_version and body.expected_version != view["resource_etag"]:
            raise ApiError(
                409,
                "resource_gewijzigd",
                "De flows in Node-RED zijn gewijzigd sinds de vorige preview; bekijk het nieuwe voorstel.",
                {"expected_version": body.expected_version, "resource_etag": view["resource_etag"]},
            )
        return 201, view, {"ETag": f'"{view["preview_hash"]}"'}

    return run_idempotent(request, session, principal, key, body.model_dump(mode="json"), action)


def _policy_keys(request: Request) -> list[Any]:
    """De gepinde policy-sleutels van de Hub; leeg zolang deze dienst niet gekoppeld is (dan wordt niets uitgevoerd)."""
    link = request.app.state.hublink.state()
    if not link.linked or link.pins is None:
        return []
    keys = []
    for pin in link.pins.policy:
        try:
            keys.append(hubkeys.public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": pin.jwk.x}))
        except ValueError:
            continue
    return keys


@router.post(
    "/apply",
    summary="Uitvoeren: alleen met een door de Hub ondertekend ExecutionRequest (§8); nu alleen flows terugzetten",
    responses={
        200: {"description": "Uitgevoerd en met readback bevestigd"},
        403: {"description": "forbidden — handtekening, geldigheid, eigen lijst, risicoklasse of goedkeuring"},
        409: {"description": "nonce_al_gebruikt, goedkeuring_past_niet, resource_gewijzigd of voorstel_verlopen"},
        422: {"description": "ongeldig_verzoek of parameters_ongeldig"},
        501: {"description": "capability_unavailable — deze actie is (nog) niet toepasbaar"},
        502: {"description": "node_red_fout — Node-RED weigerde of het resultaat is niet bevestigd"},
        503: {"description": "node_red_unavailable — er is niets gewijzigd"},
    },
)
def apply(
    request: Request,
    body: dict[str, Any] = Body(...),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    proposal = body.get("proposal")
    action_id = proposal.get("action_id") if isinstance(proposal, dict) else None
    if isinstance(action_id, str) and action_id in sso_proposals.ACTIONS:
        # de Authentik-acties hebben nog geen uitvoerpad: eerlijk 501, er wordt geen nonce opgemaakt
        raise ApiError(
            501,
            "capability_unavailable",
            "Uitvoeren is voor deze actie niet beschikbaar; er wordt niets uitgevoerd. "
            + sso_proposals.APPLY_UNAVAILABLE_NL,
            {"capability": "apply", "reden": "nog_niet_toepasbaar", "action_id": action_id},
        )

    def action() -> tuple[int, Any, dict[str, str]]:
        state = request.app.state
        return automation_restore.apply(
            session,
            state.settings,
            state.vault,
            state.http_transport,
            request=body,
            keys=_policy_keys(request),
            principal=principal,
            trace_id=tid,
            now=utcnow(),
        )

    return run_idempotent(request, session, principal, key, body, action)


@router.post(
    "/rollback",
    summary="Terugdraaien (niet beschikbaar: een herstel draai je terug met een nieuw voorstel)",
    responses={501: {"description": "capability_unavailable"}},
)
def rollback(_p: Principal = Depends(require_admin_or_service)) -> None:
    raise capability_unavailable(
        "rollback",
        "Terugdraaien is geen aparte route. Een herstel van flows draai je terug met een nieuw voorstel naar de "
        "momentopname 'voor_herstel' (met een nieuwe goedkeuring).",
    )


@router.get("/evidence/{evidence_id}", summary="Geredigeerd bewijs (audit-event of oefening)")
def evidence(
    evidence_id: str, session: Session = Depends(get_session), _p: Principal = Depends(require_admin_or_service)
) -> dict[str, Any]:
    try:
        eid = uuid.UUID(evidence_id)
    except ValueError as exc:
        raise not_found("Bewijs") from exc
    ev = session.get(AuditEvent, eid)
    if ev is not None:
        record = {
            "at": iso(ev.at),
            "domain": ev.domain,
            "action": ev.action,
            "entity_type": ev.entity_type,
            "entity_id": ev.entity_id,
            "actor": {"type": ev.actor_type, "id": ev.actor_id},
            "trace_id": str(ev.trace_id),
            "message_nl": ev.message_nl,
            "details": ev.details,
        }
        return {"id": evidence_id, "kind": "audit_event", "record": redact(record)}
    drill = session.get(SsoBreakGlassDrill, eid)
    if drill is not None:
        return {"id": evidence_id, "kind": "sso_break_glass_drill", "record": redact(sso_service.drill_dict(drill))}
    prop = session.get(SsoProposal, eid)
    if prop is not None:
        return {"id": evidence_id, "kind": "sso_proposal", "record": sso_proposals.proposal_view(prop)}
    snap = session.get(SsoAuthentikSnapshot, eid)
    if snap is not None and snap.kind == "config_export":
        return {"id": evidence_id, "kind": "sso_config_export", "record": export_meta(snap)}
    restore_row = session.get(AutomationRestore, eid)
    if restore_row is not None:
        return {
            "id": evidence_id,
            "kind": "automation_restore",
            "record": automation_restore.restore_view(restore_row),
        }
    flow_snapshot = session.get(AutomationSnapshot, eid)
    if flow_snapshot is not None:
        # alleen kenmerken (checksum, aantallen, beleid); nooit de inhoud of het credentials-bestand
        return {
            "id": evidence_id,
            "kind": "automation_snapshot",
            "record": automation_snapshots.snapshot_view(flow_snapshot),
        }
    action_request = session.get(AutomationActionRequest, eid)
    if action_request is not None:
        return {
            "id": evidence_id,
            "kind": "automation_action_request",
            "record": redact(automation_actions.request_view(action_request)),
        }
    raise not_found("Bewijs")


@router.get("/events", summary="Outbox pollen (contract §7)")
def poll_events(
    cursor: str | None = None,
    limit: int = Query(default=100, ge=1, le=MAX_LIMIT),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin_or_service),
) -> dict[str, Any]:
    after = decode_cursor(cursor) or 0
    if not isinstance(after, int):
        raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.")
    rows = list(
        session.scalars(select(OutboxEvent).where(OutboxEvent.seq > after).order_by(OutboxEvent.seq).limit(limit))
    )
    dead = session.scalar(select(func.count()).where(OutboxEvent.delivery_status == "dead_letter")) or 0
    return {
        "items": [envelope(r) for r in rows],
        "next_cursor": encode_cursor(rows[-1].seq) if rows else cursor,
        "dead_letter_count": dead,
    }


def hub_link_view(request: Request) -> dict[str, Any]:
    st = request.app.state.hublink.state()
    view = st.public()
    view["pinned_kids"] = {
        "jwt": [p.kid for p in st.pins.jwt] if st.pins else [],
        "policy": [p.kid for p in st.pins.policy] if st.pins else [],
    }
    view["rotation_sequence"] = st.pins.rotation_sequence if st.pins else None
    view["observed_at"] = iso(utcnow())
    return view


@router.get("/hub-link", summary="Koppelstatus met de Hub (witte lijst §3.5, gepinde kid's, rotation_sequence)")
def hub_link(request: Request, _p: Principal = Depends(require_connector_reader)) -> dict[str, Any]:
    return hub_link_view(request)


@router.post(
    "/hub-link/unlink",
    summary="Ontkoppelen (§3.8): door de Hub met een dienst-JWT of door een beheerder; Idempotency-Key verplicht",
    responses={401: {"description": "o.a. not_linked als al ontkoppeld (telt voor de Hub als geslaagd)"}},
)
def hub_link_unlink(
    request: Request,
    _body: dict[str, Any] | None = Body(default=None),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    if _body:
        raise ApiError(422, "validation_error", "Ontkoppelen heeft geen invoer; stuur een lege body of {}.")

    def action() -> tuple[int, Any, dict[str, str]]:
        request.app.state.hublink.unlink(trace_id=tid, actor=(principal.actor_type, principal.audit_id))
        return 200, hub_link_view(request), {}

    return run_idempotent(request, session, principal, key, {"unlink": True}, action)
