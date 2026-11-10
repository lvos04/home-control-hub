"""Connectorcontract ``/connector/v1/*`` (contract §6).

- ``read`` en ``stream`` (polling-outbox via ``/events``).
- ``propose`` (P1, B13): voorstellen voor Authentik met preview/diff/``preview_hash`` (R2). Alleen lezen in Authentik.
- ``apply``/``rollback`` geven eerlijk ``501 capability_unavailable``: toepassen vereist een door de Hub ondertekend
  ``ExecutionRequest`` (contract §8) en komt in P2. Er wordt nooit iets gesimuleerd of stil uitgevoerd.
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
from .security.auth import AuthFirstRoute, Principal, require_admin_or_service, require_connector_reader
from .sources import ALL_SOURCES, source_view
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
}
UNBUILT_ITEM_TYPES = {
    "network.device": "network.devices.read",
    "network.dns_summary": "network.dns.summary.read",
    "automation.flow": "automation.flows.read",
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
        "capabilities": ["read", "propose", "stream"],
        "unavailable_capabilities": ["apply", "rollback"],
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
        ],
        "apply_status_nl": sso_proposals.APPLY_UNAVAILABLE_NL,
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
            "read:events",
            "read:evidence",
            "read:hub_link",
            "unlink:hub_link (Hub of admin)",
        ],
        "item_types": {k: v["title_nl"] for k, v in ITEM_TYPES.items()},
        "unbuilt_item_types": UNBUILT_ITEM_TYPES,
        "limits": {"max_page_size": MAX_LIMIT, "outbound_timeout_s": {"connect": 5, "read": 15}, "max_retries": 3},
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
    summary="Voorstel maken: preview, diff, preview_hash en resource_etag (R2; alleen lezen in Authentik)",
    responses={
        409: {"description": "authentik_niet_ingesteld, authentik_versie_niet_geverifieerd of resource_gewijzigd"},
        422: {"description": "onbekende_actie, validation_error of voorstel_geblokkeerd (met blokkades)"},
        502: {"description": "Authentik weigerde het token, mist rechten of gaf een ongeldig antwoord"},
        503: {"description": "Authentik onbereikbaar"},
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


@router.post(
    "/apply",
    summary="Uitvoeren (niet beschikbaar in deze versie: vereist ondertekend ExecutionRequest, P2)",
    responses={501: {"description": "capability_unavailable"}},
)
def apply(_p: Principal = Depends(require_admin_or_service)) -> None:
    raise ApiError(
        501,
        "capability_unavailable",
        "Uitvoeren is in deze versie niet beschikbaar; er wordt niets uitgevoerd. "
        + sso_proposals.APPLY_UNAVAILABLE_NL,
        {
            "capability": "apply",
            "reden": "nog_niet_toepasbaar",
            "vereist": "door de Hub ondertekend ExecutionRequest (§8)",
        },
    )


@router.post(
    "/rollback",
    summary="Terugdraaien (niet beschikbaar in deze versie)",
    responses={501: {"description": "capability_unavailable"}},
)
def rollback(_p: Principal = Depends(require_admin_or_service)) -> None:
    raise capability_unavailable("rollback")


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
