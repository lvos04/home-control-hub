"""Connectorcontract ``/connector/v1/*`` (contract §6).

Deze dienst levert in P0 alleen ``read``. ``propose``/``apply``/``rollback`` geven eerlijk ``501
capability_unavailable`` (nooit gesimuleerd succes); ``stream`` bestaat als polling-outbox via ``/events``.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import APP_ID, CONNECTOR_PREFIX, SCHEMA_VERSION, __version__
from .deps import get_session
from .domains.energy.router import coverage_payload as energy_coverage
from .domains.sso import service as sso_service
from .domains.sso.catalog import APP_COVERAGE
from .domains.sso.models import SsoAdminAccount, SsoBreakGlassDrill
from .errors import ApiError, capability_unavailable, forbidden, not_found
from .events import envelope
from .health import connector_health
from .models import AuditEvent, OutboxEvent
from .pagination import MAX_LIMIT, decode_cursor, encode_cursor
from .redact import redact
from .security.auth import Principal, require_admin_or_service, require_connector_reader
from .sources import ALL_SOURCES, source_view
from .timeutil import iso, utcnow

router = APIRouter(prefix=CONNECTOR_PREFIX, tags=["connector"])

ITEM_TYPES: dict[str, dict[str, Any]] = {
    "source": {"roles": {"admin", "operator", "viewer", "service"}, "title_nl": "Bronnen (catalogus + toestand)"},
    "sso.app_coverage": {"roles": {"admin", "operator", "viewer", "service"}, "title_nl": "SSO-dekkingsmatrix"},
    "sso.recovery_status": {"roles": {"admin", "operator", "service"}, "title_nl": "Herstelstatus (totaal)"},
    "sso.admin_account": {"roles": {"admin"}, "title_nl": "Beheeraccounts (herstelregister)"},
    "energy.coverage": {"roles": {"admin", "operator", "viewer", "service"}, "title_nl": "Energie-dekkingsmatrix"},
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
        "capabilities": ["read", "stream"],
        "unavailable_capabilities": ["propose", "apply", "rollback"],
        "stream_mode": "polling via /connector/v1/events en push naar de Hub-inbox",
        "permissions": [
            "read:sources",
            "read:sso.app_coverage",
            "read:sso.recovery_status",
            "read:sso.admin_account (alleen admin)",
            "read:energy.coverage",
            "read:events",
            "read:evidence",
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
        data = [c.to_dict() for c in APP_COVERAGE]
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
    summary="Voorstel (niet beschikbaar in deze versie)",
    responses={501: {"description": "capability_unavailable"}},
)
def propose(_p: Principal = Depends(require_admin_or_service)) -> None:
    raise capability_unavailable("propose")


@router.post(
    "/apply",
    summary="Uitvoeren (niet beschikbaar in deze versie)",
    responses={501: {"description": "capability_unavailable"}},
)
def apply(_p: Principal = Depends(require_admin_or_service)) -> None:
    raise capability_unavailable("apply", "Uitvoeren is in deze versie niet beschikbaar; er wordt niets uitgevoerd.")


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
