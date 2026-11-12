"""B11 — beheer-API voor de Node-RED-automatisering onder ``/integrations/v1/automation`` (alleen met een Hub-JWT).

Rechten (least privilege):
- lezen (flows, catalogus, isolatie, proefruns, verzoeken): ``admin``, ``operator`` en ``viewer``;
- het adres van de Node-RED-editor, het beveiligingsprofiel, eigenaar/triggers/grenzen en flow-tokens: alleen ``admin``;
- pauzeren/hervatten, momentopname, isolatiemeting, proefrun en opnieuw aanbieden: ``admin`` of ``operator``;
- events aanbieden en de uitkomst van een actieverzoek melden: alleen de Hub (dienst-JWT).

Een flow zelf komt hier nooit: die heeft alleen de flow-API (``flowapi.py``). Deze dienst voert via deze routes niets
uit in Node-RED behalve lezen; terugzetten van flows loopt uitsluitend via ``/connector/v1/propose`` en
``/connector/v1/apply`` met een ondertekend ExecutionRequest van de Hub (B11-005).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select, tuple_
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import InstrumentedAttribute

from ... import API_PREFIX, audit, events
from ...deps import get_session, if_match, trace_id
from ...errors import ApiError, not_found
from ...idempotency import idempotency_key, run_idempotent
from ...models import IntegrationSource
from ...pagination import decode_cursor, encode_cursor, limit_param
from ...redact import looks_like_secret
from ...security.auth import (
    SERVICE_ROLE,
    AuthFirstRoute,
    Principal,
    require_admin,
    require_admin_or_operator,
    require_reader,
    require_roles,
)
from ...sources import source_ref, source_view
from ...timeutil import iso, utcnow
from .. import DOMAIN_TITLES_NL
from . import actions, eventcatalog, inbox, nodered, policy, simulate, snapshots
from .catalog import (
    FORBIDDEN_NODE_FILES,
    FORBIDDEN_NODE_TYPES,
    FORBIDDEN_NODE_TYPES_VERIFICATION,
    NODE_RED_DIGEST,
    NODE_RED_IMAGE,
    NODE_RED_TAG,
    SOURCES,
)
from .models import (
    CATALOG_STATUSES,
    DELIVERY_STATUSES,
    FLOW_STATUSES,
    REQUEST_STATUSES,
    RESTORE_STATUSES,
    AutomationActionRequest,
    AutomationDelivery,
    AutomationEvent,
    AutomationFlow,
    AutomationFlowOwner,
    AutomationFlowRun,
    AutomationFlowToken,
    AutomationFlowVersion,
    AutomationRateLimit,
    AutomationRestore,
    AutomationSnapshot,
    AutomationTrigger,
)
from .restore import restore_view

router = APIRouter(prefix=f"{API_PREFIX}/automation", tags=["automation"], route_class=AuthFirstRoute)
require_service = require_roles(SERVICE_ROLE)
Result = tuple[int, Any, dict[str, str]]

MAX_TRIGGERS = 50
MAX_OWNERS = 20
MAX_LIMITS = 50
MAX_TOKENS_PER_FLOW = 5
MAX_ALLOWED_ACTIONS = 30
ONCE = "eenmalig getoond; niet opnieuw op te vragen"
PRINCIPAL_RE = r"^[A-Za-z0-9._@:+-]{1,200}$"


# ---------------------------------------------------------------------------------------------------------- hulpjes
def _bad_cursor() -> ApiError:
    return ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.")


def _page_seq(
    session: Session, stmt: Any, column: InstrumentedAttribute[int], cursor: str | None, limit: int, view: Any
) -> dict[str, Any]:
    """Nieuwste eerst op een oplopend volgnummer."""
    after = decode_cursor(cursor)
    if after is not None:
        if not isinstance(after, int) or isinstance(after, bool):
            raise _bad_cursor()
        stmt = stmt.where(column < after)
    rows = list(session.scalars(stmt.order_by(column.desc()).limit(limit + 1)))
    nxt = encode_cursor(getattr(rows[limit - 1], column.key)) if len(rows) > limit else None
    return {"items": [view(r) for r in rows[:limit]], "next_cursor": nxt}


def _page_time(
    session: Session,
    stmt: Any,
    ts_column: InstrumentedAttribute[datetime],
    id_column: InstrumentedAttribute[uuid.UUID],
    cursor: str | None,
    limit: int,
    view: Any,
) -> dict[str, Any]:
    """Nieuwste eerst op (tijdstip, id)."""
    after = decode_cursor(cursor)
    if after is not None:
        try:
            ts, rid = datetime.fromisoformat(after[0]), uuid.UUID(after[1])
        except (ValueError, TypeError, IndexError, KeyError) as exc:
            raise _bad_cursor() from exc
        stmt = stmt.where(tuple_(ts_column, id_column) < tuple_(ts, rid))
    rows = list(session.scalars(stmt.order_by(ts_column.desc(), id_column.desc()).limit(limit + 1)))
    nxt = None
    if len(rows) > limit:
        last = rows[limit - 1]
        nxt = encode_cursor([getattr(last, ts_column.key).isoformat(), str(getattr(last, id_column.key))])
    return {"items": [view(r) for r in rows[:limit]], "next_cursor": nxt}


def _one_of(value: str | None, allowed: tuple[str, ...], field: str) -> str | None:
    if value is not None and value not in allowed:
        raise ApiError(
            422, "validation_error", f"Onbekende waarde voor '{field}'.", {"veld": field, "toegestaan": list(allowed)}
        )
    return value


def _flow_or_404(session: Session, flow_id: uuid.UUID, *, lock: bool = False) -> AutomationFlow:
    flow = session.get(AutomationFlow, flow_id, with_for_update=lock)
    if flow is None:
        raise not_found("Flow")
    return flow


def _config(session: Session, flow: AutomationFlow) -> dict[str, Any]:
    """Wat een beheerder aan een flow instelt (los van de inhoud in Node-RED)."""
    owners = session.scalars(
        select(AutomationFlowOwner)
        .where(AutomationFlowOwner.flow_id == flow.id)
        .order_by(AutomationFlowOwner.principal)
    ).all()
    triggers = session.scalars(
        select(AutomationTrigger)
        .where(AutomationTrigger.flow_id == flow.id)
        .order_by(AutomationTrigger.event_type, AutomationTrigger.schema_version)
    ).all()
    limits = session.scalars(
        select(AutomationRateLimit)
        .where(AutomationRateLimit.flow_id == flow.id)
        .order_by(AutomationRateLimit.action_id)
    ).all()
    return {
        "owner": flow.owner,
        "eigenaren": [{"principal": o.principal, "role": o.role, "note": o.note} for o in owners],
        "status": flow.status,
        "triggers": [
            {"event_type": t.event_type, "schema_version": t.schema_version, "filter": t.filter or {}} for t in triggers
        ],
        "rate_limits": [
            {"action_id": r.action_id, "max_per_hour": r.max_per_hour, "cooldown_s": r.cooldown_s} for r in limits
        ],
    }


def _config_etag(config: dict[str, Any]) -> str:
    """ETag van de instellingen van een flow. De flow heeft geen rijversie die alleen bij een beheerwijziging oploopt
    (de synchronisatie werkt de rij elke keer bij), dus de ETag is een hash over de instellingen zelf."""
    return f'W/"cfg-{policy.sha256_hex(policy.canonical(config))[:16]}"'


def _check_etag(current: str, given: str | None) -> None:
    if given is None:
        raise ApiError(
            428,
            "precondition_required",
            "Header 'If-Match' met de ETag is verplicht bij het wijzigen van een bestaand object.",
        )
    if given not in ("*", current):
        raise ApiError(
            412,
            "precondition_failed",
            "Het object is intussen gewijzigd; haal het opnieuw op en probeer het nog eens.",
            {"huidige_etag": current},
        )


def _version_view(v: AutomationFlowVersion) -> dict[str, Any]:
    return {
        "id": str(v.id),
        "seq": v.seq,
        "checksum_sha256": v.checksum_sha256,
        "node_count": v.node_count,
        "node_types": list(v.node_types or []),
        "policy_status": v.policy_status,
        "findings": list(v.findings or []),
        "snapshot_id": str(v.snapshot_id) if v.snapshot_id else None,
        "created_at": iso(v.created_at),
        "created_by": v.created_by,
    }


def _flow_brief(flow: AutomationFlow) -> dict[str, Any]:
    return {
        "id": str(flow.id),
        "source_id": flow.source_id,
        "source_flow_id": flow.source_flow_id,
        "label": flow.label,
        "owner": flow.owner,
        "status": flow.status,
        "blocked_reason": flow.blocked_reason,
        "blocked_at": iso(flow.blocked_at),
        "version": flow.version,
        "current_version_id": str(flow.current_version_id) if flow.current_version_id else None,
        "disabled_in_node_red": flow.disabled_in_node_red,
        "last_seen_at": iso(flow.last_seen_at),
    }


def _flow_detail(session: Session, flow: AutomationFlow) -> dict[str, Any]:
    config = _config(session, flow)
    version = session.get(AutomationFlowVersion, flow.current_version_id) if flow.current_version_id else None
    active_tokens = session.scalar(
        select(func.count())
        .select_from(AutomationFlowToken)
        .where(AutomationFlowToken.flow_id == flow.id, AutomationFlowToken.status == "actief")
    )
    return {
        **_flow_brief(flow),
        "eigenaren": config["eigenaren"],
        "triggers": config["triggers"],
        "rate_limits": {"standaard_max_per_uur": actions.DEFAULT_MAX_PER_HOUR, "eigen": config["rate_limits"]},
        "current_version": _version_view(version) if version is not None else None,
        "actieve_tokens": int(active_tokens or 0),
        "niet_afgeschermde_typen": simulate.unshielded_types(session, flow),
        "etag": _config_etag(config),
    }


def _token_view(t: AutomationFlowToken) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "flow_id": str(t.flow_id),
        "label": t.label,
        "last4": t.last4,
        "status": t.status,
        "allowed_actions": list(t.allowed_actions or []),
        "created_at": iso(t.created_at),
        "created_by": t.created_by,
        "last_used_at": iso(t.last_used_at),
        "revoked_at": iso(t.revoked_at),
        "revoked_reason": t.revoked_reason,
    }


def _event_view(e: AutomationEvent) -> dict[str, Any]:
    return {
        "seq": e.seq,
        "event_id": str(e.event_id),
        "source_app": e.source_app,
        "source_event_id": e.source_event_id,
        "event_type": e.event_type,
        "schema_version": e.envelope_version,
        "entity": {"type": e.entity_type, "id": e.entity_id},
        "timestamp_utc": iso(e.timestamp_utc),
        "classification": e.classification,
        "catalog_status": e.catalog_status,
        "catalog_detail": e.catalog_detail or {},
        "origin_chain": list(e.origin_chain or []),
        "received_at": iso(e.received_at),
        "received_by": e.received_by,
        "proefrun": e.test_run_id is not None,
    }


def _no_secret(value: str | None, field: str) -> str | None:
    if value and looks_like_secret(value):
        raise ValueError(f"{field} lijkt een token, sleutel of wachtwoord te bevatten; sla hier geen geheimen op")
    return value


def _flow_event(
    session: Session, event_type: str, flow: AutomationFlow, principal: Principal, tid: str, payload: dict[str, Any]
) -> None:
    events.emit(
        session,
        event_type=event_type,
        entity_type="flow",
        entity_id=str(flow.id),
        actor_type=principal.actor_type,
        actor_id=principal.audit_id,
        trace_id=tid,
        payload=payload,
    )


# ------------------------------------------------------------------------------------------- capabilities en beleid
@router.get("/capabilities", summary=f"Capabilities en bronnen — {DOMAIN_TITLES_NL['automation']}")
def capabilities(session: Session = Depends(get_session), _p: Principal = Depends(require_reader)) -> dict[str, Any]:
    return {
        "domain": "automation",
        "title_nl": DOMAIN_TITLES_NL["automation"],
        "sources": [source_view(session, s) for s in SOURCES],
        "unavailable_routes": {},
    }


@router.get("/policy", summary="Vaste veiligheidsregels voor flows (B11-001/B11-003)")
def automation_policy(request: Request, _p: Principal = Depends(require_reader)) -> dict[str, Any]:
    return {
        "forbidden_node_types": list(FORBIDDEN_NODE_TYPES),
        "forbidden_node_files": list(FORBIDDEN_NODE_FILES),
        "forbidden_node_types_verification": FORBIDDEN_NODE_TYPES_VERIFICATION,
        "allowed_modules": list(request.app.state.settings.node_red_allowed_modules),
        "actions_via": "Hub-actieverzoek (policy bepaalt de risicoklasse; risk_claim van een flow telt niet)",
        "action_refusals": dict(sorted(actions.REFUSALS_NL.items())),
        "default_max_per_hour": actions.DEFAULT_MAX_PER_HOUR,
        "node_red_image": {"repository": NODE_RED_IMAGE, "tag": NODE_RED_TAG, "digest": NODE_RED_DIGEST},
        "never_nl": [
            "Geen shell-/exec-uitvoering vanuit flows.",
            "Verwijderen of wissen (bv. een dataset) kan nooit via een flow, ook niet met goedkeuring.",
            "Boiler schakelen is via elke route verboden.",
        ],
    }


# ----------------------------------------------------------------------------------------------- isolatie (B11-001)
@router.get("/isolation", summary="Laatst gemeten isolatie van Node-RED en de stand van de synchronisatie")
def get_isolation(session: Session = Depends(get_session), _p: Principal = Depends(require_reader)) -> dict[str, Any]:
    return {
        "isolatie": snapshots.isolation_state(session),
        "synchronisatie": snapshots.state_get(session, snapshots.SYNC_KEY),
        "ingesteld": snapshots.configured(session),
        "flows": snapshots.count_flows(session),
    }


@router.post("/isolation/check", summary="Isolatie van Node-RED nu meten (alleen lezen)")
def post_isolation_check(
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_operator),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        state = request.app.state
        report = snapshots.run_isolation_check(session, state.settings, state.vault, state.http_transport, trace_id=tid)
        audit.record(
            session,
            domain="automation",
            action="automation.isolation.checked",
            entity_type="source",
            entity_id=nodered.SOURCE_ID,
            principal=principal,
            trace_id=tid,
            message_nl=f"Isolatie van Node-RED gemeten: {report['status']}.",
            details={"status": report["status"], "afwijkingen": report["afwijkingen"]},
        )
        return 200, report, {}

    return run_idempotent(request, session, principal, key, {}, action)


class ProfileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: maakt een nieuw wachtwoord voor het beheeraccount van de editor (de container moet daarna opnieuw starten met
    #: de nieuwe argumenten)
    nieuw_beheerwachtwoord: bool = False


def _mask_profile(body: Any) -> Any:
    """De bewaarde kopie voor de Idempotency-Key bevat nooit het wachtwoord of de argumenten met de sleutel."""
    masked = dict(body)
    masked["arguments"] = None
    masked["beheerwachtwoord"] = None
    masked["herhaling_nl"] = (
        "Herhaald antwoord: het wachtwoord en de argumenten worden niet bewaard. Vraag het profiel opnieuw op met een "
        "nieuwe Idempotency-Key voor de argumenten; het wachtwoord is alleen de eerste keer getoond."
    )
    return masked


@router.post(
    "/hardening-profile",
    summary="Beveiligingsprofiel voor de Custom App van Node-RED (formuliervelden en argumenten)",
)
def post_hardening_profile(
    body: ProfileIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        vault = request.app.state.vault
        profile, service_password = policy.build_profile(vault, session, new_admin_password=body.nieuw_beheerwachtwoord)
        replaced_login = False
        if service_password is not None:
            # het dienstaccount is net gemaakt: deze dienst bewaart de aanmelding zelf en toont haar nooit
            row = session.get(IntegrationSource, nodered.SOURCE_ID)
            if row is None:
                row = IntegrationSource(
                    source_id=nodered.SOURCE_ID, domain="automation", updated_by=principal.audit_id, version=1
                )
                session.add(row)
            else:
                replaced_login = bool(row.credential_ref)
                row.version += 1
                row.updated_by = principal.audit_id
            ref = source_ref(nodered.SOURCE_ID)
            vault.put(session, ref, f"{policy.SERVICE_USER}:{service_password}")
            row.credential_ref = ref
        audit.record(
            session,
            domain="automation",
            action="automation.hardening_profile.issued",
            entity_type="source",
            entity_id=nodered.SOURCE_ID,
            principal=principal,
            trace_id=tid,
            message_nl="Beveiligingsprofiel voor Node-RED "
            + ("aangemaakt." if profile.created else "opnieuw getoond.")
            + (" Het beheerwachtwoord is vervangen." if profile.admin_password_rotated else ""),
            details={
                "aangemaakt": profile.created,
                "beheerwachtwoord_vervangen": profile.admin_password_rotated,
                "aanmelding_bron_vervangen": replaced_login,
            },
        )
        out = {
            **profile.form(),
            "aangemaakt": profile.created,
            "beheerwachtwoord_vervangen": profile.admin_password_rotated,
            "aanmelding_bron_vervangen": replaced_login,
            # één argument per regel in het formulier van de Custom App; bevat de wachtwoordhashes en de
            # credentialSecret en hoort daarom nergens anders dan in dat formulier
            "arguments": profile.arguments,
            "beheerwachtwoord": profile.admin_password,
            "beheerwachtwoord_nl": ONCE if profile.admin_password else "al eerder getoond; alleen de hash is bewaard",
            "dienstaccount_nl": "De aanmelding van het dienstaccount staat in de kluis van deze dienst en wordt "
            "nooit getoond.",
            "vervolg_nl": [
                "Installeer Node-RED als Custom App met deze formuliervelden en argumenten.",
                "Stel daarna het adres van Node-RED in bij de bron 'node_red' en zet de bron aan.",
                "Meet de isolatie (POST /integrations/v1/automation/isolation/check).",
            ],
        }
        return (201 if profile.created else 200), out, {}

    return run_idempotent(request, session, principal, key, body.model_dump(), action, stored=_mask_profile)


@router.get("/editor", summary="Adres van de Node-RED-editor (alleen beheerder)")
def get_editor(session: Session = Depends(get_session), _p: Principal = Depends(require_admin)) -> dict[str, Any]:
    row = snapshots.source_row(session)
    if row is None or not row.base_url:
        raise ApiError(409, "node_red_niet_ingesteld", "Node-RED is nog niet als bron ingesteld.")
    isolation = snapshots.isolation_state(session)
    return {
        "url": row.base_url,
        "aanmelden_als": policy.ADMIN_USER,
        "isolatie": isolation["status"],
        "toegang_nl": [
            "Alleen een beheerder krijgt dit adres; een lezer of operator krijgt 403.",
            "Node-RED vraagt zelf een aanmelding; zonder aanmelding geeft de editor geen flows, nodes of instellingen.",
            "Het dienstaccount van deze dienst kan de editor niet beheren (alleen lezen en flows terugzetten).",
        ],
    }


# -------------------------------------------------------------------------------------------------------------- flows
@router.get("/flows", summary="Flows (tabbladen van Node-RED) met eigenaar, status en versie")
def list_flows(
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    stmt = select(AutomationFlow).where(AutomationFlow.source_id == nodered.SOURCE_ID)
    if _one_of(status, FLOW_STATUSES, "status"):
        stmt = stmt.where(AutomationFlow.status == status)
    after = decode_cursor(cursor)
    if after is not None:
        try:
            label, fid = str(after[0]), uuid.UUID(after[1])
        except (ValueError, TypeError, IndexError, KeyError) as exc:
            raise _bad_cursor() from exc
        stmt = stmt.where(tuple_(AutomationFlow.label, AutomationFlow.id) > tuple_(label, fid))
    rows = list(session.scalars(stmt.order_by(AutomationFlow.label, AutomationFlow.id).limit(limit + 1)))
    nxt = encode_cursor([rows[limit - 1].label, str(rows[limit - 1].id)]) if len(rows) > limit else None
    return {
        "items": [_flow_brief(f) for f in rows[:limit]],
        "next_cursor": nxt,
        "ingesteld": snapshots.configured(session),
        "synchronisatie": snapshots.state_get(session, snapshots.SYNC_KEY),
    }


@router.get("/flows/{flow_id}", summary="Eén flow met beleid, triggers, grenzen en huidige versie")
def get_flow(
    flow_id: uuid.UUID, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> dict[str, Any]:
    return _flow_detail(session, _flow_or_404(session, flow_id))


@router.get("/flows/{flow_id}/versions", summary="Versies van een flow (nieuwste eerst)")
def list_flow_versions(
    flow_id: uuid.UUID,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    _flow_or_404(session, flow_id)
    stmt = select(AutomationFlowVersion).where(AutomationFlowVersion.flow_id == flow_id)
    return _page_seq(session, stmt, AutomationFlowVersion.seq, cursor, limit, _version_view)


class OwnerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    principal: str = Field(pattern=PRINCIPAL_RE)
    role: Literal["eigenaar", "bewerker", "lezer"]
    note: str | None = Field(default=None, max_length=500)

    @field_validator("note")
    @classmethod
    def _note(cls, v: str | None) -> str | None:
        return _no_secret(actions.storable(v), "note")


class OwnerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: eigenaarlabel; leeg = geen eigenaar (dan worden de flow-tokens van de flow ingetrokken)
    owner: str = Field(max_length=200)
    eigenaren: list[OwnerEntry] = Field(default_factory=list, max_length=MAX_OWNERS)

    @field_validator("owner")
    @classmethod
    def _owner(cls, v: str) -> str:
        return _no_secret(actions.storable(v).strip(), "owner") or ""


def _flow_mutation(
    request: Request,
    session: Session,
    principal: Principal,
    key: uuid.UUID,
    match: str | None,
    flow_id: uuid.UUID,
    payload: Any,
    change: Any,
) -> Any:
    """Gedeeld verloop van een beheerwijziging op een flow: vergrendelen, ETag controleren, wijzigen, antwoord."""

    def action() -> Result:
        flow = _flow_or_404(session, flow_id, lock=True)
        _check_etag(_config_etag(_config(session, flow)), match)
        change(flow)
        session.flush()
        view = _flow_detail(session, flow)
        return 200, view, {"ETag": view["etag"]}

    return run_idempotent(request, session, principal, key, {"flow_id": str(flow_id), "body": payload}, action)


@router.put("/flows/{flow_id}/owner", summary="Eigenaar en betrokkenen van een flow vastleggen")
def put_flow_owner(
    flow_id: uuid.UUID,
    body: OwnerIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    names = [e.principal for e in body.eigenaren]
    if len(set(names)) != len(names):
        raise ApiError(422, "validation_error", "Elke betrokkene mag maar één keer voorkomen.", {"veld": "eigenaren"})

    def change(flow: AutomationFlow) -> None:
        now = utcnow()
        revoked = 0
        if not body.owner and flow.owner:
            # zonder eigenaar mag een flow niets aanvragen: bestaande tokens vervallen
            revoked = snapshots.revoke_tokens(session, flow.id, "eigenaar_verwijderd", now)
        flow.owner = body.owner
        for existing in session.scalars(select(AutomationFlowOwner).where(AutomationFlowOwner.flow_id == flow.id)):
            session.delete(existing)
        session.flush()
        for entry in body.eigenaren:
            session.add(
                AutomationFlowOwner(flow_id=flow.id, principal=entry.principal, role=entry.role, note=entry.note)
            )
        audit.record(
            session,
            domain="automation",
            action="automation.flow.owner_changed",
            entity_type="flow",
            entity_id=str(flow.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"Eigenaar van flow '{flow.label}' vastgelegd.",
            details={"owner": body.owner, "betrokkenen": len(body.eigenaren), "ingetrokken": revoked},
        )
        _flow_event(
            session,
            "flow.owner.changed",
            flow,
            principal,
            tid,
            {"ernst": "info", "label": flow.label, "heeft_eigenaar": bool(body.owner), "ingetrokken": revoked},
        )

    return _flow_mutation(request, session, principal, key, match, flow_id, body.model_dump(), change)


class StateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["actief", "gepauzeerd"]
    reden: str | None = Field(default=None, max_length=200)

    @field_validator("reden")
    @classmethod
    def _reden(cls, v: str | None) -> str | None:
        return _no_secret(actions.storable(v), "reden")


@router.put("/flows/{flow_id}/state", summary="Flow pauzeren of hervatten (afleveren van events en actieverzoeken)")
def put_flow_state(
    flow_id: uuid.UUID,
    body: StateIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_operator),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    def change(flow: AutomationFlow) -> None:
        before = flow.status
        if before in ("geblokkeerd", "verwijderd"):
            raise ApiError(
                409,
                "flow_status_conflict",
                "Deze flow is geblokkeerd door het flowbeleid of bestaat niet meer in Node-RED; de status is hier "
                "niet te wijzigen.",
                {"status": before, "reden": flow.blocked_reason},
            )
        if body.status == "gepauzeerd":
            flow.status = "gepauzeerd"
        elif before == "gepauzeerd":
            # hervatten: een tabblad dat in Node-RED uit staat blijft eerlijk 'uitgeschakeld'
            flow.status = "uitgeschakeld" if flow.disabled_in_node_red else "actief"
        if flow.status == before:
            return
        audit.record(
            session,
            domain="automation",
            action="automation.flow.state_changed",
            entity_type="flow",
            entity_id=str(flow.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"Flow '{flow.label}': {before} → {flow.status}.",
            details={"van": before, "naar": flow.status, "reden": body.reden},
        )
        _flow_event(
            session,
            "flow.state.changed",
            flow,
            principal,
            tid,
            {"ernst": "info", "label": flow.label, "van": before, "naar": flow.status},
        )

    return _flow_mutation(request, session, principal, key, match, flow_id, body.model_dump(), change)


class TriggerFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_app: str | None = Field(default=None, pattern=eventcatalog.APP_ID_RE.pattern, max_length=64)
    entity_type: str | None = Field(default=None, pattern=eventcatalog.ENTITY_TYPE_RE.pattern)


class TriggerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: str = Field(min_length=5, max_length=128)
    schema_version: str = Field(default="1.0", max_length=10)
    filter: TriggerFilter = Field(default_factory=TriggerFilter)


class TriggersIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    triggers: list[TriggerEntry] = Field(max_length=MAX_TRIGGERS)


@router.put("/flows/{flow_id}/triggers", summary="Op welke eventtypen (met schema-versie) een flow reageert")
def put_flow_triggers(
    flow_id: uuid.UUID,
    body: TriggersIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    problems = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(body.triggers):
        problem = eventcatalog.trigger_problem(entry.event_type, entry.schema_version)
        if problem is None and (entry.event_type, entry.schema_version) in seen:
            problem = "dit eventtype met deze schema-versie staat er al"
        seen.add((entry.event_type, entry.schema_version))
        if problem is not None:
            problems.append({"index": index, "event_type": entry.event_type[:128], "reden": problem})
    if problems:
        raise ApiError(
            422,
            "trigger_ongeldig",
            "Eén of meer triggers verwijzen niet naar een eventtype uit de catalogus.",
            {"fouten": problems[:20]},
        )

    def change(flow: AutomationFlow) -> None:
        if flow.status == "verwijderd":
            raise ApiError(409, "flow_verwijderd", "Deze flow bestaat niet meer in Node-RED.")
        for existing in session.scalars(select(AutomationTrigger).where(AutomationTrigger.flow_id == flow.id)):
            session.delete(existing)
        session.flush()
        now = utcnow()
        for entry in body.triggers:
            session.add(
                AutomationTrigger(
                    flow_id=flow.id,
                    event_type=entry.event_type,
                    schema_version=entry.schema_version,
                    filter=entry.filter.model_dump(exclude_none=True),
                    created_at=now,
                    created_by=principal.audit_id,
                )
            )
        audit.record(
            session,
            domain="automation",
            action="automation.flow.triggers_changed",
            entity_type="flow",
            entity_id=str(flow.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"Triggers van flow '{flow.label}' vastgelegd ({len(body.triggers)}).",
            details={"triggers": [f"{e.event_type}@{e.schema_version}" for e in body.triggers]},
        )

    return _flow_mutation(request, session, principal, key, match, flow_id, body.model_dump(), change)


class LimitEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: een action_id, of ``*``: alle acties van deze flow samen (naast de grens per actie)
    action_id: str = Field(min_length=1, max_length=80)
    #: nooit ruimer dan de standaard; 0 = deze actie mag de flow niet aanvragen
    max_per_hour: int = Field(ge=0, le=actions.DEFAULT_MAX_PER_HOUR)
    cooldown_s: int = Field(default=0, ge=0, le=86400)

    @field_validator("action_id")
    @classmethod
    def _action(cls, v: str) -> str:
        if v != actions.ANY_ACTION and not actions.ACTION_ID_RE.fullmatch(v):
            raise ValueError("geen geldige action_id (of '*')")
        return v


class LimitsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rate_limits: list[LimitEntry] = Field(max_length=MAX_LIMITS)


@router.put("/flows/{flow_id}/rate-limits", summary="Strengere grenzen per flow en actie (nooit ruimer dan standaard)")
def put_flow_rate_limits(
    flow_id: uuid.UUID,
    body: LimitsIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    ids = [e.action_id for e in body.rate_limits]
    if len(set(ids)) != len(ids):
        raise ApiError(422, "validation_error", "Elke actie mag maar één keer voorkomen.", {"veld": "rate_limits"})

    def change(flow: AutomationFlow) -> None:
        for existing in session.scalars(select(AutomationRateLimit).where(AutomationRateLimit.flow_id == flow.id)):
            session.delete(existing)
        session.flush()
        for entry in body.rate_limits:
            session.add(
                AutomationRateLimit(
                    flow_id=flow.id,
                    action_id=entry.action_id,
                    max_per_hour=entry.max_per_hour,
                    cooldown_s=entry.cooldown_s,
                )
            )
        audit.record(
            session,
            domain="automation",
            action="automation.flow.rate_limits_changed",
            entity_type="flow",
            entity_id=str(flow.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"Grenzen van flow '{flow.label}' vastgelegd ({len(body.rate_limits)}).",
            details={"grenzen": [e.model_dump() for e in body.rate_limits]},
        )

    return _flow_mutation(request, session, principal, key, match, flow_id, body.model_dump(), change)


# -------------------------------------------------------------------------------------------- flow-tokens (B11-003)
class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(default="", max_length=80)
    #: wat de flow mag AANVRAGEN: action_id's of een voorvoegsel met ``.*``; uitvoeren kan een flow nooit
    allowed_actions: list[str] = Field(min_length=1, max_length=MAX_ALLOWED_ACTIONS)

    @field_validator("label")
    @classmethod
    def _label(cls, v: str) -> str:
        return _no_secret(actions.storable(v).strip(), "label") or ""

    @field_validator("allowed_actions")
    @classmethod
    def _allowed_actions(cls, v: list[str]) -> list[str]:
        return actions.storable(v)


def _mask_token(body: Any) -> Any:
    masked = dict(body)
    masked["flow_token"] = None
    masked["herhaling_nl"] = "Herhaald antwoord: het token wordt niet bewaard en is alleen de eerste keer getoond."
    return masked


@router.post("/flows/{flow_id}/tokens", summary="Flow-token uitgeven (één keer getoond; alleen de hash wordt bewaard)")
def post_flow_token(
    flow_id: uuid.UUID,
    body: TokenIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    from . import flowapi

    wanted = list(dict.fromkeys(body.allowed_actions))
    problems = [{"actie": a[:80], "reden": p} for a in wanted if (p := actions.scope_problem(a)) is not None]
    if problems:
        raise ApiError(
            422,
            "scope_ongeldig",
            "Eén of meer acties mogen niet in de scope van een flow-token.",
            {"fouten": problems[:20]},
        )

    def action() -> Result:
        flow = _flow_or_404(session, flow_id, lock=True)
        if flow.status in ("verwijderd", "geblokkeerd"):
            raise ApiError(
                409,
                "flow_status_conflict",
                "Voor een geblokkeerde of verwijderde flow wordt geen token uitgegeven.",
                {"status": flow.status, "reden": flow.blocked_reason},
            )
        if not flow.owner:
            raise ApiError(
                409,
                "flow_zonder_eigenaar",
                "Deze flow heeft geen eigenaar; leg eerst een eigenaar vast voordat de flow iets mag aanvragen.",
            )
        active = session.scalar(
            select(func.count())
            .select_from(AutomationFlowToken)
            .where(AutomationFlowToken.flow_id == flow.id, AutomationFlowToken.status == "actief")
        )
        if int(active or 0) >= MAX_TOKENS_PER_FLOW:
            raise ApiError(
                409,
                "te_veel_tokens",
                f"Deze flow heeft al {MAX_TOKENS_PER_FLOW} actieve tokens; trek er eerst één in.",
            )
        secret, digest, last4 = flowapi.new_token()
        row = AutomationFlowToken(
            id=uuid.uuid4(),
            flow_id=flow.id,
            token_sha256=digest,
            last4=last4,
            status="actief",
            label=body.label,
            allowed_actions=wanted,
            created_at=utcnow(),
            created_by=principal.audit_id,
        )
        session.add(row)
        session.flush()
        audit.record(
            session,
            domain="automation",
            action="automation.flow_token.issued",
            entity_type="flow",
            entity_id=str(flow.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"Flow-token uitgegeven voor flow '{flow.label}' (eindigt op {last4}).",
            details={"kenmerk": str(row.id), "eindigt_op": last4, "acties": wanted, "label": body.label},
        )
        _flow_event(
            session,
            "flow.access.granted",
            flow,
            principal,
            tid,
            {"ernst": "info", "label": flow.label, "acties": wanted, "eindigt_op": last4},
        )
        out = {
            **_token_view(row),
            "flow_token": secret,
            "flow_token_nl": ONCE,
            "gebruik_nl": f"Authorization: Bearer <token> op {flowapi.PREFIX}/…; alleen aanvragen, nooit uitvoeren.",
        }
        return 201, out, {}

    return run_idempotent(
        request,
        session,
        principal,
        key,
        {"flow_id": str(flow_id), "body": body.model_dump()},
        action,
        stored=_mask_token,
    )


@router.get("/flows/{flow_id}/tokens", summary="Flow-tokens van een flow (alleen kenmerken, nooit het token)")
def list_flow_tokens(
    flow_id: uuid.UUID,
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin_or_operator),
) -> dict[str, Any]:
    _flow_or_404(session, flow_id)
    rows = session.scalars(
        select(AutomationFlowToken)
        .where(AutomationFlowToken.flow_id == flow_id)
        .order_by(AutomationFlowToken.created_at.desc(), AutomationFlowToken.id.desc())
        .limit(200)
    ).all()
    return {"items": [_token_view(t) for t in rows], "next_cursor": None}


@router.post("/flows/{flow_id}/tokens/{token_id}/revoke", summary="Flow-token intrekken (direct ongeldig)")
def revoke_flow_token(
    flow_id: uuid.UUID,
    token_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        flow = _flow_or_404(session, flow_id)
        row = session.get(AutomationFlowToken, token_id, with_for_update=True)
        if row is None or row.flow_id != flow.id:
            raise not_found("Flow-token")
        if row.status == "actief":
            row.status = "ingetrokken"
            row.revoked_at = utcnow()
            row.revoked_reason = "door_beheerder"
            audit.record(
                session,
                domain="automation",
                action="automation.flow_token.revoked",
                entity_type="flow",
                entity_id=str(flow.id),
                principal=principal,
                trace_id=tid,
                message_nl=f"Flow-token van flow '{flow.label}' ingetrokken (eindigt op {row.last4}).",
                details={"kenmerk": str(row.id), "eindigt_op": row.last4},
            )
            _flow_event(
                session,
                "flow.access.revoked",
                flow,
                principal,
                tid,
                {"ernst": "info", "label": flow.label, "eindigt_op": row.last4},
            )
        return 200, _token_view(row), {}

    return run_idempotent(request, session, principal, key, {"flow_id": str(flow_id), "id": str(token_id)}, action)


# ------------------------------------------------------------------------------------------ momentopnamen (B11-005)
@router.post("/snapshots", summary="Node-RED nu uitlezen en een momentopname vastleggen (alleen lezen)")
def post_snapshot(
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_operator),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        state = request.app.state
        result = snapshots.sync(
            session,
            state.settings,
            state.vault,
            state.http_transport,
            reason="handmatig",
            actor=principal.audit_id,
            trace_id=tid,
            force_snapshot=True,
        )
        if not result.ok:
            # de mislukte poging blijft in de synchronisatietoestand staan; er is geen momentopname gemaakt
            session.commit()
            error = result.error or {}
            raise nodered.api_error(
                nodered.NodeRedError(
                    str(error.get("reason") or "onbekend"), error.get("http_status"), error.get("path")
                )
            )
        row = session.get(AutomationSnapshot, uuid.UUID(result.snapshot_id)) if result.snapshot_id else None
        audit.record(
            session,
            domain="automation",
            action="automation.snapshot.created",
            entity_type="snapshot",
            entity_id=result.snapshot_id or "geen",
            principal=principal,
            trace_id=tid,
            message_nl="Momentopname van Node-RED vastgelegd.",
            details={"checksum_sha256": result.checksum, "flows": result.flows, "geblokkeerd": result.blocked},
        )
        out = {**result.to_dict(), "snapshot": snapshots.snapshot_view(row) if row is not None else None}
        return 201, out, {}

    return run_idempotent(request, session, principal, key, {}, action)


@router.get("/snapshots", summary="Momentopnamen van Node-RED (nieuwste eerst; versleuteld bewaard)")
def list_snapshots(
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    stmt = select(AutomationSnapshot).where(AutomationSnapshot.source_id == nodered.SOURCE_ID)
    return _page_seq(session, stmt, AutomationSnapshot.seq, cursor, limit, snapshots.snapshot_view)


def _snapshot_or_404(session: Session, snapshot_id: uuid.UUID) -> AutomationSnapshot:
    row = session.get(AutomationSnapshot, snapshot_id)
    if row is None:
        raise not_found("Momentopname")
    return row


@router.get("/snapshots/{snapshot_id}", summary="Eén momentopname (kenmerken; nooit de inhoud of credentials)")
def get_snapshot(
    snapshot_id: uuid.UUID, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> dict[str, Any]:
    return snapshots.snapshot_view(_snapshot_or_404(session, snapshot_id))


@router.get(
    "/snapshots/{snapshot_id}/diff",
    summary="Verschil met een andere momentopname (alleen nodes en veldnamen; nooit waarden)",
)
def get_snapshot_diff(
    snapshot_id: uuid.UUID,
    request: Request,
    ten_opzichte_van: uuid.UUID | None = None,
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin_or_operator),
) -> dict[str, Any]:
    row = _snapshot_or_404(session, snapshot_id)
    if ten_opzichte_van is not None:
        base = _snapshot_or_404(session, ten_opzichte_van)
    else:
        base_row = session.scalars(
            select(AutomationSnapshot)
            .where(AutomationSnapshot.source_id == row.source_id, AutomationSnapshot.seq < row.seq)
            .order_by(AutomationSnapshot.seq.desc())
            .limit(1)
        ).first()
        if base_row is None:
            raise ApiError(409, "geen_eerdere_momentopname", "Er is geen eerdere momentopname om mee te vergelijken.")
        base = base_row
    vault = request.app.state.vault
    try:
        before = snapshots.open_snapshot(vault, base)
        after = snapshots.open_snapshot(vault, row)
    except snapshots.SnapshotUnreadable as exc:
        raise ApiError(
            409,
            "momentopname_onleesbaar",
            "Deze momentopname is niet te ontsleutelen met de huidige kluissleutel of is beschadigd.",
        ) from exc
    return {
        "van": snapshots.snapshot_view(base),
        "naar": snapshots.snapshot_view(row),
        "diff": snapshots.diff_flows(before["flows"], after["flows"]),
        "credentials_gewijzigd": base.credentials_sha256 != row.credentials_sha256,
    }


# ------------------------------------------------------------------------------------------------- events (B11-002)
@router.get("/event-types", summary="Eventtypen-catalogus met schema-versies (contract §7)")
def get_event_types(_p: Principal = Depends(require_reader)) -> dict[str, Any]:
    return eventcatalog.catalog_view()


@router.post(
    "/events",
    summary="Event aanbieden voor de triggers van flows (alleen de Hub)",
    responses={
        200: {"description": "Al eerder ontvangen (zelfde event of zelfde bron-event); niets opnieuw afgeleverd"},
        201: {"description": "Bewaard en aangeboden aan de flows met een passende trigger"},
        202: {"description": "Bewaard maar niet afgeleverd (bv. onbekende schema-versie); zichtbaar en gemeld"},
        422: {"description": "event_ongeldig — de envelope zelf is niet te bewaren"},
    },
)
def post_event(
    request: Request,
    envelope: dict[str, Any] = Body(...),
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    try:
        actions.storable(envelope)
    except ValueError as exc:
        # vóór de Idempotency-Key: zo'n envelope is niet te bewaren (S-P2-310; anders een serverfout)
        raise ApiError(
            422,
            "event_ongeldig",
            "De envelope van dit event is ongeldig; er is niets bewaard of afgeleverd.",
            {"fouten": [{"veld": "", "probleem": actions.UNSTORABLE_NL}]},
        ) from exc

    def action() -> Result:
        try:
            result = inbox.intake(session, envelope, received_by=principal.audit_id, trace_id=tid)
        except eventcatalog.EnvelopeError as exc:
            raise ApiError(
                422,
                "event_ongeldig",
                "De envelope van dit event is ongeldig; er is niets bewaard of afgeleverd.",
                {"fouten": exc.fouten[:20]},
            ) from exc
        if result.duplicate:
            return 200, result.to_dict(), {}
        deliverable = result.event.catalog_status == "geldig"
        return (201 if deliverable else 202), result.to_dict(), {}

    return run_idempotent(request, session, principal, key, envelope, action)


@router.get("/events", summary="Ontvangen events met hun catalogusstatus (ook wat niet is afgeleverd)")
def list_events(
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    stmt = select(AutomationEvent)
    if _one_of(status, CATALOG_STATUSES, "status"):
        stmt = stmt.where(AutomationEvent.catalog_status == status)
    out = _page_seq(session, stmt, AutomationEvent.seq, cursor, limit, _event_view)
    out["wachtrij"] = inbox.queue_stats(session, utcnow())
    return out


@router.get("/deliveries", summary="Afleveringen aan flows (wachtrij per bron, herhalingen, dead-letter)")
def list_deliveries(
    flow_id: uuid.UUID | None = None,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    stmt = select(AutomationDelivery)
    if flow_id is not None:
        stmt = stmt.where(AutomationDelivery.flow_id == flow_id)
    if _one_of(status, DELIVERY_STATUSES, "status"):
        stmt = stmt.where(AutomationDelivery.status == status)
    return _page_time(
        session, stmt, AutomationDelivery.created_at, AutomationDelivery.id, cursor, limit, inbox.delivery_view
    )


@router.post("/deliveries/{delivery_id}/requeue", summary="Vastgelopen aflevering (dead-letter) opnieuw aanbieden")
def requeue_delivery(
    delivery_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_operator),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        row = session.get(AutomationDelivery, delivery_id, with_for_update=True)
        if row is None:
            raise not_found("Aflevering")
        if not inbox.requeue(session, row, utcnow()):
            raise ApiError(
                409,
                "aflevering_niet_vastgelopen",
                "Alleen een vastgelopen aflevering (dead-letter) van een echte flow kan opnieuw worden aangeboden.",
                {"status": row.status, "proefrun": row.run_id is not None},
            )
        audit.record(
            session,
            domain="automation",
            action="automation.delivery.requeued",
            entity_type="delivery",
            entity_id=str(row.id),
            principal=principal,
            trace_id=tid,
            message_nl="Vastgelopen aflevering opnieuw aangeboden.",
            details={"flow_id": str(row.flow_id), "event_seq": row.event_seq},
        )
        return 200, inbox.delivery_view(row), {}

    return run_idempotent(request, session, principal, key, {"id": str(delivery_id)}, action)


# ---------------------------------------------------------------------------------------- actieverzoeken (B11-003)
@router.get("/action-requests", summary="Actieverzoeken van flows (aangevraagd bij de Hub; hier nooit uitgevoerd)")
def list_action_requests(
    flow_id: uuid.UUID | None = None,
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    stmt = select(AutomationActionRequest)
    if flow_id is not None:
        stmt = stmt.where(AutomationActionRequest.flow_id == flow_id)
    if _one_of(status, REQUEST_STATUSES, "status"):
        stmt = stmt.where(AutomationActionRequest.status == status)
    return _page_time(
        session,
        stmt,
        AutomationActionRequest.created_at,
        AutomationActionRequest.id,
        cursor,
        limit,
        actions.request_view,
    )


def _request_or_404(session: Session, request_id: uuid.UUID, *, lock: bool = False) -> AutomationActionRequest:
    row = session.get(AutomationActionRequest, request_id, with_for_update=lock)
    if row is None:
        raise not_found("Actieverzoek")
    return row


@router.get("/action-requests/{request_id}", summary="Eén actieverzoek met wat de Hub terugmeldde")
def get_action_request(
    request_id: uuid.UUID, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> dict[str, Any]:
    return actions.request_view(_request_or_404(session, request_id))


class ActionResultIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["wacht_op_goedkeuring", "uitgevoerd", "geweigerd", "mislukt"]
    hub_proposal_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9._:-]+$")
    #: de risicoklasse die het beleid van de Hub bepaalde (de risk_claim van de flow telt nooit)
    hub_risk_class: Literal["R0", "R1", "R2", "R3"] | None = None
    reason: str | None = Field(default=None, max_length=80, pattern=r"^[a-z0-9_.-]+$")
    result: dict[str, Any] = Field(default_factory=dict)

    @field_validator("result")
    @classmethod
    def _result(cls, v: dict[str, Any]) -> dict[str, Any]:
        return actions.storable(v)


@router.post(
    "/action-requests/{request_id}/result",
    summary="De Hub meldt het besluit of de uitvoering van een actieverzoek (alleen de Hub)",
)
def post_action_result(
    request_id: uuid.UUID,
    body: ActionResultIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        row = _request_or_404(session, request_id, lock=True)
        before = row.status
        changed = actions.record_result(
            row,
            status=body.status,
            hub_proposal_id=body.hub_proposal_id,
            hub_risk_class=body.hub_risk_class,
            reason=body.reason,
            result=body.result,
            now=utcnow(),
        )
        if not changed:
            raise ApiError(
                409,
                "actieverzoek_afgerond",
                "Dit actieverzoek is al afgerond; de uitkomst verandert niet meer.",
                {"status": row.status},
            )
        audit.record(
            session,
            domain="automation",
            action="automation.action.result_recorded",
            entity_type="action_request",
            entity_id=str(row.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"De Hub meldde voor actieverzoek {row.action_id}: {before} → {row.status}.",
            details={
                "van": before,
                "naar": row.status,
                "hub_proposal_id": row.hub_proposal_id,
                "hub_risk_class": row.hub_risk_class,
                "reden": body.reason,
            },
        )
        return 200, actions.request_view(row), {}

    return run_idempotent(request, session, principal, key, {"id": str(request_id), "body": body.model_dump()}, action)


# ------------------------------------------------------------------------------------------ proefruns (B11-004)
@router.get("/samples", summary="Vaste voorbeeld-events voor een proefrun (alleen-lezen, met checksum)")
def get_samples(_p: Principal = Depends(require_reader)) -> dict[str, Any]:
    from . import samples

    return {"items": simulate.sample_list(), "checksum_sha256": samples.checksum(), "next_cursor": None}


class RunIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    #: leeg = alle voorbeeld-events
    sample_ids: list[str] = Field(default_factory=list, max_length=simulate.MAX_SAMPLES)
    baseline_run_id: uuid.UUID | None = None
    #: verplicht ``true`` als de flow zelf naar buiten kan (http request, mqtt, …): dat pad schermt een proefrun niet af
    bevestig_niet_afgeschermd: bool = False

    @field_validator("sample_ids")
    @classmethod
    def _sample_ids(cls, v: list[str]) -> list[str]:
        return actions.storable(v)


@router.post(
    "/flows/{flow_id}/runs",
    summary="Proefrun starten: voorbeeld-events afleveren; acties worden alleen gelogd, nooit aangevraagd",
)
def post_run(
    flow_id: uuid.UUID,
    body: RunIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_operator),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        flow = _flow_or_404(session, flow_id, lock=True)
        run = simulate.start_run(
            session,
            flow,
            sample_ids=body.sample_ids,
            baseline_run_id=body.baseline_run_id,
            confirm_unshielded=body.bevestig_niet_afgeschermd,
            created_by=principal.audit_id,
            trace_id=tid,
            now=utcnow(),
        )
        audit.record(
            session,
            domain="automation",
            action="automation.simulation.started",
            entity_type="flow",
            entity_id=str(flow.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"Proefrun gestart voor flow '{flow.label}'.",
            details={"run_id": str(run.id), "voorbeelden": list(run.sample_ids or [])},
        )
        return 201, simulate.run_view(run), {}

    return run_idempotent(
        request,
        session,
        principal,
        key,
        {"flow_id": str(flow_id), "body": body.model_dump(mode="json")},
        action,
    )


@router.get("/runs", summary="Proefruns (nieuwste eerst)")
def list_runs(
    flow_id: uuid.UUID | None = None,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    stmt = select(AutomationFlowRun)
    if flow_id is not None:
        stmt = stmt.where(AutomationFlowRun.flow_id == flow_id)
    return _page_time(
        session,
        stmt,
        AutomationFlowRun.started_at,
        AutomationFlowRun.id,
        cursor,
        limit,
        lambda r: simulate.run_view(r, with_log=False),
    )


@router.get("/runs/{run_id}", summary="Eén proefrun met logboek en vergelijking")
def get_run(
    run_id: uuid.UUID, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> dict[str, Any]:
    row = session.get(AutomationFlowRun, run_id)
    if row is None:
        raise not_found("Proefrun")
    return simulate.run_view(row)


# --------------------------------------------------------------------------------------------- herstel (B11-005)
@router.get("/restores", summary="Herstelvoorstellen en uitgevoerde herstelacties (nieuwste eerst)")
def list_restores(
    status: str | None = None,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    stmt = select(AutomationRestore)
    if _one_of(status, RESTORE_STATUSES, "status"):
        stmt = stmt.where(AutomationRestore.status == status)
    return _page_time(session, stmt, AutomationRestore.created_at, AutomationRestore.id, cursor, limit, restore_view)


@router.get("/restores/{restore_id}", summary="Eén herstelvoorstel met diff, hash en uitkomst")
def get_restore(
    restore_id: uuid.UUID, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> dict[str, Any]:
    row = session.get(AutomationRestore, restore_id)
    if row is None:
        raise not_found("Herstelvoorstel")
    return restore_view(row)
