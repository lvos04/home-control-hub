"""B13 — routes onder ``/integrations/v1/sso``.

Rechten (least privilege, B13-004): het herstelregister is alleen voor ``admin``; de totaalstatus ook voor
``operator``; de SSO-dekkingsmatrix voor alle lezers. ``evaluate``/``activations`` ook voor de Hub (service-token),
want de Hub voert de lokale noodlogin uit en meldt die hier.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from ... import API_PREFIX, audit, events
from ...deps import check_if_match, etag, get_session, if_match, trace_id
from ...errors import ApiError, not_found
from ...idempotency import idempotency_key, run_idempotent
from ...pagination import decode_cursor, encode_cursor, limit_param
from ...redact import looks_like_secret
from ...security.auth import (
    Principal,
    require_admin,
    require_admin_or_operator,
    require_admin_or_service,
)
from ...timeutil import iso, utcnow
from . import recovery, service
from .kit import KitError, check_passphrase, decrypt_kit, encrypt_kit
from .models import (
    SSO_INDEPENDENT_METHODS,
    SsoAdminAccount,
    SsoBreakGlassActivation,
    SsoBreakGlassDrill,
    SsoEmergencyAccess,
    SsoRecoveryKitExport,
    SsoRecoveryMethod,
)

router = APIRouter(prefix=f"{API_PREFIX}/sso", tags=["sso"])

SystemT = Literal["hub_local", "authentik", "truenas", "node_red", "adguard_home", "netalertx", "overig"]
LoginKindT = Literal["lokaal", "sso", "beide"]
MfaStatusT = Literal["bevestigd", "niet_ingesteld", "onbekend"]
MfaMethodT = Literal["totp", "webauthn", "herstelcodes"]
MethodTypeT = Literal[
    "lokaal_wachtwoord_lan",
    "lokaal_wachtwoord_vpn",
    "herstelcodes_offline",
    "hardwaresleutel",
    "authentik_herstelsleutel",
    "truenas_console",
    "verzegelde_envelop",
]
StorageHintT = Literal["wachtwoordmanager", "verzegelde_envelop", "kluis", "hardwaresleutel", "anders", "onbekend"]


def _no_secret(value: str, field: str) -> str:
    if looks_like_secret(value):
        raise ValueError(f"{field} lijkt een token, sleutel of wachtwoord te bevatten; sla hier geen geheimen op")
    return value


# ------------------------------------------------------------------ schema's (extra velden verboden: geen 'password')
class AccountCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    system: SystemT
    username: str = Field(min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._@+-]+$")
    display_name: str = Field(default="", max_length=120)
    is_break_glass: bool = False
    login_kind: LoginKindT
    notes: str = Field(default="", max_length=500)

    @field_validator("display_name", "notes")
    @classmethod
    def _free_text(cls, v: str, info: Any) -> str:
        return _no_secret(v, info.field_name)

    @model_validator(mode="after")
    def _break_glass(self) -> AccountCreate:
        if self.is_break_glass and self.login_kind == "sso":
            raise ValueError("een noodaccount moet zonder SSO kunnen inloggen (login_kind 'lokaal' of 'beide')")
        return self


class AccountUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = Field(default=None, max_length=120)
    is_break_glass: bool | None = None
    login_kind: LoginKindT | None = None
    status: Literal["actief", "uitgeschakeld"] | None = None
    notes: str | None = Field(default=None, max_length=500)

    @field_validator("display_name", "notes")
    @classmethod
    def _free_text(cls, v: str | None, info: Any) -> str | None:
        return None if v is None else _no_secret(v, info.field_name)


class MfaAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mfa_status: MfaStatusT
    mfa_methods: list[MfaMethodT] = Field(default_factory=list, max_length=3)

    @model_validator(mode="after")
    def _consistent(self) -> MfaAttestation:
        if self.mfa_status == "bevestigd" and not self.mfa_methods:
            raise ValueError("bij 'bevestigd' minstens één MFA-methode opgeven")
        if self.mfa_status != "bevestigd" and self.mfa_methods:
            raise ValueError("MFA-methodes alleen opgeven bij status 'bevestigd'")
        return self


class MethodCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method_type: MethodTypeT
    storage_hint: StorageHintT = "onbekend"


class Scope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cidr: str = Field(max_length=50)
    kind: Literal["lan", "vpn"]


class EmergencyAccessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    network_scopes: list[Scope] = Field(min_length=1, max_length=recovery.MAX_SCOPES)
    session_max_minutes: int = Field(default=60, ge=5, le=240)
    review_interval_days: int = Field(default=90, ge=7, le=365)
    reason: str = Field(default="", max_length=300)

    @field_validator("reason")
    @classmethod
    def _free_text(cls, v: str) -> str:
        return _no_secret(v, "reason")


class EvaluateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_id: uuid.UUID
    client_ip: str = Field(max_length=45)


class ActivationIn(EvaluateIn):
    mode: Literal["oefening", "echt"]


class DrillIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    account_id: uuid.UUID
    method_id: uuid.UUID | None = None
    mode: Literal["zelftest", "handmatig"]
    outcome: Literal["ok", "mislukt"] | None = None
    client_scope: Literal["lan", "vpn", "onbekend"] = "onbekend"
    authenticator_state: Literal["online", "offline", "onbekend"] | None = None
    notes: str = Field(default="", max_length=500)

    @field_validator("notes")
    @classmethod
    def _free_text(cls, v: str) -> str:
        return _no_secret(v, "notes")

    @model_validator(mode="after")
    def _mode_fields(self) -> DrillIn:
        if self.mode == "handmatig" and self.outcome is None:
            raise ValueError("bij een handmatige oefening is 'outcome' verplicht")
        if self.mode == "zelftest" and (self.outcome is not None or self.authenticator_state is not None):
            raise ValueError("bij een zelftest bepaalt de dienst zelf 'outcome' en 'authenticator_state'")
        return self


class KitExportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    passphrase: str = Field(min_length=1, max_length=1024, description="Wordt nooit opgeslagen of gelogd.")


class KitVerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    passphrase: str = Field(min_length=1, max_length=1024)
    kit: dict[str, Any]


# ------------------------------------------------------------------ helpers
def _settings(request: Request) -> Any:
    return request.app.state.settings


def _get_account(session: Session, account_id: uuid.UUID) -> SsoAdminAccount:
    acc = session.get(SsoAdminAccount, account_id)
    if acc is None:
        raise not_found("Beheeraccount")
    return acc


def _after_change(
    request: Request,
    session: Session,
    principal: Principal,
    tid: str,
    *,
    action: str,
    entity_type: str,
    entity_id: str,
    message_nl: str,
    event_type: str,
    payload: dict[str, Any],
    details: dict[str, Any] | None = None,
    classification: str = "internal",
) -> None:
    audit.record(
        session,
        domain="sso",
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        principal=principal,
        trace_id=tid,
        message_nl=message_nl,
        details=details or payload,
    )
    events.emit(
        session,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_type=principal.actor_type,
        actor_id=principal.audit_id,
        trace_id=tid,
        payload=payload,
        classification=classification,
    )
    service.emit_readiness_change(
        session, _settings(request).break_glass_test_max_age_days, tid, (principal.actor_type, principal.audit_id)
    )


def _account_detail(request: Request, session: Session, acc: SsoAdminAccount) -> dict[str, Any]:
    methods = session.scalars(
        select(SsoRecoveryMethod).where(SsoRecoveryMethod.account_id == acc.id).order_by(SsoRecoveryMethod.created_at)
    )
    em = session.scalar(select(SsoEmergencyAccess).where(SsoEmergencyAccess.account_id == acc.id))
    drills = session.scalars(
        select(SsoBreakGlassDrill)
        .where(SsoBreakGlassDrill.account_id == acc.id)
        .order_by(SsoBreakGlassDrill.performed_at.desc())
        .limit(5)
    )
    session.flush()
    views = [v for v in service.load_views(session) if v.id == str(acc.id)]
    readiness = (
        recovery.evaluate_account(views[0], utcnow(), _settings(request).break_glass_test_max_age_days).to_dict()
        if views and acc.status == "actief"
        else {"level": "n.v.t.", "reasons": []}
    )
    return {
        **service.account_dict(acc),
        "recovery_methods": [service.method_dict(m) for m in methods],
        "emergency_access": service.emergency_dict(em) if em else None,
        "recent_drills": [service.drill_dict(d) for d in drills],
        "readiness": readiness,
    }


# ------------------------------------------------------------------ lezen
@router.get("/recovery/status", summary="Totale herstelstatus (zonder accountnamen)")
def recovery_status(
    request: Request, session: Session = Depends(get_session), _p: Principal = Depends(require_admin_or_operator)
) -> dict[str, Any]:
    result = service.overall(session, _settings(request).break_glass_test_max_age_days)
    result.pop("accounts", None)
    return result


@router.get("/recovery/overview", summary="Herstelstatus per beheeraccount")
def recovery_overview(
    request: Request, session: Session = Depends(get_session), _p: Principal = Depends(require_admin)
) -> dict[str, Any]:
    return service.overall(session, _settings(request).break_glass_test_max_age_days)


@router.get("/recovery/accounts", summary="Beheeraccounts in het herstelregister")
def list_accounts(
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    system: SystemT | None = None,
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin),
) -> dict[str, Any]:
    stmt = select(SsoAdminAccount).order_by(SsoAdminAccount.created_at, SsoAdminAccount.id)
    if system:
        stmt = stmt.where(SsoAdminAccount.system == system)
    after = decode_cursor(cursor)
    if after is not None:
        try:
            ts, aid = datetime.fromisoformat(after[0]), uuid.UUID(after[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.") from exc
        stmt = stmt.where(tuple_(SsoAdminAccount.created_at, SsoAdminAccount.id) > tuple_(ts, aid))
    rows = list(session.scalars(stmt.limit(limit + 1)))
    has_more = len(rows) > limit
    rows = rows[:limit]
    nxt = encode_cursor([rows[-1].created_at.isoformat(), str(rows[-1].id)]) if has_more and rows else None
    return {"items": [service.account_dict(a) for a in rows], "next_cursor": nxt}


@router.get("/recovery/accounts/{account_id}", summary="Eén beheeraccount met methodes, noodtoegang en status")
def get_account(
    account_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin),
) -> Any:
    from fastapi.responses import JSONResponse

    acc = _get_account(session, account_id)
    return JSONResponse(_account_detail(request, session, acc), headers={"ETag": etag(acc.version)})


@router.get("/recovery/drills", summary="Oefeningen (nieuwste eerst)")
def list_drills(
    account_id: uuid.UUID | None = None,
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin),
) -> dict[str, Any]:
    stmt = select(SsoBreakGlassDrill).order_by(SsoBreakGlassDrill.performed_at.desc(), SsoBreakGlassDrill.id.desc())
    if account_id:
        stmt = stmt.where(SsoBreakGlassDrill.account_id == account_id)
    after = decode_cursor(cursor)
    if after is not None:
        try:
            ts, did = datetime.fromisoformat(after[0]), uuid.UUID(after[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.") from exc
        stmt = stmt.where(tuple_(SsoBreakGlassDrill.performed_at, SsoBreakGlassDrill.id) < tuple_(ts, did))
    rows = list(session.scalars(stmt.limit(limit + 1)))
    has_more = len(rows) > limit
    rows = rows[:limit]
    nxt = encode_cursor([rows[-1].performed_at.isoformat(), str(rows[-1].id)]) if has_more and rows else None
    return {"items": [service.drill_dict(d) for d in rows], "next_cursor": nxt}


# ------------------------------------------------------------------ accounts
@router.post("/recovery/accounts", status_code=201, summary="Beheeraccount registreren (zonder geheimen)")
def create_account(
    body: AccountCreate,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        exists = session.scalar(
            select(SsoAdminAccount).where(
                SsoAdminAccount.system == body.system, SsoAdminAccount.username == body.username
            )
        )
        if exists is not None:
            raise ApiError(409, "conflict", "Dit account staat al in het herstelregister.", {"id": str(exists.id)})
        acc = SsoAdminAccount(
            id=uuid.uuid4(),
            system=body.system,
            username=body.username,
            display_name=body.display_name,
            is_break_glass=body.is_break_glass,
            login_kind=body.login_kind,
            notes=body.notes,
            mfa_status="onbekend",
            mfa_methods=[],
            status="actief",
            version=1,
            created_by=principal.audit_id,
            updated_by=principal.audit_id,
        )
        session.add(acc)
        session.flush()
        _after_change(
            request,
            session,
            principal,
            tid,
            action="admin_account.registered",
            entity_type="sso_admin_account",
            entity_id=str(acc.id),
            message_nl=f"Beheeraccount {body.system}/{body.username} geregistreerd.",
            event_type="sso.admin_account.registered",
            payload={"system": body.system, "is_break_glass": body.is_break_glass, "login_kind": body.login_kind},
        )
        return 201, _account_detail(request, session, acc), {"ETag": etag(acc.version)}

    return run_idempotent(request, session, principal, key, body.model_dump(), action)


@router.patch("/recovery/accounts/{account_id}", summary="Beheeraccount wijzigen (If-Match verplicht)")
def update_account(
    account_id: uuid.UUID,
    body: AccountUpdate,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        acc = _get_account(session, account_id)
        check_if_match(acc.version, match)
        changes = body.model_dump(exclude_none=True)
        new_bg = changes.get("is_break_glass", acc.is_break_glass)
        new_lk = changes.get("login_kind", acc.login_kind)
        if new_bg and new_lk == "sso":
            raise ApiError(422, "validation_error", "Een noodaccount moet zonder SSO kunnen inloggen.")
        for k, v in changes.items():
            setattr(acc, k, v)
        acc.version += 1
        acc.updated_by = principal.audit_id
        session.flush()
        _after_change(
            request,
            session,
            principal,
            tid,
            action="admin_account.updated",
            entity_type="sso_admin_account",
            entity_id=str(acc.id),
            message_nl=f"Beheeraccount {acc.system}/{acc.username} gewijzigd.",
            event_type="sso.admin_account.updated",
            payload={"changed": sorted(changes)},
        )
        return 200, _account_detail(request, session, acc), {"ETag": etag(acc.version)}

    return run_idempotent(
        request, session, principal, key, {"id": str(account_id), "if_match": match, **body.model_dump()}, action
    )


@router.post("/recovery/accounts/{account_id}/mfa-attestation", summary="MFA-status bevestigen (attestatie)")
def attest_mfa(
    account_id: uuid.UUID,
    body: MfaAttestation,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        acc = _get_account(session, account_id)
        check_if_match(acc.version, match)
        acc.mfa_status = body.mfa_status
        acc.mfa_methods = sorted(set(body.mfa_methods))
        acc.mfa_attested_at = utcnow()
        acc.mfa_attested_by = principal.audit_id
        acc.version += 1
        acc.updated_by = principal.audit_id
        session.flush()
        _after_change(
            request,
            session,
            principal,
            tid,
            action="admin_account.mfa_attested",
            entity_type="sso_admin_account",
            entity_id=str(acc.id),
            message_nl=f"MFA-status van {acc.system}/{acc.username} bevestigd als '{body.mfa_status}'.",
            event_type="sso.admin_account.mfa_attested",
            payload={"mfa_status": body.mfa_status, "mfa_methods": acc.mfa_methods},
        )
        return 200, _account_detail(request, session, acc), {"ETag": etag(acc.version)}

    return run_idempotent(
        request, session, principal, key, {"id": str(account_id), "if_match": match, **body.model_dump()}, action
    )


# ------------------------------------------------------------------ herstelmethodes
@router.post("/recovery/accounts/{account_id}/methods", status_code=201, summary="Herstelmethode toevoegen")
def add_method(
    account_id: uuid.UUID,
    body: MethodCreate,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        acc = _get_account(session, account_id)
        m = SsoRecoveryMethod(
            id=uuid.uuid4(),
            account_id=acc.id,
            method_type=body.method_type,
            storage_hint=body.storage_hint,
            sso_independent=body.method_type in SSO_INDEPENDENT_METHODS,
            status="actief",
            version=1,
            created_by=principal.audit_id,
            updated_by=principal.audit_id,
        )
        session.add(m)
        session.flush()
        _after_change(
            request,
            session,
            principal,
            tid,
            action="recovery_method.added",
            entity_type="sso_recovery_method",
            entity_id=str(m.id),
            message_nl=f"Herstelmethode {body.method_type} toegevoegd aan {acc.system}/{acc.username}.",
            event_type="sso.recovery_method.added",
            payload={"account_id": str(acc.id), "method_type": body.method_type, "sso_independent": m.sso_independent},
        )
        return 201, service.method_dict(m), {"ETag": etag(m.version)}

    return run_idempotent(
        request, session, principal, key, {"account_id": str(account_id), **body.model_dump()}, action
    )


@router.post("/recovery/methods/{method_id}/revoke", summary="Herstelmethode intrekken (blijft in de historie)")
def revoke_method(
    method_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        m = session.get(SsoRecoveryMethod, method_id)
        if m is None:
            raise not_found("Herstelmethode")
        if m.status != "ingetrokken":
            m.status = "ingetrokken"
            m.version += 1
            m.updated_by = principal.audit_id
            session.flush()
            _after_change(
                request,
                session,
                principal,
                tid,
                action="recovery_method.revoked",
                entity_type="sso_recovery_method",
                entity_id=str(m.id),
                message_nl=f"Herstelmethode {m.method_type} ingetrokken.",
                event_type="sso.recovery_method.revoked",
                payload={"account_id": str(m.account_id), "method_type": m.method_type},
            )
        return 200, service.method_dict(m), {"ETag": etag(m.version)}

    return run_idempotent(request, session, principal, key, {"method_id": str(method_id)}, action)


# ------------------------------------------------------------------ noodtoegang
@router.put("/recovery/accounts/{account_id}/emergency-access", summary="Noodtoegang (LAN/VPN) instellen")
def put_emergency_access(
    account_id: uuid.UUID,
    body: EmergencyAccessIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    try:
        scopes = recovery.validate_scopes([s.model_dump() for s in body.network_scopes])
    except recovery.ScopeError as exc:
        raise ApiError(422, "validation_error", str(exc), {"veld": "network_scopes"}) from exc

    def action() -> tuple[int, Any, dict[str, str]]:
        acc = _get_account(session, account_id)
        if not acc.is_break_glass:
            raise ApiError(
                409, "geen_noodaccount", "Noodtoegang kan alleen voor een account dat als noodaccount is geregistreerd."
            )
        if acc.login_kind == "sso":
            raise ApiError(409, "alleen_sso", "Een account dat alleen via SSO inlogt kan geen noodtoegang krijgen.")
        em = session.scalar(select(SsoEmergencyAccess).where(SsoEmergencyAccess.account_id == acc.id))
        created = em is None
        now = utcnow()
        if em is None:
            if match not in (None, "*"):
                raise ApiError(412, "precondition_failed", "Er is nog geen noodtoegang voor dit account.")
            em = SsoEmergencyAccess(
                id=uuid.uuid4(),
                account_id=acc.id,
                version=1,
                created_by=principal.audit_id,
                last_reviewed_at=now,
                last_reviewed_by=principal.audit_id,
            )
            session.add(em)
        else:
            check_if_match(em.version, match)
            em.version += 1
            em.last_reviewed_at, em.last_reviewed_by = now, principal.audit_id
        em.network_scopes = scopes
        em.session_max_minutes = body.session_max_minutes
        em.review_interval_days = body.review_interval_days
        em.reason = body.reason
        em.status = "actief"
        em.updated_by = principal.audit_id
        session.flush()
        _after_change(
            request,
            session,
            principal,
            tid,
            action="emergency_access.changed",
            entity_type="sso_emergency_access",
            entity_id=str(em.id),
            message_nl=f"Noodtoegang voor {acc.system}/{acc.username} "
            f"{'ingesteld' if created else 'gewijzigd'} ({len(scopes)} bereik(en)).",
            event_type="sso.emergency_access.changed",
            payload={
                "account_id": str(acc.id),
                "network_scopes": scopes,
                "session_max_minutes": body.session_max_minutes,
                "status": "actief",
            },
            classification="sensitive",
        )
        return (201 if created else 200), service.emergency_dict(em), {"ETag": etag(em.version)}

    return run_idempotent(
        request,
        session,
        principal,
        key,
        {"account_id": str(account_id), "if_match": match, **body.model_dump()},
        action,
    )


def _emergency_action(kind: Literal["review", "revoke"]) -> Any:
    def endpoint(
        account_id: uuid.UUID,
        request: Request,
        session: Session = Depends(get_session),
        principal: Principal = Depends(require_admin),
        key: uuid.UUID = Depends(idempotency_key),
        match: str | None = Depends(if_match),
        tid: str = Depends(trace_id),
    ) -> Any:
        def action() -> tuple[int, Any, dict[str, str]]:
            em = session.scalar(select(SsoEmergencyAccess).where(SsoEmergencyAccess.account_id == account_id))
            if em is None:
                raise not_found("Noodtoegang")
            check_if_match(em.version, match)
            em.version += 1
            em.updated_by = principal.audit_id
            if kind == "review":
                if em.status != "actief":
                    raise ApiError(409, "conflict", "Een ingetrokken noodtoegang kan niet worden herbevestigd.")
                em.last_reviewed_at, em.last_reviewed_by = utcnow(), principal.audit_id
                msg, ev = "Noodtoegang herbevestigd.", "sso.emergency_access.reviewed"
            else:
                em.status = "ingetrokken"
                msg, ev = "Noodtoegang ingetrokken.", "sso.emergency_access.revoked"
            session.flush()
            _after_change(
                request,
                session,
                principal,
                tid,
                action=f"emergency_access.{kind}",
                entity_type="sso_emergency_access",
                entity_id=str(em.id),
                message_nl=msg,
                event_type=ev,
                payload={"account_id": str(account_id), "status": em.status},
                classification="sensitive",
            )
            return 200, service.emergency_dict(em), {"ETag": etag(em.version)}

        return run_idempotent(
            request, session, principal, key, {"account_id": str(account_id), "if_match": match, "kind": kind}, action
        )

    return endpoint


router.add_api_route(
    "/recovery/accounts/{account_id}/emergency-access/review",
    _emergency_action("review"),
    methods=["POST"],
    summary="Noodtoegang herbevestigen",
)
router.add_api_route(
    "/recovery/accounts/{account_id}/emergency-access/revoke",
    _emergency_action("revoke"),
    methods=["POST"],
    summary="Noodtoegang intrekken",
)


# ------------------------------------------------------------------ noodtoegang beoordelen en melden
def _evaluate(session: Session, account_id: uuid.UUID, client_ip: str) -> tuple[SsoAdminAccount, recovery.Evaluation]:
    acc = _get_account(session, account_id)
    em = session.scalar(select(SsoEmergencyAccess).where(SsoEmergencyAccess.account_id == acc.id))
    ev = recovery.evaluate_access(
        account_status=acc.status,
        is_break_glass=acc.is_break_glass,
        login_kind=acc.login_kind,
        policy_status=em.status if em else None,
        scopes=em.network_scopes if em else None,
        session_max_minutes=em.session_max_minutes if em else None,
        client_ip=client_ip,
    )
    return acc, ev


@router.post("/break-glass/evaluate", summary="Mag dit noodaccount vanaf dit adres? (raadpleegt Authentik nooit)")
def evaluate(
    body: EvaluateIn, session: Session = Depends(get_session), _p: Principal = Depends(require_admin_or_service)
) -> dict[str, Any]:
    _, ev = _evaluate(session, body.account_id, body.client_ip)
    return {
        **ev.to_dict(),
        "evaluated_at": iso(utcnow()),
        "note_nl": "Advies voor de Hub; de lokale noodlogin in de Hub mag niet van deze dienst afhangen.",
    }


@router.post("/break-glass/activations", status_code=201, summary="Gebruik van noodtoegang melden (audit)")
def report_activation(
    body: ActivationIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        acc, ev = _evaluate(session, body.account_id, body.client_ip)
        if not ev.allowed:
            audit.record(
                session,
                domain="sso",
                action="break_glass.denied",
                entity_type="sso_admin_account",
                entity_id=str(acc.id),
                principal=principal,
                trace_id=tid,
                message_nl="Noodtoegang geweigerd.",
                details={"reasons": ev.reasons, "mode": body.mode},
            )
            events.emit(
                session,
                event_type="sso.break_glass.denied",
                entity_type="sso_admin_account",
                entity_id=str(acc.id),
                actor_type=principal.actor_type,
                actor_id=principal.audit_id,
                trace_id=tid,
                classification="sensitive",
                payload={"reasons": [r["code"] for r in ev.reasons], "mode": body.mode},
            )
            session.commit()  # de weigering zelf blijft in de audit staan
            raise ApiError(403, "noodtoegang_geweigerd", "Noodtoegang geweigerd.", {"reasons": ev.reasons})
        now = utcnow()
        act = SsoBreakGlassActivation(
            id=uuid.uuid4(),
            account_id=acc.id,
            mode=body.mode,
            client_ip=body.client_ip.strip(),
            matched_scope=ev.matched_scope,
            activated_at=now,
            expires_at=now + timedelta(minutes=ev.session_max_minutes or 60),
            reported_by=principal.audit_id,
            rotation_required=body.mode == "echt",
        )
        session.add(act)
        session.flush()
        _after_change(
            request,
            session,
            principal,
            tid,
            action="break_glass.activated",
            entity_type="sso_break_glass_activation",
            entity_id=str(act.id),
            message_nl=f"Noodtoegang gebruikt ({body.mode}) door {acc.system}/{acc.username}.",
            event_type="sso.break_glass.activated",
            payload={
                "account_id": str(acc.id),
                "mode": body.mode,
                "expires_at": iso(act.expires_at),
                "rotation_required": act.rotation_required,
            },
            classification="sensitive",
        )
        return 201, service.activation_dict(act), {}

    return run_idempotent(request, session, principal, key, body.model_dump(), action)


@router.post("/break-glass/activations/{activation_id}/rotated", summary="Wachtwoordrotatie na gebruik bevestigen")
def confirm_rotation(
    activation_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        act = session.get(SsoBreakGlassActivation, activation_id)
        if act is None:
            raise not_found("Activatie")
        if not act.rotation_required:
            raise ApiError(409, "conflict", "Voor een oefening is geen rotatie nodig.")
        if act.rotated_at is None:
            act.rotated_at, act.rotated_by = utcnow(), principal.audit_id
            act.closed_at = act.closed_at or utcnow()
            session.flush()
            _after_change(
                request,
                session,
                principal,
                tid,
                action="break_glass.rotated",
                entity_type="sso_break_glass_activation",
                entity_id=str(act.id),
                message_nl="Rotatie na gebruik van noodtoegang bevestigd.",
                event_type="sso.break_glass.rotated",
                payload={"account_id": str(act.account_id)},
                classification="sensitive",
            )
        return 200, service.activation_dict(act), {}

    return run_idempotent(request, session, principal, key, {"activation_id": str(activation_id)}, action)


# ------------------------------------------------------------------ oefeningen
@router.post("/recovery/drills", status_code=201, summary="Oefening vastleggen: zelftest of handmatig bevestigd")
def record_drill(
    body: DrillIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        acc = _get_account(session, body.account_id)
        method: SsoRecoveryMethod | None = None
        if body.method_id is not None:
            method = session.get(SsoRecoveryMethod, body.method_id)
            if method is None or method.account_id != acc.id:
                raise not_found("Herstelmethode van dit account")
        if body.mode == "zelftest":
            outcome, auth_state, checks = service.run_selftest(request, session, acc, method)
        else:
            outcome = body.outcome or "mislukt"
            auth_state = body.authenticator_state or "onbekend"
            checks = [
                {
                    "name": "handmatige_bevestiging",
                    "status": "ok" if outcome == "ok" else "mislukt",
                    "detail_nl": "Door beheerder bevestigd na een echte login via de herstelmethode.",
                }
            ]
            if outcome == "ok" and method is not None:
                method.last_verified_at = utcnow()
        drill = SsoBreakGlassDrill(
            id=uuid.uuid4(),
            account_id=acc.id,
            method_id=method.id if method else None,
            mode=body.mode,
            outcome=outcome,
            authenticator_state=auth_state,
            client_scope=body.client_scope,
            checks=checks,
            notes=body.notes,
            performed_by=principal.audit_id,
            performed_at=utcnow(),
            trace_id=uuid.UUID(tid),
        )
        session.add(drill)
        session.flush()
        _after_change(
            request,
            session,
            principal,
            tid,
            action="recovery_drill.recorded",
            entity_type="sso_break_glass_drill",
            entity_id=str(drill.id),
            message_nl=f"Oefening ({body.mode}) voor {acc.system}/{acc.username}: {outcome}; Authentik {auth_state}.",
            event_type="sso.recovery_drill.recorded",
            payload={
                "account_id": str(acc.id),
                "mode": body.mode,
                "outcome": outcome,
                "authenticator_state": auth_state,
            },
        )
        return 201, service.drill_dict(drill), {}

    return run_idempotent(request, session, principal, key, body.model_dump(mode="json"), action)


# ------------------------------------------------------------------ herstelkit
@router.post("/recovery/kit/export", status_code=201, summary="Versleutelde herstelkit maken (zonder geheimen)")
def export_kit(
    body: KitExportIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    try:
        check_passphrase(body.passphrase)
    except KitError as exc:
        raise ApiError(422, "validation_error", str(exc), {"veld": "passphrase"}) from exc

    def action() -> tuple[int, Any, dict[str, str]]:
        content = service.build_register(session, _settings(request).break_glass_test_max_age_days, principal.audit_id)
        kit = encrypt_kit(content, body.passphrase)
        exp = SsoRecoveryKitExport(
            id=uuid.uuid4(),
            created_at=utcnow(),
            created_by=principal.audit_id,
            format=kit["format"],
            ciphertext_sha256=kit["ciphertext_sha256"],
            register_sha256=content["register_sha256"],
            accounts_count=len(content["register"]["accounts"]),
        )
        session.add(exp)
        session.flush()
        audit.record(
            session,
            domain="sso",
            action="recovery_kit.exported",
            entity_type="sso_recovery_kit_export",
            entity_id=str(exp.id),
            principal=principal,
            trace_id=tid,
            message_nl=f"Versleutelde herstelkit gemaakt ({exp.accounts_count} account(s)).",
            details={"ciphertext_sha256": exp.ciphertext_sha256, "register_sha256": exp.register_sha256},
        )
        events.emit(
            session,
            event_type="sso.recovery_kit.exported",
            entity_type="sso_recovery_kit_export",
            entity_id=str(exp.id),
            actor_type=principal.actor_type,
            actor_id=principal.audit_id,
            trace_id=tid,
            payload={"accounts_count": exp.accounts_count},
        )
        date = utcnow().strftime("%Y%m%d")
        return (
            201,
            {
                "export_id": str(exp.id),
                "file_name": f"hch-herstelkit-{date}.json",
                "accounts_count": exp.accounts_count,
                "register_sha256": exp.register_sha256,
                "contains_secrets": False,
                "kit": kit,
                "note_nl": "Bewaar dit bestand offline (bijv. USB-stick in de kluis) en de wachtwoordzin apart. "
                "De kit bevat geen wachtwoorden, codes of sleutels.",
            },
            {},
        )

    # de wachtwoordzin gaat alleen als HMAC in de verzoek-hash (zie idempotency.py)
    return run_idempotent(
        request,
        session,
        principal,
        key,
        {"passphrase_sha256": hashlib.sha256(body.passphrase.encode()).hexdigest()},
        action,
    )


@router.post("/recovery/kit/verify", summary="Controleren dat een herstelkit te openen is (wijzigt niets)")
def verify_kit(body: KitVerifyIn, _p: Principal = Depends(require_admin)) -> dict[str, Any]:
    try:
        data = decrypt_kit(body.kit, body.passphrase)
    except KitError as exc:
        raise ApiError(422, "herstelkit_onleesbaar", str(exc)) from exc
    register = data.get("register") or {}
    return {
        "readable": True,
        "format": data.get("format"),
        "created_at": data.get("created_at"),
        "accounts_count": len(register.get("accounts", [])),
        "register_sha256": data.get("register_sha256"),
        "contains_secrets": data.get("contains_secrets"),
        "procedure_steps": len(data.get("procedure_nl", [])),
    }


@router.get("/recovery/kit/exports", summary="Eerder gemaakte herstelkits (alleen metadata)")
def list_exports(
    limit: int = Query(default=20, ge=1, le=200),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin),
) -> dict[str, Any]:
    rows = session.scalars(select(SsoRecoveryKitExport).order_by(SsoRecoveryKitExport.created_at.desc()).limit(limit))
    return {
        "items": [
            {
                "export_id": str(r.id),
                "created_at": iso(r.created_at),
                "created_by": r.created_by,
                "format": r.format,
                "ciphertext_sha256": r.ciphertext_sha256,
                "register_sha256": r.register_sha256,
                "accounts_count": r.accounts_count,
            }
            for r in rows
        ],
        "next_cursor": None,
    }
