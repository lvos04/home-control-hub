"""B13-002…005 — routes onder ``/integrations/v1/sso`` voor Authentik, SSO-mapping, audit en back-up/upgrade.

Rechten (least privilege, B13-004):
- dekkingsmatrix en groep→rol-koppelingen lezen: alle lezers + de Hub (de Hub vertaalt groepen naar rollen);
- koppelingen/loginroute wijzigen: alleen ``admin`` (rollen/privileges wijzigen nooit door de Hub of AI);
- detectie, synchronisatie, export, gate en herstelcheck: ``admin`` of de Hub (service);
- rechtenkaart, events en exports inzien: alleen ``admin``; afwijkingen en voorstellen: ook ``operator``.
Een ``viewer`` kan hier niets wijzigen en ziet nooit credentials (die geeft deze dienst nergens terug).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import select, tuple_
from sqlalchemy.orm import Session

from ... import API_PREFIX, audit, events
from ...deps import check_if_match, etag, get_session, if_match, trace_id
from ...errors import ApiError, not_found
from ...idempotency import idempotency_key, run_idempotent
from ...models import ServiceState
from ...pagination import decode_cursor, encode_cursor, limit_param
from ...redact import looks_like_secret
from ...security.auth import (
    Principal,
    require_admin,
    require_admin_operator_or_service,
    require_admin_or_service,
    require_connector_reader,
)
from ...sources import ALL_SOURCES, source_view
from ...timeutil import iso, utcnow
from . import authaudit, backup, mapping, proposals
from .authentik import compat
from .authentik.client import AuthentikError
from .authentik.reader import detect, read_bindings, read_state, read_version
from .models import SsoAnomaly, SsoAppSetting, SsoAuthentikSnapshot, SsoAuthEvent, SsoGroupRoleMapping, SsoProposal
from .oidc_hub import ACTION_ID as HUB_OIDC_ACTION
from .oidc_hub import check_https_url, check_hub_client

router = APIRouter(prefix=f"{API_PREFIX}/sso", tags=["sso"])
DETECT_KEY = "authentik_detect"
SLUG = r"^[a-z0-9][a-z0-9-]{1,48}$"
USERNAME = r"^[A-Za-z0-9._@+-]{1,150}$"


def _no_secret(value: str, field: str) -> str:
    if looks_like_secret(value):
        raise ValueError(f"{field} lijkt een token, sleutel of wachtwoord te bevatten; sla hier geen geheimen op")
    return value


def _actor(p: Principal) -> tuple[str, str]:
    return (p.actor_type, p.audit_id)


# ------------------------------------------------------------------ schema's
class HubOidcIn(BaseModel):
    """Parameters voor ``sso.oidc.hub.register`` (B13-002). Redirect-URI's komen uit de Hub (D17), nooit een voorbeeld."""

    model_config = ConfigDict(extra="forbid")
    redirect_uris: list[str] = Field(min_length=1, max_length=5)
    application_slug: str = Field(default="hub", pattern=SLUG)
    application_name: str = Field(default="Hub", min_length=1, max_length=80)
    provider_name: str = Field(default="Hub (OIDC)", min_length=1, max_length=80)
    launch_url: str | None = Field(default=None, max_length=300)
    authorization_flow_slug: str = Field(default=compat.DEFAULT_AUTHZ_FLOW, pattern=SLUG)
    invalidation_flow_slug: str = Field(default=compat.DEFAULT_INVALIDATION_FLOW, pattern=SLUG)
    signing_key_name: str | None = Field(default=None, min_length=1, max_length=150)

    @field_validator("redirect_uris")
    @classmethod
    def _uris(cls, v: list[str]) -> list[str]:
        out = [check_https_url(u, "redirect_uri") for u in v]
        if len(set(out)) != len(out):
            raise ValueError("dubbele redirect_uri")
        return out

    @field_validator("launch_url")
    @classmethod
    def _launch(cls, v: str | None) -> str | None:
        return None if v is None else check_https_url(v, "launch_url")

    @field_validator("application_slug")
    @classmethod
    def _slug(cls, v: str) -> str:
        if v in compat.RESERVED_APP_SLUGS:
            raise ValueError("deze slug is in Authentik gereserveerd")
        return v

    @field_validator("application_name", "provider_name")
    @classmethod
    def _names(cls, v: str, info: Any) -> str:
        return _no_secret(v, info.field_name)


class SessionsRevokeIn(BaseModel):
    """Parameters voor ``sso.sessions.revoke`` (B13-005)."""

    model_config = ConfigDict(extra="forbid")
    usernames: list[str] = Field(default_factory=list, max_length=50)
    all_users: bool = False

    @field_validator("usernames")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        import re

        for name in v:
            if not re.match(USERNAME, name):
                raise ValueError("ongeldige gebruikersnaam")
        return sorted(set(v))

    @model_validator(mode="after")
    def _one(self) -> SessionsRevokeIn:
        if bool(self.usernames) == self.all_users:
            raise ValueError("kies óf 'usernames' óf 'all_users': true")
        return self


PARAMETER_MODELS: dict[str, type[BaseModel]] = {
    HUB_OIDC_ACTION: HubOidcIn,
    proposals.SESSIONS_ACTION: SessionsRevokeIn,
}


class ProposeIn(BaseModel):
    """ActionProposal (contract §8). ``risk_claim`` is informatief en wordt **genegeerd** voor de beslissing (EX18)."""

    model_config = ConfigDict(extra="forbid")
    action_id: str = Field(min_length=1, max_length=60)
    parameters: dict[str, Any] = Field(default_factory=dict)
    target: dict[str, Any] | None = None
    reason: str = Field(default="", max_length=300)
    actor: dict[str, Any] | None = None
    expected_version: str | None = Field(default=None, max_length=64)
    risk_claim: Literal["R0", "R1", "R2", "R3"] | None = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    expires_in_seconds: int | None = Field(default=None, ge=1, le=3600)
    idempotency_key: str | None = Field(default=None, max_length=64)

    @field_validator("reason")
    @classmethod
    def _reason(cls, v: str) -> str:
        return _no_secret(v, "reason")


class AppSettingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    login_mode: Literal["native", "oidc"]
    notes: str = Field(default="", max_length=500)

    @field_validator("notes")
    @classmethod
    def _notes(cls, v: str) -> str:
        return _no_secret(v, "notes")


class InstallationCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outcome: Literal["handmatig_bevestigd", "mislukt"]
    notes: str = Field(default="", max_length=500)

    @field_validator("notes")
    @classmethod
    def _notes(cls, v: str) -> str:
        return _no_secret(v, "notes")


class MappingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app_id: str = Field(min_length=1, max_length=60)
    authentik_group: str = Field(min_length=1, max_length=150)
    role: str = Field(min_length=1, max_length=30)

    @field_validator("authentik_group")
    @classmethod
    def _group(cls, v: str) -> str:
        v = v.strip()
        if not v or any(ord(c) < 32 for c in v):
            raise ValueError("ongeldige groepsnaam")
        return _no_secret(v, "authentik_group")


class BackupCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=120)
    taken_at: datetime | None = None


class UpgradeGateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_version: str = Field(min_length=1, max_length=20)
    backup_checkpoint: BackupCheckpoint | None = None


class RestoreCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    export_id: uuid.UUID


# ------------------------------------------------------------------ hulpfuncties
def _client(request: Request, session: Session) -> Any:
    return proposals.authentik_client(request, session)


def _record(
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
    classification: str = "internal",
) -> str:
    ev = audit.record(
        session,
        domain="sso",
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        principal=principal,
        trace_id=tid,
        message_nl=message_nl,
        details=payload,
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
    session.flush()
    return str(ev.id)


def validate_parameters(action_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
    model = PARAMETER_MODELS.get(action_id)
    if model is None:
        raise ApiError(
            422, "onbekende_actie", "Onbekende action_id; zie /connector/v1/discover.", {"action_id": action_id}
        )
    try:
        return model.model_validate(parameters).model_dump()
    except ValidationError as exc:
        problems = [
            {
                "veld": ".".join(str(p) for p in e.get("loc", ())),
                "probleem": str(e.get("msg", "")).removeprefix("Value error, "),
            }
            for e in exc.errors()
        ]
        raise ApiError(
            422, "validation_error", "De parameters van het voorstel zijn ongeldig.", {"fouten": problems}
        ) from exc


# ------------------------------------------------------------------ Authentik: status en detectie (B13-002/004)
@router.get("/authentik", summary="Authentik: bron, laatste detectie en synchronisatie (zonder externe call)")
def authentik_status(
    session: Session = Depends(get_session), _p: Principal = Depends(require_admin_operator_or_service)
) -> dict[str, Any]:
    row = session.get(ServiceState, DETECT_KEY)
    return {
        "source": source_view(session, ALL_SOURCES["authentik"]),
        "detection": dict(row.value) if row is not None else None,
        "sync": authaudit.sync_state(session),
        "verified_api": {
            "lines": [f"{y}.{m}" for y, m, _p in compat.RELEASE_LINES],
            "checked_on": compat.VERIFIED_ON,
            "evidence": "docs/b13/authentik-api-verificatie.json",
        },
    }


@router.post("/authentik/detect", summary="Authentik-versie, API-capabilities en tokenrechten nu bepalen")
def authentik_detect(
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        client = _client(request, session)
        result = detect(client)
        row = session.get(ServiceState, DETECT_KEY)
        if row is None:
            session.add(ServiceState(key=DETECT_KEY, value=result))
        else:
            row.value = result
        result["evidence_id"] = _record(
            session,
            principal,
            tid,
            action="authentik.detected",
            entity_type="integration_source",
            entity_id="authentik",
            message_nl=f"Authentik gedetecteerd: versie {result.get('version') or 'onbekend'}, status {result['status']}.",
            event_type="sso.authentik.detected",
            payload={
                "version": result.get("version"),
                "status": result["status"],
                "reason_code": result.get("reason_code"),
            },
        )
        return 200, result, {}

    return run_idempotent(request, session, principal, key, {"detect": True}, action)


# ------------------------------------------------------------------ B13-002: Hub-client controleren (alleen lezen)
@router.get("/oidc/hub/check", summary="Bestaande Hub-client in Authentik controleren (alleen lezen)")
def oidc_hub_check(
    request: Request,
    slug: str = Query(default="hub", pattern=SLUG),
    redirect_uri: list[str] | None = Query(default=None, max_length=5),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin_operator_or_service),
) -> dict[str, Any]:
    expected = None
    if redirect_uri:
        try:
            expected = [check_https_url(u, "redirect_uri") for u in redirect_uri]
        except ValueError as exc:
            raise ApiError(422, "validation_error", str(exc), {"veld": "redirect_uri"}) from exc
    client = _client(request, session)
    try:
        caps = read_version(client)
        state = read_state(client, ("applications", "providers", "scope_mappings", "groups"), caps=caps)
        app = next((a for a in state.get("applications") or [] if a.get("slug") == slug), None)
        bindings = None
        if app is not None:
            try:
                bindings = read_bindings(client, str(app["pk"]))
            except AuthentikError:
                bindings = None
    except AuthentikError as exc:
        raise proposals.authentik_api_error(exc) from exc
    discovery: dict[str, Any] | None = None
    disc_err: str | None = None
    try:
        doc = client.get_public_json(f"/application/o/{slug}/.well-known/openid-configuration")
        discovery = doc if isinstance(doc, dict) else None
        disc_err = None if discovery is not None else "antwoord_ongeldig"
    except AuthentikError as exc:
        disc_err = exc.reason
    result = check_hub_client(state, slug, expected, bindings, discovery, disc_err, proposals.hub_role_groups(session))
    result.update(
        {
            "authentik_version": caps.version,
            "observed_at": iso(utcnow()),
            "validation_nl": "Alleen gelezen; niets gewijzigd.",
        }
    )
    return result


# ------------------------------------------------------------------ voorstellen (lezen)
@router.get("/proposals", summary="Voorstellen (nieuwste eerst; alleen preview, niet toepasbaar)")
def list_proposals(
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin_operator_or_service),
) -> dict[str, Any]:
    stmt = select(SsoProposal).order_by(SsoProposal.created_at.desc(), SsoProposal.id.desc())
    after = decode_cursor(cursor)
    if after is not None:
        try:
            ts, pid = datetime.fromisoformat(after[0]), uuid.UUID(after[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.") from exc
        stmt = stmt.where(tuple_(SsoProposal.created_at, SsoProposal.id) < tuple_(ts, pid))
    rows = list(session.scalars(stmt.limit(limit + 1)))
    nxt = (
        encode_cursor([rows[limit - 1].created_at.isoformat(), str(rows[limit - 1].id)]) if len(rows) > limit else None
    )
    return {"items": [proposals.proposal_view(r) for r in rows[:limit]], "next_cursor": nxt}


@router.get("/proposals/{proposal_id}", summary="Eén voorstel met diff en preview_hash")
def get_proposal(
    proposal_id: uuid.UUID,
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin_operator_or_service),
) -> dict[str, Any]:
    row = session.get(SsoProposal, proposal_id)
    if row is None:
        raise not_found("Voorstel")
    return proposals.proposal_view(row)


# ------------------------------------------------------------------ B13-003: dekking per app en groep → rol
@router.get("/app-coverage", summary="SSO-dekkingsmatrix per app (bron + verificatiestatus, loginroute, koppelingen)")
def app_coverage(
    session: Session = Depends(get_session), _p: Principal = Depends(require_connector_reader)
) -> dict[str, Any]:
    return {
        "items": mapping.coverage(session),
        "next_cursor": None,
        "note_nl": "'geverifieerd_docs'/'geverifieerd_broncode' = in de genoemde bron gelezen, niet op een echte installatie "
        "getest. Vertrouwde-header-SSO (X-Forwarded-User e.d.) is nooit toegestaan.",
    }


@router.put("/apps/{app_id}/setting", summary="Loginroute van een app kiezen (native/oidc; If-Match bij bestaand)")
def put_app_setting(
    app_id: str,
    body: AppSettingIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    spec = mapping.app_spec(app_id)
    mapping.validate_login_mode(spec, body.login_mode)

    def action() -> tuple[int, Any, dict[str, str]]:
        row = session.get(SsoAppSetting, app_id)
        created = row is None
        if row is None:
            if match not in (None, "*"):
                raise ApiError(412, "precondition_failed", "Deze instelling bestaat nog niet.")
            row = SsoAppSetting(
                app_id=app_id,
                login_mode=body.login_mode,
                installation_check="niet_getest",
                notes=body.notes,
                version=1,
                updated_by=principal.audit_id,
            )
            session.add(row)
        else:
            check_if_match(row.version, match)
            if row.login_mode != body.login_mode:
                row.installation_check, row.checked_at, row.checked_by = "niet_getest", None, None
            row.login_mode, row.notes, row.updated_by = body.login_mode, body.notes, principal.audit_id
            row.version += 1
        session.flush()
        _record(
            session,
            principal,
            tid,
            action="app_setting.changed",
            entity_type="sso_app_setting",
            entity_id=app_id,
            message_nl=f"Loginroute van {spec.display_name} ingesteld op {body.login_mode}.",
            event_type="sso.app_setting.changed",
            payload={"app_id": app_id, "login_mode": body.login_mode},
        )
        return (201 if created else 200), mapping.setting_dict(row), {"ETag": etag(row.version)}

    return run_idempotent(request, session, principal, key, {"app_id": app_id, **body.model_dump()}, action)


@router.post("/apps/{app_id}/installation-check", summary="Echte testlogin handmatig bevestigen of als mislukt melden")
def post_installation_check(
    app_id: str,
    body: InstallationCheckIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    spec = mapping.app_spec(app_id)

    def action() -> tuple[int, Any, dict[str, str]]:
        row = session.get(SsoAppSetting, app_id)
        if row is None or row.login_mode != "oidc":
            raise ApiError(409, "conflict", "Kies eerst de loginroute 'oidc' voor deze app; alleen die wordt getest.")
        row.installation_check, row.checked_at, row.checked_by = body.outcome, utcnow(), principal.audit_id
        row.notes = body.notes or row.notes
        fallback = body.outcome == "mislukt"
        if fallback:
            row.login_mode = "native"  # mislukt → terug naar de eigen login (B13-003)
        row.version += 1
        session.flush()
        _record(
            session,
            principal,
            tid,
            action="app_setting.checked",
            entity_type="sso_app_setting",
            entity_id=app_id,
            message_nl=f"Testlogin {spec.display_name}: {body.outcome}"
            + ("; terug naar de eigen login." if fallback else "."),
            event_type="sso.app_setting.checked",
            payload={"app_id": app_id, "outcome": body.outcome, "login_mode": row.login_mode},
        )
        return (
            200,
            {**mapping.setting_dict(row), "validation_nl": "Handmatig bevestigd door een beheerder (attestatie)."},
            {"ETag": etag(row.version)},
        )

    return run_idempotent(request, session, principal, key, {"app_id": app_id, **body.model_dump()}, action)


@router.get("/role-mappings", summary="Authentik-groep → rol per app (ook voor de Hub)")
def list_mappings(
    app_id: str | None = None,
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_connector_reader),
) -> dict[str, Any]:
    stmt = select(SsoGroupRoleMapping).order_by(SsoGroupRoleMapping.app_id, SsoGroupRoleMapping.authentik_group)
    if app_id:
        stmt = stmt.where(SsoGroupRoleMapping.app_id == app_id)
    return {"items": [mapping.mapping_dict(m) for m in session.scalars(stmt)], "next_cursor": None}


@router.post("/role-mappings", status_code=201, summary="Groep aan een rol koppelen (alleen admin)")
def create_mapping(
    body: MappingIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    spec = mapping.validate_mapping(session, body.app_id, body.authentik_group, body.role)

    def action() -> tuple[int, Any, dict[str, str]]:
        exists = session.scalar(
            select(SsoGroupRoleMapping).where(
                SsoGroupRoleMapping.app_id == body.app_id, SsoGroupRoleMapping.authentik_group == body.authentik_group
            )
        )
        if exists is not None:
            raise ApiError(
                409, "conflict", "Deze groep is al aan een rol in deze app gekoppeld.", {"id": str(exists.id)}
            )
        row = SsoGroupRoleMapping(
            id=uuid.uuid4(),
            app_id=body.app_id,
            authentik_group=body.authentik_group,
            role=body.role,
            version=1,
            created_by=principal.audit_id,
            updated_by=principal.audit_id,
        )
        session.add(row)
        session.flush()
        _record(
            session,
            principal,
            tid,
            action="role_mapping.created",
            entity_type="sso_group_role_mapping",
            entity_id=str(row.id),
            message_nl=f"Groep '{body.authentik_group}' gekoppeld aan rol '{body.role}' in {spec.display_name}.",
            event_type="sso.role_mapping.changed",
            payload={
                "app_id": body.app_id,
                "authentik_group": body.authentik_group,
                "role": body.role,
                "change": "aangemaakt",
            },
        )
        return 201, mapping.mapping_dict(row), {"ETag": etag(row.version)}

    return run_idempotent(request, session, principal, key, body.model_dump(), action)


@router.delete("/role-mappings/{mapping_id}", summary="Koppeling verwijderen (If-Match verplicht)")
def delete_mapping(
    mapping_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        row = session.get(SsoGroupRoleMapping, mapping_id)
        if row is None:
            raise not_found("Koppeling")
        check_if_match(row.version, match)
        info = mapping.mapping_dict(row)
        session.delete(row)
        session.flush()
        _record(
            session,
            principal,
            tid,
            action="role_mapping.deleted",
            entity_type="sso_group_role_mapping",
            entity_id=str(mapping_id),
            message_nl=f"Koppeling '{info['authentik_group']}' → '{info['role']}' ({info['app_id']}) verwijderd.",
            event_type="sso.role_mapping.changed",
            payload={
                "app_id": info["app_id"],
                "authentik_group": info["authentik_group"],
                "role": info["role"],
                "change": "verwijderd",
            },
        )
        return 200, {"deleted": info}, {}

    return run_idempotent(request, session, principal, key, {"mapping_id": str(mapping_id)}, action)


# ------------------------------------------------------------------ B13-004: audit, afwijkingen, rechtenkaart
@router.post("/authentik/sync", summary="Events en rechtenkaart nu uit Authentik lezen (anders doet de worker het)")
def authentik_sync(
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        client = _client(request, session)
        result = authaudit.sync(session, client, _actor(principal), tid)
        session.flush()
        return 200, result, {}

    return run_idempotent(request, session, principal, key, {"sync": True}, action)


@router.get("/authentik/events", summary="Gelezen Authentik-events (minimaal, nieuwste eerst)")
def list_auth_events(
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    action: str | None = Query(default=None, max_length=40),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin),
) -> dict[str, Any]:
    stmt = select(SsoAuthEvent).order_by(SsoAuthEvent.created.desc(), SsoAuthEvent.authentik_pk.desc())
    if action:
        stmt = stmt.where(SsoAuthEvent.action == action)
    after = decode_cursor(cursor)
    if after is not None:
        try:
            ts, pk = datetime.fromisoformat(after[0]), str(after[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.") from exc
        stmt = stmt.where(tuple_(SsoAuthEvent.created, SsoAuthEvent.authentik_pk) < tuple_(ts, pk))
    rows = list(session.scalars(stmt.limit(limit + 1)))
    items = [
        {
            "authentik_pk": r.authentik_pk,
            "action": r.action,
            "username": r.username,
            "client_ip": r.client_ip,
            "created": iso(r.created),
            "model_name": r.model_name,
            "model_label": r.model_label,
        }
        for r in rows[:limit]
    ]
    nxt = (
        encode_cursor([rows[limit - 1].created.isoformat(), rows[limit - 1].authentik_pk])
        if len(rows) > limit
        else None
    )
    return {"items": items, "next_cursor": nxt, "retention_days": authaudit.RETENTION.days}


def anomaly_dict(a: SsoAnomaly) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "rule_id": a.rule_id,
        "severity": a.severity,
        "subject": a.subject,
        "message_nl": a.message_nl,
        "details": a.details,
        "first_seen": iso(a.first_seen),
        "last_seen": iso(a.last_seen),
        "count": a.count,
        "detected_at": iso(a.detected_at),
        "status": a.status,
    }


@router.get("/anomalies", summary="Afwijkingen uit Authentik-events en rechtenwijzigingen (nieuwste eerst)")
def list_anomalies(
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin_operator_or_service),
) -> dict[str, Any]:
    stmt = select(SsoAnomaly).order_by(SsoAnomaly.detected_at.desc(), SsoAnomaly.id.desc())
    after = decode_cursor(cursor)
    if after is not None:
        try:
            ts, aid = datetime.fromisoformat(after[0]), uuid.UUID(after[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.") from exc
        stmt = stmt.where(tuple_(SsoAnomaly.detected_at, SsoAnomaly.id) < tuple_(ts, aid))
    rows = list(session.scalars(stmt.limit(limit + 1)))
    nxt = (
        encode_cursor([rows[limit - 1].detected_at.isoformat(), str(rows[limit - 1].id)]) if len(rows) > limit else None
    )
    return {"items": [anomaly_dict(a) for a in rows[:limit]], "next_cursor": nxt}


@router.get(
    "/rights",
    summary="Rechtenkaart (gebruiker → groepen → rol per app) met verschillen; 'verouderd' als de lezing te oud is",
)
def rights(
    request: Request, session: Session = Depends(get_session), _p: Principal = Depends(require_admin)
) -> dict[str, Any]:
    max_age = authaudit.rights_max_age(request.app.state.settings.authentik_sync_interval_s)
    return authaudit.rights_view(session, max_age)


# ------------------------------------------------------------------ B13-005: export, gate, herstelcheck
@router.post(
    "/authentik/config-exports", status_code=201, summary="Geschoonde configuratie-export maken (API + blueprints)"
)
def create_config_export(
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        client = _client(request, session)
        try:
            row = backup.create_export(session, client, _actor(principal), tid)
        except AuthentikError as exc:
            raise proposals.authentik_api_error(exc) from exc
        meta = backup.export_meta(row)
        meta["evidence_id"] = _record(
            session,
            principal,
            tid,
            action="authentik.config_exported",
            entity_type="sso_authentik_snapshot",
            entity_id=str(row.id),
            message_nl=f"Configuratie van Authentik {row.authentik_version or '?'} geëxporteerd ("
            + ("volledig" if row.complete else "ONVOLLEDIG")
            + ").",
            event_type="sso.authentik.config_exported",
            payload={"export_id": str(row.id), "complete": row.complete, "content_sha256": row.content_sha256},
        )
        return 201, meta, {}

    return run_idempotent(request, session, principal, key, {"export": True}, action)


@router.get("/authentik/config-exports", summary="Configuratie-exports (alleen metadata)")
def list_config_exports(
    cursor: str | None = None,
    limit: int = Depends(limit_param),
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_admin),
) -> dict[str, Any]:
    stmt = (
        select(SsoAuthentikSnapshot)
        .where(SsoAuthentikSnapshot.kind == "config_export")
        .order_by(SsoAuthentikSnapshot.taken_at.desc(), SsoAuthentikSnapshot.id.desc())
    )
    after = decode_cursor(cursor)
    if after is not None:
        try:
            ts, sid = datetime.fromisoformat(after[0]), uuid.UUID(after[1])
        except (ValueError, TypeError, IndexError) as exc:
            raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.") from exc
        stmt = stmt.where(tuple_(SsoAuthentikSnapshot.taken_at, SsoAuthentikSnapshot.id) < tuple_(ts, sid))
    rows = list(session.scalars(stmt.limit(limit + 1)))
    nxt = encode_cursor([rows[limit - 1].taken_at.isoformat(), str(rows[limit - 1].id)]) if len(rows) > limit else None
    return {"items": [backup.export_meta(r) for r in rows[:limit]], "next_cursor": nxt}


@router.get("/authentik/config-exports/{export_id}", summary="Eén configuratie-export (geschoond, zonder geheimen)")
def get_config_export(
    export_id: uuid.UUID, session: Session = Depends(get_session), _p: Principal = Depends(require_admin)
) -> Any:
    row = session.get(SsoAuthentikSnapshot, export_id)
    if row is None or row.kind != "config_export":
        raise not_found("Export")
    return JSONResponse(
        {**backup.export_meta(row), "content": row.content}, headers={"ETag": f'"{row.content_sha256}"'}
    )


@router.post("/authentik/upgrade-gate", summary="Pre-upgrade-gate voor Authentik (nooit 'groen' op aannames)")
def upgrade_gate(
    body: UpgradeGateIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        client = _client(request, session)
        cp = body.backup_checkpoint.model_dump(mode="json") if body.backup_checkpoint else None
        result = backup.upgrade_gate(
            session,
            client,
            body.target_version,
            cp,
            backup_confirmed_by_hub=principal.kind == "service",
            break_glass_max_age_days=request.app.state.settings.break_glass_test_max_age_days,
        )
        result["evidence_id"] = _record(
            session,
            principal,
            tid,
            action="authentik.upgrade_gate",
            entity_type="integration_source",
            entity_id="authentik",
            message_nl=f"Pre-upgrade-gate naar {body.target_version}: {result['outcome']}.",
            event_type="sso.authentik.upgrade_gate.evaluated",
            payload={
                "target_version": body.target_version,
                "outcome": result["outcome"],
                "failed": [c["name"] for c in result["checks"] if c["status"] != "ok"],
            },
        )
        return 200, result, {}

    return run_idempotent(request, session, principal, key, body.model_dump(mode="json"), action)


@router.post("/authentik/restore-check", summary="Herstelcheck: klopt Authentik weer met een eerdere export?")
def restore_check(
    body: RestoreCheckIn,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin_or_service),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> tuple[int, Any, dict[str, str]]:
        snap = session.get(SsoAuthentikSnapshot, body.export_id)
        if snap is None or snap.kind != "config_export":
            raise not_found("Export")
        if not snap.complete:
            raise ApiError(
                409, "export_onvolledig", "Deze export is onvolledig en is geen betrouwbare vergelijkingsbasis."
            )
        client = _client(request, session)
        result = backup.restore_check(snap, client, session)
        failed = [c["name"] for c in result["checks"] if c["status"] != "ok"]
        result["evidence_id"] = _record(
            session,
            principal,
            tid,
            action="authentik.restore_check",
            entity_type="sso_authentik_snapshot",
            entity_id=str(snap.id),
            message_nl=f"Herstelcheck tegen export {snap.id}: {result['outcome']}.",
            event_type="sso.authentik.restore_check.completed",
            payload={"export_id": str(snap.id), "outcome": result["outcome"], "failed": failed},
        )
        if result["outcome"] == "afwijking":
            authaudit._record_anomaly(
                session,
                rule_id="herstel_afwijking",
                dedupe_key=f"herstel:{snap.id}:{result['evidence_id']}",
                severity="hoog",
                subject=None,
                message_nl="Na herstel/upgrade wijkt Authentik af van de export (rechten, 2FA of clients).",
                details={"failed": failed, "export_id": str(snap.id)},
                first_seen=utcnow(),
                last_seen=utcnow(),
                count=1,
                actor=_actor(principal),
                tid=tid,
            )
        return 200, result, {}

    return run_idempotent(request, session, principal, key, {"export_id": str(body.export_id)}, action)
