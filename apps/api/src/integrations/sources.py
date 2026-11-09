"""Bronnen: catalogus (alle domeinen) + runtime-toestand + configuratie + liveness-probe.

- Zonder configuratie: ``niet_geconfigureerd`` en health ``unknown`` (nooit gezond).
- Credentials alleen write-only in de vault (``vault://source/<id>``); de API toont alleen of er één is + laatste 4.
- Een probe bestaat alleen waar een gezondheids-endpoint in de catalogus staat (te verifiëren); anders
  ``capability_unavailable``. Een probe zegt alleen "endpoint antwoordde", niets over de volledige werking.
- Een meting ouder dan :data:`PROBE_MAX_AGE` (15 min, gelijk aan de inventaris-TTL van de Hub) is verouderd: de API
  geeft dan ``unknown`` met ``reason_code: meting_verouderd`` en de tijd van de laatste meting, nooit de laatst bekende
  stand ("nooit healthy op stale cache", 05_OPERATIES; ADR-0012/ADR-0013). Statuspagina en connector-health gebruiken
  dezelfde regel.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from . import API_PREFIX, audit, events
from .config import Settings
from .deps import check_if_match, etag, get_session, if_match, trace_id
from .domains import DOMAINS, SourceSpec
from .domains.automation.catalog import SOURCES as AUTOMATION_SOURCES
from .domains.energy.catalog import SOURCES as ENERGY_SOURCES
from .domains.network.catalog import SOURCES as NETWORK_SOURCES
from .domains.sso.catalog import SOURCES as SSO_SOURCES
from .errors import ApiError, capability_unavailable, not_found
from .hubclient import HubUrlError, validate_hub_url
from .idempotency import idempotency_key, run_idempotent
from .models import IntegrationSource
from .redact import looks_like_secret
from .security.auth import Principal, require_admin, require_reader
from .timeutil import ensure_aware, iso, utcnow

ALL_SOURCES: dict[str, SourceSpec] = {
    s.source_id: s for s in (*NETWORK_SOURCES, *AUTOMATION_SOURCES, *SSO_SOURCES, *ENERGY_SOURCES)
}


#: een bronmeting ouder dan dit telt als onbekend (nooit de laatst bekende stand); ADR-0012/ADR-0013
PROBE_MAX_AGE = timedelta(minutes=15)


def probe_is_stale(measured_at: datetime | None, now: datetime | None = None) -> bool:
    """``True`` als er geen meting is of de meting ouder is dan :data:`PROBE_MAX_AGE`."""
    return measured_at is None or (now or utcnow()) - ensure_aware(measured_at) > PROBE_MAX_AGE


def effective_probe(row: IntegrationSource | None, now: datetime | None = None) -> tuple[str, str]:
    """(status, reason_code) zoals die nu naar buiten gaat: uit/niet ingesteld en verouderd zijn ``unknown``."""
    if row is None:
        return "unknown", "niet_geconfigureerd"
    if not row.enabled:
        return "unknown", "uitgeschakeld"
    if not row.base_url:
        return "unknown", "niet_geconfigureerd"
    if row.last_probe_at is None:
        return "unknown", row.last_probe_reason or "nog_niet_gecontroleerd"
    if probe_is_stale(row.last_probe_at, now):
        return "unknown", "meting_verouderd"
    return row.last_probe_status, row.last_probe_reason or "nog_niet_gecontroleerd"


def source_ref(source_id: str) -> str:
    return f"vault://source/{source_id.replace('_', '-')}"


def runtime_view(spec: SourceSpec, row: IntegrationSource | None, last4: str | None = None) -> dict[str, Any]:
    if row is None:
        return {
            "configured": False,
            "enabled": False,
            "base_url": None,
            "credential_present": False,
            "credential_last4": None,
            "health": {"status": "unknown", "reason_code": "niet_geconfigureerd", "observed_at": None, "detail": {}},
            "version": 0,
            "etag": None,
        }
    return {
        "configured": bool(row.base_url),
        "enabled": row.enabled,
        "base_url": row.base_url,
        "credential_present": row.credential_ref is not None,
        "credential_last4": last4,
        "health": _health_view(row),
        "version": row.version,
        "etag": etag(row.version),
        "updated_at": iso(row.updated_at),
        "updated_by": row.updated_by,
    }


def _health_view(row: IntegrationSource) -> dict[str, Any]:
    status, reason = effective_probe(row)
    detail: dict[str, Any] = row.last_probe_detail or {}
    if reason == "meting_verouderd":  # alleen de tijd van de laatste meting, niet de oude stand of details
        detail = {"max_leeftijd_s": int(PROBE_MAX_AGE.total_seconds())}
    return {"status": status, "reason_code": reason, "observed_at": iso(row.last_probe_at), "detail": detail}


def _last4(session: Session, ref: str | None) -> str | None:
    if not ref:
        return None
    from .models import VaultSecret

    row = session.get(VaultSecret, ref)
    return row.last4 if row is not None and row.last4 else None


def source_view(session: Session, spec: SourceSpec) -> dict[str, Any]:
    row = session.get(IntegrationSource, spec.source_id)
    return {**spec.to_dict(), "runtime": runtime_view(spec, row, _last4(session, row.credential_ref if row else None))}


def probe_http(
    settings: Settings, transport: httpx.BaseTransport | None, base_url: str, path: str
) -> tuple[str, str, dict[str, Any]]:
    """Eén GET op het liveness-pad; geeft (status, reason_code, detail). Volgt geen redirects."""
    timeout = httpx.Timeout(
        connect=settings.http_connect_timeout_s, read=settings.http_read_timeout_s, write=5.0, pool=5.0
    )
    started = time.monotonic()
    try:
        # contract §5: uitgaande calls negeren proxy-omgevingsvariabelen (trust_env=False)
        with httpx.Client(timeout=timeout, transport=transport, follow_redirects=False, trust_env=False) as client:
            resp = client.get(base_url + path)
    except httpx.TimeoutException:
        return "down", "timeout", {"elapsed_ms": int((time.monotonic() - started) * 1000)}
    except httpx.TransportError:
        return "down", "onbereikbaar", {"elapsed_ms": int((time.monotonic() - started) * 1000)}
    detail = {"http_status": resp.status_code, "elapsed_ms": int((time.monotonic() - started) * 1000), "path": path}
    if 200 <= resp.status_code < 300:
        return "healthy", "liveness_ok", detail
    if resp.status_code >= 500:
        return "down", "http_5xx", detail
    return "unknown", "onverwacht_antwoord", detail


def probe_source(request: Request, session: Session, source_id: str) -> tuple[str, str, dict[str, Any]]:
    spec = ALL_SOURCES[source_id]
    if not spec.probe_path:
        raise capability_unavailable(f"{source_id}.probe", "Voor deze bron is (nog) geen gezondheidscontrole gebouwd.")
    row = session.get(IntegrationSource, source_id)
    if row is None or not row.base_url or not row.enabled:
        return "unknown", "niet_geconfigureerd", {}
    status, reason, detail = probe_http(
        request.app.state.settings, request.app.state.http_transport, row.base_url, spec.probe_path
    )
    row.last_probe_at = utcnow()
    row.last_probe_status = status
    row.last_probe_reason = reason
    row.last_probe_detail = detail
    return status, reason, detail


router = APIRouter(prefix=API_PREFIX, tags=["bronnen"])


class SourceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    base_url: str | None = Field(default=None, max_length=500, description="LAN-adres van de app (http/https).")
    enabled: bool = False
    credential: str | None = Field(
        default=None, min_length=8, max_length=4096, description="Write-only; wordt versleuteld in de vault bewaard."
    )
    clear_credential: bool = False


@router.get("/sources", summary="Alle bronnen (catalogus + toestand)")
def list_sources(
    domain: str | None = None,
    session: Session = Depends(get_session),
    _p: Principal = Depends(require_reader),
) -> dict[str, Any]:
    if domain is not None and domain not in DOMAINS:
        raise ApiError(400, "invalid_domain", f"Onbekend domein; kies uit {', '.join(DOMAINS)}.")
    items = [source_view(session, s) for s in ALL_SOURCES.values() if domain is None or s.domain == domain]
    return {"items": items, "next_cursor": None}


@router.get("/sources/{source_id}", summary="Eén bron")
def get_source(
    source_id: str, session: Session = Depends(get_session), _p: Principal = Depends(require_reader)
) -> dict[str, Any]:
    spec = ALL_SOURCES.get(source_id)
    if spec is None:
        raise not_found("Bron")
    return source_view(session, spec)


@router.put("/sources/{source_id}", summary="Bron configureren (adres, aan/uit, credential)")
def put_source(
    source_id: str,
    body: SourceConfig,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    match: str | None = Depends(if_match),
    tid: str = Depends(trace_id),
) -> Any:
    spec = ALL_SOURCES.get(source_id)
    if spec is None:
        raise not_found("Bron")
    settings: Settings = request.app.state.settings
    base_url: str | None = None
    if body.base_url:
        try:
            base_url = validate_hub_url(
                body.base_url, settings.allow_loopback_hub, label="Het adres van de bron", allow_path=True
            )
        except HubUrlError as exc:
            raise ApiError(422, "validation_error", str(exc), {"veld": "base_url"}) from exc
    if body.enabled and not base_url:
        raise ApiError(422, "validation_error", "Een bron aanzetten kan alleen met een adres.", {"veld": "base_url"})
    payload = body.model_dump()
    payload["credential"] = bool(body.credential)  # nooit de waarde in de verzoek-hash/opslag

    def action() -> tuple[int, Any, dict[str, str]]:
        row = session.get(IntegrationSource, source_id)
        created = row is None
        if row is None:
            if match not in (None, "*"):
                raise ApiError(412, "precondition_failed", "Deze bron bestaat nog niet.")
            row = IntegrationSource(source_id=source_id, domain=spec.domain, updated_by=principal.audit_id, version=1)
            session.add(row)
        else:
            check_if_match(row.version, match)
            row.version += 1
        changed_url = row.base_url != base_url
        row.base_url = base_url
        row.enabled = body.enabled
        row.updated_by = principal.audit_id
        if changed_url:
            row.last_probe_status, row.last_probe_reason, row.last_probe_at, row.last_probe_detail = (
                "unknown",
                None,
                None,
                {},
            )
        vault = request.app.state.vault
        if body.clear_credential and row.credential_ref:
            vault.delete(session, row.credential_ref)
            row.credential_ref = None
        if body.credential:
            ref = source_ref(source_id)
            vault.put(session, ref, body.credential)
            row.credential_ref = ref
        session.flush()
        audit.record(
            session,
            domain=spec.domain,
            action="source.configured",
            entity_type="integration_source",
            entity_id=source_id,
            principal=principal,
            trace_id=tid,
            message_nl=f"Bron {spec.display_name} {'aangemaakt' if created else 'gewijzigd'}.",
            details={"base_url": base_url, "enabled": body.enabled, "credential_changed": bool(body.credential)},
        )
        events.emit(
            session,
            event_type=f"{spec.domain}.source.configured",
            entity_type="integration_source",
            entity_id=source_id,
            actor_type=principal.actor_type,
            actor_id=principal.audit_id,
            trace_id=tid,
            payload={"enabled": body.enabled, "configured": bool(base_url)},
        )
        view = source_view(session, spec)
        return (201 if created else 200), view, {"ETag": etag(row.version)}

    return run_idempotent(request, session, principal, key, {"source_id": source_id, **payload}, action)


@router.post("/sources/{source_id}/probe", summary="Bereikbaarheid van de bron nu controleren")
def post_probe(
    source_id: str,
    request: Request,
    session: Session = Depends(get_session),
    principal: Principal = Depends(require_admin),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    spec = ALL_SOURCES.get(source_id)
    if spec is None:
        raise not_found("Bron")

    def action() -> tuple[int, Any, dict[str, str]]:
        status, reason, detail = probe_source(request, session, source_id)
        audit.record(
            session,
            domain=spec.domain,
            action="source.probed",
            entity_type="integration_source",
            entity_id=source_id,
            principal=principal,
            trace_id=tid,
            message_nl=f"Bereikbaarheid van {spec.display_name} gecontroleerd: {status} ({reason}).",
            details=detail,
        )
        return (
            200,
            {
                "source_id": source_id,
                "status": status,
                "reason_code": reason,
                "detail": detail,
                "observed_at": iso(utcnow()),
            },
            {},
        )

    return run_idempotent(request, session, principal, key, {"source_id": source_id}, action)


def reject_secretish(value: str, field: str) -> str:
    if looks_like_secret(value):
        raise ValueError(f"{field} lijkt een token, sleutel of wachtwoord te bevatten; sla geen geheimen op")
    return value
