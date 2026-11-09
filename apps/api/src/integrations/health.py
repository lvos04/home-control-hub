"""``/healthz`` (proces leeft), ``/readyz`` (afhankelijkheden ok) en de connector-health (contract §5/§6)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import APP_ID, __version__
from .domains.sso import service as sso_service
from .models import IntegrationSource, OutboxEvent
from .security.secrets import secrets_present
from .timeutil import iso, utcnow

router = APIRouter(tags=["gezondheid"])


@router.get("/healthz", summary="Proces leeft (zonder auth, zonder geheimen)")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "app_id": APP_ID, "version": __version__}


def readiness(request: Request) -> tuple[bool, list[dict[str, Any]]]:
    state = request.app.state
    checks: list[dict[str, Any]] = []
    db_ok = state.db.ping()
    checks.append({"name": "database", "status": "ok" if db_ok else "fout"})
    if db_ok:
        current = state.db.current_revision()
        at_head = current is not None and current == state.alembic_head
        checks.append(
            {
                "name": "migraties",
                "status": "ok" if at_head else "fout",
                "detail": {"huidig": current, "verwacht": state.alembic_head},
            }
        )
    present = secrets_present(state.settings.secrets_dir)
    checks.append({"name": "geheimen", "status": "ok" if all(present.values()) else "fout", "detail": present})
    return all(c["status"] == "ok" for c in checks), checks


@router.get("/readyz", summary="Klaar voor verkeer: database, migraties, geheimen (zonder auth)")
def readyz(request: Request) -> JSONResponse:
    ok, checks = readiness(request)
    return JSONResponse({"status": "ready" if ok else "not_ready", "checks": checks}, status_code=200 if ok else 503)


def _check(name: str, status: str, detail: Any = None, reason: str | None = None) -> dict[str, Any]:
    return {"name": name, "status": status, "observed_at": iso(utcnow()), "detail": detail or {}, "reason_code": reason}


def connector_health(request: Request, session: Session) -> dict[str, Any]:
    state = request.app.state
    checks: list[dict[str, Any]] = []
    db_ok = state.db.ping()
    checks.append(_check("database", "healthy" if db_ok else "down"))
    if not db_ok:
        return {
            "status": "down",
            "observed_at": iso(utcnow()),
            "reason_code": "database_onbereikbaar",
            "checks": checks,
        }

    current = state.db.current_revision()
    checks.append(
        _check(
            "migraties",
            "healthy" if current == state.alembic_head else "degraded",
            {"huidig": current, "verwacht": state.alembic_head},
        )
    )
    link = state.enrollment.state(session)
    coupled = link.get("status") == "gekoppeld"
    checks.append(
        _check(
            "hub_koppeling",
            "healthy" if coupled else "degraded",
            {"status": link.get("status")},
            None if coupled else link.get("reason"),
        )
    )
    js = state.jwks.status()
    if not coupled:
        jwks_status, jwks_reason = "unknown", "niet_gekoppeld"
    elif js.available and not js.stale:
        jwks_status, jwks_reason = "healthy", None
    elif js.available:
        jwks_status, jwks_reason = "degraded", "verouderd"
    elif js.age_s is None and js.last_error is None:
        jwks_status, jwks_reason = "unknown", "nog_niet_opgehaald"
    else:
        jwks_status, jwks_reason = "down", js.last_error or "niet_beschikbaar"
    checks.append(_check("hub_jwks", jwks_status, {"keys": js.keys, "age_s": js.age_s}, jwks_reason))

    dead = session.scalar(select(func.count()).where(OutboxEvent.delivery_status == "dead_letter")) or 0
    stale_pending = (
        session.scalar(
            select(func.count()).where(
                OutboxEvent.delivery_status == "pending", OutboxEvent.timestamp_utc < utcnow() - timedelta(hours=1)
            )
        )
        or 0
    )
    outbox_status = "degraded" if dead or (coupled and stale_pending) else "healthy"
    checks.append(
        _check(
            "outbox",
            outbox_status,
            {"dead_letter": dead, "pending_ouder_dan_1u": stale_pending},
            "dead_letter" if dead else ("achterstand" if outbox_status != "healthy" else None),
        )
    )

    readiness_result = sso_service.overall(session, state.settings.break_glass_test_max_age_days)
    reasons = readiness_result["reasons"]
    checks.append(
        _check(
            "herstelregister",
            readiness_result["health"],
            readiness_result["counts"],
            reasons[0]["code"] if reasons else None,
        )
    )

    rows = {r.source_id: r for r in session.scalars(select(IntegrationSource))}
    from .sources import ALL_SOURCES

    counts = {"healthy": 0, "degraded": 0, "down": 0, "unknown": 0}
    for sid in ALL_SOURCES:
        row = rows.get(sid)
        st = row.last_probe_status if row is not None and row.enabled else "unknown"
        counts[st] = counts.get(st, 0) + 1
    src_status = (
        "down"
        if counts["down"]
        else ("degraded" if counts["degraded"] else ("healthy" if counts["unknown"] == 0 else "unknown"))
    )
    checks.append(_check("bronnen", src_status, counts, "niet_geconfigureerd" if counts["unknown"] else None))

    service_checks = [c for c in checks if c["name"] in ("migraties", "hub_koppeling", "hub_jwks", "outbox")]
    bad = [c for c in service_checks if c["status"] not in ("healthy", "unknown")]
    # de dienst zelf draait; een uitgevallen afhankelijkheid (Hub/JWKS/outbox) maakt hem 'degraded', nooit 'healthy'
    status = "degraded" if bad or not coupled else "healthy"
    reason = next((c["reason_code"] or c["name"] for c in service_checks if c["status"] != "healthy"), None)
    return {
        "status": status,
        "observed_at": iso(utcnow()),
        "reason_code": reason if status != "healthy" else None,
        "checks": checks,
    }
