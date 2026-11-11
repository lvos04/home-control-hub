"""``/healthz`` (proces leeft), ``/readyz`` (afhankelijkheden ok) en de connector-health (contract 1.3 §5/§6/§6.2)."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import APP_ID, __version__
from .domains.automation import inbox as flow_inbox
from .domains.automation import snapshots as flow_snapshots
from .domains.sso import service as sso_service
from .models import IntegrationSource, OutboxEvent, ServiceState
from .security.secrets import secrets_present
from .timeutil import ensure_aware, iso, utcnow
from .worker import HEARTBEAT_KEY

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


@router.get("/readyz", summary="Klaar voor verkeer: database, migraties, geheimen (zonder auth, zonder geheimen)")
def readyz(request: Request) -> JSONResponse:
    ok, checks = readiness(request)
    # koppelstatus alleen als informatie (witte lijst §3.5); een niet-gekoppelde dienst is wel 'ready'
    body = {
        "status": "ready" if ok else "not_ready",
        "checks": checks,
        "hub_link": request.app.state.hublink.public_state(),
    }
    return JSONResponse(body, status_code=200 if ok else 503)


#: contract 1.3 §6: totaal = de slechtste check in deze volgorde (zoals het Peil-totaal: onbekend is nooit groen)
ERNST = {"healthy": 0, "unknown": 1, "degraded": 2, "down": 3}
#: een hartslag van de worker is vers zolang hij niet ouder is dan 3 rondes (minstens 60 s)
WORKER_STIL_NA_RONDES = 3
#: een wachtrij die niet afneemt: het oudste te verzenden event wacht langer dan dit (gekoppeld) → degraded
JOBS_STIL_NA = timedelta(hours=1)


def _check(
    name: str, status: str, detail: Any = None, reason: str | None = None, observed_at: datetime | None = None
) -> dict[str, Any]:
    return {
        "name": name,
        "status": status,
        "observed_at": iso(observed_at or utcnow()),
        "detail": detail or {},
        "reason_code": reason,
    }


def _worker_check(session: Session, interval_s: float) -> tuple[dict[str, Any], dict[str, Any]]:
    """Vaste checks ``worker`` (``observed_at`` = laatste hartslag) en ``jobs`` (wachtrij, bezig, laatste job klaar)."""
    row = session.get(ServiceState, HEARTBEAT_KEY)
    beat = dict(row.value) if row is not None else {}
    at = _parse(beat.get("at"))
    now = utcnow()
    grens = timedelta(seconds=max(60.0, WORKER_STIL_NA_RONDES * float(beat.get("interval_s") or interval_s)))
    detail = {"laatste_hartslag": beat.get("at"), "mislukte_stappen": beat.get("mislukte_stappen", [])}
    if at is None:
        worker = _check("worker", "unknown", detail, "worker_nog_geen_hartslag")
    elif now - at > grens:
        worker = _check("worker", "degraded", detail, "worker_stil", observed_at=at)
    elif beat.get("mislukte_stappen"):
        worker = _check("worker", "degraded", detail, "workerstap_mislukt", observed_at=at)
    else:
        worker = _check("worker", "healthy", detail, None, observed_at=at)
    pending = session.scalar(select(func.count()).where(OutboxEvent.delivery_status == "pending")) or 0
    retrying = (
        session.scalar(select(func.count()).where(OutboxEvent.delivery_status == "pending", OutboxEvent.attempts > 0))
        or 0
    )
    dead = session.scalar(select(func.count()).where(OutboxEvent.delivery_status == "dead_letter")) or 0
    oldest = session.scalar(select(func.min(OutboxEvent.timestamp_utc)).where(OutboxEvent.delivery_status == "pending"))
    return worker, {
        "wachtrij": int(pending),
        "bezig": int(retrying),
        "laatste_job_klaar": beat.get("laatste_job_klaar"),
        "dead_letter": int(dead),
        "oudste_wachtend": iso(oldest) if oldest is not None else None,
    }


def _automation_check(session: Session) -> dict[str, Any] | None:
    """Eigen check ``automatisering`` (B11), alleen als Node-RED is ingesteld en aan staat ("niet ingesteld" is geen
    meting). Een gemeten afwijking in de isolatie, een mislukte synchronisatie, een geblokkeerde flow of een
    vastgelopen aflevering is ``degraded``; een isolatie die (nog) niet vers gemeten is, is ``unknown``."""
    if not flow_snapshots.configured(session):
        return None
    now = utcnow()
    isolation = flow_snapshots.isolation_state(session, now)
    sync = flow_snapshots.state_get(session, flow_snapshots.SYNC_KEY) or {}
    flows = flow_snapshots.count_flows(session)
    queue = flow_inbox.queue_stats(session, now)
    dead = int(queue["afleveringen"].get("dead_letter", 0))
    detail = {
        "isolatie": isolation["status"],
        "afwijkingen": list(isolation.get("afwijkingen") or []),
        "synchronisatie_ok": sync.get("ok"),
        "laatste_synchronisatie": sync.get("laatste_ok"),
        "flows": flows,
        "dead_letter": dead,
        "niet_afgeleverd_24u": queue["niet_afgeleverd_24u"],
    }
    observed = _parse(isolation.get("measured_at")) or _parse(sync.get("laatste_poging"))
    if isolation["status"] == "afwijking":
        return _check("automatisering", "degraded", detail, "isolatie_afwijking", observed_at=observed)
    if sync.get("ok") is False:
        return _check("automatisering", "degraded", detail, "synchronisatie_mislukt", observed_at=observed)
    if flows.get("geblokkeerd"):
        return _check("automatisering", "degraded", detail, "flow_geblokkeerd", observed_at=observed)
    if dead:
        return _check("automatisering", "degraded", detail, "dead_letter", observed_at=observed)
    if isolation["status"] != "gemeten_in_orde":
        reason = str(isolation.get("reden") or "isolatie_niet_gemeten")
        return _check("automatisering", "unknown", detail, reason, observed_at=observed)
    return _check("automatisering", "healthy", detail, None, observed_at=observed)


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return ensure_aware(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def connector_health(request: Request, session: Session) -> dict[str, Any]:
    """Connector-health volgens contract 1.3 §6/§6.2 (C1.3-HCH-07).

    - ``status`` = de slechtste check (``healthy`` < ``unknown`` < ``degraded`` < ``down``); ``reason_code`` = die van de
      eerste slechtste check.
    - Vaste namen: ``database``, ``worker`` (``observed_at`` = laatste hartslag), ``jobs`` (``detail.wachtrij``,
      ``detail.bezig``, ``detail.laatste_job_klaar``; een wachtrij die niet afneemt → ``degraded``) en ``hub_link``.
      Eigen checks: ``migraties``, ``hub_sleutels``, ``herstelregister``, ``automatisering`` (B11) en ``bronnen``.
    - Wat niet is ingesteld, is geen check (geen bron ingesteld, leeg herstelregister): "niet ingesteld" is geen
      meting en zou het totaal anders nooit groen laten worden (zoals Peil 1.1.1, E10). Een ingestelde bron zonder
      verse meting telt als ``unknown`` met ``meting_verouderd`` (§6.2)."""
    state = request.app.state
    checks: list[dict[str, Any]] = []
    db_ok = state.db.ping()
    checks.append(_check("database", "healthy" if db_ok else "down", None, None if db_ok else "database_onbereikbaar"))
    link = state.hublink.state()
    coupled = link.linked
    hub: tuple[str, str | None]
    if link.corrupt:
        hub = ("down", "koppelstatus_onleesbaar")
    elif coupled and link.confirmed_at:
        hub = ("healthy", None)
    elif coupled:
        hub = ("degraded", "niet_bevestigd")
    else:
        hub = ("unknown", "niet_gekoppeld" if link.state == "nooit_gekoppeld" else link.state)
    checks.append(
        _check(
            "hub_link",
            hub[0],
            {"state": link.state, "bevestigd": bool(link.confirmed_at), "koppelen_bezig": link.pending is not None},
            hub[1],
        )
    )
    # §4.5: vertrouwd worden alleen de gepinde sleutels (geen JWKS via HTTP); een geweigerde sleutelrotatie stopt het
    # toepassen van verdere rotaties en is een incident
    if coupled and link.pins is not None:
        blocked = link.key_rotation_blocked_sequence
        checks.append(
            _check(
                "hub_sleutels",
                "degraded" if blocked is not None else "healthy",
                {
                    "jwt": len(link.pins.jwt),
                    "policy": len(link.pins.policy),
                    "rotation_sequence": link.pins.rotation_sequence,
                    "keyset_fingerprint": link.pins.keyset_fingerprint,
                },
                "sleutelrotatie_geweigerd" if blocked is not None else None,
            )
        )
    if db_ok:
        current = state.db.current_revision()
        at_head = current is not None and current == state.alembic_head
        checks.append(
            _check(
                "migraties",
                "healthy" if at_head else "down",  # /readyz is dan 503: de dienst neemt geen verkeer aan
                {"huidig": current, "verwacht": state.alembic_head},
                None if at_head else "schema_niet_actueel",
            )
        )
        worker, jobs = _worker_check(session, state.settings.worker_interval_s)
        checks.append(worker)
        stil = (
            coupled
            and jobs["oudste_wachtend"] is not None
            and utcnow() - (_parse(jobs["oudste_wachtend"]) or utcnow()) > JOBS_STIL_NA
        )
        jobs_reason = "dead_letter" if jobs["dead_letter"] else ("wachtrij_neemt_niet_af" if stil else None)
        checks.append(_check("jobs", "degraded" if jobs_reason else "healthy", jobs, jobs_reason))

        readiness_result = sso_service.overall(session, state.settings.break_glass_test_max_age_days)
        if readiness_result["counts"]["accounts"]:
            reasons = readiness_result["reasons"]
            checks.append(
                _check(
                    "herstelregister",
                    readiness_result["health"],
                    readiness_result["counts"],
                    reasons[0]["code"] if reasons else None,
                )
            )

        automation = _automation_check(session)
        if automation is not None:
            checks.append(automation)

        from .sources import ALL_SOURCES, effective_probe

        rows = {r.source_id: r for r in session.scalars(select(IntegrationSource))}
        configured = {sid: r for sid, r in rows.items() if sid in ALL_SOURCES and r.enabled and r.base_url}
        if configured:
            now = utcnow()
            counts = {"healthy": 0, "degraded": 0, "down": 0, "unknown": 0}
            stale = 0
            seen: list[datetime] = []
            oud: list[datetime] = []
            for row in configured.values():
                st, why = effective_probe(row, now)
                stale += why == "meting_verouderd"
                counts[st] = counts.get(st, 0) + 1
                if row.last_probe_at is not None:
                    (oud if why == "meting_verouderd" else seen).append(ensure_aware(row.last_probe_at))
            src_status = max((k for k, v in counts.items() if v), key=ERNST.__getitem__)
            # §6.2: een verse storing of beperking is de oorzaak (nooit verborgen achter "verouderd"); anders noemt een
            # verouderde meting zichzelf, met de tijd van de laatste meting en zonder de oude stand
            if src_status in ("down", "degraded") or (src_status == "unknown" and not stale):
                src_reason: str | None = "bron_" + src_status
            else:
                src_reason = "meting_verouderd" if stale else None
            detail: dict[str, Any] = {
                **counts,
                "verouderd": stale,
                "ingesteld": len(configured),
                "totaal": len(ALL_SOURCES),
            }
            if oud:
                detail["laatste_meting_verouderd"] = iso(max(oud))
            checks.append(
                _check(
                    "bronnen",
                    src_status,
                    detail,
                    src_reason,
                    # zo vers als de oudste meting die meetelt: een verouderde meting maakt de check nooit "nu gemeten"
                    observed_at=min([*seen, *oud]) if seen or oud else None,
                )
            )
    status = max((c["status"] for c in checks), key=ERNST.__getitem__)
    worst = next(c for c in checks if c["status"] == status)
    return {
        "status": status,
        "observed_at": iso(utcnow()),
        "reason_code": None if status == "healthy" else (worst["reason_code"] or worst["name"]),
        "checks": checks,
    }
