"""FastAPI-app-fabriek."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import APIRouter, Depends, FastAPI, Request, Response
from sqlalchemy.orm import Session

from . import API_PREFIX, APP_ID, __version__, audit
from .bodylimit import BodyLimitMiddleware
from .config import Settings
from .connector import router as connector_router
from .db import Database
from .deps import get_session, trace_id
from .domains.automation.router import router as automation_router
from .domains.energy.router import router as energy_router
from .domains.network.router import router as network_router
from .domains.sso.authentik_router import router as sso_authentik_router
from .domains.sso.router import router as sso_router
from .enrollment import JWKS_PATH, EnrollmentService, stored_jwks
from .errors import TRACE_HEADER, install_handlers, trace_id_for
from .health import router as health_router
from .hubclient import HubClient
from .idempotency import idempotency_key, run_idempotent
from .migrations import head_revision
from .security.auth import Authenticator, JwtPolicy, Principal, require_admin
from .security.jwks import JwksCache
from .security.replay import ReplayGuard
from .security.secrets import ensure_secrets, load_identity, load_vault_key, public_jwk
from .security.vault import Vault
from .sources import router as sources_router
from .status_page import Throttle, new_unpair_code
from .status_page import router as status_router

log = logging.getLogger("integrations")


class HubLinkCache:
    """Leest de koppelstatus (die ook de worker kan schrijven) met een korte TTL en houdt de JWKS-cache in lijn."""

    def __init__(
        self, db: Database, enrollment: EnrollmentService, hub: HubClient, jwks: JwksCache, ttl_s: float
    ) -> None:
        self.db, self.enrollment, self.hub, self.jwks, self.ttl_s = db, enrollment, hub, jwks, ttl_s
        self._lock = threading.Lock()
        self._loaded_at: float | None = None
        self._hash: str | None = None
        self._hub_url: str | None = None
        self._enrolled_at: str | None = None

    def invalidate(self) -> None:
        with self._lock:
            self._loaded_at = None

    def _refresh(self) -> None:
        now = time.monotonic()
        if self._loaded_at is not None and now - self._loaded_at < self.ttl_s:
            return
        try:
            with self.db.sessions() as s:
                st = self.enrollment.state(s)
                doc = stored_jwks(s)
        except Exception:  # database weg → fail-closed: geen service-token geldig
            self._hash = None
            self._loaded_at = None
            return
        self._loaded_at = now
        if st.get("status") != "gekoppeld":
            if self._hub_url is not None:
                self.jwks.set_fetcher(None)
                self.jwks.clear()
            self._hash, self._hub_url, self._enrolled_at = None, None, None
            return
        hub_url = st.get("hub_url")
        if hub_url != self._hub_url or st.get("enrolled_at") != self._enrolled_at:
            self.jwks.clear()
            url = str(hub_url)
            self.jwks.set_fetcher(lambda: self.hub.get_json(url, JWKS_PATH))
            if doc is not None:
                try:
                    self.jwks.seed(doc)
                except ValueError:
                    log.warning("opgeslagen JWKS is ongeldig; wordt opnieuw opgehaald")
            self._hub_url, self._enrolled_at = hub_url, st.get("enrolled_at")
        self._hash = st.get("service_token_sha256")

    def service_token_hash(self) -> str | None:
        with self._lock:
            self._refresh()
            return self._hash


def _enrollment_router() -> APIRouter:
    r = APIRouter(prefix=API_PREFIX, tags=["koppeling"])

    @r.get("/enrollment", summary="Koppelstatus met de Hub")
    def enrollment_state(
        request: Request, session: Session = Depends(get_session), _p: Principal = Depends(require_admin)
    ) -> dict[str, Any]:
        state = request.app.state.enrollment.public_state(session)
        js = request.app.state.jwks.status()
        state["jwks"] = {"available": js.available, "keys": js.keys, "age_s": js.age_s, "stale": js.stale}
        return state

    @r.post("/enrollment/unpair", summary="Ontkoppelen van de Hub (admin)")
    def unpair(
        request: Request,
        session: Session = Depends(get_session),
        principal: Principal = Depends(require_admin),
        key: uuid.UUID = Depends(idempotency_key),
        tid: str = Depends(trace_id),
    ) -> Any:
        def action() -> tuple[int, Any, dict[str, str]]:
            request.app.state.enrollment.unpair(session)
            audit.record(
                session,
                domain="sso",
                action="hub.unpair",
                entity_type="hub_link",
                entity_id="hub",
                principal=principal,
                trace_id=tid,
                message_nl="Ontkoppeld van de Hub door een beheerder.",
            )
            return 200, request.app.state.enrollment.public_state(session), {}

        resp = run_idempotent(request, session, principal, key, {"unpair": True}, action)
        request.app.state.link.invalidate()
        return resp

    return r


def create_app(settings: Settings | None = None, transport: httpx.BaseTransport | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    created = ensure_secrets(settings.secrets_dir)
    if created:
        log.info("eerste start: geheimen aangemaakt in %s: %s", settings.secrets_dir, ", ".join(created))
    vault = Vault(load_vault_key(settings.secrets_dir))
    identity = public_jwk(load_identity(settings.secrets_dir))
    db = Database(settings.database_url)
    hub = HubClient(settings, transport=transport)
    enrollment = EnrollmentService(settings, vault, identity, hub)
    # De ophaalbegrenzing mag nooit langer zijn dan de verse periode: anders is er na TTL + max. oud een gat waarin
    # geen enkele JWT geldig is, terwijl de Hub gewoon bereikbaar is (gevonden in de CI-E2E met TTL 2 s).
    min_refresh = min(settings.jwks_min_refresh_interval_s, settings.jwks_ttl_s)
    jwks = JwksCache(None, settings.jwks_ttl_s, settings.jwks_max_stale_s, min_refresh)
    link = HubLinkCache(db, enrollment, hub, jwks, settings.link_cache_ttl_s)
    policy = JwtPolicy(settings.jwt_issuer, settings.jwt_audience, settings.jwt_max_lifetime_s, settings.jwt_leeway_s)
    unpair_code = new_unpair_code()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        log.warning(
            "Lokale ontkoppelcode (alleen geldig tot de volgende herstart; alleen nodig om een verloren Hub te "
            "vervangen): %s",
            unpair_code,
        )
        yield
        db.dispose()

    app = FastAPI(
        title="Home Control Hub — integratiedienst",
        version=__version__,
        description=(
            "Integraties B10 netwerk/privacy, B11 Node-RED, B13 Authentik/SSO (incl. beheerherstel B13-001) en "
            "B14 energie/resources voor TrueNAS Home Platform V2. Niet-gebouwde functies geven "
            "`501 capability_unavailable`; nooit gesimuleerd succes."
        ),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.vault = vault
    app.state.db = db
    app.state.hub = hub
    app.state.enrollment = enrollment
    app.state.jwks = jwks
    app.state.link = link
    app.state.auth = Authenticator(jwks, policy, link.service_token_hash)
    app.state.replay_guard = ReplayGuard(db, settings.jwt_leeway_s)
    app.state.http_transport = transport
    app.state.alembic_head = head_revision(settings)
    app.state.unpair_code_sha256 = hashlib.sha256(unpair_code.encode()).hexdigest()
    app.state.pair_throttle = Throttle()
    app.state.app_id = APP_ID

    install_handlers(app)
    # vóór alles (ook vóór de auth): te grote bodies worden niet ingelezen
    app.add_middleware(BodyLimitMiddleware)

    @app.middleware("http")
    async def trace_and_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        tid = trace_id_for(request)
        response = await call_next(request)
        response.headers.setdefault(TRACE_HEADER, tid)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        if request.url.path.startswith((API_PREFIX, "/connector/")):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    for r in (
        health_router,
        status_router,
        connector_router,
        _enrollment_router(),
        sources_router,
        sso_router,
        sso_authentik_router,
        network_router,
        automation_router,
        energy_router,
    ):
        app.include_router(r)
    return app
