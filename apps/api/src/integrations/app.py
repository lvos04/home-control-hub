"""FastAPI-app-fabriek."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response

from . import API_PREFIX, APP_ID, __version__
from .bodylimit import BodyLimitMiddleware
from .config import Settings
from .connector import router as connector_router
from .db import Database
from .domains.automation.router import router as automation_router
from .domains.energy.router import router as energy_router
from .domains.network.router import router as network_router
from .domains.sso.authentik_router import router as sso_authentik_router
from .domains.sso.router import router as sso_router
from .enrollment import HubLink
from .errors import TRACE_HEADER, install_handlers, trace_id_for
from .health import router as health_router
from .hubclient import HubClient
from .hublink_store import HubLinkStore
from .migrations import head_revision
from .security.auth import Authenticator, JwtPolicy
from .security.replay import ReplayGuard
from .security.secrets import enroll_public_jwk, ensure_secrets, load_identity, load_vault_key
from .security.vault import Vault
from .sources import router as sources_router
from .status_page import Meldingen, PairThrottle
from .status_page import router as status_router

log = logging.getLogger("integrations")


def create_app(settings: Settings | None = None, transport: httpx.BaseTransport | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    created = ensure_secrets(settings.secrets_dir)
    if created:
        log.info("eerste start: geheimen aangemaakt in %s: %s", settings.secrets_dir, ", ".join(created))
    vault = Vault(load_vault_key(settings.secrets_dir))
    identity = enroll_public_jwk(load_identity(settings.secrets_dir))
    db = Database(settings.database_url)
    hub = HubClient(settings, transport=transport)
    store = HubLinkStore(settings.secrets_dir)
    hublink = HubLink(settings, store, identity, hub, db, vault)
    policy = JwtPolicy(settings.jwt_issuer, settings.jwt_audience, settings.jwt_max_lifetime_s, settings.jwt_leeway_s)
    replay = ReplayGuard(db, settings.jwt_leeway_s)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # §3.5: een koppeling uit een oudere versie eenmalig naar hub-link.json; §3.6 stap 5: een koppelcodepoging van
        # een vorig API-proces is onderbroken (het geheim was alleen in dat proces bekend)
        hublink.ensure_migrated()
        try:
            hublink.recover_after_restart(process="api")
        except OSError as exc:
            log.error("hub-link.json niet bij te werken (%s); de dienst vertrouwt niets van de Hub", type(exc).__name__)
        yield
        db.dispose()

    app = FastAPI(
        title="Home Control Hub — integratiedienst",
        version=__version__,
        description=(
            "Integraties B10 netwerk/privacy, B11 Node-RED, B13 Authentik/SSO (incl. beheerherstel B13-001) en "
            "B14 energie/resources voor TrueNAS Home Platform V2 (platformcontract 1.3). Niet-gebouwde functies "
            "geven `501 capability_unavailable`; nooit gesimuleerd succes."
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
    app.state.hublink_store = store
    app.state.hublink = hublink
    app.state.auth = Authenticator(store, policy, replay, on_unknown_kid=hublink.request_key_poll)
    app.state.replay_guard = replay
    app.state.http_transport = transport
    app.state.alembic_head = head_revision(settings)
    app.state.pair_throttle = PairThrottle()
    app.state.meldingen = Meldingen()
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
        sources_router,
        sso_router,
        sso_authentik_router,
        network_router,
        automation_router,
        energy_router,
    ):
        app.include_router(r)
    return app
