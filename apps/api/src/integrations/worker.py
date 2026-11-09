"""Worker: koppelen met het omgevingstoken, outbox pushen, Authentik synchroniseren (B13-004), verlopen
noodactivaties sluiten, opruimen (idempotency, JWT-replaycache, oude Authentik-events)."""

from __future__ import annotations

import logging
import random
import threading
import time
import uuid
from dataclasses import dataclass, field

import httpx

from . import events
from .config import Settings
from .db import Database
from .domains.sso import authaudit
from .domains.sso.authentik.client import AuthentikError, client_from_source
from .domains.sso.service import close_expired_activations
from .enrollment import EVENTS_INBOX_PATH, EnrollmentService
from .hubclient import HubClient
from .idempotency import purge_expired
from .security.replay import purge_expired as purge_jti
from .security.secrets import ensure_secrets, load_identity, load_vault_key, public_jwk
from .security.vault import Vault

log = logging.getLogger("integrations.worker")


@dataclass
class WorkerState:
    next_enroll_at: float = 0.0
    enroll_failures: int = 0
    last_purge: float = 0.0
    next_authentik_sync: float = 0.0
    stats: dict[str, int] = field(
        default_factory=lambda: {"pushed": 0, "push_failed": 0, "closed_activations": 0, "authentik_syncs": 0}
    )


class Worker:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        ensure_secrets(settings.secrets_dir)
        self.vault = Vault(load_vault_key(settings.secrets_dir))
        self.db = Database(settings.database_url)
        self.hub = HubClient(settings, transport=transport)
        self.transport = transport
        self.enrollment = EnrollmentService(
            settings, self.vault, public_jwk(load_identity(settings.secrets_dir)), self.hub
        )
        self.state = WorkerState()

    def enroll_step(self, now: float) -> None:
        if now < self.state.next_enroll_at:
            return
        with self.db.sessions() as s:
            outcome = self.enrollment.enroll_with_env_token(s)
            s.commit()
        if outcome is None or outcome.ok:
            self.state.enroll_failures = 0
            return
        if outcome.retryable:
            self.state.enroll_failures += 1
            delay = min(900.0, 15.0 * (2 ** (self.state.enroll_failures - 1))) * random.uniform(0.8, 1.2)  # noqa: S311
            self.state.next_enroll_at = now + delay

    def push_step(self) -> None:
        with self.db.sessions() as s:
            st = self.enrollment.state(s)
            if st.get("status") != "gekoppeld":
                return  # niet gekoppeld: events blijven 'pending' (geen poging geteld); de Hub kan ook pollen
            token = self.enrollment.service_token(s)
            hub_url = st.get("hub_url")
            if not token or not hub_url:
                return
            for ev in events.due_for_push(s):
                try:
                    resp = self.hub.request(
                        "POST",
                        hub_url,
                        EVENTS_INBOX_PATH,
                        json=events.envelope(ev),
                        headers={"Authorization": f"Bearer {token}"},
                        attempts=1,
                    )
                    ok = resp.status_code in (200, 201, 202, 204, 409)  # 409 = al ontvangen (dedupe in de Hub)
                    err = f"http_{resp.status_code}"
                except httpx.HTTPError as exc:
                    ok, err = False, type(exc).__name__
                if ok:
                    events.mark_delivered(ev)
                    self.state.stats["pushed"] += 1
                else:
                    events.mark_failed(ev, err)
                    self.state.stats["push_failed"] += 1
            s.commit()

    def authentik_step(self, now: float) -> None:
        """B13-004: events en rechtenkaart uit Authentik lezen (alleen als de bron ingesteld en aan staat)."""
        interval = self.settings.authentik_sync_interval_s
        if interval <= 0 or now < self.state.next_authentik_sync:
            return
        self.state.next_authentik_sync = now + interval
        with self.db.sessions() as s:
            try:
                client = client_from_source(s, self.settings, self.vault, self.transport)
            except AuthentikError:
                return  # niet ingesteld/uit: niets te doen (de status toont dat al)
            authaudit.sync(s, client, ("system", "home-control-hub:worker"), str(uuid.uuid4()))
            s.commit()
        self.state.stats["authentik_syncs"] += 1

    def housekeeping_step(self, now: float) -> None:
        with self.db.sessions() as s:
            self.state.stats["closed_activations"] += close_expired_activations(s)
            if now - self.state.last_purge > 3600:
                purge_expired(s)
                purge_jti(s)
                authaudit.purge_old_events(s)
                self.state.last_purge = now
            s.commit()

    def run_once(self) -> None:
        now = time.monotonic()
        for step in (
            lambda: self.enroll_step(now),
            self.push_step,
            lambda: self.authentik_step(now),
            lambda: self.housekeeping_step(now),
        ):
            try:
                step()
            except Exception:  # een fout in één stap mag de andere niet blokkeren
                log.exception("workerstap mislukt")

    def run(self, stop: threading.Event) -> None:
        log.info("worker gestart (interval %.0f s)", self.settings.worker_interval_s)
        while not stop.is_set():
            self.run_once()
            stop.wait(self.settings.worker_interval_s)
        self.db.dispose()
        log.info("worker gestopt")
