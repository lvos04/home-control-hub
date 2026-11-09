"""Worker: koppelen met het env-token, de koppeling onderhouden (bevestigen, token roteren op verzoek van de Hub,
ondertekende sleutelrotaties pollen; contract 1.2 §3.6–§3.8, §4.5), outbox pushen, Authentik synchroniseren (B13-004),
verlopen noodactivaties sluiten en opruimen (idempotency, JWT-replaycache, oude Authentik-events)."""

from __future__ import annotations

import logging
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
from .enrollment import EVENTS_INBOX_PATH, HubLink
from .hubclient import HubClient
from .hublink_store import HubLinkStore
from .idempotency import purge_expired
from .security.replay import purge_expired as purge_jti
from .security.secrets import enroll_public_jwk, ensure_secrets, load_identity, load_vault_key
from .security.vault import Vault

log = logging.getLogger("integrations.worker")


@dataclass
class WorkerState:
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
        self.store = HubLinkStore(settings.secrets_dir)
        self.hublink = HubLink(
            settings,
            self.store,
            enroll_public_jwk(load_identity(settings.secrets_dir)),
            self.hub,
            self.db,
            self.vault,
        )
        self.state = WorkerState()
        self._started = False

    def start_step(self) -> None:
        """Eén keer per proces (§3.5/§3.6 stap 5): oude koppeling overzetten, onderbroken pogingen afsluiten."""
        if self._started:
            return
        if not self.hublink.ensure_migrated():
            return  # database nog niet bereikbaar: volgende ronde opnieuw (tot dan wordt er niet gekoppeld)
        self.hublink.recover_after_restart(process="worker")
        self._started = True

    def enroll_step(self) -> None:
        if not self._started:
            return
        self.hublink.env_tick(str(uuid.uuid4()))

    def link_step(self) -> None:
        if self._started:
            self.hublink.maintenance_tick(str(uuid.uuid4()))

    def push_step(self) -> None:
        if not self.store.read().linked:
            return  # niet gekoppeld: events blijven 'pending' (geen poging geteld); de Hub kan ook pollen
        trace = str(uuid.uuid4())
        with self.db.sessions() as s:
            for ev in events.due_for_push(s):
                try:
                    resp = self.hublink.call("POST", EVENTS_INBOX_PATH, json_body=events.envelope(ev), trace_id=trace)
                except httpx.HTTPError as exc:
                    resp, err = None, type(exc).__name__
                else:
                    err = "niet_gekoppeld" if resp is None else f"http_{resp.status_code}"
                if resp is None and err == "niet_gekoppeld":
                    break  # intussen ontkoppeld of ingetrokken (bv. 401 + services/self 401): niets meer pushen
                ok = resp is not None and resp.status_code in (200, 201, 202, 204, 409)  # 409 = al ontvangen
                if ok:
                    events.mark_delivered(ev)
                    self.state.stats["pushed"] += 1
                else:
                    events.mark_failed(ev, err)
                    self.state.stats["push_failed"] += 1
                if resp is not None and resp.status_code == 401:
                    break  # de koppeling is (mogelijk) ingetrokken; services/self is al gevraagd
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
            self.start_step,
            self.enroll_step,
            self.link_step,
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
