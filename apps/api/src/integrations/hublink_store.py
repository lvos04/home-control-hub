"""Koppelstatus met de Hub in ``/appdata/secrets/hub-link.json`` (contract 1.2 §3.5).

- Eén bestand, 0600, in ``/appdata/secrets`` (0700); eigenaar is de procesgebruiker (568 in de image).
- Schrijven: nieuw bestand in dezelfde map (``O_CREAT|O_EXCL``, 0600) → ``fsync`` → ``rename`` → ``fsync`` van de map,
  onder een exclusieve vergrendeling op ``hub-link.lock`` (API en worker schrijven allebei; lezen-wijzigen-schrijven
  gebeurt altijd binnen de vergrendeling).
- Lezen: elk proces leest het bestand opnieuw zodra inode, mtime of grootte verandert. Zo geldt een ontkoppeling,
  intrekking of rotatie door het ene proces direct voor het andere.
- **Niet** in de database: een database-herstel brengt geen oude koppeling, oude pins of een ingetrokken token terug,
  en een database-export (B12) bevat geen credentials.
- Onleesbaar bestand → fail-closed: niets wordt vertrouwd (``not_linked``) en de statuspagina biedt géén
  koppelformulier (onbekend of de dienst al eens gekoppeld was, dus geldt hij als "al eens gekoppeld"). Herstel gaat
  via een nieuw enrollment-token in het formulier van de Custom App (§3.8).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import threading
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError

from . import APP_ID
from .timeutil import utcnow

log = logging.getLogger("integrations.hublink")

LINK_FILE = "hub-link.json"
LOCK_FILE = "hub-link.lock"
MAX_USED_TOKENS = 20

State = Literal["nooit_gekoppeld", "gekoppeld", "ontkoppeld", "ingetrokken"]
Via = Literal["token", "koppelcode"]

#: Vaste Nederlandse melding per ``last_error.code`` (§3.5). Codes uit het contract plus enkele eigen (ADR-0010).
ERROR_MESSAGES: dict[str, str] = {
    "hub_onbereikbaar": "Koppelen mislukt: de Hub was niet bereikbaar (netwerkfout, time-out, doorverwijzing of "
    "storing bij de Hub).",
    "hub_weigerde": "Koppelen mislukt: de Hub weigerde het token of de koppelcode (onbekend, verlopen of al gebruikt).",
    "hub_incompatibel": "Koppelen mislukt: de Hub vond het verzoek ongeldig; de versies van de Hub en deze dienst "
    "passen niet bij elkaar.",
    "hub_antwoord_ongeldig": "Koppelen mislukt: het antwoord van de Hub klopte niet; er is niets opgeslagen.",
    "hub_vingerafdruk_onjuist": "Koppelen mislukt: de sleutelset-vingerafdruk van de Hub klopt niet; er is niets "
    "opgeslagen.",
    "enroll_endpoint_ontbreekt": "Koppelen mislukt: deze Hub-versie kent aanmelden niet.",
    "rate_limited": "De Hub vraagt even te wachten: te veel mislukte pogingen vanaf dit adres.",
    "koppelen_onderbroken": "Koppelen is onderbroken (herstart). Voer de koppelcode opnieuw in of maak in de Hub een "
    "nieuw token.",
    "token_verlopen_na_60_min": "Koppelen met het token is na 60 minuten niet gelukt en wordt niet meer geprobeerd. "
    "Maak een nieuw token in de Hub.",
    "token_ongeldig": "HUB_ENROLLMENT_TOKEN heeft niet het juiste formaat (enr_ + 43 tekens) en wordt niet gebruikt.",
    "vingerafdruk_ongeldig": "HUB_KEY_FINGERPRINT heeft niet het formaat XXXX-XXXX-XXXX-XXXX; er wordt niet "
    "gekoppeld tot dat is hersteld.",
    "hub_adres_ongeldig": "HUB_URL is ongeldig (alleen http(s)://<adres>[:<poort>], geen localhost, pad of "
    "inloggegevens); er wordt niet gekoppeld.",
    "ingetrokken_door_hub": "De Hub heeft deze koppeling ingetrokken. Opnieuw koppelen gaat via de Hub.",
    "overzetten_onvolledig": "De koppeling uit een oudere versie kon niet volledig worden overgezet. Opnieuw koppelen "
    "gaat via de Hub.",
}


def error_message(code: str | None) -> str | None:
    if code is None:
        return None
    return ERROR_MESSAGES.get(code, "Koppelen is niet gelukt.")


def now_iso() -> str:
    return utcnow().isoformat().replace("+00:00", "Z")


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class PublicJwk(_Model):
    kty: Literal["OKP"] = "OKP"
    crv: Literal["Ed25519"] = "Ed25519"
    x: str


class Pin(_Model):
    kid: str
    jwk: PublicJwk
    thumbprint: str
    pinned_at: str
    source: Literal["enroll", "rotation", "overgezet"] = "enroll"


class Pins(_Model):
    jwt: list[Pin]
    policy: list[Pin]
    keyset_fingerprint: str
    rotation_sequence: int = 0


class Pending(_Model):
    kind: Via
    secret_sha256: str
    hub_url: str
    started_at: str
    attempts: int = 0


class LastError(_Model):
    code: str
    at: str


class LinkState(_Model):
    schema_version: str = "1.2"
    state: State = "nooit_gekoppeld"
    app_id: str = APP_ID
    hub_url: str | None = None
    service_id: str | None = None
    via: Via | None = None
    first_linked_at: str | None = None
    linked_at: str | None = None
    confirmed_at: str | None = None
    service_token: str | None = None
    service_token_last4: str | None = None
    pins: Pins | None = None
    previous_pins: Pins | None = None
    pending: Pending | None = None
    used_enrollment_token_sha256: list[str] = Field(default_factory=list)
    last_error: LastError | None = None
    # aanvullend (ADR-0010): een rotatieverzoek van de Hub en een geweigerde sleutelrotatie overleven een herstart
    token_rotation_requested_at: str | None = None
    key_rotation_blocked_sequence: int | None = None

    _corrupt: bool = PrivateAttr(default=False)

    @property
    def corrupt(self) -> bool:
        return self._corrupt

    @property
    def linked(self) -> bool:
        """Alleen ``gekoppeld`` mét token en pins vertrouwt Hub-JWT's (§3.5)."""
        return self.state == "gekoppeld" and bool(self.service_token) and self.pins is not None

    @property
    def ever_linked(self) -> bool:
        """Bepaalt of de statuspagina nog een koppelformulier mag tonen (§3.7); onleesbaar telt als 'wel'."""
        return self._corrupt or self.first_linked_at is not None

    def remember_token(self, digest: str) -> None:
        if digest not in self.used_enrollment_token_sha256:
            self.used_enrollment_token_sha256.append(digest)
        self.used_enrollment_token_sha256 = self.used_enrollment_token_sha256[-MAX_USED_TOKENS:]

    def public(self) -> dict[str, Any]:
        """Witte lijst voor statuspagina, ``/readyz`` en ``GET /connector/v1/hub-link`` (§3.5): nooit het
        service-token of ``pending.secret_sha256``."""
        return {
            "state": self.state,
            "koppelen_bezig": self.pending is not None,
            "hub_url": self.hub_url,
            "service_id": self.service_id,
            "via": self.via,
            "linked_at": self.linked_at,
            "first_linked_at": self.first_linked_at,
            "keyset_fingerprint": self.pins.keyset_fingerprint if self.pins else None,
            "service_token_last4": self.service_token_last4,
            "last_error": (
                {"code": self.last_error.code, "message": error_message(self.last_error.code)}
                if self.last_error
                else None
            ),
        }


def _clone(state: LinkState) -> LinkState:
    copy = state.model_copy(deep=True)
    copy._corrupt = state._corrupt
    return copy


class HubLinkStore:
    """Lezen (met verversen bij wijziging) en atomisch schrijven van ``hub-link.json``."""

    def __init__(self, secrets_dir: Path) -> None:
        self.dir = secrets_dir
        self.path = secrets_dir / LINK_FILE
        self.lock_path = secrets_dir / LOCK_FILE
        self._cache: tuple[tuple[int, int, int], LinkState] | None = None
        self._mutex = threading.Lock()

    # -------------------------------------------------------------- lezen
    def _load(self) -> LinkState:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return LinkState()
        except OSError as exc:  # bv. geen rechten: onbekend → fail-closed
            log.error("hub-link.json is niet te lezen (%s); de dienst vertrouwt niets van de Hub", type(exc).__name__)
            broken = LinkState()
            broken._corrupt = True
            return broken
        key = (st.st_ino, st.st_mtime_ns, st.st_size)
        with self._mutex:
            if self._cache is not None and self._cache[0] == key:
                return _clone(self._cache[1])
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("geen object")
            state = LinkState.model_validate(data)
        except (OSError, ValueError, ValidationError) as exc:
            log.error("hub-link.json is onleesbaar (%s); de dienst vertrouwt niets van de Hub", type(exc).__name__)
            state = LinkState()
            state._corrupt = True
        with self._mutex:
            self._cache = (key, state)
        return _clone(state)

    def read(self) -> LinkState:
        """Actuele status (leest opnieuw zodra het bestand veranderd is). Ontbreekt het bestand: ``nooit_gekoppeld``."""
        return self._load()

    def exists(self) -> bool:
        return self.path.exists()

    # -------------------------------------------------------------- schrijven
    @contextlib.contextmanager
    def locked(self) -> Iterator[None]:
        self.dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _write(self, state: LinkState) -> None:
        data = state.model_dump(mode="json")
        payload = (json.dumps(data, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
        tmp = self.dir / f".hub-link.{uuid.uuid4().hex}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
        dir_fd = os.open(self.dir, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        with self._mutex:
            self._cache = None

    def update(self, change: Callable[[LinkState], LinkState | None]) -> LinkState:
        """Lezen-wijzigen-schrijven onder de vergrendeling. ``change`` geeft de nieuwe status, of ``None`` = niets."""
        with self.locked():
            with self._mutex:
                self._cache = None  # binnen de vergrendeling altijd vers lezen
            current = self._load()
            new = change(_clone(current))
            if new is None:
                return current
            self._write(new)
            new._corrupt = False  # het bestand is nu weer leesbaar
            return new

    def write_initial(self, state: LinkState) -> bool:
        """Schrijf alleen als het bestand nog niet bestaat (onder de vergrendeling). Geeft ``True`` als geschreven."""
        with self.locked():
            if self.path.exists():
                return False
            self._write(state)
            return True
