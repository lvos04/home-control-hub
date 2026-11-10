"""Koppelstatus met de Hub in ``/appdata/secrets/hub-link.json`` (contract 1.3 §3.5).

- Eén bestand, 0600, in ``/appdata/secrets`` (0700); eigenaar is de procesgebruiker (568 in de image).
- Schrijven: nieuw bestand in dezelfde map (``O_CREAT|O_EXCL``, 0600) → ``fsync`` → ``rename`` → ``fsync`` van de map,
  onder een exclusieve vergrendeling op ``hub-link.lock`` (API en worker schrijven allebei; lezen-wijzigen-schrijven
  gebeurt altijd binnen de vergrendeling).
- Lezen: elk proces leest het bestand opnieuw zodra inode, mtime of grootte verandert. Zo geldt een ontkoppeling,
  intrekking of rotatie door het ene proces direct voor het andere.
- **Niet** in de database: een database-herstel brengt geen oude koppeling, oude pins of een ingetrokken token terug,
  en een database-export (B12) bevat geen credentials.
- ``schema_version``: deze dienst schrijft ``"1.3"``; een lezer accepteert elke ``1.x`` en negeert onbekende velden.
- Onleesbaar (geen geldige JSON, geen object, een andere major van ``schema_version``, ontbrekende verplichte velden
  ``schema_version``/``state``, een andere eigenaar dan dit proces of rechten ruimer dan 0600) → fail-closed: niets
  wordt vertrouwd (``not_linked``) en de statuspagina biedt géén
  koppelformulier (onbekend of de dienst al eens gekoppeld was, dus geldt hij als "al eens gekoppeld"). Herstel gaat
  via een nieuw enrollment-token in het formulier van de Custom App (§3.8).
- Moet er over een onleesbaar bestand heen geschreven worden (bv. ``pending`` of ``last_error`` van een env-token),
  dan blijft het origineel bewaard als ``hub-link.json.onleesbaar-<tijd>`` en krijgt de nieuwe status
  ``unreadable_replaced_at``. Zolang er daarna niet opnieuw gekoppeld is, geldt de status nog steeds als onleesbaar:
  geen koppelformulier, niets vertrouwd. Zonder die markering zou een gewone schrijfactie het bestand stil terugzetten
  naar ``nooit_gekoppeld`` en verscheen het koppelformulier weer (open bij fout; review contract 1.2, ADR-0013).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import stat
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
    "koppelstatus_onleesbaar": "Het koppelbestand van deze dienst is onleesbaar; de dienst vertrouwt niets van de Hub. "
    "Opnieuw koppelen gaat via een nieuw token van de Hub (HUB_ENROLLMENT_TOKEN).",
}
UNREADABLE_SUFFIX = ".onleesbaar-"


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


#: deze dienst volgt contract 1.3 en schrijft die versie (§3.5); lezen: elke 1.x
SCHEMA_VERSION = "1.3"
#: zonder deze velden is het bestand onleesbaar (§3.5 "ontbrekende verplichte velden")
REQUIRED_FIELDS = ("schema_version", "state")


class LinkState(_Model):
    schema_version: str = SCHEMA_VERSION
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
    # aanvullend (ADR-0013): een onleesbaar bestand is vervangen (origineel bewaard als hub-link.json.onleesbaar-<tijd>)
    # zonder dat er sindsdien gekoppeld is; onbekend of de dienst al eens gekoppeld was
    unreadable_replaced_at: str | None = None

    _corrupt: bool = PrivateAttr(default=False)

    @property
    def unreadable(self) -> bool:
        """Het bestand zelf is nu onleesbaar (alleen dan wordt het origineel apart gezet bij een schrijfactie)."""
        return self._corrupt

    @property
    def corrupt(self) -> bool:
        """Koppelstatus onbekend: het bestand is onleesbaar, of een onleesbaar bestand is vervangen en er is sindsdien
        niet opnieuw gekoppeld. Dan geen koppelformulier en niets vertrouwd (fail-closed)."""
        return self._corrupt or (self.unreadable_replaced_at is not None and self.first_linked_at is None)

    @property
    def linked(self) -> bool:
        """Alleen ``gekoppeld`` mét token en pins vertrouwt Hub-JWT's (§3.5)."""
        return self.state == "gekoppeld" and bool(self.service_token) and self.pins is not None

    @property
    def ever_linked(self) -> bool:
        """Bepaalt of de statuspagina nog een koppelformulier mag tonen (§3.7); onleesbaar telt als 'wel'."""
        return self.corrupt or self.first_linked_at is not None

    def remember_token(self, digest: str) -> None:
        if digest not in self.used_enrollment_token_sha256:
            self.used_enrollment_token_sha256.append(digest)
        self.used_enrollment_token_sha256 = self.used_enrollment_token_sha256[-MAX_USED_TOKENS:]

    def public(self) -> dict[str, Any]:
        """Witte lijst voor statuspagina, ``/readyz`` en ``GET /connector/v1/hub-link`` (§3.5): nooit het
        service-token of ``pending.secret_sha256``. Is de koppelstatus onbekend (onleesbaar), dan meldt ``last_error``
        dat met de vaste code ``koppelstatus_onleesbaar``: ``state`` alleen zou dan ten onrechte "nooit gekoppeld"
        lijken."""
        error = LastError(code="koppelstatus_onleesbaar", at=now_iso()) if self.corrupt else self.last_error
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
            "last_error": ({"code": error.code, "message": error_message(error.code)} if error else None),
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
        self._cache: tuple[tuple[int, int, int, int, int], LinkState] | None = None
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
        key = (st.st_ino, st.st_mtime_ns, st.st_size, st.st_uid, st.st_mode)
        with self._mutex:
            if self._cache is not None and self._cache[0] == key:
                return _clone(self._cache[1])
        try:
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
                raise PermissionError("verkeerde eigenaar of rechten ruimer dan 0600")
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("geen object")
            missing = [f for f in REQUIRED_FIELDS if f not in data]
            if missing:
                raise ValueError(f"verplichte velden ontbreken: {', '.join(missing)}")
            version = data["schema_version"]
            if not isinstance(version, str) or version.split(".", 1)[0] != "1":
                raise ValueError("andere major van schema_version")
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
        state.schema_version = SCHEMA_VERSION  # een dienst schrijft de versie van het contract dat hij volgt (§3.5)
        data = state.model_dump(mode="json")
        payload = (json.dumps(data, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
        tmp = self.dir / f".hub-link.{uuid.uuid4().hex}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        # geërfde ACL's van de dataset (bv. NFSv4 op TrueNAS) kunnen de modus ruimer maken dan gevraagd; een ruimer
        # bestand leest deze dienst zelf als onleesbaar (§3.5), dus de modus expliciet op 0600 zetten waar dat kan
        with contextlib.suppress(OSError):
            os.fchmod(fd, 0o600)
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
            if current.corrupt and new.first_linked_at is None:
                # nog steeds onbekend of de dienst al eens gekoppeld was: dat blijft na het schrijven zichtbaar
                # (geen koppelformulier, niets vertrouwd) tot een geslaagde koppeling via een nieuw token
                new.unreadable_replaced_at = current.unreadable_replaced_at or new.unreadable_replaced_at or now_iso()
            if current.unreadable:
                self._set_aside_unreadable()
            self._write(new)
            new._corrupt = False  # het bestand is nu weer leesbaar
            return new

    def _set_aside_unreadable(self) -> None:
        """Bewaar een onleesbaar ``hub-link.json`` (0600, zelfde map) voor onderzoek vóór het vervangen."""
        aside = self.dir / f"{LINK_FILE}{UNREADABLE_SUFFIX}{utcnow().strftime('%Y%m%dT%H%M%S%fZ')}"
        try:
            os.rename(self.path, aside)
        except OSError as exc:
            log.error(
                "onleesbaar hub-link.json kon niet apart worden gezet (%s); het wordt vervangen", type(exc).__name__
            )
            return
        # een bestand van een andere eigenaar (ook een reden voor "onleesbaar") kan dit proces niet aanpassen; het staat
        # dan nog steeds in de map secrets (0700) en is bewaard
        with contextlib.suppress(OSError):
            os.chmod(aside, 0o600)
        log.error(
            "onleesbaar hub-link.json bewaard als %s; de koppelstatus blijft onbekend tot opnieuw koppelen", aside.name
        )

    def write_initial(self, state: LinkState) -> bool:
        """Schrijf alleen als het bestand nog niet bestaat (onder de vergrendeling). Geeft ``True`` als geschreven."""
        with self.locked():
            if self.path.exists():
                return False
            self._write(state)
            return True
