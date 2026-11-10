"""Koppelen met de Hub volgens contract 1.3 §3 (enrollment, bevestigen, intrekken, rotatie) en §4.5 (pins).

- ``POST {HUB_URL}/api/v1/services/enroll`` met precies ``{app_id, enrollment_token | pairing_code, version, base_url,
  public_key_jwk}`` (§3.3). Het antwoord wordt volledig gecontroleerd, de sleutelset-vingerafdruk zelf berekend en
  vergeleken (met ``HUB_KEY_FINGERPRINT`` of de op de statuspagina ingevoerde vingerafdruk); pas daarna wordt in één
  atomaire stap ``hub-link.json`` geschreven (§3.5) en met ``GET /api/v1/services/self`` bevestigd (§3.6). Nieuw in 1.3:
  ``rotation_sequence`` uit het antwoord (ontbreekt bij een Hub 1.2 → 0) wordt ``pins.rotation_sequence``; de dienst
  vraagt daarna alleen ``key-rotations?after=<waarde>`` (§4.5).
- Twee routes: het eenmalige env-token (worker, met backoff, stoppen na 60 min) en een koppelcode op de statuspagina
  (API-proces, één poging per formulier, alleen zolang de dienst nog nooit gekoppeld was, §3.7).
- Alle Hub-aanroepen volgen **nooit** een redirect en negeren proxy-omgevingsvariabelen (``hubclient``).
- 401 van de Hub op een aanroep met het service-token → eerst ``GET /api/v1/services/self``; pas bij opnieuw 401
  ``ingetrokken``. Netwerkfouten, 5xx en 429 zijn nooit een intrekking (§3.8).
- ``Hub-Token-Rotation: required`` → ``POST /api/v1/services/self/rotate``, het nieuwe token atomair opslaan en met
  ``services/self`` bevestigen (§3.8); ook na een onderbroken rotatie, want de Hub herhaalt de header.
- Sleutelrotatie (§4.5): ``GET /api/v1/auth/key-rotations?after=<n>`` zonder authenticatie; alleen statements die met
  een **gepinde** sleutel van hetzelfde doel zijn ondertekend, in volgorde en zonder gaten. Een via HTTP opgehaalde
  JWKS voegt nooit vertrouwen toe (deze dienst haalt de JWKS daarom niet eens op).
- Eenmalige overzetting van een koppeling uit de database (versie vóór 1.2) naar ``hub-link.json`` (§3.5).

Koppelen, ontkoppelen, intrekken en rotatie zijn geen ``action_id``'s (§8): ze lopen alleen via deze vaste paden.
"""

from __future__ import annotations

import json
import logging
import random
import re
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
import jwt
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import APP_ID, __version__, audit, events
from .config import Settings
from .db import Database
from .hubclient import HubClient, HubUrlError, validate_hub_url
from .hublink_store import (
    HubLinkStore,
    LastError,
    LinkState,
    Pending,
    Pin,
    Pins,
    PublicJwk,
    error_message,
    now_iso,
)
from .security.hubkeys import (
    ENROLLMENT_TOKEN_RE,
    SERVICE_TOKEN_RE,
    InvalidKeyError,
    fingerprints_equal,
    jwk_thumbprint,
    keyset_fingerprint,
    normalize_fingerprint,
    normalize_pairing_code,
    public_key_from_jwk,
    sha256_hex,
    validate_hub_jwk,
)
from .security.vault import Vault
from .timeutil import utcnow

log = logging.getLogger("integrations.enrollment")

ENROLL_PATH = "/api/v1/services/enroll"
SELF_PATH = "/api/v1/services/self"
ROTATE_PATH = "/api/v1/services/self/rotate"
KEY_ROTATIONS_PATH = "/api/v1/auth/key-rotations"
EVENTS_INBOX_PATH = "/api/v1/events/inbox"
ENROLL_FIELDS = ("app_id", "version", "base_url", "public_key_jwk")  # + precies één van enrollment_token/pairing_code
ENROLLMENT_WINDOW = timedelta(minutes=60)  # §3.3: automatisch stoppen 60 min na de eerste poging
KOPPELCODE_STALE = timedelta(minutes=2)  # een koppelcodepoging duurt hooguit één verzoek (5 s + 15 s)
BACKOFF_START = 5.0
BACKOFF_MAX = 15 * 60.0
KEY_POLL_MIN_GAP = 30.0  # §4.5: extra poll bij een onbekende kid hooguit 1× per 30 s
ROTATION_TYP = "hub-key-rotation+jws"
BASE_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(/[^\s?#]*)?$")  # §3.3 (zelfde regel als de Hub)
WORKER_ACTOR = ("system", "home-control-hub:worker")
RESPONSE_FIELDS: dict[str, type] = {
    "schema_version": str,
    "service_id": str,
    "app_id": str,
    "service_token": str,
    "token_type": str,
    "hub_issuer": str,
    "jwks": dict,
    "policy_public_key": dict,
    "keyset_fingerprint": str,
    "jwks_url": str,
    "events_inbox_url": str,
    "key_rotation_url": str,
    "enrollment_replayed": bool,
}
#: nieuw in 1.3 (§3.3): ontbreekt bij een Hub 1.2 (dan 0); aanwezig → een geheel getal ≥ 0
ROTATION_SEQUENCE_FIELD = "rotation_sequence"
#: vaste ``last_error``-code per HTTP-uitkomst van ``POST /enroll`` (§3.3/§3.5); overige 4xx = incompatibel
ENROLL_STATUS_CODES = {
    401: "hub_weigerde",
    404: "enroll_endpoint_ontbreekt",
    413: "hub_incompatibel",
    422: "hub_incompatibel",
}
# Oude opslag (vóór contract 1.2): sleutels in service_state en het token in de vault (ADR-0002).
LEGACY_STATE_KEYS = ("hub_link", "hub_jwks", "hub_policy_key")
LEGACY_TOKEN_REF = "vault://hub/service-token"  # noqa: S105 - referentie, geen geheim


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def stale_koppelcode(pending: Pending) -> bool:
    """Een koppelcodepoging duurt hooguit één verzoek; ouder dan 2 min (of onleesbare tijd) = verweesd."""
    if pending.kind != "koppelcode":
        return False
    started = parse_iso(pending.started_at)
    return started is None or utcnow() - started >= KOPPELCODE_STALE


def backoff_delay(attempts: int) -> float:
    """Exponentieel met jitter: start 5 s, hooguit 15 min tussen pogingen (§3.3)."""
    base = min(BACKOFF_MAX, BACKOFF_START * float(2 ** max(0, attempts - 1)))
    return float(min(BACKOFF_MAX, base * random.uniform(0.8, 1.2)))  # noqa: S311 - jitter, geen cryptografie


class InvalidResponseError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class EnrollOutcome:
    """Uitkomst van één poging. ``kind``: ``ok`` | ``definitive`` | ``transient`` | ``rate_limited`` | ``refused``
    (niet verstuurd: ongeldige invoer, er loopt al een poging, of koppelen via de statuspagina mag niet meer)."""

    kind: str
    code: str | None = None
    retry_after: float | None = None

    @property
    def ok(self) -> bool:
        return self.kind == "ok"

    @property
    def message_nl(self) -> str:
        return "Gekoppeld met de Hub." if self.ok else (error_message(self.code) or "Koppelen is niet gelukt.")


def _pins_from(
    jwks: list[dict[str, str]], policy: list[dict[str, str]], source: str, now: str, rotation_sequence: int = 0
) -> Pins:
    def pin(jwk: dict[str, str]) -> Pin:
        return Pin(
            kid=jwk["kid"],
            jwk=PublicJwk(x=jwk["x"]),
            thumbprint=jwk_thumbprint(jwk),
            pinned_at=now,
            source=source,  # type: ignore[arg-type]
        )

    return Pins(
        jwt=[pin(k) for k in jwks],
        policy=[pin(k) for k in policy],
        keyset_fingerprint=keyset_fingerprint(jwks, policy),
        rotation_sequence=rotation_sequence,
    )


def pin_jwks(pins: Pins) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    def as_jwk(p: Pin) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "x": p.jwk.x, "kid": p.kid}

    return [as_jwk(p) for p in pins.jwt], [as_jwk(p) for p in pins.policy]


def validate_enroll_response(data: Any, expected_fingerprint: str | None) -> dict[str, Any]:
    """Alle controles van §3.3 vóór opslaan. Gooit :class:`InvalidResponseError` met de ``last_error``-code.

    Onbekende extra velden worden genegeerd; aliassen uit eerdere aannames (``token``, ``id``, ``policy_public_jwk``,
    ``kind``, ``secret``) tellen niet."""
    if not isinstance(data, dict):
        raise InvalidResponseError("hub_antwoord_ongeldig", "antwoord is geen object")
    for name, typ in RESPONSE_FIELDS.items():
        value = data.get(name)
        if not isinstance(value, typ) or (typ is not bool and isinstance(value, bool)):
            raise InvalidResponseError("hub_antwoord_ongeldig", f"veld {name} ontbreekt of heeft het verkeerde type")
    if data["schema_version"].split(".", 1)[0] != "1":  # elke 1.x ("1.3", en "1.2" van een oudere Hub)
        raise InvalidResponseError("hub_antwoord_ongeldig", f"schema_version {data['schema_version']!r} onbekend")
    sequence = data.get(ROTATION_SEQUENCE_FIELD, 0)  # Hub 1.2: ontbreekt → 0 (§3.3)
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise InvalidResponseError("hub_antwoord_ongeldig", "rotation_sequence is geen geheel getal ≥ 0")
    if data["app_id"] != APP_ID:
        raise InvalidResponseError("hub_antwoord_ongeldig", "app_id in het antwoord is niet die van deze dienst")
    try:
        uuid.UUID(data["service_id"])
    except ValueError as exc:
        raise InvalidResponseError("hub_antwoord_ongeldig", "service_id is geen UUID") from exc
    if not SERVICE_TOKEN_RE.match(data["service_token"]):
        raise InvalidResponseError("hub_antwoord_ongeldig", "service_token past niet in het patroon svc_ + 43 tekens")
    if data["token_type"] != "Bearer" or data["hub_issuer"] != "hub":  # noqa: S105 - vaste waarde, geen geheim
        raise InvalidResponseError("hub_antwoord_ongeldig", "token_type of hub_issuer klopt niet")
    keys = data["jwks"].get("keys")
    if not isinstance(keys, list) or not keys:
        raise InvalidResponseError("hub_antwoord_ongeldig", "jwks bevat geen sleutels")
    try:
        jwks = [validate_hub_jwk(k) for k in keys]
        policy = validate_hub_jwk(data["policy_public_key"])
    except InvalidKeyError as exc:
        raise InvalidResponseError("hub_antwoord_ongeldig", f"ongeldige sleutel: {exc}") from exc
    if len({k["kid"] for k in jwks}) != len(jwks):
        raise InvalidResponseError("hub_antwoord_ongeldig", "kid komt dubbel voor in jwks")
    computed = keyset_fingerprint(jwks, [policy])
    if not fingerprints_equal(data["keyset_fingerprint"], computed):
        raise InvalidResponseError("hub_vingerafdruk_onjuist", "de gemelde vingerafdruk past niet bij de sleutels")
    if expected_fingerprint is not None and not fingerprints_equal(expected_fingerprint, computed):
        raise InvalidResponseError("hub_vingerafdruk_onjuist", "de sleutelset-vingerafdruk wijkt af van de verwachte")
    return {**data, "_jwks": jwks, "_policy": policy, "_fingerprint": computed, "_sequence": sequence}


class HubLink:
    """Alle uitgaande Hub-interactie van deze dienst (API-proces én worker) rond de koppeling."""

    def __init__(
        self,
        settings: Settings,
        store: HubLinkStore,
        identity_jwk: dict[str, str],
        hub: HubClient,
        db: Database | None = None,
        vault: Vault | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.identity_jwk = identity_jwk
        self.hub = hub
        self.db = db
        self.vault = vault
        self.migrated = False
        self._next_env_attempt = 0.0
        self._next_confirm = 0.0
        self._next_heartbeat = 0.0
        self._next_rotate = 0.0
        self._next_key_poll = 0.0
        self._last_key_poll = -KEY_POLL_MIN_GAP
        self._poll_lock = threading.Lock()
        self._warned: set[str] = set()

    # ------------------------------------------------------------------ hulp
    def state(self) -> LinkState:
        return self.store.read()

    def public_state(self) -> dict[str, Any]:
        return self.store.read().public()

    def _record(
        self,
        action: str,
        event_type: str,
        message_nl: str,
        details: dict[str, Any],
        trace_id: str,
        actor: tuple[str, str] = WORKER_ACTOR,
    ) -> None:
        """Audit + outbox-event (best effort: de koppelstatus zelf staat in het bestand, niet in de database)."""
        if self.db is None:
            return
        try:
            with self.db.sessions() as s:
                audit.record(
                    s,
                    domain="hub_link",
                    action=action,
                    entity_type="hub_link",
                    entity_id="hub",
                    principal=None,
                    trace_id=trace_id,
                    actor_override=actor,
                    message_nl=message_nl,
                    details=details,
                )
                events.emit(
                    s,
                    event_type=event_type,
                    # 1.3 §7: de vaste service.*-events gaan over de dienst zelf (entity = deze dienst)
                    entity_type="service",
                    entity_id=APP_ID,
                    actor_type=actor[0],
                    actor_id=actor[1],
                    trace_id=trace_id,
                    payload=details,
                )
                s.commit()
        except Exception:
            log.exception("audit/event van %s kon niet worden vastgelegd", action)

    def enroll_body(self, credential_field: str, credential: str) -> dict[str, Any]:
        """Het verzoek van §3.3, exact deze velden (onbekende velden → 422 bij de Hub)."""
        if credential_field not in ("enrollment_token", "pairing_code"):
            raise ValueError(credential_field)
        return {
            "app_id": APP_ID,
            credential_field: credential,
            "version": __version__,
            "base_url": self._base_url(),
            "public_key_jwk": dict(self.identity_jwk),
        }

    def _base_url(self) -> str | None:
        """``base_url`` is alleen informatief (§3.3). Een ongeldige ``HCH_PUBLIC_URL`` zou de Hub met 422 laten weigeren en
        het token verbranden; daarom dan ``null`` sturen (met een waarschuwing)."""
        url = self.settings.public_url
        if url is None:
            return None
        if len(url) <= 512 and BASE_URL_RE.match(url):
            return url
        self._warn_once("base_url", "HCH_PUBLIC_URL past niet in http(s)://host[:poort][/pad]; base_url wordt null")
        return None

    def _bearer(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _warn_once(self, key: str, msg: str, *args: Any) -> None:
        if key not in self._warned:
            self._warned.add(key)
            log.warning(msg, *args)

    @staticmethod
    def _log(kind: str, level: int, msg: str, *args: Any) -> None:
        """Een koppelcodepoging logt de statuspagina zelf met precies één regel (§3.7); hier dan alleen op DEBUG."""
        log.log(logging.DEBUG if kind == "koppelcode" else level, msg, *args)

    @staticmethod
    def pending_is_stale(pending: Pending) -> bool:
        """Een verweesde koppelcodepoging (afgebroken verzoek) telt niet als lopende poging (§3.6 stap 5)."""
        return stale_koppelcode(pending)

    # ------------------------------------------------------------------ enrollment
    def _begin(self, kind: str, secret_digest: str, hub_url: str) -> Pending | str:
        """Claim de poging atomair (onder de bestandsvergrendeling): nooit twee enrollments tegelijk, en een
        koppelcode alleen zolang de dienst nog nooit gekoppeld is (§3.7). Geeft de ``Pending`` of een weigercode
        (``koppelen_bezig`` | ``al_gekoppeld``); dan wordt er niets naar de Hub gestuurd."""
        result: dict[str, Pending | str] = {}

        def change(st: LinkState) -> LinkState | None:
            p = st.pending
            if p is not None and kind == "token" and p.kind == "koppelcode" and stale_koppelcode(p):
                p = None  # verweesde koppelcodepoging (afgebroken verzoek): telt als onderbroken
            if kind == "koppelcode":
                if st.ever_linked:
                    result["p"] = "al_gekoppeld"
                    return None
                if p is not None and not stale_koppelcode(p):
                    result["p"] = "koppelen_bezig"  # ook een dubbel verstuurd formulier met dezelfde code
                    return None
            elif p is not None and p.kind == "koppelcode":
                result["p"] = "koppelen_bezig"
                return None
            if p is not None and p.kind == kind and p.secret_sha256 == secret_digest:
                p.attempts += 1
                p.hub_url = hub_url
                st.pending = p
            else:
                st.pending = Pending(
                    kind=kind,  # type: ignore[arg-type]
                    secret_sha256=secret_digest,
                    hub_url=hub_url,
                    started_at=now_iso(),
                    attempts=1,
                )
            result["p"] = st.pending
            return st

        self.store.update(change)
        return result["p"]

    def _fail(self, code: str, *, kind: str, secret_digest: str, definitive: bool) -> None:
        """Mislukt (§3.6 stap 4): ``pending`` weg, ``last_error``; een bestaande koppeling blijft zoals hij was. Het
        Hub-adres van de mislukte poging wordt nergens bewaard (het stond alleen in ``pending``)."""

        def change(st: LinkState) -> LinkState:
            if st.pending is not None and st.pending.secret_sha256 == secret_digest:
                st.pending = None
            st.last_error = LastError(code=code, at=now_iso())
            if definitive and kind == "token":
                st.remember_token(secret_digest)
            return st

        self.store.update(change)

    def _set_error(self, code: str) -> None:
        """Alleen ``last_error`` bijwerken (``pending`` blijft); schrijft niets als de code al zo staat."""

        def change(st: LinkState) -> LinkState | None:
            if st.last_error is not None and st.last_error.code == code:
                return None
            st.last_error = LastError(code=code, at=now_iso())
            return st

        self.store.update(change)

    def attempt(
        self,
        *,
        hub_url: str,
        kind: str,
        credential: str,
        expected_fingerprint: str | None,
        trace_id: str,
        actor: tuple[str, str] = WORKER_ACTOR,
    ) -> EnrollOutcome:
        """Eén enroll-poging (§3.6 stap 2–4). ``kind``: ``token`` (env) of ``koppelcode`` (statuspagina)."""
        digest = sha256_hex(credential)
        claim = self._begin(kind, digest, hub_url)
        if isinstance(claim, str):
            self._log(kind, logging.INFO, "koppelen (%s) niet gestart: %s", kind, claim)
            return EnrollOutcome("refused", claim)
        field = "enrollment_token" if kind == "token" else "pairing_code"
        body = self.enroll_body(field, credential)
        koppelcode = kind == "koppelcode"
        try:
            resp = self.hub.request("POST", hub_url, ENROLL_PATH, json=body)
        except httpx.HTTPError as exc:
            self._log(kind, logging.WARNING, "koppelen: Hub niet bereikbaar (%s)", type(exc).__name__)
            return self._transient_or_fail("hub_onbereikbaar", koppelcode, digest)
        status = resp.status_code
        if status == 200:
            try:
                data = validate_enroll_response(resp.json(), expected_fingerprint)
            except (InvalidResponseError, ValueError) as exc:
                code = exc.code if isinstance(exc, InvalidResponseError) else "hub_antwoord_ongeldig"
                self._log(kind, logging.WARNING, "koppelen geweigerd door deze dienst: %s (%s)", code, exc)
                self._fail(code, kind=kind, secret_digest=digest, definitive=True)
                return EnrollOutcome("definitive", code)
            self._succeed(data, hub_url=hub_url, kind=kind, digest=digest, trace_id=trace_id, actor=actor)
            self.confirm(trace_id=trace_id)
            return EnrollOutcome("ok")
        if status == 429:  # opnieuw na Retry-After, niet eerder (§3.3)
            outcome = self._transient_or_fail("rate_limited", koppelcode, digest)
            return EnrollOutcome("rate_limited", outcome.code, _retry_after(resp))
        if 300 <= status < 400 or status >= 500:  # 3xx = storing, nooit volgen
            return self._transient_or_fail("hub_onbereikbaar", koppelcode, digest)
        # overige 4xx: definitief; het verzoek past niet bij deze Hub (geen weigering van het token zelf)
        last = ENROLL_STATUS_CODES.get(status, "hub_incompatibel")
        self._log(kind, logging.WARNING, "koppelen: Hub antwoordde HTTP %s (%s)", status, last)
        self._fail(last, kind=kind, secret_digest=digest, definitive=True)
        return EnrollOutcome("definitive", last)

    def _transient_or_fail(self, code: str, koppelcode: bool, digest: str) -> EnrollOutcome:
        # koppelcode: het geheim staat alleen in dit verzoek, dus geen herhaling op de achtergrond (de gebruiker probeert
        # opnieuw); env-token: pending blijft staan en de worker probeert het met backoff opnieuw
        if koppelcode:
            self._fail(code, kind="koppelcode", secret_digest=digest, definitive=False)
        else:
            self._set_error(code)
        return EnrollOutcome("transient", code)

    def _succeed(
        self, data: dict[str, Any], *, hub_url: str, kind: str, digest: str, trace_id: str, actor: tuple[str, str]
    ) -> None:
        now = now_iso()
        token = str(data["service_token"])

        def change(st: LinkState) -> LinkState:
            new = LinkState(
                state="gekoppeld",
                hub_url=hub_url,
                service_id=str(data["service_id"]),
                via=kind,  # type: ignore[arg-type]
                first_linked_at=st.first_linked_at or now,
                linked_at=now,
                confirmed_at=None,
                service_token=token,
                service_token_last4=token[-4:],
                pins=_pins_from(data["_jwks"], [data["_policy"]], "enroll", now, int(data["_sequence"])),
                previous_pins=st.pins or st.previous_pins,
                pending=None,
                used_enrollment_token_sha256=list(st.used_enrollment_token_sha256),
                last_error=None,
            )
            if kind == "token":
                new.remember_token(digest)
            return new

        self.store.update(change)
        self._log(
            kind, logging.INFO, "gekoppeld met de Hub via %s (sleutelset-vingerafdruk %s)", kind, data["_fingerprint"]
        )
        self._record(
            "hub.linked",
            "service.hub_link.linked",
            f"Gekoppeld met de Hub via {kind}.",
            {
                "hub_url": hub_url,
                "via": kind,
                "service_id": str(data["service_id"]),
                "keyset_fingerprint": data["_fingerprint"],
                "enrollment_replayed": bool(data["enrollment_replayed"]),
            },
            trace_id,
            actor,
        )

    def pair_with_code(self, *, hub_url: str, pairing_code: str, fingerprint: str, trace_id: str) -> EnrollOutcome:
        """Statuspagina (§3.7): invoer als geheel controleren (nooit afkappen), dan één poging met koppelcode +
        verplichte vingerafdruk."""
        try:
            url = validate_hub_url(hub_url, self.settings.allow_loopback_hub)
        except HubUrlError:
            return EnrollOutcome("refused", "ongeldig_hub_adres")
        code = normalize_pairing_code(pairing_code)
        if code is None:
            return EnrollOutcome("refused", "ongeldige_koppelcode")
        expected = normalize_fingerprint(fingerprint)
        if expected is None:
            return EnrollOutcome("refused", "ongeldige_vingerafdruk")
        if not self.ensure_migrated():
            return EnrollOutcome("refused", "database_onbereikbaar")
        return self.attempt(
            hub_url=url,
            kind="koppelcode",
            credential=code,
            expected_fingerprint=expected,
            trace_id=trace_id,
            actor=("user", "statuspagina"),
        )

    def env_tick(self, trace_id: str, *, now: float | None = None) -> EnrollOutcome | None:
        """Worker: het env-token gebruiken zolang dat zinvol is (§3.2, §3.6, §3.8). ``None`` = niets gedaan."""
        mono = time.monotonic() if now is None else now
        s = self.settings
        token, raw_url = s.enrollment_token, s.hub_url
        st = self.store.read()
        if not token or not raw_url:
            if st.pending is not None and st.pending.kind == "token":
                self._interrupted(st.pending.secret_sha256)
            return None
        if s.enrollment_token_legacy_name:
            self._warn_once(
                "legacy",
                "ENROLLMENT_TOKEN is verouderd en vervalt na deze release; gebruik HUB_ENROLLMENT_TOKEN in het formulier",
            )
        digest = sha256_hex(token)
        if digest in st.used_enrollment_token_sha256:
            return None  # al afgehandeld (geslaagd of definitief mislukt): nooit opnieuw proberen
        try:
            hub_url = validate_hub_url(raw_url, s.allow_loopback_hub, label="HUB_URL")
        except HubUrlError as exc:
            self._warn_once("url", "HUB_URL is ongeldig (%s); er wordt niet gekoppeld", exc)
            self._set_error("hub_adres_ongeldig")
            return EnrollOutcome("refused", "hub_adres_ongeldig")
        expected: str | None = None
        if s.hub_key_fingerprint is not None:
            expected = normalize_fingerprint(s.hub_key_fingerprint)
            if expected is None:  # aanwezig ⇒ verplicht te controleren; onleesbaar ⇒ nooit koppelen
                self._warn_once("fp", "HUB_KEY_FINGERPRINT heeft niet het formaat XXXX-XXXX-XXXX-XXXX; niet gekoppeld")
                self._set_error("vingerafdruk_ongeldig")
                return EnrollOutcome("refused", "vingerafdruk_ongeldig")
        if st.pending is not None and st.pending.kind == "koppelcode":
            if not stale_koppelcode(st.pending):
                return None  # een koppelpoging via de statuspagina loopt; nooit twee enrollments tegelijk
            self._interrupted(st.pending.secret_sha256)
            st = self.store.read()
        if st.pending is not None and st.pending.kind == "token" and st.pending.secret_sha256 != digest:
            self._interrupted(st.pending.secret_sha256)  # ander env-token: de oude poging is onderbroken
            st = self.store.read()
        if not ENROLLMENT_TOKEN_RE.match(token):
            log.warning("HUB_ENROLLMENT_TOKEN heeft niet het formaat enr_ + 43 tekens; niet gebruikt")
            self._fail("token_ongeldig", kind="token", secret_digest=digest, definitive=True)
            return EnrollOutcome("definitive", "token_ongeldig")
        if st.pending is not None and st.pending.kind == "token":
            started = parse_iso(st.pending.started_at)
            if started is None or utcnow() - started > ENROLLMENT_WINDOW:
                log.warning("koppelen met het env-token is na 60 min niet gelukt; gestopt")
                self._fail("token_verlopen_na_60_min", kind="token", secret_digest=digest, definitive=True)
                return EnrollOutcome("definitive", "token_verlopen_na_60_min")
        if mono < self._next_env_attempt:
            return None
        outcome = self.attempt(
            hub_url=hub_url, kind="token", credential=token, expected_fingerprint=expected, trace_id=trace_id
        )
        if outcome.kind == "rate_limited":
            self._next_env_attempt = mono + (outcome.retry_after or 60.0)
        elif outcome.kind == "transient":
            pending = self.store.read().pending
            self._next_env_attempt = mono + backoff_delay(pending.attempts if pending else 1)
        return outcome

    def _interrupted(self, digest: str) -> None:
        def change(st: LinkState) -> LinkState | None:
            if st.pending is None or st.pending.secret_sha256 != digest:
                return None
            st.pending = None
            st.last_error = LastError(code="koppelen_onderbroken", at=now_iso())
            return st

        self.store.update(change)

    def recover_after_restart(self, *, process: str) -> None:
        """§3.6 stap 5. ``process``: ``api`` (koppelcodes horen bij het API-proces) of ``worker`` (env-token)."""

        def change(st: LinkState) -> LinkState | None:
            p = st.pending
            if p is None:
                return None
            if p.kind == "koppelcode" and process != "api" and not stale_koppelcode(p):
                return None  # mogelijk nog bezig in het API-proces
            if p.kind == "token":
                token = self.settings.enrollment_token
                if process != "worker" or (token and sha256_hex(token) == p.secret_sha256):
                    return None  # zelfde env-token: de worker herhaalt de poging (toegestane herhaling)
            st.pending = None
            st.last_error = LastError(code="koppelen_onderbroken", at=now_iso())
            return st

        self.store.update(change)

    # ------------------------------------------------------------------ dienst → Hub (service-token)
    def _note_rotation(self, resp: httpx.Response) -> None:
        if resp.headers.get("hub-token-rotation", "").strip().lower() == "required":

            def change(st: LinkState) -> LinkState | None:
                if not st.linked or st.token_rotation_requested_at:
                    return None
                st.token_rotation_requested_at = now_iso()
                return st

            self.store.update(change)

    def confirm(self, *, trace_id: str) -> bool | None:
        """``GET /api/v1/services/self`` met het huidige token (§3.6 stap 3). ``True`` bevestigd, ``False``
        ingetrokken (401), ``None`` onbekend (storing, 5xx, 429 of een oude Hub)."""
        st = self.store.read()
        if not st.linked or st.hub_url is None or st.service_token is None:
            return None
        token = st.service_token
        try:
            resp = self.hub.request("GET", st.hub_url, SELF_PATH, headers=self._bearer(token))
        except httpx.HTTPError:
            return None
        self._note_rotation(resp)
        if resp.status_code == 401:
            self.mark_revoked(trace_id=trace_id, token=token)
            return False
        if resp.status_code != 200:
            if resp.status_code == 404:
                self._warn_once(
                    "self404", "de Hub kent GET /api/v1/services/self niet (oude Hub); koppeling onbevestigd"
                )
            return None
        try:
            data = resp.json()
            ok = isinstance(data, dict) and data.get("service_id") == st.service_id
        except ValueError:
            ok, data = False, None
        if not ok:
            log.warning("services/self gaf een onverwacht antwoord; de koppeling blijft onbevestigd")
            return None

        def change(cur: LinkState) -> LinkState | None:
            if cur.service_token != token or cur.confirmed_at is not None:
                return None  # intussen vervangen, of al bevestigd (de periodieke bevestiging schrijft niets)
            cur.confirmed_at = now_iso()
            return cur

        self.store.update(change)
        reported = data.get("keyset_fingerprint") if isinstance(data, dict) else None
        if reported and st.pins and not fingerprints_equal(str(reported), st.pins.keyset_fingerprint):
            # alleen een melding: een nieuwe Hub-sleutel komt er uitsluitend via een ondertekende rotatie of opnieuw
            # koppelen (§4.5); de Hub ondertekent pas met een nieuwe sleutel als elke dienst de rotatie heeft
            self._warn_once("fpdiff", "de Hub meldt een andere sleutelset-vingerafdruk dan de gepinde; niets gewijzigd")
        return True

    def call(self, method: str, path: str, *, json_body: Any = None, trace_id: str) -> httpx.Response | None:
        """Geauthenticeerde aanroep naar de Hub met het service-token (§4.4). ``None`` als niet gekoppeld.
        Netwerkfouten gaan door naar de aanroeper (nooit een intrekking)."""
        st = self.store.read()
        if not st.linked or st.hub_url is None or st.service_token is None:
            return None
        resp = self.hub.request(method, st.hub_url, path, json=json_body, headers=self._bearer(st.service_token))
        self._note_rotation(resp)
        if resp.status_code == 401:
            self.confirm(trace_id=trace_id)  # §3.8: pas bij 401 op services/self is het een intrekking
        return resp

    def mark_revoked(self, *, trace_id: str, token: str | None = None) -> None:
        def change(st: LinkState) -> LinkState | None:
            if st.state != "gekoppeld" or (token is not None and st.service_token != token):
                return None
            st.state = "ingetrokken"
            st.service_token = None
            st.previous_pins = st.pins or st.previous_pins
            st.pins = None
            st.confirmed_at = None
            st.token_rotation_requested_at = None
            st.last_error = LastError(code="ingetrokken_door_hub", at=now_iso())
            return st

        before = self.store.read().state
        after = self.store.update(change)
        if before == "gekoppeld" and after.state == "ingetrokken":
            log.warning("de Hub heeft de koppeling ingetrokken; Hub-JWT's worden vanaf nu geweigerd")
            self._record(
                "hub.revoked",
                "service.hub_link.revoked",
                "De Hub heeft de koppeling ingetrokken (services/self gaf 401).",
                {"hub_url": after.hub_url, "ernst": "middel"},
                trace_id,
            )

    def unlink(self, *, trace_id: str, actor: tuple[str, str]) -> LinkState:
        """``POST /connector/v1/hub-link/unlink`` (§3.8): ontkoppeld, token gewist, pins alleen nog voor audit."""

        def change(st: LinkState) -> LinkState | None:
            if st.state != "gekoppeld":
                return None
            st.state = "ontkoppeld"
            st.service_token = None
            st.service_token_last4 = None
            st.previous_pins = st.pins or st.previous_pins
            st.pins = None
            st.confirmed_at = None
            st.token_rotation_requested_at = None
            st.last_error = None
            return st

        before = self.store.read().state
        result = self.store.update(change)
        if before == "gekoppeld" and result.state == "ontkoppeld":
            log.info("ontkoppeld van de Hub door %s", actor[1])
            self._record(
                "hub.unlinked",
                "service.hub_link.unlinked",
                "Ontkoppeld van de Hub.",
                {"hub_url": result.hub_url, "door": actor[1]},
                trace_id,
                actor,
            )
        return result

    def rotate_token(self, *, trace_id: str) -> bool | None:
        """§3.8: ``POST /api/v1/services/self/rotate`` → nieuw token atomair opslaan → bevestigen met ``services/self``."""
        st = self.store.read()
        if not st.linked or st.hub_url is None or st.service_token is None:
            return None
        old = st.service_token
        try:
            resp = self.hub.request("POST", st.hub_url, ROTATE_PATH, headers=self._bearer(old))
        except httpx.HTTPError:
            return None
        if resp.status_code == 401:
            self.confirm(trace_id=trace_id)
            return False
        if resp.status_code != 200:
            log.warning("token roteren: de Hub antwoordde HTTP %s", resp.status_code)
            return None
        try:
            data = resp.json()
            new = data["service_token"]
            if not isinstance(new, str) or not SERVICE_TOKEN_RE.match(new) or data.get("service_id") != st.service_id:
                raise ValueError("ongeldig rotatie-antwoord")
        except (ValueError, KeyError, TypeError):
            log.warning("token roteren: onverwacht antwoord van de Hub; het oude token blijft in gebruik")
            return None

        def change(cur: LinkState) -> LinkState | None:
            if cur.service_token != old:
                return None
            cur.service_token = new
            cur.service_token_last4 = new[-4:]
            cur.token_rotation_requested_at = None
            cur.confirmed_at = None
            return cur

        self.store.update(change)
        self._record(
            "hub.token_rotated",
            "service.token.rotated",
            "Service-token geroteerd op verzoek van de Hub.",
            {"service_token_last4": new[-4:], "oude_tokens_geldig_tot": data.get("oude_tokens_geldig_tot")},
            trace_id,
        )
        return self.confirm(trace_id=trace_id) is not False

    # ------------------------------------------------------------------ sleutelrotatie (§4.5)
    def poll_key_rotations(self, *, trace_id: str) -> int | None:
        """Haal ondertekende rotaties op en pas ze in volgorde toe. Geeft het aantal toegepaste statements."""
        with self._poll_lock:
            self._last_key_poll = time.monotonic()
            st = self.store.read()
            if not st.linked or st.pins is None or st.hub_url is None:
                return None
            try:
                resp = self.hub.request(
                    "GET", st.hub_url, KEY_ROTATIONS_PATH, params={"after": st.pins.rotation_sequence}
                )
            except httpx.HTTPError:
                return None
            if resp.status_code == 404:
                return 0  # Hub zonder sleutelrotatie
            if resp.status_code != 200:
                return None
            try:
                items = resp.json()["items"]
                if not isinstance(items, list):
                    raise TypeError("items")
            except (ValueError, KeyError, TypeError):
                log.warning("sleutelrotaties: onverwacht antwoord van de Hub")
                return None
            return self._apply_rotations(items, trace_id)

    def _apply_rotations(self, items: list[Any], trace_id: str) -> int:
        applied = 0

        def order(i: Any) -> float:  # ongeldige items achteraan: daar stopt het toepassen (incident)
            seq = i.get("sequence") if isinstance(i, dict) else None
            return float(seq) if isinstance(seq, int) and not isinstance(seq, bool) else float("inf")

        for raw in sorted(items, key=order):
            item: dict[str, Any] = raw if isinstance(raw, dict) else {"sequence": None, "statement": None}
            st = self.store.read()
            if not st.linked or st.pins is None:
                break
            expected = st.pins.rotation_sequence + 1
            try:
                new_pins = verify_rotation(item, st.pins, expected)
            except InvalidResponseError as exc:
                if st.key_rotation_blocked_sequence != expected:
                    log.error("sleutelrotatie %s geweigerd: %s; verdere statements niet toegepast", expected, exc)

                    def block(cur: LinkState, seq: int = expected) -> LinkState:
                        cur.key_rotation_blocked_sequence = seq
                        return cur

                    self.store.update(block)
                    self._record(
                        "hub.key_rotation_rejected",
                        "service.key_rotation.rejected",
                        "Een sleutelrotatie van de Hub is geweigerd; verdere rotaties zijn gestopt (incident).",
                        {"sequence": expected, "reason": str(exc), "ernst": "hoog"},
                        trace_id,
                    )
                break

            def change(cur: LinkState, pins: Pins = new_pins, seq: int = expected) -> LinkState | None:
                if not cur.linked or cur.pins is None or cur.pins.rotation_sequence != seq - 1:
                    return None
                cur.pins = pins
                cur.key_rotation_blocked_sequence = None
                return cur

            self.store.update(change)
            applied += 1
            self._record(
                "hub.key_rotation_applied",
                "service.key_rotation.applied",
                "Ondertekende sleutelrotatie van de Hub toegepast.",
                {"sequence": expected, "keyset_fingerprint": new_pins.keyset_fingerprint},
                trace_id,
            )
        return applied

    def request_key_poll(self) -> None:
        """Onbekende ``kid`` in een JWT: op de achtergrond een extra poll (hooguit 1× per 30 s; §4.5). Het verzoek
        zelf wacht daar niet op en krijgt direct 401 ``unknown_key``."""
        if time.monotonic() - self._last_key_poll < KEY_POLL_MIN_GAP:
            return
        self._last_key_poll = time.monotonic()
        threading.Thread(
            target=self._safe_poll, name="hub-key-poll", daemon=True, kwargs={"trace_id": str(uuid.uuid4())}
        ).start()

    def _safe_poll(self, trace_id: str) -> None:
        try:
            self.poll_key_rotations(trace_id=trace_id)
        except Exception:
            log.exception("sleutelrotaties ophalen mislukt")

    # ------------------------------------------------------------------ worker-ronde
    def maintenance_tick(self, trace_id: str) -> None:
        """Bevestigen (ook na herstart en periodiek, §3.6/§3.8), rotatie op verzoek van de Hub, sleutelrotaties
        pollen (§4.5)."""
        mono = time.monotonic()
        st = self.store.read()
        if not st.linked:
            return
        if st.confirmed_at is None:
            if mono >= self._next_confirm and self.confirm(trace_id=trace_id) is None:
                self._next_confirm = mono + 60.0
        elif mono >= self._next_heartbeat:
            self._next_heartbeat = mono + self.settings.hub_heartbeat_interval_s
            self.confirm(trace_id=trace_id)  # 401 → ingetrokken; noteert Hub-Token-Rotation
        st = self.store.read()
        if st.linked and st.token_rotation_requested_at and mono >= self._next_rotate:
            if self.rotate_token(trace_id=trace_id) is None:
                self._next_rotate = mono + 60.0
            st = self.store.read()
        if st.linked and mono >= self._next_key_poll:
            self._next_key_poll = mono + self.settings.hub_key_poll_interval_s
            self.poll_key_rotations(trace_id=trace_id)

    # ------------------------------------------------------------------ overzetten (vóór 1.2 → hub-link.json)
    def ensure_migrated(self) -> bool:
        """Eenmalige overzetting (§3.5) en daarna de oude rijen verwijderen. ``True`` als het bestand nu de bron is."""
        if self.migrated:
            return True
        if self.db is None:
            self.migrated = True
            return True
        try:
            outcome = migrate_legacy(self.store, self.db, self._vault_get)
        except Exception as exc:
            log.warning("koppeling uit de database overzetten nog niet gelukt (%s); later opnieuw", type(exc).__name__)
            return False
        if outcome not in ("bestond", "nieuw"):
            log.info("koppeling uit een oudere versie: %s", outcome)
        self.migrated = True
        return True

    def _vault_get(self, session: Session, ref: str) -> str | None:
        return self.vault.get(session, ref) if self.vault is not None else None


def _retry_after(resp: httpx.Response) -> float:
    try:
        return max(1.0, float(resp.headers.get("retry-after", "60")))
    except ValueError:
        return 60.0


def _is_int(value: Any) -> bool:
    """Geheel getal, geen ``bool`` (``True == 1`` mag geen volgnummer 1 zijn)."""
    return isinstance(value, int) and not isinstance(value, bool)


def verify_rotation(item: dict[str, Any], pins: Pins, expected_sequence: int) -> Pins:
    """Controleer één rotatie-statement (§4.5) tegen de **gepinde** sleutels en geef de nieuwe pins."""
    if not _is_int(item.get("sequence")) or item.get("sequence") != expected_sequence:
        raise InvalidResponseError(
            "sleutelrotatie_ongeldig", f"volgnummer {item.get('sequence')!r} ≠ {expected_sequence}"
        )
    statement = item.get("statement")
    if not isinstance(statement, str) or statement.count(".") != 2:
        raise InvalidResponseError("sleutelrotatie_ongeldig", "statement is geen JWS")
    try:
        header = jwt.get_unverified_header(statement)
    except jwt.PyJWTError as exc:
        raise InvalidResponseError("sleutelrotatie_ongeldig", "JWS-header onleesbaar") from exc
    if header.get("alg") != "EdDSA" or header.get("typ") != ROTATION_TYP or not isinstance(header.get("kid"), str):
        raise InvalidResponseError(
            "sleutelrotatie_ongeldig", "header moet alg EdDSA, typ hub-key-rotation+jws en kid hebben"
        )
    signer: tuple[str, Pin] | None = None
    for purpose, group in (("jwt", pins.jwt), ("policy", pins.policy)):
        for pin in group:
            if pin.kid == header["kid"]:
                signer = (purpose, pin)
    if signer is None:
        raise InvalidResponseError("sleutelrotatie_ongeldig", "ondertekend met een sleutel die niet gepind is")
    purpose, pin = signer
    try:
        key = public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": pin.jwk.x})
        decoded = jwt.api_jws.decode_complete(statement, key, algorithms=["EdDSA"])
        payload = json.loads(decoded["payload"])
    except (jwt.PyJWTError, ValueError, InvalidKeyError) as exc:
        raise InvalidResponseError("sleutelrotatie_ongeldig", "handtekening of inhoud klopt niet") from exc
    if not isinstance(payload, dict) or payload.get("type") != "hub_key_rotation" or payload.get("iss") != "hub":
        raise InvalidResponseError("sleutelrotatie_ongeldig", "type of iss klopt niet")
    if payload.get("sequence") != expected_sequence or not _is_int(payload.get("sequence")):
        raise InvalidResponseError("sleutelrotatie_ongeldig", "volgnummer in de inhoud klopt niet")
    if not isinstance(payload.get("issued_at"), str):
        raise InvalidResponseError("sleutelrotatie_ongeldig", "issued_at ontbreekt")
    if payload.get("purpose") != purpose:
        raise InvalidResponseError(
            "sleutelrotatie_ongeldig", "één statement wijzigt alleen het doel van zijn eigen sleutel"
        )
    add, retire = payload.get("add"), payload.get("retire")
    if not isinstance(add, list) or not isinstance(retire, list) or not all(isinstance(k, str) for k in retire):
        raise InvalidResponseError("sleutelrotatie_ongeldig", "add/retire hebben het verkeerde type")
    try:
        added = [validate_hub_jwk(k) for k in add]
    except InvalidKeyError as exc:
        raise InvalidResponseError("sleutelrotatie_ongeldig", f"nieuwe sleutel ongeldig: {exc}") from exc
    current = list(pins.jwt if purpose == "jwt" else pins.policy)
    known = {p.kid for p in current}
    if any(kid not in known for kid in retire):
        raise InvalidResponseError("sleutelrotatie_ongeldig", "intrekken van een onbekende sleutel")
    now = now_iso()
    kept = [p for p in current if p.kid not in set(retire)]
    for jwk_ in added:
        existing = next((p for p in kept if p.kid == jwk_["kid"]), None)
        if existing is not None and existing.jwk.x != jwk_["x"]:
            raise InvalidResponseError("sleutelrotatie_ongeldig", "bestaande kid met een andere sleutel")
        if existing is None:
            kept.append(
                Pin(
                    kid=jwk_["kid"],
                    jwk=PublicJwk(x=jwk_["x"]),
                    thumbprint=jwk_thumbprint(jwk_),
                    pinned_at=now,
                    source="rotation",
                )
            )
    if not kept:
        raise InvalidResponseError(
            "sleutelrotatie_ongeldig", "de laatste sleutel van een doel mag niet worden ingetrokken"
        )
    jwt_pins = kept if purpose == "jwt" else list(pins.jwt)
    policy_pins = kept if purpose == "policy" else list(pins.policy)
    new = Pins(jwt=jwt_pins, policy=policy_pins, keyset_fingerprint="", rotation_sequence=expected_sequence)
    jwks, policy = pin_jwks(new)
    new.keyset_fingerprint = keyset_fingerprint(jwks, policy)
    return new


# ---------------------------------------------------------------------------------------------- overzetten (1.1 → 1.2)
def _legacy_state(rows: dict[str, dict[str, Any]], token: str | None, ever_linked_audit: bool) -> LinkState:
    """Koppeling uit ``service_state`` + vault (versie vóór contract 1.2, ADR-0002) als bestandsstatus (§3.5)."""
    now = now_iso()
    old = rows.get("hub_link") or {}
    status = old.get("status")
    st = LinkState(hub_url=old.get("hub_url") or old.get("previous_hub_url"), service_id=old.get("service_id"))
    via = old.get("via")
    st.via = via if via in ("token", "koppelcode") else None
    for key in ("used_token_sha256", "rejected_token_sha256"):
        digest = old.get(key)
        if isinstance(digest, str) and len(digest) == 64:
            st.remember_token(digest)
    linked_at = old.get("enrolled_at") if isinstance(old.get("enrolled_at"), str) else None
    if status == "gekoppeld":
        st.first_linked_at = st.linked_at = linked_at or now
        try:
            jwks_doc = (rows.get("hub_jwks") or {}).get("jwks") or {}
            jwks = [validate_hub_jwk(k) for k in jwks_doc.get("keys", [])]
            policy = validate_hub_jwk((rows.get("hub_policy_key") or {}).get("jwk"))
            if not jwks or token is None or not SERVICE_TOKEN_RE.match(token):
                raise ValueError("onvolledig")
            pins = _pins_from(jwks, [policy], "overgezet", now)
        except Exception as exc:  # ontbrekende policy-sleutel, ongeldige JWK, token in een oud formaat, ...
            log.warning(
                "oude koppeling niet volledig over te zetten (%s); opnieuw koppelen via de Hub", type(exc).__name__
            )
            st.state = "ontkoppeld"
            st.last_error = LastError(code="overzetten_onvolledig", at=now)
            return st
        st.state = "gekoppeld"
        st.service_token, st.service_token_last4 = token, token[-4:]
        st.pins = pins
        return st  # confirmed_at leeg: de worker bevestigt met services/self (401 → ingetrokken)
    if old.get("reason") == "ontkoppeld" or old.get("unpaired_at") or ever_linked_audit:
        st.state = "ontkoppeld"
        unpaired = old.get("unpaired_at")
        st.first_linked_at = unpaired if isinstance(unpaired, str) else now
        return st
    st.hub_url = None  # het adres van een mislukte poging wordt nergens bewaard (§3.6)
    st.service_id = None
    return st


def migrate_legacy(store: HubLinkStore, db: Database, vault_get: Callable[[Session, str], str | None]) -> str:
    """Eenmalige overzetting (§3.5) en daarna de oude rijen verwijderen. Idempotent; geeft wat er gebeurde.

    Alleen als ``hub-link.json`` nog **niet** bestaat wordt de oude koppeling overgezet (of een lege status geschreven);
    bestaat het bestand al, dan wint het bestand en worden (bv. door een database-herstel teruggekomen) oude rijen alleen
    verwijderd. Zo brengt een database-herstel nooit een oude koppeling, oude pins of een ingetrokken token terug.
    Veilig als API en worker het tegelijk doen (schrijven onder de bestandsvergrendeling, verwijderen met ``DELETE``).
    """
    from .models import AuditEvent, ServiceState, VaultSecret

    with db.sessions() as s:
        rows = {
            r.key: dict(r.value) for r in s.scalars(select(ServiceState).where(ServiceState.key.in_(LEGACY_STATE_KEYS)))
        }
        vault_row = s.get(VaultSecret, LEGACY_TOKEN_REF)
        had_old = bool(rows) or vault_row is not None
        written = False
        if not store.exists():
            token: str | None = None
            if vault_row is not None:
                try:
                    token = vault_get(s, LEGACY_TOKEN_REF)
                except Exception:  # onleesbaar (andere vault-sleutel): niet overzetten
                    token = None
            audit_linked = (
                s.scalar(select(AuditEvent.id).where(AuditEvent.action.in_(("hub.pair", "hub.unpair"))).limit(1))
                is not None
            )
            state = _legacy_state(rows, token, audit_linked) if had_old or audit_linked else LinkState()
            written = store.write_initial(state)
        if had_old:
            s.execute(delete(ServiceState).where(ServiceState.key.in_(LEGACY_STATE_KEYS)))
            s.execute(delete(VaultSecret).where(VaultSecret.ref == LEGACY_TOKEN_REF))
            s.commit()
    if had_old and written:
        return f"overgezet (state {store.read().state})"
    if had_old:
        return "oude rijen verwijderd (hub-link.json bestond al)"
    return "nieuw" if written else "bestond"
