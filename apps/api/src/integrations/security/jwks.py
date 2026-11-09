"""Hub-JWKS met caching en fail-closed gedrag (contract §4).

- Alleen Ed25519-sleutels (``kty=OKP``, ``crv=Ed25519``); andere sleutels worden genegeerd.
- Verse cache (< ``ttl_s``) → direct gebruiken. Onbekende ``kid`` → één keer verversen (hooguit elke
  ``min_refresh_interval_s``), dan weigeren.
- Mislukt verversen, dan wordt de oude set nog hooguit ``max_stale_s`` gebruikt; daarna **fail-closed**:
  elke JWT wordt geweigerd tot de Hub weer bereikbaar is. Nooit "open access".
"""

from __future__ import annotations

import base64
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class JwksUnavailable(Exception):
    """Er is geen bruikbare (verse of nog toegestane oude) sleutelset."""


class UnknownKey(Exception):
    """De ``kid`` staat niet in de sleutelset (ook niet na verversen)."""


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def parse_jwks(doc: Any) -> dict[str, Ed25519PublicKey]:
    """Zet een JWKS-document om naar ``{kid: sleutel}``. Ongeldige of niet-Ed25519-sleutels worden overgeslagen."""
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise ValueError("JWKS-document heeft geen 'keys'-lijst")
    keys: dict[str, Ed25519PublicKey] = {}
    for idx, jwk in enumerate(doc["keys"]):
        if not isinstance(jwk, dict):
            continue
        if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
            continue
        if jwk.get("use") not in (None, "sig") or jwk.get("alg") not in (None, "EdDSA"):
            continue
        x = jwk.get("x")
        if not isinstance(x, str):
            continue
        try:
            raw = _b64url_decode(x)
            if len(raw) != 32:
                continue
            key = Ed25519PublicKey.from_public_bytes(raw)
        except ValueError:
            continue
        kid = jwk.get("kid")
        keys[str(kid) if isinstance(kid, str) and kid else f"#{idx}"] = key
    return keys


@dataclass
class JwksStatus:
    available: bool
    age_s: float | None
    keys: int
    last_error: str | None
    stale: bool


class JwksCache:
    def __init__(
        self,
        fetch: Callable[[], Any] | None,
        ttl_s: float = 300,
        max_stale_s: float = 900,
        min_refresh_interval_s: float = 30,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self.ttl_s = ttl_s
        self.max_stale_s = max_stale_s
        self.min_refresh_interval_s = min_refresh_interval_s
        self._clock = clock
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._last_error: str | None = None
        self._lock = threading.Lock()

    def set_fetcher(self, fetch: Callable[[], Any] | None) -> None:
        with self._lock:
            self._fetch = fetch

    def seed(self, doc: Any) -> None:
        """Vult de cache met een JWKS uit de enrollment-respons (telt als vers opgehaald)."""
        keys = parse_jwks(doc)
        with self._lock:
            self._keys = keys
            self._fetched_at = self._clock()
            self._last_error = None

    def clear(self) -> None:
        with self._lock:
            self._keys = {}
            self._fetched_at = None
            self._last_attempt = None
            self._last_error = None

    def _age(self) -> float | None:
        return None if self._fetched_at is None else self._clock() - self._fetched_at

    def _refresh_locked(self) -> None:
        now = self._clock()
        if self._fetch is None:
            self._last_error = "geen_hub_gekoppeld"
            return
        # begrens het aantal ophaalpogingen (ook bij een vloed aan tokens met onbekende kid)
        if self._last_attempt is not None and now - self._last_attempt < self.min_refresh_interval_s:
            return
        self._last_attempt = now
        try:
            keys = parse_jwks(self._fetch())
        except Exception as exc:  # netwerk-, HTTP- of formaatfout: nooit doorlaten
            self._last_error = type(exc).__name__
            return
        if not keys:
            self._last_error = "lege_sleutelset"
            return
        self._keys = keys
        self._fetched_at = self._clock()
        self._last_error = None

    def get_key(self, kid: str | None) -> Ed25519PublicKey:
        with self._lock:
            age = self._age()
            if age is None or age > self.ttl_s:
                self._refresh_locked()
                age = self._age()
            if age is None or age > self.ttl_s + self.max_stale_s:
                raise JwksUnavailable(self._last_error or "geen_sleutelset")
            key = self._lookup(kid)
            if key is None:
                self._refresh_locked()
                key = self._lookup(kid)
            if key is None:
                raise UnknownKey(kid or "")
            return key

    def _lookup(self, kid: str | None) -> Ed25519PublicKey | None:
        if kid:
            return self._keys.get(kid)
        if len(self._keys) == 1:  # zonder kid alleen als er precies één sleutel is
            return next(iter(self._keys.values()))
        return None

    def status(self) -> JwksStatus:
        with self._lock:
            age = self._age()
            available = age is not None and age <= self.ttl_s + self.max_stale_s and bool(self._keys)
            return JwksStatus(
                available=available,
                age_s=None if age is None else round(age, 1),
                keys=len(self._keys),
                last_error=self._last_error,
                stale=age is not None and age > self.ttl_s,
            )
