"""Sleutels, thumbprints, vingerafdrukken en tokenformaten voor het koppelen met de Hub (contract 1.2 §3.3, §3.4, §4.5).

- **Thumbprint** = RFC 7638: ``base64url(SHA-256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}'))``.
- **Sleutelset-vingerafdruk** (voor mensen): SHA-256 over de UTF-8-tekst
  ``"jl-hub-keyset-v1\\njwt:" + <thumbprints van jwks.keys, gesorteerd op bytewaarde, met komma's> + "\\npolicy:" +
  <thumbprint van de policy-sleutel>``; daarvan de eerste 80 bit als Crockford-base32, ``XXXX-XXXX-XXXX-XXXX``.
- Invoer (vingerafdruk én koppelcode) wordt vergeleken na normalisatie: hoofdletterongevoelig, ``O→0``, ``I/L→1``,
  streepjes/spaties en andere tekens genegeerd.

De testvectoren uit het contract staan in ``tests/unit/test_hubkeys.py``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
KEYSET_PREFIX = "jl-hub-keyset-v1"
ENROLLMENT_TOKEN_RE = re.compile(r"^enr_[A-Za-z0-9_-]{43}$")
SERVICE_TOKEN_RE = re.compile(r"^svc_[A-Za-z0-9_-]{43}$")
_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "k"})


class InvalidKeyError(ValueError):
    """Ongeldige of niet-publieke sleutel."""


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def raw_public(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _x_bytes(x: object) -> bytes:
    if not isinstance(x, str):
        raise InvalidKeyError("x ontbreekt of is geen tekst")
    try:
        raw = base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
    except (binascii.Error, ValueError) as exc:
        raise InvalidKeyError("x is geen base64url") from exc
    if len(raw) != 32 or b64url(raw) != x:
        raise InvalidKeyError("x moet precies 32 bytes in canonieke base64url zijn")
    return raw


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638-thumbprint van een **publieke** Ed25519-JWK."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise InvalidKeyError("alleen Ed25519 (kty OKP, crv Ed25519)")
    if _PRIVATE_MEMBERS & set(jwk):
        raise InvalidKeyError("JWK bevat privé-sleuteldelen")
    x = jwk.get("x")
    _x_bytes(x)
    canonical = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def public_key_from_jwk(jwk: Mapping[str, Any]) -> Ed25519PublicKey:
    jwk_thumbprint(jwk)  # valideert vorm en canonieke x
    return Ed25519PublicKey.from_public_bytes(_x_bytes(jwk["x"]))


def enroll_jwk(key: Ed25519PublicKey) -> dict[str, str]:
    """Publieke sleutel van deze dienst voor ``POST /api/v1/services/enroll`` (§3.3): precies ``kty, crv, x, kid`` met
    ``kid`` = RFC 7638-thumbprint; **geen** ``use``/``alg`` (de Hub weigert die in 1.2 met 422)."""
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw_public(key))}
    return {**jwk, "kid": jwk_thumbprint(jwk)}


def validate_hub_jwk(jwk: object) -> dict[str, str]:
    """Een JWK uit het enroll-antwoord of een rotatie-statement (§3.3): geldig Ed25519 zonder ``d``, met ``use: sig``,
    ``alg: EdDSA`` en een ``kid``. Geeft de genormaliseerde publieke JWK ``{kty, crv, x, kid}``."""
    if not isinstance(jwk, dict):
        raise InvalidKeyError("JWK is geen object")
    jwk_thumbprint(jwk)
    if jwk.get("use") != "sig" or jwk.get("alg") != "EdDSA":
        raise InvalidKeyError("JWK moet use 'sig' en alg 'EdDSA' hebben")
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not 1 <= len(kid) <= 128:
        raise InvalidKeyError("kid ontbreekt of is ongeldig")
    return {"kty": "OKP", "crv": "Ed25519", "x": str(jwk["x"]), "kid": kid}


def _crockford(data: bytes) -> str:
    bits = "".join(f"{byte:08b}" for byte in data)
    bits += "0" * (-len(bits) % 5)
    return "".join(CROCKFORD[int(bits[i : i + 5], 2)] for i in range(0, len(bits), 5))


def keyset_fingerprint(jwt_keys: Iterable[Mapping[str, Any]], policy_keys: Iterable[Mapping[str, Any]]) -> str:
    """Sleutelset-vingerafdruk ``XXXX-XXXX-XXXX-XXXX`` (§4.5).

    Contract 1.2 kent precies één policy-sleutel. Tijdens een (toekomstige) policy-rotatie kunnen er tijdelijk twee
    gepind zijn; dan worden hun thumbprints net als bij ``jwt`` gesorteerd en met komma's verbonden (ADR-0010, zoals
    appstore-en-fork). Met één policy-sleutel is de uitkomst precies die van het contract.
    """
    jwt_tp = sorted(jwk_thumbprint(k) for k in jwt_keys)
    policy_tp = sorted(jwk_thumbprint(k) for k in policy_keys)
    if not jwt_tp or not policy_tp:
        raise InvalidKeyError("minstens één JWT-sleutel en één policy-sleutel nodig")
    text = f"{KEYSET_PREFIX}\njwt:{','.join(jwt_tp)}\npolicy:{','.join(policy_tp)}"
    code = _crockford(hashlib.sha256(text.encode("utf-8")).digest()[:10])
    return "-".join(code[i : i + 4] for i in range(0, 16, 4))


def normalize_code(value: str) -> str:
    """Hoofdletters, alleen ASCII-letters/cijfers, ``O→0``, ``I/L→1`` (vingerafdruk én koppelcode)."""
    cleaned = "".join(ch for ch in value.upper() if ch.isascii() and ch.isalnum())
    return cleaned.replace("O", "0").replace("I", "1").replace("L", "1")


def normalize_fingerprint(value: str | None) -> str | None:
    """16 Crockford-tekens, of ``None`` als de invoer geen geldige vingerafdruk kan zijn."""
    if not value or len(value) > 64:
        return None
    code = normalize_code(value)
    return code if len(code) == 16 and all(ch in CROCKFORD for ch in code) else None


def format_fingerprint(value: str | None) -> str | None:
    """Genormaliseerde vingerafdruk in groepen ``XXXX-XXXX-XXXX-XXXX`` (of ``None``)."""
    code = normalize_fingerprint(value)
    return None if code is None else "-".join(code[i : i + 4] for i in range(0, 16, 4))


def fingerprints_equal(expected: str | None, actual: str | None) -> bool:
    exp = normalize_fingerprint(expected)
    return exp is not None and exp == normalize_fingerprint(actual)


def normalize_pairing_code(value: str | None) -> str | None:
    """Koppelcode (§3.3): invoer ≤ 32 tekens die na normalisatie precies 12 Crockford-tekens oplevert; anders ``None``.
    Geeft de code in groepen ``XXXX-XXXX-XXXX`` (de Hub normaliseert zelf ook en vergelijkt de SHA-256)."""
    if not value or len(value) > 32:
        return None
    code = normalize_code(value)
    if len(code) != 12 or any(ch not in CROCKFORD for ch in code):
        return None
    return f"{code[0:4]}-{code[4:8]}-{code[8:12]}"


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
