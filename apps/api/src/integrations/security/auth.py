"""Authenticatie en rollen (contract §4).

Twee soorten ``Authorization: Bearer``:

1. **Hub-JWT** (gebruikerscontext): EdDSA, ``iss=hub``, ``aud=home-control-hub``, ``sub``, ``roles``,
   ``exp - iat <= 120 s``; sleutel uit de Hub-JWKS (gecachet, fail-closed).
2. **Service-token** (dienst-naar-dienst): het token dat deze dienst bij de enrollment van de Hub kreeg. Alleen de
   Hub (uitgever) kent het; wij bewaren het versleuteld in de vault plus een SHA-256 voor vergelijking in constante tijd.
   Zie ADR-0002 voor deze interpretatie.

Zonder geldige auth → 401 ``unauthorized``; zonder koppeling of bruikbare JWKS ook 401 (fail-closed).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import jwt
from fastapi import Depends, Request

from ..errors import forbidden, unauthorized
from .jwks import JwksCache, JwksUnavailable, UnknownKey

KNOWN_ROLES = frozenset({"admin", "operator", "viewer", "kind"})
SERVICE_ROLE = "service"


@dataclass(frozen=True)
class Principal:
    kind: str  # "user" | "service"
    subject: str
    roles: frozenset[str] = field(default_factory=frozenset)
    token_id: str | None = None

    @property
    def audit_id(self) -> str:
        return f"{self.kind}:{self.subject}"

    @property
    def actor_type(self) -> str:
        return "user" if self.kind == "user" else "system"

    def has_any(self, roles: set[str] | frozenset[str]) -> bool:
        return bool(self.roles & roles)


@dataclass
class JwtPolicy:
    issuer: str = "hub"
    audience: str = "home-control-hub"
    max_lifetime_s: int = 120
    leeway_s: int = 30


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def validate_jwt(token: str, cache: JwksCache, policy: JwtPolicy) -> Principal:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise unauthorized("token_onleesbaar") from exc
    if header.get("alg") != "EdDSA":
        raise unauthorized("algoritme_niet_toegestaan")
    kid = header.get("kid")
    try:
        key = cache.get_key(kid if isinstance(kid, str) else None)
    except JwksUnavailable as exc:
        raise unauthorized(
            "jwks_niet_beschikbaar", "Niet geautoriseerd: sleutels van de Hub zijn niet beschikbaar."
        ) from exc
    except UnknownKey as exc:
        raise unauthorized("onbekende_sleutel") from exc
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key=key,
            algorithms=["EdDSA"],
            audience=policy.audience,
            issuer=policy.issuer,
            leeway=policy.leeway_s,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise unauthorized("token_verlopen") from exc
    except jwt.InvalidAudienceError as exc:
        raise unauthorized("verkeerde_audience") from exc
    except jwt.InvalidIssuerError as exc:
        raise unauthorized("verkeerde_issuer") from exc
    except jwt.PyJWTError as exc:
        raise unauthorized("token_ongeldig") from exc
    exp, iat = claims.get("exp"), claims.get("iat")
    if not isinstance(exp, int | float) or not isinstance(iat, int | float) or exp - iat > policy.max_lifetime_s:
        raise unauthorized("levensduur_te_lang")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise unauthorized("geen_subject")
    raw_roles = claims.get("roles", [])
    roles = (
        frozenset(r for r in raw_roles if isinstance(r, str) and r in KNOWN_ROLES)
        if isinstance(raw_roles, list)
        else frozenset()
    )
    jti = claims.get("jti")
    return Principal(kind="user", subject=sub, roles=roles, token_id=jti if isinstance(jti, str) else None)


class Authenticator:
    """Wordt in ``app.state.auth`` gezet; de service-token-hash komt uit de enrollment-status."""

    def __init__(self, cache: JwksCache, policy: JwtPolicy, service_token_hash: Callable[[], str | None]) -> None:
        self.cache = cache
        self.policy = policy
        self._service_token_hash = service_token_hash

    def authenticate(self, authorization: str | None) -> Principal:
        if not authorization:
            raise unauthorized("geen_token")
        scheme, _, token = authorization.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise unauthorized("geen_bearer_token")
        # altijd eerst de koppelstatus verversen: die bepaalt ook welke Hub-JWKS geldig is
        expected = self._service_token_hash()
        if token.count(".") == 2:
            return validate_jwt(token, self.cache, self.policy)
        if not expected:
            raise unauthorized("niet_gekoppeld", "Niet geautoriseerd: deze dienst is nog niet aan de Hub gekoppeld.")
        if not hmac.compare_digest(sha256_hex(token), expected):
            raise unauthorized("service_token_ongeldig")
        return Principal(kind="service", subject="hub", roles=frozenset({SERVICE_ROLE}))


def current_principal(request: Request) -> Principal:
    auth: Authenticator = request.app.state.auth
    principal = auth.authenticate(request.headers.get("Authorization"))
    request.state.principal = principal
    return principal


def require_roles(*roles: str) -> Callable[..., Principal]:
    allowed = frozenset(roles)

    def _dep(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has_any(allowed):
            raise forbidden("rol_ontbreekt", f"Hiervoor is een van deze rollen nodig: {', '.join(sorted(allowed))}.")
        return principal

    return _dep


# Veelgebruikte combinaties (least privilege; B13-004)
require_admin = require_roles("admin")
require_admin_or_operator = require_roles("admin", "operator")
require_reader = require_roles("admin", "operator", "viewer")
require_connector_reader = require_roles("admin", "operator", "viewer", SERVICE_ROLE)
require_admin_or_service = require_roles("admin", SERVICE_ROLE)
