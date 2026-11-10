"""Inkomende authenticatie en rollen (contract 1.2 §4): alleen Hub-JWT's, gecontroleerd tegen de **gepinde** sleutels.

- Gebruikers: JWT met ``token_use: "user"`` (§4.2), rollen ⊂ {admin, operator, viewer, kind}; rol ``kind`` wint altijd.
- De Hub als dienst: dienst-JWT met ``token_use: "hub_service"``, ``sub: "hub"``, ``roles: ["service"]`` en de eigen
  ``service_id`` (§4.3) → principal ``service:hub`` met rol ``service`` (nooit ``admin``; rechten in ADR-0010).
- Een inkomend ``Bearer svc_…`` (een service-token) wordt **niet** geaccepteerd (``service_token_not_accepted``).
- Vertrouwensset = ``pins.jwt`` uit ``hub-link.json`` (§4.5); een via HTTP opgehaalde JWKS voegt nooit iets toe.
  Onbekende ``kid`` → direct 401 ``unknown_key`` en op de achtergrond een extra poll van de ondertekende
  sleutelrotaties (hooguit 1× per 30 s).
- ``jti`` verplicht op elke JWT; een mutatie (POST/PUT/PATCH/DELETE) met een al gebruikte ``jti`` → 401
  ``token_replayed``, behalve een exacte herhaling (zelfde ``jti``, methode, pad en ``Idempotency-Key``), die de
  idempotency-laag met het opgeslagen resultaat beantwoordt. Replaycontrole niet mogelijk → 503
  ``replay_check_unavailable`` (fail-closed, §4.6).
- Vaste ``reason``-waarden (Engels) en controlevolgorde: ``state`` → tokensoort → handtekening/``kid`` → claims →
  ``token_use`` → ``jti`` → schemavalidatie van de body (§4.7). Rol (403) en ``Idempotency-Key`` komen pas ná de
  authenticatie (RV9). :class:`AuthFirstRoute` dwingt dat af: FastAPI leest een JSON-body vóór de afhankelijkheden en
  zou een onleesbare body zonder geldige aanmelding met 422 beantwoorden; nu is dat altijd 401. Nooit "open access"
  (EX16).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import jwt
from fastapi import Depends, Request
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from ..errors import ApiError, forbidden
from .hubkeys import InvalidKeyError, public_key_from_jwk

if TYPE_CHECKING:
    from ..hublink_store import HubLinkStore
    from .replay import ReplayGuard

KNOWN_ROLES = frozenset({"admin", "operator", "viewer", "kind"})
SERVICE_ROLE = "service"
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: Vaste ``reason``-waarden van §4.7 (Engels, voor machines); de ``message`` is Nederlands.
REASON_MESSAGES: dict[str, str] = {
    "not_linked": "Niet geautoriseerd: deze dienst is (nog) niet met de Hub gekoppeld.",
    "revoked": "Niet geautoriseerd: de Hub heeft de koppeling ingetrokken; opnieuw koppelen gaat via de Hub.",
    "service_token_not_accepted": "Niet geautoriseerd: een service-token wordt hier niet geaccepteerd; de Hub meldt "
    "zich met een dienst-JWT.",
    "unknown_key": "Niet geautoriseerd: het token is ondertekend met een sleutel die deze dienst niet vertrouwt.",
    "token_expired": "Niet geautoriseerd: het token is verlopen.",
    "invalid_token": "Niet geautoriseerd: geen of een ongeldig token.",
    "token_use_invalid": "Niet geautoriseerd: het token is niet bedoeld voor dit gebruik.",
    "jti_missing": "Niet geautoriseerd: het token heeft geen 'jti'.",
    "token_replayed": "Niet geautoriseerd: dit token is al voor een andere wijziging gebruikt; vraag een nieuw token "
    "aan de Hub.",
}
REASONS = tuple(REASON_MESSAGES)


def auth_error(reason: str) -> ApiError:
    if reason not in REASON_MESSAGES:  # pragma: no cover - programmeerfout
        raise ValueError(reason)
    return ApiError(401, "unauthorized", REASON_MESSAGES[reason], {"reason": reason}, {"WWW-Authenticate": "Bearer"})


@dataclass(frozen=True)
class Principal:
    kind: str  # "user" | "service"
    subject: str
    roles: frozenset[str] = field(default_factory=frozenset)
    token_id: str | None = None
    expires_at: float | None = None

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


def _same_uuid(a: Any, b: str | None) -> bool:
    if not isinstance(a, str) or not b:
        return False
    try:
        return uuid.UUID(a) == uuid.UUID(b)
    except ValueError:
        return False


def principal_from_claims(claims: dict[str, Any], own_service_id: str | None) -> Principal:
    """De ``token_use``-controles van §4.3 (stap 5 van §4.7)."""
    use = claims.get("token_use")
    roles = claims.get("roles")
    if not isinstance(roles, list) or not all(isinstance(r, str) for r in roles):
        raise auth_error("token_use_invalid")
    exp = float(claims["exp"])
    jti = claims.get("jti") if isinstance(claims.get("jti"), str) else None
    if use == "user":
        if SERVICE_ROLE in roles:
            raise auth_error("token_use_invalid")
        known = frozenset(r for r in roles if r in KNOWN_ROLES)
        if "kind" in known:  # §4.2: rol 'kind' wint altijd van andere rollen in dezelfde JWT
            known = frozenset({"kind"})
        return Principal("user", str(claims["sub"])[:200], known, jti, exp)
    if use == "hub_service":
        if (
            claims.get("sub") != "hub"
            or roles != [SERVICE_ROLE]
            or not _same_uuid(claims.get("service_id"), own_service_id)
        ):
            raise auth_error("token_use_invalid")
        return Principal("service", "hub", frozenset({SERVICE_ROLE}), jti, exp)
    raise auth_error("token_use_invalid")


class Authenticator:
    """Wordt in ``app.state.auth`` gezet. Leest bij elk verzoek de actuele koppelstatus (``hub-link.json``)."""

    def __init__(
        self,
        store: HubLinkStore,
        policy: JwtPolicy,
        replay: ReplayGuard | None = None,
        on_unknown_kid: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.policy = policy
        self.replay = replay
        self.on_unknown_kid = on_unknown_kid

    def authenticate(
        self,
        authorization: str | None,
        *,
        method: str = "GET",
        path: str = "/",
        idempotency_key: str | None = None,
    ) -> Principal:
        # 1. state
        link = self.store.read()
        if link.state == "ingetrokken":
            raise auth_error("revoked")
        if not link.linked or link.pins is None:
            raise auth_error("not_linked")
        # 2. tokensoort
        scheme, _, token = (authorization or "").partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            raise auth_error("invalid_token")
        if token.startswith("svc_"):
            raise auth_error("service_token_not_accepted")
        if len(token) > 8192 or token.count(".") != 2:
            raise auth_error("invalid_token")
        # 3. handtekening en kid: alleen gepinde sleutels, vergeleken op de sleutel zelf (x)
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise auth_error("invalid_token") from exc
        if header.get("alg") != "EdDSA":
            raise auth_error("invalid_token")
        kid = header.get("kid")
        pin = next((p for p in link.pins.jwt if isinstance(kid, str) and p.kid == kid), None)
        if pin is None:
            if self.on_unknown_kid is not None:
                self.on_unknown_kid()  # achtergrond-poll; dit verzoek wacht er niet op
            raise auth_error("unknown_key")
        try:
            key = public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": pin.jwk.x})
        except InvalidKeyError as exc:  # pragma: no cover - pins zijn bij het opslaan al gecontroleerd
            raise auth_error("unknown_key") from exc
        # 4. claims
        p = self.policy
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                audience=p.audience,
                issuer=p.issuer,
                leeway=p.leeway_s,
                # strict_aud: ``aud`` moet precies de string ``<app_id>`` zijn (§4.2/§4.3); een lijst met meerdere
                # diensten zou dezelfde JWT ook bij een andere dienst bruikbaar maken (review contract 1.2, ADR-0013)
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub"], "strict_aud": True},
            )
        except jwt.ExpiredSignatureError as exc:
            raise auth_error("token_expired") from exc
        except jwt.PyJWTError as exc:
            raise auth_error("invalid_token") from exc
        exp, iat = claims.get("exp"), claims.get("iat")
        if not isinstance(exp, int | float) or not isinstance(iat, int | float) or isinstance(exp, bool):
            raise auth_error("invalid_token")
        if float(exp) - float(iat) > p.max_lifetime_s:
            raise auth_error("invalid_token")
        if claims.get("aud") != p.audience or claims.get("iss") != p.issuer:  # ook zonder strict_aud: alleen een string
            raise auth_error("invalid_token")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise auth_error("invalid_token")
        # 5. token_use
        principal = principal_from_claims(claims, link.service_id)
        # 6. jti (+ replaycache voor mutaties)
        jti = claims.get("jti")
        if not isinstance(jti, str) or not 1 <= len(jti) <= 128:
            raise auth_error("jti_missing")
        if method.upper() in MUTATING_METHODS:
            if self.replay is None:  # pragma: no cover - de app zet altijd een replaycache
                raise ApiError(503, "replay_check_unavailable", "De controle op hergebruik van tokens ontbreekt.")
            self.replay.check(
                iss=p.issuer,
                jti=jti,
                exp=float(exp),
                subject=principal.audit_id,
                method=method.upper(),
                path=path,
                idempotency_key=idempotency_key,
            )
        return principal


def current_principal(request: Request) -> Principal:
    """De aangemelde principal van dit verzoek. Al aangemeld in dit verzoek (``AuthFirstRoute``) → dezelfde
    principal: de ``jti`` van een mutatie wordt nooit twee keer verbruikt."""
    existing = getattr(request.state, "principal", None)
    if isinstance(existing, Principal):
        return existing
    auth: Authenticator = request.app.state.auth
    principal = auth.authenticate(
        request.headers.get("Authorization"),
        method=request.method,
        path=request.url.path,
        idempotency_key=request.headers.get("Idempotency-Key"),
    )
    request.state.principal = principal
    return principal


def _uses_principal(dependant: Dependant) -> bool:
    return any(d.call is current_principal or _uses_principal(d) for d in dependant.dependencies)


class AuthFirstRoute(APIRoute):
    """Route die eerst authenticeert (§4.7, RV9): vóór het lezen van de body, vóór rol en ``Idempotency-Key``.

    Alleen voor routes met ``current_principal`` in hun afhankelijkheden; andere routes (``/healthz``, de statuspagina)
    blijven ongewijzigd. Een geweigerde aanmelding wordt door de gewone foutafhandeling een 401 met ``reason``."""

    def get_route_handler(self) -> Callable[[Request], Any]:
        handler = super().get_route_handler()
        if not _uses_principal(self.dependant):
            return handler

        async def authenticate_first(request: Request) -> Response:
            if request.method in MUTATING_METHODS:
                # eerst de 1 MiB-laag (§4.7: de eerste stap van de controlevolgorde): de body wordt hier alleen begrensd
                # ingelezen (BodyLimitMiddleware, ook chunked) en nog niet geparsed
                await request.body()
            await run_in_threadpool(current_principal, request)
            response: Response = await handler(request)
            return response

        return authenticate_first


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
require_admin_operator_or_service = require_roles("admin", "operator", SERVICE_ROLE)
