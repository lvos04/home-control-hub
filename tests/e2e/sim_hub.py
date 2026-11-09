"""Simulator van de Hub volgens platformcontract 1.2 (§3.3–§3.8, §4.2–§4.5, §7). ALLEEN voor tests.

Eén implementatie (``HubSim``) voor twee vormen:
- de integratietests in ``apps/api/tests`` gebruiken hem in-proces via ``httpx.MockTransport``;
- de dienst-E2E start hem als echt HTTP-proces (``uvicorn sim_hub:app``) met testhulp onder ``/sim/*``.

Gedrag volgt de Hub (``ai-server-manager`` ``apps/api/src/hub/routers/services.py``) en het contract exact:
- ``POST /api/v1/services/enroll``: onbekende velden, beide of geen van ``enrollment_token``/``pairing_code``, een
  ``public_key_jwk`` met ``use``/``alg``/``d`` of een ``kid`` die niet de RFC 7638-thumbprint is → ``422
  validation_error``; onbekend/verlopen/al gebruikt/``app_id`` past niet → ``401 invalid_enrollment``; na 10 mislukte
  pogingen (401) binnen 15 min van één bron-IP → ``429 rate_limited`` + ``Retry-After``; toegestane herhaling (zelfde
  geheim, ``app_id`` en sleutel, binnen 60 min, uitgegeven token nooit gebruikt) → 200 met ``enrollment_replayed``.
- ``GET /api/v1/services/self`` en ``POST /api/v1/services/self/rotate`` (Bearer service-token), met
  ``Hub-Token-Rotation: required`` zolang een rotatie is aangevraagd of een ouder token wordt gebruikt terwijl het
  nieuwste nooit gebruikt is.
- ``GET /api/v1/auth/jwks`` en ``GET /api/v1/auth/key-rotations?after=n`` (ondertekende statements, §4.5).
- ``POST /api/v1/events/inbox`` (Bearer service-token) met dezelfde envelope-regels als de Hub (§7).
- Gebruikers-JWT's (``token_use: user``) en dienst-JWT's (``token_use: hub_service``) met ``jti``, ``nbf``, ≤ 120 s.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request, Response

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
APP_NAME = re.compile(r"^[a-z]([-a-z0-9]*[a-z0-9])?$")
ENR = re.compile(r"^enr_[A-Za-z0-9_-]{43}$")
VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+_-]*$")
BASE_URL = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]+(/[^\s?#]*)?$")
ENROLL_FIELDS = {"app_id", "enrollment_token", "pairing_code", "version", "base_url", "public_key_jwk"}
JWK_FIELDS = {"kty", "crv", "x", "kid"}
ENVELOPE_KEYS = {
    "schema_version",
    "event_id",
    "source_app",
    "source_event_id",
    "event_type",
    "entity",
    "timestamp_utc",
    "trace_id",
    "correlation_id",
    "actor",
    "classification",
    "payload",
    "payload_ref",
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def thumbprint(x: str) -> str:
    canon = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    return b64url(hashlib.sha256(canon.encode()).digest())


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def normalize_code(value: str) -> str:
    cleaned = "".join(ch for ch in value.upper() if ch.isascii() and ch.isalnum())
    return cleaned.replace("O", "0").replace("I", "1").replace("L", "1")


def keyset_fingerprint(jwt_x: list[str], policy_x: list[str]) -> str:
    jtp = ",".join(sorted(thumbprint(x) for x in jwt_x))
    ptp = ",".join(sorted(thumbprint(x) for x in policy_x))
    digest = hashlib.sha256(f"jl-hub-keyset-v1\njwt:{jtp}\npolicy:{ptp}".encode()).digest()[:10]
    bits = "".join(f"{b:08b}" for b in digest)
    code = "".join(CROCKFORD[int(bits[i : i + 5], 2)] for i in range(0, 80, 5))
    return "-".join(code[i : i + 4] for i in range(0, 16, 4))


def envelope_problems(ev: Any) -> list[str]:
    """Dezelfde envelope-regels als de inbox van de echte Hub (``apps/api/src/hub/events/envelope.py``, §7)."""
    if not isinstance(ev, dict):
        return ["geen object"]
    problems = []
    if set(ev) - ENVELOPE_KEYS:
        problems.append(f"onbekende velden: {sorted(set(ev) - ENVELOPE_KEYS)}")
    if ev.get("schema_version") != "1.0":
        problems.append("schema_version")
    et = ev.get("event_type")
    if not isinstance(et, str) or len(et) > 128 or not re.match(r"^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$", et):
        problems.append(f"event_type {et!r}")
    ent = ev.get("entity") or {}
    if not re.match(r"^[a-z0-9_.-]{1,64}$", str(ent.get("type", ""))) or not 1 <= len(str(ent.get("id", ""))) <= 200:
        problems.append("entity")
    actor = ev.get("actor") or {}
    if actor.get("type") not in ("system", "user", "ai", "flow") or not 1 <= len(str(actor.get("id", ""))) <= 128:
        problems.append("actor")
    if ev.get("classification") not in ("public", "internal", "sensitive"):
        problems.append("classification")
    if not str(ev.get("timestamp_utc", "")).endswith("Z"):
        problems.append("timestamp_utc")
    if len(json.dumps(ev.get("payload") or {}, default=str).encode()) > 16 * 1024:
        problems.append("payload te groot")
    return problems


@dataclass
class SimKey:
    private: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def x(self) -> str:
        raw = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return b64url(raw)

    @property
    def kid(self) -> str:
        return hashlib.sha256(self.x.encode()).hexdigest()[:16]  # zoals de Hub: geen eis in 1.2

    def jwk(self) -> dict[str, str]:
        return {"kty": "OKP", "crv": "Ed25519", "x": self.x, "kid": self.kid, "use": "sig", "alg": "EdDSA"}


@dataclass
class Grant:
    kind: str
    secret_hash: str
    app_id: str
    expires_at: float
    used_at: float | None = None
    used_with_thumbprint: str | None = None
    service_id: str | None = None


@dataclass
class Token:
    token_hash: str
    service_id: str
    grant_secret: str | None
    created_at: float
    first_used_at: float | None = None
    revoked: bool = False
    expires_at: float | None = None


@dataclass
class Reply:
    status: int
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)


def _err(status: int, code: str, message: str, headers: dict[str, str] | None = None, **details: Any) -> Reply:
    body = {"code": code, "message": message, "details": details, "trace_id": str(uuid.uuid4())}
    return Reply(status, body, headers or {})


class HubSim:
    """De Hub als simulator. Thread-veilig (de E2E-server en de testthread delen hem)."""

    audience = "home-control-hub"

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.jwt_keys: list[SimKey] = [SimKey()]
        self.policy_keys: list[SimKey] = [SimKey()]
        self.signing: SimKey = self.jwt_keys[0]
        self.grants: dict[tuple[str, str], Grant] = {}
        self.tokens: dict[str, Token] = {}
        self.services: dict[str, dict[str, Any]] = {}  # app_id → {service_id, status, version, enrolled_at, …}
        self.failures: dict[str, list[float]] = {}
        self.enroll_requests: list[dict[str, Any]] = []
        self.inbox: list[dict[str, Any]] = []
        self.rejected: list[dict[str, Any]] = []
        self.rotations: list[dict[str, Any]] = []
        self.calls: list[tuple[str, str]] = []
        self.up = True
        self.enroll_override: Any = None  # callable(body) -> Reply | None (storingen/vervalsingen in tests)
        self.inbox_status: int | None = None  # forceer een status op de inbox (bv. 503)
        self.window_s = 15 * 60
        self.max_failures = 10

    # ------------------------------------------------------------------ sleutels en JWT's
    def jwks(self) -> dict[str, Any]:
        return {"keys": [k.jwk() for k in self.jwt_keys]}

    def policy_jwk(self) -> dict[str, str]:
        return self.policy_keys[-1].jwk()

    def fingerprint(self) -> str:
        return keyset_fingerprint([k.x for k in self.jwt_keys], [self.policy_keys[-1].x])

    def _jwt(self, claims: dict[str, Any], key: SimKey | None = None, kid: str | None = None) -> str:
        k = key or self.signing
        return jwt.encode(claims, k.private, algorithm="EdDSA", headers={"kid": kid or k.kid, "typ": "JWT"})

    def user_jwt(
        self,
        roles: list[str] | tuple[str, ...] = (),
        *,
        sub: str = "user-1",
        lifetime: int = 60,
        iat_offset: int = 0,
        key: SimKey | None = None,
        kid: str | None = None,
        **overrides: Any,
    ) -> str:
        now = int(time.time()) + iat_offset
        claims: dict[str, Any] = {
            "iss": "hub",
            "aud": self.audience,
            "sub": sub,
            "token_use": "user",
            "roles": list(roles),
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "jti": str(uuid.uuid4()),
        }
        for name, value in overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        return self._jwt(claims, key, kid)

    def service_jwt(self, service_id: str | None = None, *, key: SimKey | None = None, **overrides: Any) -> str:
        sid = service_id or self.service_id()
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": "hub",
            "aud": self.audience,
            "sub": "hub",
            "token_use": "hub_service",
            "roles": ["service"],
            "service_id": sid,
            "iat": now,
            "nbf": now,
            "exp": now + 60,
            "jti": str(uuid.uuid4()),
        }
        for name, value in overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        return self._jwt(claims, key)

    def service_id(self, app_id: str = "home-control-hub") -> str | None:
        svc = self.services.get(app_id)
        return None if svc is None else str(svc["service_id"])

    # ------------------------------------------------------------------ beheer (wat een beheerder in de Hub-UI doet)
    def new_enrollment_token(self, app_id: str = "home-control-hub", ttl_s: float = 3600) -> str:
        token = "enr_" + secrets.token_urlsafe(32)
        with self.lock:
            self.grants[("token", sha256_hex(token))] = Grant("token", sha256_hex(token), app_id, time.time() + ttl_s)
        return token

    def new_pairing_code(self, app_id: str = "home-control-hub", ttl_s: float = 3600) -> str:
        raw = "".join(secrets.choice(CROCKFORD) for _ in range(12))
        code = f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"
        with self.lock:
            self.grants[("koppelcode", sha256_hex(raw))] = Grant(
                "koppelcode", sha256_hex(raw), app_id, time.time() + ttl_s
            )
        return code

    def expire_grants(self) -> None:
        with self.lock:
            for g in self.grants.values():
                g.expires_at = time.time() - 1

    def revoke(self, app_id: str = "home-control-hub") -> None:
        with self.lock:
            svc = self.services[app_id]
            svc["status"] = "revoked"
            for t in self.tokens.values():
                if t.service_id == svc["service_id"]:
                    t.revoked = True

    def request_rotation(self, app_id: str = "home-control-hub") -> None:
        with self.lock:
            self.services[app_id]["rotation_requested"] = True

    def add_key_rotation(
        self,
        purpose: str,
        *,
        add: list[SimKey] | None = None,
        retire: list[str] | None = None,
        signer: SimKey | None = None,
        sequence: int | None = None,
        tamper: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Een ondertekend rotatie-statement (§4.5). Standaard ondertekend met de eerste sleutel van dat doel."""
        with self.lock:
            group = self.jwt_keys if purpose == "jwt" else self.policy_keys
            seq = sequence if sequence is not None else len(self.rotations) + 1
            payload = {
                "type": "hub_key_rotation",
                "iss": "hub",
                "sequence": seq,
                "issued_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "purpose": purpose,
                "add": [k.jwk() for k in (add or [])],
                "retire": list(retire or []),
                **(tamper or {}),
            }
            key = signer or group[0]
            statement = jwt.api_jws.encode(
                json.dumps(payload).encode(),
                key.private,
                algorithm="EdDSA",
                headers={"kid": key.kid, "typ": "hub-key-rotation+jws"},
            )
            item = {"sequence": seq, "statement": statement}
            self.rotations.append(item)
            if tamper is None and signer is None:
                for k in add or []:
                    group.append(k)
                group[:] = [k for k in group if k.kid not in set(retire or [])]
            return item

    # ------------------------------------------------------------------ HTTP
    def handle(self, method: str, path: str, headers: dict[str, str], body: bytes, client_ip: str) -> Reply:
        with self.lock:
            self.calls.append((method, path))
            if not self.up:
                return _err(503, "service_unavailable", "De Hub is tijdelijk niet beschikbaar.")
            if path == "/api/v1/services/enroll" and method == "POST":
                return self.enroll(body, client_ip)
            if path == "/api/v1/services/self" and method == "GET":
                return self.self_(headers)
            if path == "/api/v1/services/self/rotate" and method == "POST":
                return self.rotate(headers)
            if path == "/api/v1/auth/jwks" and method == "GET":
                return Reply(200, self.jwks())
            if path == "/api/v1/auth/key-rotations" and method == "GET":
                return self.key_rotations(headers.get("x-sim-query", ""))
            if path == "/api/v1/events/inbox" and method == "POST":
                return self.events_inbox(headers, body)
            return _err(404, "not_found", "Niet gevonden.")

    def _fail(self, ip: str) -> None:
        self.failures.setdefault(ip, []).append(time.time())

    def enroll(self, raw: bytes, ip: str) -> Reply:
        try:
            body = json.loads(raw)
        except ValueError:
            return _err(422, "validation_error", "Geen geldige JSON.")
        if isinstance(body, dict):
            self.enroll_requests.append(
                {k: v for k, v in body.items() if k not in ("enrollment_token", "pairing_code")}
            )
        if self.enroll_override is not None:
            forced = self.enroll_override(body)
            if forced is not None:
                return forced
        recent = [t for t in self.failures.get(ip, []) if time.time() - t < self.window_s]
        self.failures[ip] = recent
        if len(recent) >= self.max_failures:
            wait = max(1, int(self.window_s - (time.time() - recent[0])))
            return _err(429, "rate_limited", "Te veel mislukte aanmeldingen.", {"Retry-After": str(wait)})
        problem = self._validate(body)
        if problem:
            return _err(422, "validation_error", "De invoer is ongeldig.", fouten=[problem])
        if body.get("enrollment_token") is not None:
            kind, hashed = "token", sha256_hex(body["enrollment_token"])
        else:
            kind, hashed = "koppelcode", sha256_hex(normalize_code(body["pairing_code"]))
        tp = thumbprint(body["public_key_jwk"]["x"])
        grant = self.grants.get((kind, hashed))
        now = time.time()
        ok = grant is not None and grant.app_id == body["app_id"] and grant.expires_at > now
        replay = False
        if ok and grant is not None and grant.used_at is not None:
            issued = [t for t in self.tokens.values() if t.grant_secret == hashed]
            replay = (
                grant.used_with_thumbprint == tp
                and bool(issued)
                and not any(t.revoked for t in issued[-1:])
                and all(t.first_used_at is None for t in issued)
            )
            ok = replay
        if not ok or grant is None:
            self._fail(ip)
            return _err(401, "invalid_enrollment", "Enrollment-token of koppelcode ongeldig, al gebruikt of verlopen.")
        app_id = body["app_id"]
        svc = self.services.get(app_id)
        if replay:
            for t in self.tokens.values():
                if t.grant_secret == hashed:
                    t.revoked = True
        else:
            grant.used_at, grant.used_with_thumbprint = now, tp
            if svc is None:
                svc = {"service_id": str(uuid.uuid4()), "app_id": app_id}
                self.services[app_id] = svc
            for t in self.tokens.values():
                if t.service_id == svc["service_id"]:
                    t.revoked = True
        assert svc is not None
        svc.update(status="active", version=body["version"], enrolled_at=now, rotation_requested=False)
        token = "svc_" + secrets.token_urlsafe(32)
        self.tokens[sha256_hex(token)] = Token(sha256_hex(token), svc["service_id"], hashed, now)
        self.failures.pop(ip, None)
        return Reply(
            200,
            {
                "schema_version": "1.2",
                "service_id": svc["service_id"],
                "app_id": app_id,
                "service_token": token,
                "token_type": "Bearer",
                "hub_issuer": "hub",
                "jwks": self.jwks(),
                "policy_public_key": self.policy_jwk(),
                "keyset_fingerprint": self.fingerprint(),
                "jwks_url": "/api/v1/auth/jwks",
                "events_inbox_url": "/api/v1/events/inbox",
                "key_rotation_url": "/api/v1/auth/key-rotations",
                "enrollment_replayed": replay,
            },
            {"Cache-Control": "no-store"},
        )

    @staticmethod
    def _validate(body: Any) -> str | None:
        if not isinstance(body, dict):
            return "geen object"
        extra = set(body) - ENROLL_FIELDS
        if extra:
            return f"onbekende velden: {sorted(extra)}"
        for name in ("app_id", "version", "base_url", "public_key_jwk"):
            if name not in body:
                return f"{name} ontbreekt"
        app_id = body["app_id"]
        if not isinstance(app_id, str) or not 1 <= len(app_id) <= 40 or not APP_NAME.match(app_id):
            return "app_id"
        token, code = body.get("enrollment_token"), body.get("pairing_code")
        if (token is None) == (code is None):
            return "precies één van enrollment_token of pairing_code"
        if token is not None and (not isinstance(token, str) or not ENR.match(token)):
            return "enrollment_token"
        if code is not None:
            if not isinstance(code, str) or len(code) > 32:
                return "pairing_code"
            norm = normalize_code(code)
            if len(norm) != 12 or any(ch not in CROCKFORD for ch in norm):
                return "pairing_code"
        version = body["version"]
        if not isinstance(version, str) or not 1 <= len(version) <= 64 or not VERSION.match(version):
            return "version"
        base = body["base_url"]
        if base is not None and (not isinstance(base, str) or len(base) > 512 or not BASE_URL.match(base)):
            return "base_url"
        jwk_ = body["public_key_jwk"]
        if not isinstance(jwk_, dict) or set(jwk_) - JWK_FIELDS:
            return "public_key_jwk: alleen kty, crv, x en kid"
        if jwk_.get("kty") != "OKP" or jwk_.get("crv") != "Ed25519" or len(str(jwk_.get("x", ""))) != 43:
            return "public_key_jwk"
        if "kid" in jwk_ and jwk_["kid"] != thumbprint(str(jwk_["x"])):
            return "kid moet de RFC 7638-thumbprint zijn"
        return None

    def _service_principal(self, headers: dict[str, str]) -> tuple[dict[str, Any], Token] | Reply:
        auth = headers.get("authorization", "")
        if not auth.startswith("Bearer svc_"):
            return _err(401, "unauthorized", "Niet geautoriseerd.")
        tok = self.tokens.get(sha256_hex(auth[7:]))
        now = time.time()
        if tok is None or tok.revoked or (tok.expires_at is not None and tok.expires_at < now):
            return _err(401, "unauthorized", "Niet geautoriseerd.")
        svc = next((s for s in self.services.values() if s["service_id"] == tok.service_id), None)
        if svc is None or svc["status"] != "active":
            return _err(401, "unauthorized", "Niet geautoriseerd.")
        if tok.first_used_at is None:
            tok.first_used_at = now
            for older in self.tokens.values():  # §3.8: oude tokens vervallen 10 min na het eerste gebruik
                if older.service_id == tok.service_id and older.created_at < tok.created_at and not older.revoked:
                    older.expires_at = min(older.expires_at or now + 86400, now + 600)
        return svc, tok

    def _rotation_header(self, svc: dict[str, Any], tok: Token) -> dict[str, str]:
        mine = [t for t in self.tokens.values() if t.service_id == svc["service_id"] and not t.revoked]
        newest = max(mine, key=lambda t: t.created_at) if mine else None
        stale = newest is not None and newest is not tok and newest.first_used_at is None
        return {"Hub-Token-Rotation": "required"} if svc.get("rotation_requested") or stale else {}

    def self_(self, headers: dict[str, str]) -> Reply:
        got = self._service_principal(headers)
        if isinstance(got, Reply):
            return got
        svc, tok = got
        return Reply(
            200,
            {
                "service_id": svc["service_id"],
                "app_id": svc["app_id"],
                "status": svc["status"],
                "version": svc.get("version"),
                "enrolled_at": datetime.fromtimestamp(svc["enrolled_at"], UTC).isoformat().replace("+00:00", "Z"),
                "keyset_fingerprint": self.fingerprint(),
            },
            self._rotation_header(svc, tok),
        )

    def rotate(self, headers: dict[str, str]) -> Reply:
        got = self._service_principal(headers)
        if isinstance(got, Reply):
            return got
        svc, current = got
        now = time.time()
        for t in self.tokens.values():
            if t.service_id == svc["service_id"] and t is not current and t.first_used_at is None and not t.revoked:
                t.revoked = True  # herhaalde rotatie: nooit gebruikte nieuwe tokens vervallen
        current.expires_at = min(current.expires_at or now + 86400, now + 86400)
        token = "svc_" + secrets.token_urlsafe(32)
        self.tokens[sha256_hex(token)] = Token(sha256_hex(token), svc["service_id"], None, now + 0.001)
        svc["rotation_requested"] = False
        until = datetime.fromtimestamp(now + 86400, UTC).isoformat().replace("+00:00", "Z")
        return Reply(
            200,
            {"service_id": svc["service_id"], "service_token": token, "oude_tokens_geldig_tot": until},
            {"Cache-Control": "no-store"},
        )

    def key_rotations(self, query: str) -> Reply:
        after = 0
        m = re.search(r"(?:^|&)after=(-?\d+)", query)
        if m:
            after = int(m.group(1))
        return Reply(200, {"items": [i for i in self.rotations if i["sequence"] > after]})

    def events_inbox(self, headers: dict[str, str], raw: bytes) -> Reply:
        got = self._service_principal(headers)
        if isinstance(got, Reply):
            return got
        svc, tok = got
        if self.inbox_status is not None:
            return Reply(self.inbox_status, {"code": "x"}, self._rotation_header(svc, tok))
        event = json.loads(raw)
        problems = envelope_problems(event)
        if problems:  # zoals de echte Hub: 422 bij een ongeldige envelope
            self.rejected.append({"event_type": event.get("event_type"), "problems": problems})
            return _err(422, "validation_error", "Ongeldige envelope.", problems=problems)
        if any(e["event_id"] == event["event_id"] for e in self.inbox):
            return Reply(200, {"status": "duplicaat"}, self._rotation_header(svc, tok))
        self.inbox.append(event)
        return Reply(202, {"status": "ontvangen"}, self._rotation_header(svc, tok))


# ---------------------------------------------------------------------------------------------- HTTP-server (E2E)
def _build_app() -> Any:
    sim = HubSim()
    api = FastAPI(title="sim-hub")
    api.state.sim = sim
    state: dict[str, Any] = {"authentik_up": True}

    def _reply(r: Reply) -> Response:
        return Response(
            content=b"" if r.body is None else json.dumps(r.body).encode(),
            status_code=r.status,
            media_type="application/json",
            headers=r.headers,
        )

    @api.api_route("/api/v1/{rest:path}", methods=["GET", "POST"])
    async def hub(request: Request, rest: str) -> Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        headers["x-sim-query"] = request.url.query
        ip = request.client.host if request.client else "?"
        return _reply(sim.handle(request.method, f"/api/v1/{rest}", headers, await request.body(), ip))

    @api.post("/sim/grant")
    async def grant(request: Request) -> dict[str, Any]:
        body = await request.json()
        kind = body.get("kind", "token")
        secret = sim.new_enrollment_token() if kind == "token" else sim.new_pairing_code()
        return {"secret": secret, "fingerprint": sim.fingerprint()}

    @api.post("/sim/token")
    async def token(request: Request) -> dict[str, str]:
        body = await request.json()
        return {"token": sim.user_jwt(body.get("roles", []), sub=body.get("sub", "e2e-user"))}

    @api.post("/sim/service-jwt")
    async def service_token() -> dict[str, str]:
        return {"token": sim.service_jwt()}

    @api.post("/sim/outage")
    async def outage(request: Request) -> dict[str, bool]:
        sim.up = not bool((await request.json()).get("on"))
        return {"up": sim.up}

    @api.post("/sim/revoke")
    async def revoke() -> dict[str, bool]:
        sim.revoke()
        return {"ok": True}

    @api.post("/sim/request-rotation")
    async def request_rotation() -> dict[str, bool]:
        sim.request_rotation()
        return {"ok": True}

    @api.post("/sim/key-rotation")
    async def key_rotation() -> dict[str, Any]:
        new = SimKey()
        sim.add_key_rotation("jwt", add=[new])
        sim.signing = new
        return {"kid": new.kid, "fingerprint": sim.fingerprint()}

    @api.get("/sim/state")
    async def sim_state() -> dict[str, Any]:
        return {
            "fingerprint": sim.fingerprint(),
            "service_id": sim.service_id(),
            "enroll_requests": sim.enroll_requests,
            "calls": sim.calls[-200:],
            "tokens": len(sim.tokens),
        }

    @api.get("/sim/inbox")
    async def sim_inbox() -> list[dict[str, Any]]:
        return sim.inbox

    @api.get("/sim/rejected")
    async def rejected() -> list[dict[str, Any]]:
        return sim.rejected

    @api.post("/sim/authentik")
    async def set_authentik(request: Request) -> dict[str, bool]:
        state["authentik_up"] = bool((await request.json()).get("up"))
        return {"up": state["authentik_up"]}

    @api.get("/sim/authentik/-/health/live/")
    async def authentik_live() -> Response:
        return Response(status_code=200 if state["authentik_up"] else 503)

    return api


def __getattr__(name: str) -> Any:  # ``uvicorn sim_hub:app`` bouwt de app pas bij gebruik
    if name == "app":
        globals()["app"] = _build_app()
        return globals()["app"]
    raise AttributeError(name)


__all__ = ["HubSim", "Reply", "SimKey", "envelope_problems", "keyset_fingerprint", "thumbprint"]
