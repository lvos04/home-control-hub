"""Simulator van de Hub (+ Authentik-liveness) voor de dienst-E2E. ALLEEN voor tests; geen productiecode.

Biedt wat home-control-hub van de Hub verwacht (aanname, zie ADR-0002):
- ``GET  /api/v1/auth/jwks``         JWKS met één Ed25519-sleutel
- ``POST /api/v1/services/enroll``   eenmalig token (``SIM_ENROLL_TOKEN``) → service-token + JWKS
- ``POST /api/v1/events/inbox``      ontvangt events (alleen met het uitgegeven service-token)
Plus testhulpmiddelen onder ``/sim/*`` (JWT uitgeven, inbox lezen, Authentik aan/uit).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Header, HTTPException, Request, Response

KEY = Ed25519PrivateKey.generate()
RAW = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
X = base64.urlsafe_b64encode(RAW).rstrip(b"=").decode()
KID = (
    base64.urlsafe_b64encode(
        hashlib.sha256(
            json.dumps({"crv": "Ed25519", "kty": "OKP", "x": X}, separators=(",", ":"), sort_keys=True).encode()
        ).digest()
    )
    .rstrip(b"=")
    .decode()
)
JWKS = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": X, "kid": KID, "use": "sig", "alg": "EdDSA"}]}

STATE: dict[str, Any] = {
    "enroll_token": os.environ.get("SIM_ENROLL_TOKEN", ""),
    "used": False,
    "service_token": "svc-" + secrets.token_urlsafe(32),
    "enroll_requests": [],
    "inbox": [],
    "authentik_up": True,
}

app = FastAPI(title="sim-hub")


@app.get("/api/v1/auth/jwks")
def jwks() -> dict[str, Any]:
    return JWKS


@app.post("/api/v1/services/enroll", status_code=201)
async def enroll(request: Request) -> dict[str, Any]:
    body = await request.json()
    STATE["enroll_requests"].append({k: v for k, v in body.items() if k != "secret"})
    if STATE["used"] or not STATE["enroll_token"] or body.get("secret") != STATE["enroll_token"]:
        raise HTTPException(401, "token ongeldig")
    STATE["used"] = True
    return {"service_id": str(uuid.uuid4()), "service_token": STATE["service_token"], "jwks": JWKS}


# Zelfde envelope-regels als de inbox van de echte Hub (ai-server-manager apps/api/src/hub/events/envelope.py,
# contract §7). Zo valt een event dat de Hub zou weigeren (en dat dan als dead-letter eindigt) al in de tests op.
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


def envelope_problems(ev: Any) -> list[str]:
    import json as _json
    import re as _re

    if not isinstance(ev, dict):
        return ["geen object"]
    problems = []
    if set(ev) - ENVELOPE_KEYS:
        problems.append(f"onbekende velden: {sorted(set(ev) - ENVELOPE_KEYS)}")
    if ev.get("schema_version") != "1.0":
        problems.append("schema_version")
    et = ev.get("event_type")
    if not isinstance(et, str) or len(et) > 128 or not _re.match(r"^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$", et):
        problems.append(f"event_type {et!r}")
    ent = ev.get("entity") or {}
    if not _re.match(r"^[a-z0-9_.-]{1,64}$", str(ent.get("type", ""))) or not 1 <= len(str(ent.get("id", ""))) <= 200:
        problems.append("entity")
    actor = ev.get("actor") or {}
    if actor.get("type") not in ("system", "user", "ai", "flow") or not 1 <= len(str(actor.get("id", ""))) <= 128:
        problems.append("actor")
    if ev.get("classification") not in ("public", "internal", "sensitive"):
        problems.append("classification")
    if not str(ev.get("timestamp_utc", "")).endswith("Z"):
        problems.append("timestamp_utc")
    if len(_json.dumps(ev.get("payload") or {}, default=str).encode()) > 16 * 1024:
        problems.append("payload te groot")
    return problems


@app.post("/api/v1/events/inbox", status_code=202)
async def inbox(request: Request, authorization: str = Header(default="")) -> dict[str, str]:
    if authorization != f"Bearer {STATE['service_token']}":
        raise HTTPException(401)
    event = await request.json()
    problems = envelope_problems(event)
    if problems:  # zoals de echte Hub: 422 bij een ongeldige envelope
        STATE.setdefault("rejected", []).append({"event_type": event.get("event_type"), "problems": problems})
        raise HTTPException(422, problems)
    if any(e["event_id"] == event["event_id"] for e in STATE["inbox"]):
        return {"status": "duplicaat"}
    STATE["inbox"].append(event)
    return {"status": "ontvangen"}


@app.post("/sim/token")
async def token(request: Request) -> dict[str, str]:
    body = await request.json()
    now = int(time.time())
    claims = {
        "iss": "hub",
        "aud": "home-control-hub",
        "sub": body.get("sub", "e2e-user"),
        "roles": body.get("roles", []),
        "iat": now,
        "exp": now + 100,
        "jti": str(uuid.uuid4()),
    }
    return {"token": jwt.encode(claims, KEY, algorithm="EdDSA", headers={"kid": KID})}


@app.get("/sim/rejected")
async def rejected() -> list[dict[str, Any]]:
    return list(STATE.get("rejected", []))


@app.get("/sim/inbox")
def sim_inbox() -> list[dict[str, Any]]:
    return STATE["inbox"]


@app.get("/sim/enroll-requests")
def sim_enroll_requests() -> list[dict[str, Any]]:
    return STATE["enroll_requests"]


@app.post("/sim/authentik")
async def set_authentik(request: Request) -> dict[str, bool]:
    STATE["authentik_up"] = bool((await request.json()).get("up"))
    return {"up": STATE["authentik_up"]}


@app.get("/sim/authentik/-/health/live/")
def authentik_live() -> Response:
    return Response(status_code=200 if STATE["authentik_up"] else 503)
