"""Gedeelde fixtures: Hub-sleutels/JWT's, een nep-Hub (httpx.MockTransport) en een test-PostgreSQL.

Integratietests gebruiken ``HCH_TEST_DATABASE_URL`` (standaard de gedeelde ontwikkel-PostgreSQL op 127.0.0.1:5432,
database ``hch_test_api``). Er worden nooit echte apps, NAS'en of accounts aangesproken.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text

from integrations.config import Settings
from integrations.security.secrets import public_jwk
from tests.fakes.authentik_fake import AuthentikFake

ADMIN_DB_URL = os.environ.get("HCH_TEST_ADMIN_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/postgres")
TEST_DB_NAME = os.environ.get("HCH_TEST_DB_NAME", "hch_test_api")
REPO_ROOT = Path(__file__).resolve().parents[3]

ENV_TOKEN = "env-enroll-token-0123456789"  # testwaarde (nep-Hub)
PAIR_CODE = "KOPP-ELCO-DE42"
HUB_URL = "http://hub.test:30400"
AUTHENTIK_URL = "http://authentik.test:9000"


def _db_url(name: str) -> str:
    base = os.environ.get("HCH_TEST_DATABASE_URL")
    if base:
        return base
    return ADMIN_DB_URL.rsplit("/", 1)[0] + "/" + name


def recreate_database(name: str) -> str:
    eng = create_engine(ADMIN_DB_URL, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        c.execute(text(f'CREATE DATABASE "{name}"'))
    eng.dispose()
    return _db_url(name)


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


@dataclass
class HubKeys:
    private: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)

    @property
    def jwk(self) -> dict[str, str]:
        return public_jwk(self.private)

    @property
    def kid(self) -> str:
        return self.jwk["kid"]

    def jwks(self) -> dict[str, Any]:
        return {"keys": [self.jwk]}

    def token(
        self,
        roles: list[str] | None = None,
        sub: str = "user-1",
        aud: str = "home-control-hub",
        iss: str = "hub",
        lifetime: int = 60,
        iat_offset: int = 0,
        kid: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = int(time.time()) + iat_offset
        claims = {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "roles": roles or [],
            "iat": now,
            "exp": now + lifetime,
            "jti": str(uuid.uuid4()),
            **(extra or {}),
        }
        return jwt.encode(claims, self.private, algorithm="EdDSA", headers={"kid": kid or self.kid})


@dataclass
class FakeHub:
    """Nep-Hub + nep-Authentik (``tests/fakes/authentik_fake.py``) voor httpx.MockTransport."""

    keys: HubKeys
    up: bool = True
    authentik_up: bool = True
    authentik: AuthentikFake = field(default_factory=AuthentikFake)
    issued_token: str = field(default_factory=lambda: "svc-" + uuid.uuid4().hex + uuid.uuid4().hex)
    used: set[str] = field(default_factory=set)
    enroll_requests: list[dict[str, Any]] = field(default_factory=list)
    inbox: list[dict[str, Any]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    inbox_status: int = 202
    jwks_calls: int = 0
    include_jwks_in_enroll: bool = True

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host == "authentik.test":
            if not self.authentik_up:
                raise httpx.ConnectError("verbinding geweigerd", request=request)
            return self.authentik.handle(request)
        if url.host != "hub.test":
            raise httpx.ConnectError("onbekende host", request=request)
        if not self.up:
            raise httpx.ConnectError("hub offline", request=request)
        if url.path == "/api/v1/auth/jwks":
            self.jwks_calls += 1
            return httpx.Response(200, json=self.keys.jwks())
        if url.path == "/api/v1/services/enroll" and request.method == "POST":
            import json

            body = json.loads(request.content)
            self.enroll_requests.append(body)
            secret = body.get("secret")
            valid = {ENV_TOKEN, PAIR_CODE}
            if secret not in valid or secret in self.used:
                return httpx.Response(401, json={"code": "unauthorized"})
            self.used.add(secret)
            data: dict[str, Any] = {"service_id": str(uuid.uuid4()), "service_token": self.issued_token}
            if self.include_jwks_in_enroll:
                data["jwks"] = self.keys.jwks()
            return httpx.Response(201, json=data)
        if url.path == "/api/v1/events/inbox" and request.method == "POST":
            if request.headers.get("Authorization") != f"Bearer {self.issued_token}":
                return httpx.Response(401)
            import json

            event = json.loads(request.content)
            problems = envelope_problems(event)
            if problems:  # zoals de Hub: 422 bij een ongeldige envelope
                self.rejected.append({"event_type": event.get("event_type"), "problems": problems})
                return httpx.Response(422, json={"code": "validation_error", "details": problems})
            self.inbox.append(event)
            return httpx.Response(self.inbox_status)
        return httpx.Response(404)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


@pytest.fixture
def hub_keys() -> HubKeys:
    return HubKeys()


@pytest.fixture
def fake_hub(hub_keys: HubKeys) -> FakeHub:
    return FakeHub(hub_keys)


@pytest.fixture
def authentik_fake(fake_hub: FakeHub) -> AuthentikFake:
    return fake_hub.authentik


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "appdata"
    d.mkdir()
    return d


# ------------------------------------------------------------------ integratie (PostgreSQL)
@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    try:
        url = recreate_database(TEST_DB_NAME)
    except Exception as exc:  # pragma: no cover - lokaal overslaan, in CI hard falen
        if os.environ.get("CI"):
            pytest.fail(
                f"PostgreSQL niet beschikbaar in CI: {type(exc).__name__} (integratietests mogen niet stil vervallen)"
            )
        pytest.skip(f"PostgreSQL niet beschikbaar: {type(exc).__name__}")
    settings = Settings(database_url=url)
    from integrations.migrations import upgrade

    upgrade(settings)
    yield url


TRUNCATE = (
    "TRUNCATE service_state, idempotency_record, outbox_event, vault_secret, integration_source, audit_event, "
    "sso_admin_account, sso_recovery_method, sso_emergency_access, sso_break_glass_activation, sso_break_glass_drill, "
    "sso_recovery_kit_export, jwt_jti_use, sso_app_setting, sso_group_role_mapping, sso_proposal, "
    "sso_authentik_snapshot, sso_auth_event, sso_anomaly RESTART IDENTITY CASCADE"
)


CLEAN_TABLES = [
    t.strip() for t in TRUNCATE.removeprefix("TRUNCATE ").removesuffix(" RESTART IDENTITY CASCADE").split(",")
]


def _clean(url: str) -> None:
    """Snel leegmaken: DELETE (zonder FK-triggers) is ~50x sneller dan TRUNCATE op kleine tabellen; anders TRUNCATE."""
    eng = create_engine(url)
    try:
        with eng.begin() as c:
            c.execute(text("SET LOCAL session_replication_role = replica"))
            for table in CLEAN_TABLES:
                c.execute(text(f"DELETE FROM {table}"))  # noqa: S608 - vaste tabelnamen uit deze module
            c.execute(text("ALTER TABLE outbox_event ALTER COLUMN seq RESTART"))
    except Exception:  # geen superuser: dan de langzame, altijd werkende weg
        with eng.begin() as c:
            c.execute(text(TRUNCATE))
    finally:
        eng.dispose()


@pytest.fixture
def clean_db(database_url: str) -> Iterator[str]:
    _clean(database_url)
    yield database_url


@pytest.fixture
def make_settings(data_dir: Path, clean_db: str) -> Callable[..., Settings]:
    def _make(**overrides: Any) -> Settings:
        base: dict[str, Any] = {
            "data_dir": data_dir,
            "database_url": clean_db,
            "hub_url": None,
            "enrollment_token": None,
            "jwks_min_refresh_interval_s": 0,
            "link_cache_ttl_s": 0,
        }
        base.update(overrides)
        return Settings(**base)

    return _make


@pytest.fixture
def app_factory(make_settings: Callable[..., Settings], fake_hub: FakeHub) -> Callable[..., Any]:
    from fastapi.testclient import TestClient

    from integrations.app import create_app

    clients: list[TestClient] = []

    def _make(**overrides: Any) -> TestClient:
        app = create_app(make_settings(**overrides), transport=fake_hub.transport)
        client = TestClient(app)
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture
def client(app_factory: Callable[..., Any]) -> Any:
    return app_factory()


@pytest.fixture
def paired_client(client: Any) -> Any:
    """App die via de koppelcode met de nep-Hub gekoppeld is."""
    state = client.app.state
    with state.db.sessions() as s:
        outcome = state.enrollment.enroll_with_code(s, HUB_URL, PAIR_CODE)
        s.commit()
    assert outcome.ok, outcome.reason
    state.link.invalidate()
    return client


class TokenHeaders(dict[str, str]):
    """Authorization-header die voor elke mutatie (via ``idem``) een **nieuwe** JWT maakt, zoals de Hub dat doet:
    een JWT (``jti``) mag voor hooguit één wijziging gebruikt worden (B13-002, replaybescherming)."""

    def __init__(self, mint: Callable[[], str]) -> None:
        super().__init__({"Authorization": f"Bearer {mint()}"})
        self.mint = mint


@pytest.fixture
def auth(hub_keys: HubKeys) -> Callable[..., dict[str, str]]:
    def _auth(*roles: str, sub: str = "user-1") -> dict[str, str]:
        return TokenHeaders(lambda: hub_keys.token(list(roles), sub=sub))

    return _auth


def idem(headers: dict[str, str] | None = None, key: str | None = None, **extra: str) -> dict[str, str]:
    base = dict(headers or {})
    if isinstance(headers, TokenHeaders):
        base["Authorization"] = f"Bearer {headers.mint()}"
    return {**base, "Idempotency-Key": key or str(uuid.uuid4()), **extra}
