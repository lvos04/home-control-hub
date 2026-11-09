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
    """Nep-Hub + nep-Authentik voor httpx.MockTransport."""

    keys: HubKeys
    up: bool = True
    authentik_up: bool = True
    issued_token: str = field(default_factory=lambda: "svc-" + uuid.uuid4().hex + uuid.uuid4().hex)
    used: set[str] = field(default_factory=set)
    enroll_requests: list[dict[str, Any]] = field(default_factory=list)
    inbox: list[dict[str, Any]] = field(default_factory=list)
    inbox_status: int = 202
    jwks_calls: int = 0
    include_jwks_in_enroll: bool = True

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host == "authentik.test":
            if not self.authentik_up:
                raise httpx.ConnectError("verbinding geweigerd", request=request)
            if url.path == "/-/health/live/":
                return httpx.Response(200, text="")
            return httpx.Response(404)
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

            self.inbox.append(json.loads(request.content))
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
    "sso_recovery_kit_export RESTART IDENTITY CASCADE"
)


@pytest.fixture
def clean_db(database_url: str) -> Iterator[str]:
    eng = create_engine(database_url)
    with eng.begin() as c:
        c.execute(text(TRUNCATE))
    eng.dispose()
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


@pytest.fixture
def auth(hub_keys: HubKeys) -> Callable[..., dict[str, str]]:
    def _auth(*roles: str, sub: str = "user-1") -> dict[str, str]:
        return {"Authorization": f"Bearer {hub_keys.token(list(roles), sub=sub)}"}

    return _auth


def idem(headers: dict[str, str] | None = None, key: str | None = None, **extra: str) -> dict[str, str]:
    return {**(headers or {}), "Idempotency-Key": key or str(uuid.uuid4()), **extra}
