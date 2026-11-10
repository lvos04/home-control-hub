"""Gedeelde fixtures: Hub-sleutels/JWT's, een nep-Hub (httpx.MockTransport) en een test-PostgreSQL.

Integratietests gebruiken ``HCH_TEST_DATABASE_URL`` (standaard de gedeelde ontwikkel-PostgreSQL op 127.0.0.1:5432,
database ``hch_test_api``). Er worden nooit echte apps, NAS'en of accounts aangesproken.
"""

from __future__ import annotations

import importlib.util
import os
import sys
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
from tests.fakes.authentik_fake import AuthentikFake

ADMIN_DB_URL = os.environ.get("HCH_TEST_ADMIN_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/postgres")
TEST_DB_NAME = os.environ.get("HCH_TEST_DB_NAME", "hch_test_api")
REPO_ROOT = Path(__file__).resolve().parents[3]

ENV_TOKEN = "enr_" + ("hchTestEnvToken_" * 3)[:43]  # testwaarde (alleen de nep-Hub kent hem)
PAIR_CODE = "KOPP-ELCO-DE42"  # normaliseert naar 12 Crockford-tekens (O→0, L→1)
HUB_URL = "http://hub.test:30400"
AUTHENTIK_URL = "http://authentik.test:9000"
SIM_CLIENT_IP = "192.0.2.10"  # RFC 5737-documentatieadres; alleen voor de rate-limit van de nep-Hub
#: wat een browser bij een formulier-POST van de eigen pagina meestuurt (contract 1.3 §3.7): Origin = schema://Host van
#: de TestClient (``http://testserver``; 'testserver' is een naam zonder punt en dus een toegestane Host)
BROWSER_HEADERS = {"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"}


def _load_sim_hub() -> Any:
    """De Hub-simulator van de dienst-E2E (``tests/e2e/sim_hub.py``) is ook de nep-Hub van deze tests (§3.3 exact)."""
    name = "hch_sim_hub"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "tests" / "e2e" / "sim_hub.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sim_hub = _load_sim_hub()
HubSim = sim_hub.HubSim
SimKey = sim_hub.SimKey


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


envelope_problems = sim_hub.envelope_problems


@dataclass
class HubKeys:
    """De ondertekensleutel van de nep-Hub (gepind bij het koppelen) en hulp om JWT's te maken."""

    sim: Any = field(default_factory=lambda: HubSim())

    @property
    def key(self) -> Any:
        return self.sim.signing

    @property
    def private(self) -> Ed25519PrivateKey:
        return self.key.private  # type: ignore[no-any-return]

    @property
    def jwk(self) -> dict[str, str]:
        return self.key.jwk()  # type: ignore[no-any-return]

    @property
    def kid(self) -> str:
        return str(self.key.kid)

    def jwks(self) -> dict[str, Any]:
        return self.sim.jwks()  # type: ignore[no-any-return]

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
        """Gebruikers-JWT zoals de Hub die maakt (§4.2): ``token_use: user``, ``nbf``, ``jti``."""
        now = int(time.time()) + iat_offset
        claims = {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "token_use": "user",
            "roles": roles or [],
            "iat": now,
            "nbf": now,
            "exp": now + lifetime,
            "jti": str(uuid.uuid4()),
            **(extra or {}),
        }
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.private, algorithm="EdDSA", headers={"kid": kid or self.kid, "typ": "JWT"})


@dataclass
class FakeHub:
    """Nep-Hub (``HubSim`` uit ``tests/e2e/sim_hub.py``) + nep-Authentik voor ``httpx.MockTransport``."""

    keys: HubKeys
    up: bool = True
    authentik_up: bool = True
    authentik: AuthentikFake = field(default_factory=AuthentikFake)
    client_ip: str = SIM_CLIENT_IP
    requests: list[httpx.Request] = field(default_factory=list)
    # paden waarvan de Hub het verzoek wél verwerkt maar het antwoord verloren gaat (crash/time-out halverwege)
    drop_response: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        from integrations.security.hubkeys import normalize_code, sha256_hex

        now = time.time()
        Grant = sim_hub.Grant
        self.sim.grants[("token", sha256_hex(ENV_TOKEN))] = Grant(
            "token", sha256_hex(ENV_TOKEN), "home-control-hub", now + 3600
        )
        code = normalize_code(PAIR_CODE)
        self.sim.grants[("koppelcode", sha256_hex(code))] = Grant(
            "koppelcode", sha256_hex(code), "home-control-hub", now + 3600
        )

    @property
    def sim(self) -> Any:
        return self.keys.sim

    @property
    def enroll_requests(self) -> list[dict[str, Any]]:
        return self.sim.enroll_requests  # type: ignore[no-any-return]

    @property
    def inbox(self) -> list[dict[str, Any]]:
        return self.sim.inbox  # type: ignore[no-any-return]

    @property
    def rejected(self) -> list[dict[str, Any]]:
        return self.sim.rejected  # type: ignore[no-any-return]

    def fingerprint(self) -> str:
        return str(self.sim.fingerprint())

    def service_auth(self) -> TokenHeaders:
        """Dienst-JWT van de Hub (§4.3), per mutatie (via ``idem``) een nieuwe."""
        return TokenHeaders(lambda: self.sim.service_jwt())

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = request.url
        if url.host == "authentik.test":
            if not self.authentik_up:
                raise httpx.ConnectError("verbinding geweigerd", request=request)
            return self.authentik.handle(request)
        if url.host != "hub.test":
            raise httpx.ConnectError("onbekende host", request=request)
        if not self.up:
            raise httpx.ConnectError("hub offline", request=request)
        headers = {k.lower(): v for k, v in request.headers.items()}
        headers["x-sim-query"] = url.query.decode() if isinstance(url.query, bytes) else str(url.query)
        reply = self.sim.handle(request.method, url.path, headers, request.content, self.client_ip)
        if url.path in self.drop_response:
            self.drop_response.remove(url.path)
            raise httpx.ReadTimeout("antwoord verloren", request=request)
        return httpx.Response(reply.status, json=reply.body, headers=reply.headers)

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
            "allow_loopback_hub": False,
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
        client = TestClient(app, headers=BROWSER_HEADERS)
        client.__enter__()
        clients.append(client)
        return client

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


@pytest.fixture
def client(app_factory: Callable[..., Any]) -> Any:
    return app_factory()


def pair(client: Any, fake_hub: FakeHub, code: str = PAIR_CODE) -> Any:
    """Koppelen via de koppelcode + vingerafdruk (zoals de statuspagina, §3.7); geeft de uitkomst."""
    return client.app.state.hublink.pair_with_code(
        hub_url=HUB_URL, pairing_code=code, fingerprint=fake_hub.fingerprint(), trace_id=str(uuid.uuid4())
    )


@pytest.fixture
def paired_client(client: Any, fake_hub: FakeHub) -> Any:
    """App die via de koppelcode met de nep-Hub gekoppeld is."""
    outcome = pair(client, fake_hub)
    assert outcome.ok, outcome.code
    return client


class TokenHeaders(dict[str, str]):
    """Authorization-header die bij **elk** verzoek (en elke ``idem``/``fresh``) een nieuwe JWT maakt, zoals de Hub:
    een JWT (``jti``) mag voor hooguit één mutatie gebruikt worden (§4.6). Tests die hergebruik willen bewijzen,
    gebruiken een vaste token-tekst."""

    def __init__(self, mint: Callable[[], str]) -> None:
        super().__init__({"Authorization": f"Bearer {mint()}"})
        self.mint = mint

    def items(self) -> Any:  # httpx leest headers via items(): per verzoek een nieuwe JWT
        return {**dict(super().items()), "Authorization": f"Bearer {self.mint()}"}.items()


@pytest.fixture
def auth(hub_keys: HubKeys) -> Callable[..., dict[str, str]]:
    def _auth(*roles: str, sub: str = "user-1") -> dict[str, str]:
        return TokenHeaders(lambda: hub_keys.token(list(roles), sub=sub))

    return _auth


def fresh(headers: dict[str, str]) -> dict[str, str]:
    """Dezelfde soort token, maar met een nieuwe ``jti`` (per mutatie een nieuwe JWT, §4.6)."""
    if isinstance(headers, TokenHeaders):
        return {**headers, "Authorization": f"Bearer {headers.mint()}"}
    return dict(headers)


def idem(headers: dict[str, str] | None = None, key: str | None = None, **extra: str) -> dict[str, str]:
    base = dict(headers or {})
    if isinstance(headers, TokenHeaders):
        base["Authorization"] = f"Bearer {headers.mint()}"
    return {**base, "Idempotency-Key": key or str(uuid.uuid4()), **extra}
