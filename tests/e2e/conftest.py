"""Dienst-E2E: echte processen (API + worker van home-control-hub) tegen een Hub-simulator in een eigen proces.

Vereist: de Python-omgeving met ``apps/api[dev]`` en een PostgreSQL (standaard de lokale ontwikkel-PostgreSQL;
database ``hch_test_e2e``). Geen echte NAS, Hub, Authentik of accounts.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, text

ADMIN_DB_URL = os.environ.get("HCH_TEST_ADMIN_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/postgres")
E2E_DB = "hch_test_e2e"
HERE = Path(__file__).resolve().parent
ENROLL_TOKEN = "e2e-eenmalig-token-0123456789"


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return int(port)


def wait_http(url: str, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=2).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.3)
    raise RuntimeError(f"{url} kwam niet op")


class TokenHeaders(dict[str, str]):
    """Authorization-header; ``fresh()`` haalt een nieuwe JWT bij de Hub-simulator. Een JWT mag voor hooguit één
    wijziging gebruikt worden (replaybescherming B13-002), dus de tests vragen per mutatie een nieuwe, zoals de Hub."""

    def __init__(self, stack: Stack, roles: tuple[str, ...]) -> None:
        self.stack, self.roles = stack, roles
        super().__init__(stack.mint(roles))

    def fresh(self) -> dict[str, str]:
        return self.stack.mint(self.roles)


@dataclass
class Stack:
    hch: str
    hub: str
    hub_proc: subprocess.Popen[bytes]
    procs: list[subprocess.Popen[bytes]]
    authentik: str = ""
    logs: Path | None = None  # stdout/stderr van API, worker en simulators (voor de lekcontrole)

    def mint(self, roles: tuple[str, ...]) -> dict[str, str]:
        r = httpx.post(f"{self.hub}/sim/token", json={"roles": list(roles)}, timeout=5)
        return {"Authorization": f"Bearer {r.json()['token']}"}

    def token(self, *roles: str) -> TokenHeaders:
        return TokenHeaders(self, roles)


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    try:
        eng = create_engine(ADMIN_DB_URL, isolation_level="AUTOCOMMIT")
        with eng.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{E2E_DB}" WITH (FORCE)'))
            c.execute(text(f'CREATE DATABASE "{E2E_DB}"'))
        eng.dispose()
    except Exception as exc:  # pragma: no cover - lokaal overslaan, in CI hard falen
        if os.environ.get("CI"):
            pytest.fail(f"PostgreSQL niet beschikbaar in CI: {type(exc).__name__} (E2E mag niet stil vervallen)")
        pytest.skip(f"PostgreSQL niet beschikbaar: {type(exc).__name__}")
    db_url = ADMIN_DB_URL.rsplit("/", 1)[0] + "/" + E2E_DB
    hub_port, hch_port, ak_port = free_port(), free_port(), free_port()
    hub_url, hch_url = f"http://127.0.0.1:{hub_port}", f"http://127.0.0.1:{hch_port}"
    data = tmp_path_factory.mktemp("appdata")
    logs = tmp_path_factory.mktemp("logs")
    base_env = {k: v for k, v in os.environ.items() if not k.startswith(("HCH_", "HUB_"))}
    hub_env = {**base_env, "SIM_ENROLL_TOKEN": ENROLL_TOKEN, "PYTHONPATH": str(HERE)}
    hub_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "sim_hub:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(hub_port),
            "--log-level",
            "warning",
        ],
        env=hub_env,
        cwd=HERE,
        stdout=open(logs / "hub.log", "wb"),
        stderr=subprocess.STDOUT,
    )
    wait_http(f"{hub_url}/api/v1/auth/jwks")
    ak_url = f"http://127.0.0.1:{ak_port}"
    ak_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "sim_authentik:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(ak_port),
            "--log-level",
            "warning",
        ],
        env={**base_env, "PYTHONPATH": str(HERE)},
        cwd=HERE,
        stdout=open(logs / "authentik.log", "wb"),
        stderr=subprocess.STDOUT,
    )
    wait_http(f"{ak_url}/-/health/live/")
    env = {
        **base_env,
        "HCH_DATA_DIR": str(data),
        "HCH_DATABASE_URL": db_url,
        "HUB_URL": hub_url,
        "HUB_ENROLLMENT_TOKEN": ENROLL_TOKEN,
        "HCH_ALLOW_LOOPBACK_HUB": "1",
        "HCH_WORKER_INTERVAL_S": "1",
        "HCH_JWKS_TTL_S": "2",
        "HCH_JWKS_MAX_STALE_S": "1",
        "HCH_AUTHENTIK_SYNC_INTERVAL_S": "2",
    }
    subprocess.run([sys.executable, "-m", "integrations", "init"], env=env, check=True, capture_output=True)
    subprocess.run([sys.executable, "-m", "integrations", "migrate"], env=env, check=True, capture_output=True)
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "integrations", "api", "--host", "127.0.0.1", "--port", str(hch_port)],
            env=env,
            stdout=open(logs / "api.log", "wb"),
            stderr=subprocess.STDOUT,
        ),
        subprocess.Popen(
            [sys.executable, "-m", "integrations", "worker"],
            env=env,
            stdout=open(logs / "worker.log", "wb"),
            stderr=subprocess.STDOUT,
        ),
    ]
    wait_http(f"{hch_url}/healthz")
    st = Stack(hch_url, hub_url, hub_proc, procs, ak_url, logs)
    yield st
    for p in [*procs, hub_proc, ak_proc]:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
