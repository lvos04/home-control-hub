"""Dienst-E2E: echte processen (API + worker van home-control-hub) tegen een Hub-simulator in een eigen proces.

Vereist: de Python-omgeving met ``apps/api[dev]`` en een PostgreSQL (standaard de lokale ontwikkel-PostgreSQL;
database ``hch_test_e2e``). Geen echte NAS, Hub, Authentik of accounts.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine, text

ADMIN_DB_URL = os.environ.get("HCH_TEST_ADMIN_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/postgres")
E2E_DB = "hch_test_e2e"
HERE = Path(__file__).resolve().parent


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
    """Authorization-header; bij elk verzoek (en ``fresh()``) een nieuwe JWT van de Hub-simulator, zoals de Hub:
    een JWT (``jti``) mag voor hooguit één wijziging gebruikt worden (contract 1.2 §4.6)."""

    def __init__(self, stack: Stack, roles: tuple[str, ...] | None) -> None:
        self.stack, self.roles = stack, roles
        super().__init__(self._mint())

    def _mint(self) -> dict[str, str]:
        return self.stack.mint(self.roles) if self.roles is not None else self.stack.mint_service()

    def fresh(self) -> dict[str, str]:
        return self._mint()

    def items(self) -> Any:  # httpx leest headers via items(): per verzoek een nieuwe JWT
        return self._mint().items()


@dataclass
class Stack:
    hch: str
    hub: str
    hub_proc: subprocess.Popen[bytes]
    procs: list[subprocess.Popen[bytes]]
    authentik: str = ""
    logs: Path | None = None  # stdout/stderr van API, worker en simulators (voor de lekcontrole)
    data: Path | None = None
    env: dict[str, str] = field(default_factory=dict)
    enroll_tokens: list[str] = field(default_factory=list)

    def mint(self, roles: tuple[str, ...]) -> dict[str, str]:
        r = httpx.post(f"{self.hub}/sim/token", json={"roles": list(roles)}, timeout=5)
        return {"Authorization": f"Bearer {r.json()['token']}"}

    def mint_service(self) -> dict[str, str]:
        r = httpx.post(f"{self.hub}/sim/service-jwt", timeout=5)
        return {"Authorization": f"Bearer {r.json()['token']}"}

    def token(self, *roles: str) -> TokenHeaders:
        return TokenHeaders(self, roles)

    def service(self) -> TokenHeaders:
        """Dienst-JWT van de Hub (``token_use: hub_service``, §4.3)."""
        return TokenHeaders(self, None)

    def link_file(self) -> dict[str, Any]:
        assert self.data is not None
        return dict(json.loads((self.data / "secrets" / "hub-link.json").read_text(encoding="utf-8")))

    def grant(self) -> dict[str, str]:
        g = httpx.post(f"{self.hub}/sim/grant", json={"kind": "token"}, timeout=5).json()
        self.enroll_tokens.append(g["secret"])
        return dict(g)

    def restart_worker(self, **extra_env: str) -> None:
        """Herstart de worker met andere env (zoals de Hub via ``app.update`` een nieuw token meegeeft, §3.8)."""
        assert self.logs is not None
        old = self.procs[1]
        old.terminate()
        old.wait(15)
        self.env.update(extra_env)
        self.procs[1] = subprocess.Popen(
            [sys.executable, "-m", "integrations", "worker"],
            env=self.env,
            stdout=open(self.logs / "worker.log", "ab"),
            stderr=subprocess.STDOUT,
        )


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
    base_env = {k: v for k, v in os.environ.items() if not k.startswith(("HCH_", "HUB_", "ENROLLMENT_TOKEN"))}
    hub_env = {**base_env, "PYTHONPATH": str(HERE)}
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
    wait_http(f"{hub_url}/sim/state")
    grant = httpx.post(f"{hub_url}/sim/grant", json={"kind": "token"}, timeout=5).json()
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
        "HUB_ENROLLMENT_TOKEN": grant["secret"],
        "HUB_KEY_FINGERPRINT": grant["fingerprint"],
        "HCH_ALLOW_LOOPBACK_HUB": "1",
        "HCH_WORKER_INTERVAL_S": "1",
        "HCH_HUB_HEARTBEAT_S": "1",
        "HCH_HUB_KEY_POLL_S": "1",
        "HCH_AUTHENTIK_SYNC_INTERVAL_S": "2",
        # proxy-omgevingsvariabelen worden genegeerd (§3.2/§5): een kapotte proxy mag het koppelen niet raken
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
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
    st = Stack(hch_url, hub_url, hub_proc, procs, ak_url, logs, data, env, [grant["secret"]])
    yield st
    for p in [*st.procs, hub_proc, ak_proc]:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
