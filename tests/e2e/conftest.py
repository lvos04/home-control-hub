"""Dienst-E2E: echte processen (API + worker van home-control-hub) tegen een Hub-simulator in een eigen proces.

Daarnaast draaien een nep-Authentik en een nep-Node-RED als eigen processen; de dienst gebruikt ze pas als een test de
bron instelt.

Vereist: de Python-omgeving met ``apps/api[dev]`` en een PostgreSQL (standaard de lokale ontwikkel-PostgreSQL;
database ``hch_test_e2e``). Geen echte NAS, Hub, Authentik of accounts.

Variant "alleen-lezen" (``make e2e-alleen-lezen``, A-10 van KLEIN-48): met ``HCH_E2E_RO_IMAGE=<image van deze app>``
draaien API en worker in een container van die image (``--network host``), met de code en de migraties uit de
werkboom (``PYTHONPATH``, alleen-lezen) en de datamap van de nep-Node-RED via ``docker -v …:ro``, zoals een Custom
App die map koppelt. De dienst meet die koppeling zelf (``fstatvfs``, ``ST_RDONLY``) en neemt het versleutelde
credentials-bestand dan mee. Zonder die variabele is de datamap een gewone, beschrijfbare map (een alleen-lezen
koppeling op de machine zelf vraagt root) en telt hij als ``niet_gekoppeld``. Lokaal achter de docker-lock.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import uuid
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
API_DIR = HERE.parents[1] / "apps" / "api"
#: variant "alleen-lezen" (zie boven): de image van deze app (``make image``); leeg = API en worker als gewone processen
RO_IMAGE = os.environ.get("HCH_E2E_RO_IMAGE", "")
CT_SRC, CT_ALEMBIC, CT_NODE_RED = "/hch/src", "/hch/alembic", "/node-red-data"
DOCKER = "docker"


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


def _docker_argv(name: str, env: dict[str, str], nr_data: Path) -> list[str]:
    """``docker run`` voor de variant "alleen-lezen": de code en migraties uit de werkboom (niet die in de image), de
    appdata op hetzelfde pad en de datamap van Node-RED **alleen-lezen** (``:ro``). Waarden van variabelen gaan via de
    omgeving van ``docker`` mee (``-e NAAM``), niet op de opdrachtregel."""
    data = env["HCH_DATA_DIR"]
    argv = [
        DOCKER,
        "run",
        "--rm",
        "--init",
        "--name",
        name,
        "--network",
        "host",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "-v",
        f"{API_DIR / 'src'}:{CT_SRC}:ro",
        "-v",
        f"{API_DIR / 'alembic'}:{CT_ALEMBIC}:ro",
        "-v",
        f"{data}:{data}",
        "-v",
        f"{nr_data}:{CT_NODE_RED}:ro",
        "-e",
        f"PYTHONPATH={CT_SRC}",
        "-e",
        f"HCH_ALEMBIC_DIR={CT_ALEMBIC}",
        "-e",
        f"HCH_NODE_RED_DATA_DIR={CT_NODE_RED}",
    ]
    for key in sorted(env):
        passed = key.startswith(("HCH_", "HUB_")) or key.endswith("_PROXY")
        if passed and key not in ("HCH_ALEMBIC_DIR", "HCH_NODE_RED_DATA_DIR"):
            argv += ["-e", key]
    return [*argv, "--entrypoint", "python", RO_IMAGE]


def _dienst(
    args: list[str], env: dict[str, str], log: Path, mode: str, nr_data: Path, containers: list[str]
) -> subprocess.Popen[bytes]:
    """Start ``integrations <args>``: als gewoon proces, of in de variant "alleen-lezen" in een eigen container."""
    argv = [sys.executable, "-m", "integrations", *args]
    if RO_IMAGE:
        name = f"hch-e2e-ro-{args[0]}-{uuid.uuid4().hex[:12]}"
        containers.append(name)
        argv = [*_docker_argv(name, env, nr_data), "-m", "integrations", *args]
    return subprocess.Popen(argv, env=env, stdout=open(log, mode), stderr=subprocess.STDOUT)


def _check_ro_image(env: dict[str, str], nr_data: Path, containers: list[str]) -> None:
    """De variant "alleen-lezen" moet de code uit de werkboom draaien (anders toetst een mutatie niets) en de datamap
    echt alleen-lezen zien; anders hard falen, nooit stil overslaan."""
    name = f"hch-e2e-ro-proef-{uuid.uuid4().hex[:12]}"
    containers.append(name)
    code = (
        f"import os, integrations; fd = os.open({CT_NODE_RED!r}, os.O_RDONLY | os.O_DIRECTORY); "
        "print(integrations.__file__, bool(os.fstatvfs(fd).f_flag & os.ST_RDONLY))"
    )
    try:
        out = subprocess.run(
            [*_docker_argv(name, env, nr_data), "-c", code], env=env, capture_output=True, text=True, timeout=120
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.fail(f"variant alleen-lezen: docker niet bruikbaar ({type(exc).__name__})")
    if out.stdout.split() != [f"{CT_SRC}/integrations/__init__.py", "True"]:
        pytest.fail(f"variant alleen-lezen: onverwachte proef in {RO_IMAGE}: {out.stdout!r} {out.stderr[-500:]!r}")


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
    node_red: str = ""  # nep-Node-RED (B11); pas in gebruik als een test de bron instelt
    nr_data: Path | None = None  # datamap van de nep-Node-RED
    #: variant "alleen-lezen": de dienst ziet de datamap via ``docker -v …:ro`` en neemt de credentials mee
    credentials_ro: bool = False
    containers: list[str] = field(default_factory=list)  # eigen containers (variant "alleen-lezen"), bij naam opgeruimd

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
        assert self.logs is not None and self.nr_data is not None
        old = self.procs[1]
        old.terminate()
        old.wait(15)
        self.env.update(extra_env)
        self.procs[1] = _dienst(["worker"], self.env, self.logs / "worker.log", "ab", self.nr_data, self.containers)


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
    hub_port, hch_port, ak_port, nr_port = free_port(), free_port(), free_port(), free_port()
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
    nr_url = f"http://127.0.0.1:{nr_port}"
    nr_data = tmp_path_factory.mktemp("node-red-data")
    nr_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "sim_node_red:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(nr_port),
            "--log-level",
            "warning",
        ],
        env={**base_env, "PYTHONPATH": str(HERE), "SIM_NODE_RED_DATA_DIR": str(nr_data)},
        cwd=HERE,
        stdout=open(logs / "node-red.log", "wb"),
        stderr=subprocess.STDOUT,
    )
    wait_http(f"{nr_url}/sim/state")
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
        "HCH_NODE_RED_SYNC_INTERVAL_S": "2",
        # de datamap van Node-RED: hier een gewone, beschrijfbare map (een alleen-lezen-koppeling vraagt root); de dienst
        # telt hem daarom als niet_gekoppeld (S-P2-320) en neemt het credentials-bestand niet mee. In de variant
        # "alleen-lezen" ziet de dienst dezelfde map via docker -v …:ro (_docker_argv) en neemt hij ze wel mee.
        "HCH_NODE_RED_DATA_DIR": str(nr_data),
        # proxy-omgevingsvariabelen worden genegeerd (§3.2/§5): een kapotte proxy mag het koppelen niet raken
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "ALL_PROXY": "http://127.0.0.1:9",
    }
    subprocess.run([sys.executable, "-m", "integrations", "init"], env=env, check=True, capture_output=True)
    subprocess.run([sys.executable, "-m", "integrations", "migrate"], env=env, check=True, capture_output=True)
    containers: list[str] = []
    procs: list[subprocess.Popen[bytes]] = []  # restart_worker vervangt procs[1] in deze lijst
    try:
        if RO_IMAGE:
            _check_ro_image(env, nr_data, containers)
        api_args = ["api", "--host", "127.0.0.1", "--port", str(hch_port)]
        procs.append(_dienst(api_args, env, logs / "api.log", "wb", nr_data, containers))
        procs.append(_dienst(["worker"], env, logs / "worker.log", "wb", nr_data, containers))
        wait_http(f"{hch_url}/healthz", timeout=60 if RO_IMAGE else 30)
        st = Stack(hch_url, hub_url, hub_proc, procs, ak_url, logs, data, env, [grant["secret"]], nr_url)
        st.nr_data, st.credentials_ro, st.containers = nr_data, bool(RO_IMAGE), containers
        yield st
    finally:
        for p in [*procs, hub_proc, ak_proc, nr_proc]:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
        for name in containers:  # alleen de eigen containers, bij naam (--rm ruimt ze normaal al op)
            subprocess.run([DOCKER, "rm", "-f", name], capture_output=True, check=False)
