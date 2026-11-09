"""Interop tegen de ECHTE Hub (``lvos04/ai-server-manager``), niet tegen de simulator. ALLEEN lokaal, niet in CI.

Draait de Hub-API uit een eigen checkout/venv van ``ai-server-manager`` (bv. ``git archive`` van de branch naar een
tijdelijke map en ``pip install apps/api``) en deze dienst (API + worker) als echte processen, elk met een eigen
PostgreSQL-database. Overgeslagen als ``HCH_REAL_HUB_PYTHON`` (de Python van een venv waarin het pakket ``hub`` is
geïnstalleerd) niet is gezet:

    HCH_REAL_HUB_PYTHON=/pad/naar/hub-venv/bin/python pytest -q tests/interop -p no:cacheprovider

Getoetst (contract 1.2): eerste beheerder met de setupcode; een verkeerde ``HUB_KEY_FINGERPRINT`` slaat niets op;
koppelen met enrollment-token + ``HUB_KEY_FINGERPRINT`` uit de Hub, bevestigen met ``services/self`` (§3.3, §3.6);
gepinde sleutels = de JWKS van de Hub (§4.5); gebruikers-JWT van de Hub geaccepteerd, ``jti``-hergebruik voor een
tweede mutatie niet (§4.6); service-token inkomend geweigerd (§4.3); ``key-rotations`` (lege lijst) zonder fout;
rotatie op verzoek van de beheerder (§3.8); dienst-JWT van de Hub mag ``hub-link`` lezen en ontkoppelen, daarna 401
``not_linked`` (ook bij herhalen); opnieuw koppelen met een nieuw token (zelfde ``service_id``) en intrekken door de
Hub → ``revoked``. De dienst-JWT wordt met de sleutelring van de Hub zelf gemaakt (``hub.keys.KeyRing``): de route
``POST /api/v1/services/{id}/unlink`` van de Hub vraagt een gemeten dienstadres (D03 + inventaris) dat hier niet bestaat.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine, text

HUB_PYTHON = os.environ.get("HCH_REAL_HUB_PYTHON", "")
ADMIN_DB_URL = os.environ.get("HCH_TEST_ADMIN_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/postgres")
APP_ID = "home-control-hub"
HUB_DB, SVC_DB = "hch_interop_hub", "hch_interop_dienst"

pytestmark = pytest.mark.skipif(not HUB_PYTHON, reason="HCH_REAL_HUB_PYTHON niet gezet (alleen lokaal)")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _db(name: str) -> str:
    eng = create_engine(ADMIN_DB_URL, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        c.execute(text(f'CREATE DATABASE "{name}"'))
    eng.dispose()
    return ADMIN_DB_URL.rsplit("/", 1)[0] + "/" + name


def _wait(cond: Callable[[], Any], timeout: float = 40.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = cond()
            if value:
                return value
        except (httpx.HTTPError, OSError, ValueError, KeyError):
            pass
        time.sleep(0.5)
    raise AssertionError("voorwaarde niet binnen de tijd bereikt")


class Lab:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.procs: dict[str, subprocess.Popen[bytes]] = {}
        clean = {k: v for k, v in os.environ.items() if not k.startswith(("HCH_", "HUB_", "ENROLLMENT_TOKEN"))}
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
            clean.pop(k, None)
        self.hub_port, self.api_port = _free_port(), _free_port()
        self.hub_url, self.api_url = f"http://127.0.0.1:{self.hub_port}", f"http://127.0.0.1:{self.api_port}"
        self.hub_env = {
            **clean,
            "HUB_DATA_DIR": str(root / "hub-appdata"),
            "HUB_DATABASE_URL": _db(HUB_DB),
            "HUB_COOKIE_SECURE": "false",
        }
        self.svc_data = root / "dienst-appdata"
        self.svc_env = {
            **clean,
            "HCH_DATA_DIR": str(self.svc_data),
            "HCH_DATABASE_URL": _db(SVC_DB),
            "HCH_ALLOW_LOOPBACK_HUB": "1",  # alleen lokaal: de Hub draait op 127.0.0.1
            "HCH_WORKER_INTERVAL_S": "1",
            "HCH_HUB_HEARTBEAT_S": "2",
            "HCH_HUB_KEY_POLL_S": "2",
            "HCH_AUTHENTIK_SYNC_INTERVAL_S": "0",
            "HUB_URL": self.hub_url,
        }
        self.http = httpx.Client(base_url=self.hub_url, timeout=15, trust_env=False)
        self.csrf = ""

    # ------------------------------------------------------------------ processen
    def start(self, name: str, cmd: list[str], env: dict[str, str]) -> None:
        log = open(self.root / f"{name}.log", "ab")  # blijft open zolang het proces draait
        self.procs[name] = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)

    def stop(self, name: str) -> None:
        proc = self.procs.pop(name, None)
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(15)
            except subprocess.TimeoutExpired:
                proc.kill()

    def start_hub(self) -> str:
        out = subprocess.run(
            [HUB_PYTHON, "-m", "hub", "init"], env=self.hub_env, capture_output=True, text=True, check=True
        ).stdout
        code = re.search(r"SETUPCODE[^:]*:\s*([0-9A-Z-]+)", out)
        assert code, out
        subprocess.run([HUB_PYTHON, "-m", "hub", "migrate"], env=self.hub_env, check=True, capture_output=True)
        self.start(
            "hub", [HUB_PYTHON, "-m", "hub", "api", "--host", "127.0.0.1", "--port", str(self.hub_port)], self.hub_env
        )
        _wait(lambda: self.http.get("/api/v1/setup/status").status_code == 200)
        return code.group(1)

    def start_service(self, enrollment_token: str, fingerprint: str) -> None:
        env = {**self.svc_env, "HUB_ENROLLMENT_TOKEN": enrollment_token, "HUB_KEY_FINGERPRINT": fingerprint}
        for step in ("init", "migrate"):
            subprocess.run([sys.executable, "-m", "integrations", step], env=env, check=True, capture_output=True)
        if "api" not in self.procs:
            self.start(
                "api",
                [sys.executable, "-m", "integrations", "api", "--host", "127.0.0.1", "--port", str(self.api_port)],
                env,
            )
        self.start("worker", [sys.executable, "-m", "integrations", "worker"], env)
        _wait(lambda: httpx.get(f"{self.api_url}/healthz", timeout=2, trust_env=False).status_code == 200)

    # ------------------------------------------------------------------ Hub als beheerder
    def hub_post(self, path: str, body: Any = None, idem: bool = False) -> httpx.Response:
        headers = {"X-CSRF-Token": self.csrf}
        if idem:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        return self.http.post(path, json=body, headers=headers)

    def enrollment_token(self) -> dict[str, Any]:
        r = self.hub_post("/api/v1/services/enrollment-tokens", {"app_id": APP_ID})
        assert r.status_code == 201, r.text
        return dict(r.json())

    def user_jwt(self) -> str:
        r = self.hub_post("/api/v1/auth/service-jwt", {"audience": APP_ID})
        assert r.status_code == 200, r.text
        return str(r.json()["token"])

    def hub_service_jwt(self, service_id: str) -> str:
        """Dienst-JWT met de sleutelring van de Hub zelf (zie de moduletekst)."""
        script = (
            "import sys; from pathlib import Path; from hub.keys import KeyRing; "
            "print(KeyRing.load(Path(sys.argv[1])).issue_hub_service_jwt(audience=sys.argv[2], "
            "service_id=sys.argv[3])[0])"
        )
        secrets = Path(self.hub_env["HUB_DATA_DIR"]) / "secrets"
        return subprocess.run(
            [HUB_PYTHON, "-c", script, str(secrets), APP_ID, service_id],
            env=self.hub_env,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    def service_record(self) -> dict[str, Any]:
        items = self.http.get("/api/v1/services").json()["items"]
        return next(i for i in items if i["app_id"] == APP_ID)

    # ------------------------------------------------------------------ dienst
    def link(self) -> dict[str, Any]:
        return dict(json.loads((self.svc_data / "secrets" / "hub-link.json").read_text()))

    def api(self, method: str, path: str, token: str, idem: bool = False) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"}
        if idem:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        return httpx.request(method, f"{self.api_url}{path}", headers=headers, timeout=10, trust_env=False)


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    lb = Lab(tmp_path_factory.mktemp("interop"))
    try:
        yield lb
    finally:
        for name in list(lb.procs):
            lb.stop(name)
        lb.http.close()


def test_real_hub_lifecycle(lab: Lab) -> None:
    setup_code = lab.start_hub()
    r = lab.http.post(
        "/api/v1/setup/admin",
        json={"setup_code": setup_code, "username": "beheer", "password": "interop-" + uuid.uuid4().hex},
    )
    assert r.status_code == 200, r.text
    lab.csrf = r.json()["csrf_token"]

    # 0. verkeerde HUB_KEY_FINGERPRINT (testvector uit §4.5, niet de sleutelset van deze Hub): niets opgeslagen en
    #    het token is afgehandeld (§3.3, §3.6 stap 4)
    wrong = lab.enrollment_token()
    assert wrong["keyset_fingerprint"] != "MEGG-8GFG-2E4Y-K2RQ"
    lab.start_service(wrong["enrollment_token"], "MEGG-8GFG-2E4Y-K2RQ")
    refused = _wait(lambda: (d := lab.link())["last_error"] and d)
    assert refused["last_error"]["code"] == "hub_vingerafdruk_onjuist" and refused["state"] == "nooit_gekoppeld"
    assert refused["service_token"] is None and refused["pins"] is None and refused["pending"] is None
    assert len(refused["used_enrollment_token_sha256"]) == 1
    lab.stop("worker")

    # 1. koppelen met enrollment-token + HUB_KEY_FINGERPRINT van de echte Hub
    grant = lab.enrollment_token()
    lab.start_service(grant["enrollment_token"], grant["keyset_fingerprint"])
    link = _wait(lambda: (d := lab.link())["state"] == "gekoppeld" and d.get("confirmed_at") and d)
    assert link["pins"]["keyset_fingerprint"] == grant["keyset_fingerprint"] and link["via"] == "token"
    jwks = lab.http.get("/api/v1/auth/jwks").json()
    assert [p["kid"] for p in link["pins"]["jwt"]] == [k["kid"] for k in jwks["keys"]]
    record = lab.service_record()
    assert record["status"] == "active" and record["id"] == link["service_id"]
    assert any(t["eerst_gebruikt"] for t in record["tokens"])  # services/self bevestigd met het nieuwe token

    # 2. gebruikers-JWT van de Hub; jti-hergebruik voor een tweede mutatie geweigerd; service-token geweigerd
    tok = lab.user_jwt()
    assert lab.api("GET", "/connector/v1/discover", tok).status_code == 200
    hub_link = lab.api("GET", "/connector/v1/hub-link", tok).json()
    assert hub_link["keyset_fingerprint"] == grant["keyset_fingerprint"] and hub_link["rotation_sequence"] == 0
    assert lab.api("POST", "/connector/v1/apply", tok, idem=True).status_code == 501
    r = lab.api("POST", "/connector/v1/rollback", tok, idem=True)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "token_replayed"
    real_token = lab.link()["service_token"]
    r = lab.api("GET", "/connector/v1/discover", real_token)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "service_token_not_accepted"

    # 3. sleutelrotaties pollen: de Hub geeft een lege lijst → geen fout (§4.5)
    assert lab.http.get("/api/v1/auth/key-rotations", params={"after": 0}).json() == {"items": []}
    time.sleep(3)
    assert lab.link().get("key_rotation_blocked_sequence") is None

    # 4. rotatie van het service-token op verzoek van de beheerder (§3.8)
    old_last4 = lab.link()["service_token_last4"]
    r = lab.hub_post(f"/api/v1/services/{link['service_id']}/rotate", idem=True)
    assert r.status_code == 202, r.text
    _wait(lambda: (d := lab.link())["service_token_last4"] != old_last4 and d.get("confirmed_at"))
    assert lab.service_record()["rotatie"]["aangevraagd_op"] is None

    # 5. dienst-JWT van de Hub: hub-link lezen en ontkoppelen; daarna weigert de dienst elke Hub-JWT (§3.8, §4.3)
    assert lab.api("GET", "/connector/v1/hub-link", lab.hub_service_jwt(link["service_id"])).status_code == 200
    r = lab.api("POST", "/connector/v1/hub-link/unlink", lab.hub_service_jwt(link["service_id"]), idem=True)
    assert r.status_code == 200 and r.json()["state"] == "ontkoppeld", r.text
    r = lab.api("GET", "/connector/v1/discover", lab.user_jwt())
    assert r.status_code == 401 and r.json()["details"]["reason"] == "not_linked"
    r = lab.api("POST", "/connector/v1/hub-link/unlink", lab.hub_service_jwt(link["service_id"]), idem=True)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "not_linked"  # telt voor de Hub als geslaagd

    # 6. opnieuw koppelen met een nieuw token (zelfde service_id), daarna intrekken door de Hub → fail-closed
    lab.stop("worker")
    grant2 = lab.enrollment_token()
    lab.start_service(grant2["enrollment_token"], grant2["keyset_fingerprint"])
    relinked = _wait(lambda: (d := lab.link())["state"] == "gekoppeld" and d.get("confirmed_at") and d)
    assert relinked["service_id"] == link["service_id"] and relinked["previous_pins"] is not None
    assert lab.api("GET", "/connector/v1/discover", lab.user_jwt()).status_code == 200
    r = lab.hub_post(f"/api/v1/services/{link['service_id']}/revoke", idem=True)
    assert r.status_code == 200, r.text
    _wait(lambda: lab.link()["state"] == "ingetrokken")
    r = lab.api("GET", "/connector/v1/discover", lab.user_jwt())
    assert r.status_code == 401 and r.json()["details"]["reason"] == "revoked"
