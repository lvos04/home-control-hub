"""Interop tegen de ECHTE Hub (``lvos04/ai-server-manager``), niet tegen de simulator. ALLEEN lokaal, niet in CI.

Draait de Hub-API uit een eigen checkout/venv van ``ai-server-manager`` (bv. ``git archive`` van de branch naar een
tijdelijke map en ``pip install apps/api``) en deze dienst (API + worker) als echte processen, elk met een eigen
PostgreSQL-database. Overgeslagen als ``HCH_REAL_HUB_PYTHON`` (de Python van een venv waarin het pakket ``hub`` is
geïnstalleerd) niet is gezet:

    HCH_REAL_HUB_PYTHON=/pad/naar/hub-venv/bin/python pytest -q tests/interop -p no:cacheprovider

Getoetst (contract 1.2, en sinds de Hub 1.3 volgt ook 1.3: ``schema_version`` ``"1.3"`` en ``rotation_sequence`` in
``hub-link.json``, en ``service.hub_link.linked`` afgeleverd in de inbox van de echte Hub): eerste beheerder met de setupcode; een verkeerde ``HUB_KEY_FINGERPRINT`` slaat niets op;
koppelen met enrollment-token + ``HUB_KEY_FINGERPRINT`` uit de Hub, bevestigen met ``services/self`` (§3.3, §3.6);
gepinde sleutels = de JWKS van de Hub (§4.5); gebruikers-JWT van de Hub geaccepteerd, ``jti``-hergebruik voor een
tweede mutatie niet (§4.6); service-token inkomend geweigerd (§4.3); ``key-rotations`` (lege lijst) zonder fout;
rotatie op verzoek van de beheerder (§3.8); dienst-JWT van de Hub mag ``hub-link`` lezen en ontkoppelen, daarna 401
``not_linked`` (ook bij herhalen); opnieuw koppelen met een nieuw token (zelfde ``service_id``) en intrekken door de
Hub → ``revoked``. De dienst-JWT wordt met de sleutelring van de Hub zelf gemaakt (``hub.keys.KeyRing``): de route
``POST /connector/v1/hub-link/unlink`` wordt zo rechtstreeks getoetst met een verse dienst-JWT.

B11 (S-P2-340): een flow in Node-RED (de nep-Node-RED van de dienst-E2E, ``tests/e2e/sim_node_red.py``; Node-RED zelf
is hier Sim-getest) vraagt met een flow-token ``notification.send`` aan; het event ``flow.action.requested`` komt door
de inbox van de echte Hub en wordt daar een gewoon voorstel met actor ``flow`` (``hub.actions.flows``), zonder dat deze
dienst iets uitvoert. De bron-ID van elk event is de ``event_id`` (uniek, ook na herstel). Een beheerder keurt
vervolgens een R2-herstel goed. De Hub ondertekent het verzoek en bevestigt de readback. Hetzelfde verzoek met één
gewijzigd teken wordt door de connector geweigerd.
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
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import httpx
import pytest
from sqlalchemy import create_engine, text

HUB_PYTHON = os.environ.get("HCH_REAL_HUB_PYTHON", "")
E2E_DIR = Path(__file__).resolve().parents[1] / "e2e"
A = "/integrations/v1/automation"
ADMIN_DB_URL = os.environ.get("HCH_TEST_ADMIN_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/postgres")
HUB_FIXTURE = Path(__file__).with_name("hub_herstelproef.py")
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
            "HCH_NODE_RED_SYNC_INTERVAL_S": "2",
            "HUB_URL": self.hub_url,
        }
        self.nr_port = _free_port()
        self.nr_url = f"http://127.0.0.1:{self.nr_port}"
        self.nr_env = {**clean, "PYTHONPATH": str(E2E_DIR), "SIM_NODE_RED_DATA_DIR": str(root / "node-red-data")}
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
        self.start("hub", [HUB_PYTHON, str(HUB_FIXTURE), "api", str(self.hub_port)], self.hub_env)
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

    def start_node_red(self) -> None:
        """De nep-Node-RED van de dienst-E2E als echt HTTP-proces (Sim-getest)."""
        (self.root / "node-red-data").mkdir(exist_ok=True)
        cmd = [sys.executable, "-m", "uvicorn", "sim_node_red:app", "--host", "127.0.0.1", "--port", str(self.nr_port)]
        self.start("node-red", cmd, self.nr_env)
        _wait(lambda: httpx.get(f"{self.nr_url}/sim/state", timeout=2, trust_env=False).status_code == 200)

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

    def hub_action(self, action_request_id: str) -> dict[str, Any] | None:
        """Het voorstel dat de echte Hub van een flowverzoek maakte (vaste request_id: ``hub.actions.flows``)."""
        script = (
            "import sys, uuid; from hub.actions.flows import request_id_voor; "
            "print(request_id_voor(sys.argv[1], uuid.UUID(sys.argv[2])))"
        )
        rid = subprocess.run(
            [HUB_PYTHON, "-c", script, APP_ID, action_request_id], capture_output=True, text=True, check=True
        ).stdout.strip()
        r = self.http.get(f"/api/v1/actions/{rid}")
        if r.status_code == 404:  # nog niet afgeleverd
            return None
        assert r.status_code == 200, r.text
        return dict(r.json())

    def service_record(self) -> dict[str, Any]:
        items = self.http.get("/api/v1/services").json()["items"]
        return next(i for i in items if i["app_id"] == APP_ID)

    # ------------------------------------------------------------------ dienst
    def link(self) -> dict[str, Any]:
        return dict(json.loads((self.svc_data / "secrets" / "hub-link.json").read_text()))

    def api(
        self, method: str, path: str, token: str, idem: bool = False, body: Any = None, if_match: bool = False
    ) -> httpx.Response:
        headers = {"Authorization": f"Bearer {token}"}
        if idem:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        if if_match:
            headers["If-Match"] = "*"
        return httpx.request(method, f"{self.api_url}{path}", headers=headers, json=body, timeout=10, trust_env=False)


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

    # 1b. contract 1.3: hub-link.json met schema_version "1.3" en rotation_sequence uit het enroll-antwoord (§3.3,
    #     §3.5); het event van de koppeling (service.hub_link.linked, §7) komt door de inbox van de echte Hub (geen
    #     weigering, geen dead-letter): de bron controleert vóór verzending dezelfde grenzen als de inbox
    assert link["schema_version"] == "1.3" and link["pins"]["rotation_sequence"] == 0
    eng = create_engine(lab.svc_env["HCH_DATABASE_URL"])
    try:

        def afgeleverd() -> list[Any] | None:
            with eng.connect() as c:
                rows = list(c.execute(text("SELECT event_type, delivery_status, last_error FROM outbox_event")))
            return rows if rows and all(r[1] == "delivered" for r in rows) else None

        rows = _wait(afgeleverd)
    finally:
        eng.dispose()
    assert "service.hub_link.linked" in {r[0] for r in rows}, rows

    # 2. gebruikers-JWT van de Hub; jti-hergebruik voor een tweede mutatie geweigerd; service-token geweigerd
    tok = lab.user_jwt()
    assert lab.api("GET", "/connector/v1/discover", tok).status_code == 200
    hub_link = lab.api("GET", "/connector/v1/hub-link", tok).json()
    assert hub_link["keyset_fingerprint"] == grant["keyset_fingerprint"] and hub_link["rotation_sequence"] == 0
    r = lab.api("POST", "/connector/v1/apply", tok, idem=True, body={})  # leeg verzoek: geweigerd, niets uitgevoerd
    assert r.status_code == 422 and r.json()["code"] == "execution_request_ongeldig", r.text
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

    # B11, 4(a): een flowverzoek wordt bij de Hub een voorstel met actor flow. 4(b/c): ondertekend herstel en weigering.
    flow_request_becomes_a_hub_proposal(lab)
    with observe_connector(lab) as (port, apply_requests):
        restore_via_hub(lab, port, apply_requests)

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


def flow_request_becomes_a_hub_proposal(lab: Lab) -> None:
    """S-P2-340 bouwpunt 4(a): ``flow.action.requested`` wordt bij de echte Hub-code een voorstel (B11-003, B01-008)."""
    from tests.e2e.test_automation_e2e import DIENST, TAB, _beveiliging, _flows_v1

    lab.start_node_red()
    profile = _beveiliging()  # de beheerder beveiligt Node-RED zelf (besluit C-12); alleen testwaarden
    assert httpx.post(f"{lab.nr_url}/sim/arguments", json={"arguments": profile["herstelargumenten"]}).json()[
        "beveiligd"
    ]
    assert httpx.post(f"{lab.nr_url}/sim/deploy", json={"flows": _flows_v1(), "credentials": {}}).status_code == 200
    bron = {"base_url": lab.nr_url, "enabled": True, "credential": f"{DIENST}:{profile['dienstwachtwoord']}"}
    r = lab.api("PUT", "/integrations/v1/sources/node_red", lab.user_jwt(), idem=True, body=bron, if_match=True)
    assert r.status_code in (200, 201), r.text

    def flow() -> dict[str, Any] | None:
        items = lab.api("GET", f"{A}/flows", lab.user_jwt()).json()["items"]
        return next((i for i in items if i["source_flow_id"] == TAB), None)

    f = _wait(flow)
    assert f["status"] == "actief", f
    r = lab.api("PUT", f"{A}/flows/{f['id']}/owner", lab.user_jwt(), True, {"owner": "beheer", "eigenaren": []}, True)
    assert r.status_code == 200, r.text
    r = lab.api(
        "POST",
        f"{A}/flows/{f['id']}/tokens",
        lab.user_jwt(),
        True,
        {"label": "interop", "allowed_actions": ["notification.send"]},
    )
    assert r.status_code == 201, r.text
    flow_token = r.json()["flow_token"]
    verzoek = {
        "action_id": "notification.send",
        "target": {},
        "parameters": {"titel": "Interop", "tekst": "Flowverzoek tegen de echte Hub-code"},
        "reason": "Interoptest S-P2-340",
        "risk_claim": "R3",  # telt nooit mee (EX18)
    }
    r = lab.api("POST", f"{A}/flow-api/actions", flow_token, idem=True, body=verzoek)
    assert r.status_code == 202 and r.json()["status"] == "aangevraagd", r.text
    action_request_id = r.json()["id"]

    try:
        voorstel = _wait(lambda: lab.hub_action(action_request_id))
    except AssertionError:
        audit = lab.http.get("/api/v1/audit", params={"limit": 20}).text
        raise AssertionError(f"geen voorstel bij de Hub; audit: {audit[:3000]}") from None
    assert voorstel["actor"] == {"type": "flow", "id": f"flow:{f['id']}"}, voorstel
    assert voorstel["action_id"] == "notification.send" and voorstel["risk_claim"] is None
    # dezelfde classificatie als een voorstel van een mens: R0, geen goedkeuring nodig, niet vanzelf uitgevoerd
    assert (voorstel["status"], voorstel["risk_class"], voorstel["goedkeuring_nodig"]) == ("klaar", "R0", False), (
        voorstel
    )
    # het event kwam door de inbox van de echte Hub (afgeleverd, geen dead-letter) met de event-ID als bron-ID
    eng = create_engine(lab.svc_env["HCH_DATABASE_URL"])
    try:
        with eng.connect() as c:
            rows = list(
                c.execute(
                    text(
                        "SELECT event_id, delivery_status FROM outbox_event WHERE event_type = 'flow.action.requested'"
                    )
                )
            )
    finally:
        eng.dispose()
    assert [r[1] for r in rows] == ["delivered"], rows
    hub_events = lab.http.get("/api/v1/events", params={"event_type": "flow.action.requested"}).json()["items"]
    assert [(e["event_id"], e["source_event_id"]) for e in hub_events] == [(str(rows[0][0]), str(rows[0][0]))]
    # deze dienst voert zelf niets uit: Node-RED kreeg geen enkele schrijfactie
    assert httpx.get(f"{lab.nr_url}/sim/state").json()["writes"] == []


@contextmanager
def observe_connector(lab: Lab) -> Iterator[tuple[int, list[dict[str, Any]]]]:
    """Stuurt de twee lokale connectoroproepen ongewijzigd door. Alleen de apply-body blijft in het testgeheugen."""
    applied: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path not in ("/connector/v1/propose", "/connector/v1/apply"):
                self.send_error(404)
                return
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if self.path == "/connector/v1/apply":
                applied.append(json.loads(body))
            headers = {key: self.headers[key] for key in ("Content-Type", "Authorization", "Idempotency-Key")}
            reply = httpx.post(lab.api_url + self.path, content=body, headers=headers, trust_env=False, timeout=10)
            self.send_response(reply.status_code)
            self.send_header("Content-Type", reply.headers["Content-Type"])
            self.end_headers()
            self.wfile.write(reply.content)

    with HTTPServer(("localhost", 0), Handler) as server:
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            yield server.server_port, applied
        finally:
            server.shutdown()
            worker.join()


def restore_via_hub(lab: Lab, connector_port: int, apply_requests: list[dict[str, Any]]) -> None:
    """Een beheerder vraagt bij de Hub om herstel van de eerste stand van de lokale simulator."""
    from tests.e2e.test_automation_e2e import _flows_v1, _flows_v2

    snapshot = lab.api("POST", f"{A}/snapshots", lab.user_jwt(), idem=True)
    assert snapshot.status_code == 201
    with httpx.Client(base_url=lab.nr_url, trust_env=False) as nr:
        current = nr.post("/sim/deploy", json={"flows": _flows_v2(), "credentials": {}})
        assert current.status_code == 200 and nr.get("/sim/state").json()["flows"] == _flows_v2()

    subprocess.run(
        [HUB_PYTHON, str(HUB_FIXTURE), "inventaris", APP_ID, str(connector_port)], env=lab.hub_env, check=True
    )
    body = {
        "action_id": "automation.flows.restore",
        "target": {"app_id": APP_ID, "resource": "node_red"},
        "parameters": {"snapshot_id": snapshot.json()["snapshot"]["id"]},
        "reason": "Herstel de eerste stand van de simulator",
    }
    preview = lab.api("POST", "/connector/v1/propose", lab.user_jwt(), idem=True, body=body)
    assert preview.status_code == 201
    assert preview.json()["target"] == body["target"] and preview.json()["parameters"] == body["parameters"]
    response = lab.hub_post("/api/v1/actions", body, idem=True)
    state = httpx.get(f"{lab.nr_url}/sim/state", trust_env=False).json()
    assert state["flows"] == _flows_v2() and state["writes"] == []
    if response.status_code != 201:
        pytest.fail(
            f"Connector HTTP {preview.status_code} (diff={type(preview.json()['diff']).__name__}); "
            f"Hub HTTP {response.status_code} {response.json()['code']} "
            f"({response.json()['details'].get('reason_code')}); Node-RED: 0 schrijfacties",
            pytrace=False,
        )
    proposal = response.json()
    assert (proposal["status"], proposal["risk_class"]) == ("wacht_op_goedkeuring", "R2")
    action = f"/api/v1/actions/{proposal['request_id']}"
    approval = {field: proposal[field] for field in ("preview_hash", "resource_etag", "policy_hash")}
    assert "backup_gate_rood" in {b["code"] for b in proposal["blokkades"]}
    denied = lab.hub_post(f"{action}/approve", approval, idem=True)
    assert (denied.status_code, denied.json()["code"]) == (409, "actie_geblokkeerd")
    assert not apply_requests
    subprocess.run([HUB_PYTHON, "-m", "hub", "backup-now"], env=lab.hub_env, check=True, capture_output=True)
    approved = lab.hub_post(f"{action}/approve", approval, idem=True)
    assert approved.status_code == 200, approved.json().get("details")
    result = lab.hub_post(f"{action}/execute", idem=True)
    if result.status_code != 200:
        state = httpx.get(f"{lab.nr_url}/sim/state", trust_env=False).json()
        pytest.fail(
            f"Hub HTTP {result.status_code} {result.json().get('code')}; Node-RED: {len(state['writes'])} schrijfactie(s)"
        )
    assert result.json()["status"] == "uitgevoerd"
    proof = result.json()["resultaat"]
    readback = proof["readback"]
    assert readback["gelezen"] is True and readback["gelijk_aan_momentopname"] is True
    assert readback["snapshot_id"] == snapshot.json()["snapshot"]["id"]
    assert readback["checksum_sha256"] == snapshot.json()["snapshot"]["checksum_sha256"]
    (change,) = preview.json()["diff"][0]["changes"]
    assert change == {
        "field": "checksum_sha256",
        "before": proposal["resource_etag"].removeprefix("sha256:"),
        "after": readback["checksum_sha256"],
    }
    assert proof["after_hash"] == "sha256:" + readback["checksum_sha256"]
    assert proof["before_hash"] == proposal["resource_etag"]
    assert proof["policy_hash"] == approval["policy_hash"] and proof["methode"] == body["action_id"]
    state = httpx.get(f"{lab.nr_url}/sim/state", trust_env=False).json()
    assert state["flows"] == _flows_v1() and len(state["writes"]) == 1

    # 4(c): verander één letter in het ondertekende bericht. Een verse dienst-JWT en Idempotency-Key zorgen
    # dat de antwoordcache en de JWT-replaycontrole de controle op de handtekening niet afdekken.
    (signed,) = apply_requests
    assert signed["approval"]["request_id"] == proposal["request_id"]
    assert signed["proposal"]["reason"] == body["reason"]
    bearer = lab.hub_service_jwt(lab.link()["service_id"])
    duplicate = lab.api("POST", "/connector/v1/apply", bearer, idem=True, body=signed)
    assert (duplicate.status_code, duplicate.json()["code"]) == (409, "nonce_al_gebruikt")
    repeated_token = lab.api("POST", "/connector/v1/apply", bearer, idem=True, body=signed)
    assert (repeated_token.status_code, repeated_token.json()["details"]["reason"]) == (401, "token_replayed")
    signed["proposal"]["reason"] = "h" + signed["proposal"]["reason"][1:]
    bearer = lab.hub_service_jwt(lab.link()["service_id"])
    refused = lab.api("POST", "/connector/v1/apply", bearer, idem=True, body=signed)
    assert (refused.status_code, refused.json()["code"]) == (403, "forbidden")
    assert refused.json()["details"]["reason"] == "handtekening_ongeldig"
    after = httpx.get(f"{lab.nr_url}/sim/state", trust_env=False).json()
    assert (after["flows"], after["rev"], after["writes"]) == (state["flows"], state["rev"], state["writes"])
