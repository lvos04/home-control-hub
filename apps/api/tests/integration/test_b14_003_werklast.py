"""B14-003 tegen een bevestigde Hub-simulator en eigen PostgreSQL. De twee werkelijke leesvormen uit §4.4."""

from __future__ import annotations

import itertools
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import select

from integrations.domains.energy.models import EnergyWorkload, EnergyWorkloadReservation
from integrations.models import AuditEvent, IntegrationSource
from integrations.timeutil import utcnow
from tests.conftest import HUB_URL, PAIR_CODE, REPO_ROOT, idem

ENERGY = "/integrations/v1/energy"
PLAN = ENERGY + "/workloads"
SOURCE = "/integrations/v1/sources/mediaguard_encoding"
HTTPS_HUB = HUB_URL.replace("http://", "https://")
NAS = "/api/v1/observability/nas"
PRIVATE_TEXT = "Kijken: fictieve titel en kijker"
DAY = datetime(2026, 10, 25, tzinfo=UTC)


class WorkloadHub:
    def __init__(self, fake_hub):
        self.registration = fake_hub
        self.path = f"/api/v1/adapterkoppelingen/{uuid4()}/mediaguard"
        self.calls = []
        self.errors = {}
        self.offline = False
        at = utcnow().isoformat()
        self.nas = {
            "items": [
                {
                    "id": i,
                    "metriek": metric,
                    "eenheid": "%",
                    "bron": source,
                    "status": "ok",
                    "laatste_waarde": 25,
                    "observed_at": at,
                }
                for i, (metric, source) in enumerate(
                    (
                        ("cpu.gebruik", "truenas.reporting.realtime"),
                        ("geheugen.beschikbaar_pct", "beszel"),
                        ("gpu.gebruik", "beszel"),
                    ),
                    start=1,
                )
            ],
            "onbekend": [],
            "ttl_seconden": 120,
        }
        self.encoding = {
            "status": "gemeten",
            "observed_at": at,
            "max_age_s": 900,
            "banen": [{"lane": "cpu", "running": 0, "paused": True}, {"lane": "gpu", "running": 1, "paused": False}],
        }

    def handle(self, request):
        path = request.url.path
        self.calls.append((request.method, str(request.url)))
        assert request.method == "GET" and path in {NAS, self.path}
        assert str(request.url) == HTTPS_HUB + path
        assert not request.content and "cookie" not in request.headers
        if self.offline:
            raise httpx.ConnectError("Gesimuleerde onderbreking", request=request)
        auth = self.registration.sim.self_(dict(request.headers))
        if auth.status != 200:
            return httpx.Response(auth.status)
        if path in self.errors:
            return httpx.Response(self.errors[path])
        return httpx.Response(200, json=self.nas if path == NAS else self.encoding)


@pytest.fixture
def planner(client, fake_hub, auth):
    state = client.app.state
    result = state.hublink.pair_with_code(
        hub_url=HTTPS_HUB, pairing_code=PAIR_CODE, fingerprint=fake_hub.fingerprint(), trace_id=str(uuid4())
    )
    assert result.ok
    assert state.hublink.confirm(trace_id=str(uuid4()))
    upstream = WorkloadHub(fake_hub)
    state.hub.transport = httpx.MockTransport(upstream.handle)
    r = client.put(
        SOURCE,
        json={"base_url": HTTPS_HUB + upstream.path, "enabled": True},
        headers=idem(auth("admin"), **{"If-Match": "*"}),
    )
    assert r.status_code == 201, r.text
    return client, upstream


def test_werklast_leest_alleen_de_twee_contractroutes_en_toont_de_brontijd(planner, auth):
    client, hub = planner
    r = client.get(PLAN, headers=auth("viewer"), params={"date": hub.encoding["observed_at"][:10]})
    assert r.status_code == 200
    plan = r.json()
    assert {w["priority_class"] for w in plan["items"]} == {"interactief", "hoog", "normaal", "achtergrond"}
    av1 = next(w for w in plan["items"] if w["workload_key"] == "av1")
    assert av1["preemptible"] and av1["needs_safe_checkpoint"]
    nas = plan["sources"]["truenas_metrics"]
    assert nas["status"] == "gemeten" and len(nas["items"]) == 3 and nas["onbekend"] == []
    assert {m["waarde_pct"] for m in nas["items"]} == {25}
    measured = plan["sources"]["mediaguard_encoding"]
    assert measured["status"] == "gemeten"
    assert measured["banen"] == [
        hub.encoding["banen"][0] | {"wait_reason": "eigenaar_gepauzeerd"},
        hub.encoding["banen"][1] | {"wait_reason": None},
    ]
    assert datetime.fromisoformat(measured["observed_at"]) == datetime.fromisoformat(hub.encoding["observed_at"])
    assert [h["encoding"] for h in plan["hours"] if h["encoding"]["status"] == "gemeten"] == [measured]
    assert all(h["slots"] == [] for h in plan["hours"])
    assert hub.calls == [("GET", HTTPS_HUB + NAS), ("GET", HTTPS_HUB + hub.path)]


def test_bestaand_adapteradres_blijft_leesbaar(planner, auth):
    client, hub = planner
    oud_adres = HTTPS_HUB.replace("hub.test", "HUB.test")
    state = client.app.state
    state.hublink_store.update(lambda link: link.model_copy(update={"hub_url": oud_adres}))
    with state.db.sessions.begin() as db:
        db.get_one(IntegrationSource, "mediaguard_encoding").base_url = oud_adres + hub.path
    response = client.get(PLAN, headers=auth("viewer"))
    assert response.status_code == 200 and response.json()["sources"]["mediaguard_encoding"]["status"] == "gemeten"
    assert ("GET", HTTPS_HUB + hub.path) in hub.calls


def test_uitval_en_ingetrokken_dienst_toont_onbekend(planner, auth, fake_hub):
    client, hub = planner
    hub.errors[hub.path] = 403
    partial = client.get(PLAN, headers=auth("viewer")).json()["sources"]
    assert partial["truenas_metrics"]["status"] == "gemeten"
    assert partial["mediaguard_encoding"] == {"status": "onbekend", "observed_at": None, "banen": None}
    for offline in (True, False):
        hub.offline = offline
        if not offline:
            fake_hub.sim.revoke()
        plan = client.get(PLAN, headers=auth("viewer")).json()
        assert (
            plan["sources"]["truenas_metrics"]["status"]
            == plan["sources"]["mediaguard_encoding"]["status"]
            == "onbekend"
        )
        assert len(plan["sources"]["truenas_metrics"]["onbekend"]) == 3
        assert len(plan["hours"]) == 24 and all(h["encoding"]["banen"] is None for h in plan["hours"])


def test_onbruikbare_meetwaarden_en_vrije_brontekst(planner, auth):
    client, hub = planner
    hub.encoding["banen"][0]["reason_nl"] = PRIVATE_TEXT
    hub.encoding["kijkgeschiedenis"] = [PRIVATE_TEXT]
    before = deepcopy(hub.encoding)
    r = client.get(PLAN, headers=auth("viewer"))
    assert PRIVATE_TEXT not in r.text
    lane = r.json()["sources"]["mediaguard_encoding"]["banen"][0]
    assert set(lane) == {"lane", "running", "paused", "wait_reason"} and lane["paused"] is True
    assert hub.encoding == before
    hub.nas["items"][0]["laatste_waarde"] = 125
    hub.nas["items"][1]["observed_at"] = (utcnow() + timedelta(minutes=1)).isoformat()
    hub.encoding["max_age_s"] = 86400
    hub.encoding["observed_at"] = (utcnow() - timedelta(minutes=16)).isoformat()
    sources = client.get(PLAN, headers=auth("viewer")).json()["sources"]
    assert sources["truenas_metrics"]["status"] == "gedeeltelijk"
    assert sources["truenas_metrics"]["onbekend"] == ["cpu.gebruik", "geheugen.beschikbaar_pct"]
    assert sources["mediaguard_encoding"]["status"] == "onbekend" and sources["mediaguard_encoding"]["banen"] is None
    hub.encoding["observed_at"] = utcnow().isoformat()
    hub.encoding["banen"] = [hub.encoding["banen"][0]] * 2
    assert client.get(PLAN, headers=auth("viewer")).json()["sources"]["mediaguard_encoding"]["banen"] is None


def test_bronrechten_en_bevestigd_adres(planner, auth):
    client, hub = planner
    assert client.get(PLAN).status_code == 401
    assert client.get(PLAN, headers=auth("kind")).status_code == 403
    for address in (
        HTTPS_HUB.replace("hub.test", "andere.test") + hub.path,
        HUB_URL + hub.path,
        HTTPS_HUB + "/api/v1/services",
    ):
        r = client.put(
            SOURCE, json={"base_url": address, "enabled": True}, headers=idem(auth("admin"), **{"If-Match": "*"})
        )
        assert r.status_code == 422
    assert not hub.calls
    client.app.state.hublink_store.update(lambda current: current.model_copy(update={"confirmed_at": None}))
    assert client.get(PLAN, headers=auth("viewer")).json()["sources"]["truenas_metrics"]["status"] == "onbekend"
    assert not hub.calls


def test_planregel_alleen_op_gelijktijdige_minuten_en_geen_vrije_wachtreden(linked, auth):
    # Bestaande rijen mogen eigen ID's, historische statussen en een vrije wachtreden hebben.
    with linked.app.state.db.sessions.begin() as db:
        stream = EnergyWorkload(owner_app="jelly-leon", workload_key="transcode", priority_class="interactief")
        encode = EnergyWorkload(owner_app="media-guard-ultimate", workload_key="av1", priority_class="achtergrond")
        db.add_all([stream, encode])
        db.flush()
        background = uuid4()
        for w, start, end, status, id_ in (
            (stream, 10, 25, "actief", uuid4()),
            (stream, 30, 40, "voorstel", uuid4()),
            (encode, 0, 55, "gepland", background),
            (encode, 65, 70, "wacht", uuid4()),
        ):
            db.add(
                EnergyWorkloadReservation(
                    id=id_,
                    workload_id=w.id,
                    window_start=DAY + timedelta(minutes=start),
                    window_end=DAY + timedelta(minutes=end),
                    status=status,
                    wait_reason_nl=PRIVATE_TEXT,
                    resources={"privé": PRIVATE_TEXT},
                )
            )
    r = linked.get(PLAN, params={"date": DAY.date().isoformat()}, headers=auth("viewer"))
    assert r.status_code == 200 and PRIVATE_TEXT not in r.text
    plan = r.json()
    slots = [s for s in plan["hours"][0]["slots"] if s["reservation_id"] == str(background)]
    assert [
        (
            datetime.fromisoformat(s["start"]).minute,
            datetime.fromisoformat(s["end"]).minute,
            s["status"],
            s["wait_reason"],
        )
        for s in slots
    ] == [(0, 10, "gepland", None), (10, 25, "wacht", "interactieve_werklast"), (25, 55, "gepland", None)]
    assert plan["hours"][1]["slots"][0]["wait_reason"] == "onbekend"
    assert [r["status"] for r in plan["reservations"] if r["id"] == str(background)] == ["gepland"]
    assert len([w for w in plan["items"] if w["workload_key"] == "av1"]) == 1
    with linked.app.state.db.sessions() as db:
        assert db.get(EnergyWorkloadReservation, background).status == "gepland"


@pytest.mark.parametrize(("day", "count"), [("2026-03-29", 23), ("2026-10-25", 25)])
def test_planner_volgt_lokale_daggrenzen(linked, auth, day, count):
    r = linked.get(PLAN, params={"date": day, "timezone": "Europe/Amsterdam"}, headers=auth("viewer"))
    assert r.status_code == 200
    hours = r.json()["hours"]
    assert len(hours) == count and all(h["end"] == n["start"] for h, n in itertools.pairwise(hours))


def test_openapi_energie_heeft_alleen_leesroutes_en_de_bestaande_drempelinstelling():
    paths = json.loads((REPO_ROOT / "docs/openapi/home-control-hub.openapi.json").read_text())["paths"]
    assert set(paths[PLAN]) == {"get"}
    assert {(p, m) for p, ops in paths.items() if p.startswith(ENERGY + "/") for m in ops if m != "get"} == {
        (ENERGY + "/alert-thresholds", "put")
    }


PROPOSE = "/connector/v1/propose"
ACTION = "energy.reservations.propose"


def proposal(plan, start=DAY, end=DAY + timedelta(hours=1), workload="av1"):
    choice = next(w for w in plan["items"] if w["workload_key"] == workload)
    return {
        "action_id": ACTION,
        "parameters": {"workload_id": choice["id"], "window_start": start.isoformat(), "window_end": end.isoformat()},
    }


def test_r1_voorstel_replay_audit_en_geen_uitvoering(planner, auth, fake_hub):
    client, hub = planner
    assert (
        client.get("/connector/v1/discover", headers=auth("viewer"))
        .json()["actions"]
        .count(
            {
                "action_id": ACTION,
                "title_nl": "Reserveringsvenster voorstellen",
                "task_id": "B14-003",
                "risk_class_min": "R1",
                "apply_status": "alleen_voorstel",
            }
        )
        == 1
    )
    day = {"date": DAY.date().isoformat()}
    request = proposal(client.get(PLAN, params=day, headers=auth("viewer")).json())
    request.update(risk_claim="R0", reason=PRIVATE_TEXT)
    before = deepcopy(hub.encoding)
    hub.calls.clear()
    assert client.post(PROPOSE, json=request, headers=idem(auth("viewer"))).status_code == 403
    assert client.post(PROPOSE, json=request, headers=auth("admin")).status_code == 400
    key = str(uuid4())
    r = client.post(PROPOSE, json=request, headers=idem(fake_hub.service_auth(), key))
    assert r.status_code == 201, r.text
    saved = r.json()
    assert saved["status"] == "voorstel" and saved["risk_class_min"] == saved["risk_claim"] == "R1"
    assert saved["apply_status"] == "alleen_voorstel" and saved["diff"][0]["after"]["status"] == "voorstel"
    assert r.headers["ETag"] == f'"{saved["preview_hash"]}"' and PRIVATE_TEXT not in r.text
    again = client.post(PROPOSE, json=request, headers=idem(fake_hub.service_auth(), key))
    assert again.status_code == 201 and again.json() == saved and again.headers["Idempotent-Replay"] == "true"
    apply = client.post("/connector/v1/apply", json={"proposal": saved}, headers=idem(fake_hub.service_auth()))
    assert apply.status_code == 501 and apply.json()["code"] == "capability_unavailable"
    assert not hub.calls
    plan = client.get(PLAN, params=day, headers=auth("viewer")).json()
    assert [r["id"] for r in plan["reservations"]] == [saved["proposal_id"]]
    assert plan["hours"][0]["slots"][0]["status"] == "voorstel" and not plan["hours"][1]["slots"]
    with client.app.state.db.sessions() as db:
        row = db.get(EnergyWorkloadReservation, UUID(saved["proposal_id"]))
        assert row.status == "voorstel" and row.wait_reason_nl is None and row.resources == {}
        audit = db.scalars(select(AuditEvent).where(AuditEvent.action == "reservation.proposed")).one()
        assert audit.entity_id == saved["proposal_id"] and PRIVATE_TEXT not in json.dumps(audit.details)
    assert hub.calls == [("GET", HTTPS_HUB + NAS), ("GET", HTTPS_HUB + hub.path)] and hub.encoding == before


def test_overlap_grenzen_doel_en_parametercontrole(linked, auth):
    client = linked
    plan = client.get(PLAN, headers=auth("viewer")).json()
    body = proposal(plan)
    p = body["parameters"]

    def send(b):
        return client.post(PROPOSE, json=b, headers=idem(auth("admin")))

    assert send(body | {"target": {"app_id": "onbekend"}}).status_code == 422
    for change in (
        {"window_start": "2026-10-25T01:00:00"},
        {"window_end": p["window_start"]},
        {"status": "actief"},
        {"wait_reason_nl": PRIVATE_TEXT},
        {"window_start": 0},
    ):
        assert send(body | {"parameters": p | change}).status_code == 422
    assert send(body | {"parameters": p | {"workload_id": str(uuid4())}}).status_code == 404
    assert send(body | {"expected_version": "verouderd"}).status_code == 409
    assert send(body).status_code == 201
    for start, end in ((-30, 1), (0, 60), (10, 20), (59, 70), (-1, 61)):
        r = send(proposal(plan, DAY + timedelta(minutes=start), DAY + timedelta(minutes=end)))
        assert r.status_code == 409 and r.json()["code"] == "reservering_overlapt"
    assert send(proposal(plan, DAY + timedelta(hours=1), DAY + timedelta(hours=2))).status_code == 201
    assert send(proposal(plan, workload="backup")).status_code == 201
    assert (
        len(client.get(PLAN, params={"date": DAY.date().isoformat()}, headers=auth("viewer")).json()["reservations"])
        == 3
    )


@pytest.mark.parametrize("same_key", [False, True])
def test_gelijktijdig_eerste_voorstel_is_atomair(linked, auth, same_key):
    plan = linked.get(PLAN, headers=auth("viewer")).json()
    body = proposal(plan)
    first = str(uuid4())
    start = Barrier(2)

    def send(key):
        headers = idem(auth("admin"), key)
        start.wait(timeout=10)
        return linked.post(PROPOSE, json=body, headers=headers)

    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(send, (first, first if same_key else str(uuid4()))))
    assert sorted(r.status_code for r in replies) == ([201, 201] if same_key else [201, 409])
    if same_key:
        assert replies[0].json() == replies[1].json()
        assert sum(r.headers.get("Idempotent-Replay") == "true" for r in replies) == 1
    with linked.app.state.db.sessions() as db:
        assert len(db.scalars(select(EnergyWorkloadReservation)).all()) == 1
        assert len(db.scalars(select(AuditEvent).where(AuditEvent.action == "reservation.proposed")).all()) == 1


def test_voor_na_kijkgegevens_voortgang_en_mediabestand(planner, auth, tmp_path):
    client, hub = planner
    state_file = tmp_path / "eigenaar.json"
    media = tmp_path / "testmedia"
    media.write_bytes(b"synthetische mediainhoud")
    state_file.write_text(
        json.dumps(
            {
                "mediaserver": "actief",
                "stream": True,
                "kijkers": [{"gezien": True, "favoriet": False}, {"gezien": False, "hervatpunt": 40}],
                "av1": [{"lane": "cpu", "checkpoint": 37}, {"lane": "gpu", "checkpoint": 68}],
            }
        )
    )
    before = state_file.read_bytes(), media.read_bytes()

    def source_read(request):
        if request.url.path == hub.path:
            owner = json.loads(state_file.read_text())
            # De eigenaar levert de pauzestand en houdt zelf de checkpoints en kijkgegevens.
            hub.encoding["banen"] = [
                {"lane": job["lane"], "running": int(not owner["stream"]), "paused": owner["stream"]}
                for job in owner["av1"]
            ]
        return hub.handle(request)

    client.app.state.hub.transport = httpx.MockTransport(source_read)
    first = client.get(PLAN, headers=auth("viewer")).json()
    saved = client.post(PROPOSE, json=proposal(first), headers=idem(auth("admin")))
    assert saved.status_code == 201
    assert (
        client.post("/connector/v1/apply", json={"proposal": saved.json()}, headers=idem(auth("admin"))).status_code
        == 501
    )
    last = client.get(PLAN, headers=auth("viewer")).json()
    assert first["sources"] == last["sources"]
    assert all(b["wait_reason"] == "eigenaar_gepauzeerd" for b in last["sources"]["mediaguard_encoding"]["banen"])
    assert len(last["sources"]["mediaguard_encoding"]["banen"]) == 2
    assert hub.calls == [("GET", HTTPS_HUB + NAS), ("GET", HTTPS_HUB + hub.path)] * 2
    assert (state_file.read_bytes(), media.read_bytes()) == before
