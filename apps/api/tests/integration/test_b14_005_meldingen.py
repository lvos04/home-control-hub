"""B14-005 / EX27. Van beheerdrempels en gesimuleerde bronmetingen tot de uitgaande contract-envelope."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime, timedelta
from threading import Barrier
from uuid import UUID, uuid4

import httpx
import pytest
from sqlalchemy import select

from integrations import events
from integrations.domains.energy.alerts import SETTINGS_KEY, notify_changes
from integrations.domains.energy.models import EnergyUsageInterval
from integrations.domains.energy.usage_sync import STATE_KEY
from integrations.models import AuditEvent, IntegrationSource, OutboxEvent, ServiceState
from integrations.worker import Worker
from tests.b11 import envelope
from tests.conftest import ENV_TOKEN, REPO_ROOT, envelope_problems, idem
from tests.fakes.my_house_energy import MyHouseEnergy
from tests.integration.test_b14_001_dekkingsmatrix import ENERGY, configure, energieblok
from tests.integration.test_b14_002_tijdreeks import hours, row

THRESHOLDS = ENERGY + "/alert-thresholds"
LIMITS = {"offline_after_minutes": 60, "boiler_increase_kwh": 1, "nas_increase_points": 20, "daily_budget_eur": 6}
DAY = date(2026, 5, 12)


def install(client, auth):
    response = client.put(THRESHOLDS, json=LIMITS, headers=idem(auth("admin")))
    assert response.status_code == 200, response.text
    return response


def outgoing(client):
    with client.app.state.db.sessions() as db:
        return [
            events.envelope(e)
            for e in db.scalars(
                select(OutboxEvent)
                .where(OutboxEvent.event_type.like("energy.%"), OutboxEvent.event_type != "energy.source.configured")
                .order_by(OutboxEvent.seq)
            )
        ]


def statuses(client, auth):
    response = client.get(ENERGY + "/alerts", headers=auth("viewer"))
    assert response.status_code == 200, response.text
    return {(r["rule"], r["role"]): r["status"] for r in response.json()["items"]}


def types(client):
    return [e["event_type"] for e in outgoing(client)]


@pytest.fixture
def house(linked, auth):
    fake = MyHouseEnergy()
    assert configure(linked, auth, fake).status_code == 201
    fake.summary["meters"].append({"role": "boiler", "unit": "kWh"})
    fake.tariffs = [{"valid_from": DAY.isoformat(), "import_per_kwh": 1}]
    return fake


def supply(house, count, *, peak=True, grid=2):
    house.hour_rows[DAY] = [
        reading
        for i, stamp in enumerate(hours(DAY)[:count])
        for reading in (row(stamp, grid), row(stamp, 5 if peak and i >= 5 else 1, role="boiler", device="testmeter B"))
    ]


@pytest.fixture
def tick(linked, house, fake_hub, monkeypatch):
    transport = httpx.MockTransport(
        lambda req: house.handle(req) if req.url.host == "woning.test" else fake_hub.handler(req)
    )

    def run(at):
        monkeypatch.setattr("integrations.worker.utcnow", lambda: at)
        monkeypatch.setattr("integrations.domains.energy.router.utcnow", lambda: at)
        # De nieuwe worker kan zich alleen op de bewaarde incidenttoestand baseren.
        worker = Worker(linked.app.state.settings, transport)
        try:
            worker.energy_step(1)
        finally:
            worker.db.dispose()

    return run


def test_drempels_rechten_validatie_en_herhaling(linked, auth):
    assert linked.get(THRESHOLDS, headers=auth("admin")).json() is None
    for role in ("viewer", "operator", "kind"):
        assert linked.put(THRESHOLDS, json=LIMITS, headers=idem(auth(role))).status_code == 403
    assert linked.put(THRESHOLDS, json=LIMITS, headers=auth("admin")).status_code == 400
    for change in (
        {"offline_after_minutes": -1},
        {"offline_after_minutes": True},
        {"boiler_increase_kwh": 0},
        {"nas_increase_points": 101},
        {"daily_budget_eur": -1},
        {"daily_budget_eur": "6"},
        {"schakelen": True},
    ):
        assert linked.put(THRESHOLDS, json=LIMITS | change, headers=idem(auth("admin"))).status_code == 422
    assert linked.get(THRESHOLDS, headers=auth("admin")).json() is None
    key = str(uuid4())
    for _ in range(2):
        result = linked.put(THRESHOLDS, headers=idem(auth("admin"), key=key), json=LIMITS)
        assert result.status_code == 200 and result.json() == LIMITS and result.headers["etag"] == 'W/"1"'
    changed = LIMITS | {"daily_budget_eur": 10}
    assert linked.put(THRESHOLDS, headers=idem(auth("admin"), key=key), json=changed).status_code == 422
    assert linked.put(THRESHOLDS, headers=idem(auth("admin")), json=changed).status_code == 428
    assert linked.put(THRESHOLDS, headers=idem(auth("admin"), **{"If-Match": 'W/"8"'}), json=changed).status_code == 412
    with linked.app.state.db.sessions() as db:
        assert len(db.scalars(select(AuditEvent).where(AuditEvent.action == "thresholds.updated")).all()) == 1
    updated = linked.put(THRESHOLDS, headers=idem(auth("admin"), **{"If-Match": 'W/"1"'}), json=changed)
    assert updated.status_code == 200 and updated.headers["etag"] == 'W/"2"'
    assert linked.get(THRESHOLDS, headers=auth("admin")).json() == changed


def test_openapi_energie_en_boiler_alleen_meten():
    paths = json.loads((REPO_ROOT / "docs/openapi/home-control-hub.openapi.json").read_text())["paths"]
    writes = {"post", "put", "patch", "delete"}
    energy = {p: ops for p, ops in paths.items() if p.startswith(ENERGY + "/")}
    assert {p for p, ops in energy.items() if "get" in ops} >= {
        ENERGY + "/meters",
        ENERGY + "/usage",
        ENERGY + "/alerts",
    }
    assert {(p, method) for p, ops in energy.items() for method in writes & ops.keys()} == {(THRESHOLDS, "put")}
    assert all(not writes.intersection(ops) for p, ops in paths.items() if "boiler" in p.lower())


def test_gelijktijdige_eerste_instelling_heeft_een_versie_en_auditregel(linked, auth):
    key = str(uuid4())
    barrier = Barrier(2, timeout=10)

    def put():
        headers = idem(auth("admin"), key=key)
        barrier.wait()
        return linked.put(THRESHOLDS, headers=headers, json=LIMITS)

    with ThreadPoolExecutor(max_workers=2) as pool:
        requests = [pool.submit(put) for _ in range(2)]
        for request in requests:
            response = request.result(timeout=15)
            assert response.status_code == 200 and response.headers["ETag"] == 'W/"1"'
    with linked.app.state.db.sessions() as db:
        assert len(db.scalars(select(AuditEvent).where(AuditEvent.action == "thresholds.updated")).all()) == 1


def test_verouderd_geeft_alleen_meteruitval_en_herstel(linked, auth, house, tick):
    install(linked, auth)
    supply(house, 6)
    stamp = hours(DAY)[6]
    tick(stamp + timedelta(hours=2))
    expected = ["energy.meter_offline.down"] * 2
    assert types(linked) == expected
    view = statuses(linked, auth)
    assert view["meter_offline", "p1_net"] == view["meter_offline", "boiler_socket"] == "afwijkend"
    assert view["meter_offline", "airco_outdoor"] == "onbekend"
    assert view["daily_budget", "p1_net"] == view["boiler_usage", "boiler_socket"] == "onbekend"
    tick(stamp + timedelta(hours=3))
    assert types(linked) == expected
    supply(house, 10, peak=False, grid=0.25)
    tick(stamp + timedelta(hours=4))
    assert types(linked) == expected + ["energy.meter_offline.recovered"] * 2
    records = outgoing(linked)
    assert [r["entity"] for r in records[:2]] == [r["entity"] for r in records[2:]]
    assert len({r["entity"]["id"] for r in records}) == 2


def test_bekende_meter_zonder_eerste_meting_krijgt_eerst_de_wachttijd(linked, auth, tick):
    install(linked, auth)
    stamp = hours(DAY)[4]
    tick(stamp)
    assert statuses(linked, auth)["meter_offline", "p1_net"] == "onbekend"
    tick(stamp + timedelta(minutes=60))
    assert not outgoing(linked)
    tick(stamp + timedelta(minutes=61))
    assert types(linked) == ["energy.meter_offline.down"] * 2


def snapshot(db):
    intervals = db.scalars(select(EnergyUsageInterval).order_by(EnergyUsageInterval.id))
    return [(r.id, r.meter_id, r.start_utc, r.end_utc, r.delta, r.quality, r.source_ref) for r in intervals]


def test_statuspagina_toont_open_meldingen_tot_herstel_en_behoudt_archief(linked, auth, house, tick):
    install(linked, auth)
    supply(house, 6)
    stamp = hours(DAY)[6] + timedelta(minutes=2)
    tick(stamp)
    with linked.app.state.db.sessions() as db:
        voor = snapshot(db)
        assert sum(r[4] is not None for r in voor) == 12
    meldingen = outgoing(linked)
    assert len(meldingen) == 2
    assert linked.get(ENERGY + "/meters", headers=auth("viewer")).status_code == 200
    blok = energieblok(linked)
    assert "Afwijkend boilerverbruik" in blok and "Dagbudget overschreden" in blok
    assert all(x not in blok for x in ("EUR", "€", "testmeter B", "<form", "<button"))
    with linked.app.state.db.sessions() as db:
        assert snapshot(db) == voor
    assert outgoing(linked) == meldingen
    house.status = 503
    tick(stamp + timedelta(minutes=1))
    assert "Afwijkend boilerverbruik" in energieblok(linked)
    house.status = 200
    supply(house, 10, peak=False, grid=0.25)
    tick(hours(DAY)[10])
    assert "Geen openstaande afwijkingen geregistreerd." in energieblok(linked)
    supply(house, 12)
    tick(hours(DAY)[12])
    assert "Dagbudget overschreden" in energieblok(linked)
    assert configure(linked, auth, MyHouseEnergy()).is_success
    assert "Dagbudget overschreden" not in energieblok(linked)


def test_aanhoudende_piek_een_event_ook_na_herstart_en_geen_persoonsgegevens(linked, auth, house, tick):
    supply(house, 6)
    stamp = hours(DAY)[6] + timedelta(minutes=2)
    tick(stamp)
    with linked.app.state.db.sessions() as db:
        before = snapshot(db)
        archive = db.get(ServiceState, STATE_KEY)
        archive.value = {k: v for k, v in archive.value.items() if k not in ("scope", "watch_since")}
        db.commit()  # archief in de vorm van vóór B14-005
    assert sum(r[4] is not None for r in before) == 12 and not outgoing(linked)
    install(linked, auth)
    tick(stamp)
    with linked.app.state.db.sessions() as db:
        after = set(snapshot(db))
        assert set(before) <= after
        # De reguliere archiefronde mag ook onbekende uren van een eerdere woningdag aanvullen.
        assert all(r[4] is None and r[5] == "onbekend" for r in after.difference(before))
    failed = sorted(["energy.boiler_usage.degraded", "energy.daily_budget.degraded"])
    for count in (6, 7, 8, 9):
        supply(house, count)
        tick(hours(DAY)[count] + timedelta(minutes=2))
        assert sorted(types(linked)) == failed
    house.status = 503
    tick(hours(DAY)[9] + timedelta(minutes=5))
    assert statuses(linked, auth)["boiler_usage", "boiler_socket"] == "onbekend"
    assert sorted(types(linked)) == failed
    house.status = 200
    supply(house, 10, peak=False, grid=0.25)
    tick(hours(DAY)[10])
    records = outgoing(linked)
    assert len(records) == 4
    for rule, role in (("boiler_usage", "boiler_socket"), ("daily_budget", "p1_net")):
        problem, recovery = [e for e in records if e["payload"]["regel"] == rule]
        assert [events.event_role(e["event_type"]) for e in (problem, recovery)] == ["probleem", "herstel"]
        assert problem["entity"] == recovery["entity"]
        UUID(problem["entity"]["id"])
        for e, severity in ((problem, "middel"), (recovery, "info")):
            assert not envelope_problems(e)
            assert e["actor"] == {"type": "system", "id": "home-control-hub:worker"}
            assert e["payload"] == {"regel": rule, "rol": role, "bron": "my_house", "ernst": severity}
            assert all(s not in json.dumps(e) for s in (house.token, house.address, str(house.home), "testmeter B"))
    assert {method for method, _ in house.calls} == {"GET"}


def test_dagbudget_begint_op_de_nieuwe_woningdag(linked, auth, house, tick):
    install(linked, auth)
    supply(house, 24, peak=False)
    morgen = DAY + timedelta(days=1)
    middernacht = hours(morgen)[0]
    regel = ("daily_budget", "p1_net")
    tick(middernacht - timedelta(minutes=5))
    assert statuses(linked, auth)[regel] == "afwijkend"
    tick(middernacht + timedelta(minutes=5))
    assert statuses(linked, auth)[regel] == "onbekend"
    house.hour_rows[morgen] = [row(middernacht, 1)]
    tick(middernacht + timedelta(hours=1))
    assert statuses(linked, auth)[regel] == "normaal"


def test_onvolledig_ongeprijsd_en_geschat_blijven_onbekend(linked, auth, house, tick):
    install(linked, auth)
    supply(house, 6)
    first, last = hours(DAY)[0], hours(DAY)[5]
    house.hour_rows[DAY] = [r for r in house.hour_rows[DAY] if (r["role"], r["at"]) != ("grid", first.isoformat())]
    house.hour_rows[DAY][-1]["quality"] = "estimated"
    tick(last + timedelta(hours=1))
    state = statuses(linked, auth)
    assert state["daily_budget", "p1_net"] == state["boiler_usage", "boiler_socket"] == "onbekend"
    supply(house, 6, peak=False)
    house.tariffs = []
    tick(last + timedelta(hours=1))
    assert statuses(linked, auth)["daily_budget", "p1_net"] == "onbekend" and not outgoing(linked)


def test_actieve_bron_zonder_viewerkoppeling_geeft_geen_verbruiksmelding(linked, auth, house, tick):
    supply(house, 6)
    stamp = hours(DAY)[6]
    tick(stamp)
    install(linked, auth)
    with linked.app.state.db.sessions() as db:
        db.get(IntegrationSource, "my_house").credential_ref = None
        db.commit()
    tick(stamp)
    state = statuses(linked, auth)
    assert state["boiler_usage", "boiler_socket"] == state["daily_budget", "p1_net"] == "onbekend"
    assert not outgoing(linked)


def cpu(stamp, value, **extra):
    item = envelope(
        "monitoring.metric.recorded",
        source_app="ai-server-manager",
        entity={"type": "nas", "id": "nas"},
        payload={
            "metriek": "cpu.gebruik",
            "eenheid": "%",
            "status": "ok",
            "waarde": value,
            "observed_at": stamp.isoformat(),
            "naam": "testonderwerp",
            "adres": "woning.test",
            "credential": ENV_TOKEN,
            **extra,
        },
    )
    item["timestamp_utc"] = stamp.isoformat()
    return item


def test_nas_groei_uit_de_hub_geen_herstel_bij_veroudering(linked, auth, fake_hub, tick):
    install(linked, auth)
    start = datetime.now(UTC) + timedelta(minutes=1)
    path = "/integrations/v1/automation/events"
    assert linked.post(path, json=cpu(start, 99), headers=idem(auth("viewer"))).status_code == 403
    assert statuses(linked, auth)["nas_load", "nas"] == "onbekend"
    for i, n in enumerate((30, 40, 50, 70, 72)):
        at = start + timedelta(minutes=5 * i)
        assert linked.post(path, json=cpu(at, n), headers=idem(fake_hub.service_auth())).status_code == 201
        tick(at + timedelta(seconds=10))
    assert types(linked) == ["energy.nas_load.degraded"]
    assert statuses(linked, auth)["nas_load", "nas"] == "afwijkend"
    at = start + timedelta(minutes=40)
    tick(at)
    assert statuses(linked, auth)["nas_load", "nas"] == "onbekend"
    assert types(linked) == ["energy.nas_load.degraded"]
    readings = ((101, {}), (0, {"status": "unknown"}), (35, {"observed_at": start.isoformat()}), (35, {}))
    for i, (value, metadata) in enumerate(readings):
        stamp = at + timedelta(minutes=i)
        assert (
            linked.post(path, json=cpu(stamp, value, **metadata), headers=idem(fake_hub.service_auth())).status_code
            == 201
        )
        tick(stamp)
        if i < len(readings) - 1:
            assert statuses(linked, auth)["nas_load", "nas"] == "onbekend"
            assert types(linked) == ["energy.nas_load.degraded"]
    problem, recovery = outgoing(linked)
    assert recovery["event_type"] == "energy.nas_load.recovered" and problem["entity"] == recovery["entity"]
    for e, severity in ((problem, "middel"), (recovery, "info")):
        assert not envelope_problems(e)
        assert e["payload"] == {"regel": "nas_load", "rol": "nas", "bron": "truenas_metrics", "ernst": severity}
        assert all(s not in json.dumps(e) for s in (ENV_TOKEN, "woning.test", "testonderwerp"))


def test_mislukte_transactie_laat_geen_half_incident_achter(linked, auth, house, tick, monkeypatch):
    install(linked, auth)
    supply(house, 6)
    stamp = hours(DAY)[6]
    emit = events.emit

    def fail_second(db, **kwargs):
        if kwargs["event_type"] == "energy.daily_budget.degraded":
            raise RuntimeError("Gesimuleerde schrijffout")
        return emit(db, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(events, "emit", fail_second)
        with pytest.raises(RuntimeError, match="Gesimuleerde schrijffout"):
            tick(stamp)
    with linked.app.state.db.sessions() as db:
        assert not db.get(ServiceState, SETTINGS_KEY).value.get("open")
    assert not outgoing(linked)
    tick(stamp)
    assert len(outgoing(linked)) == 2


def test_twee_workers_melden_een_overgang(linked, auth, house, tick):
    supply(house, 6)
    stamp = hours(DAY)[6]
    tick(stamp)
    install(linked, auth)
    barrier = Barrier(2, timeout=10)
    link = linked.app.state.hublink_store.read()

    def run():
        with linked.app.state.db.sessions() as db:
            barrier.wait()
            notify_changes(db, stamp, link)

    with ThreadPoolExecutor(max_workers=2) as pool:
        workers = [pool.submit(run) for _ in range(2)]
        for worker in workers:
            worker.result(timeout=15)
    assert sorted(types(linked)) == ["energy.boiler_usage.degraded", "energy.daily_budget.degraded"]
