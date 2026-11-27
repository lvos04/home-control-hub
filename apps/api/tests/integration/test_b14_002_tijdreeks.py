"""B14-002. Van de viewer-export via de worker en PostgreSQL tot het perioderapport."""

from __future__ import annotations

import random
from datetime import UTC, date, datetime, time, timedelta
from time import monotonic
from typing import Any
from uuid import NAMESPACE_DNS, uuid4, uuid5
from zoneinfo import ZoneInfo

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from integrations.domains.energy.models import EnergyMeter, EnergyMeterRole, EnergyTariff, EnergyUsageInterval
from integrations.models import ServiceState
from integrations.worker import HEARTBEAT_KEY, Worker
from tests.fakes.my_house_energy import MyHouseEnergy
from tests.integration.test_b14_001_dekkingsmatrix import ENERGY, configure

ZONE = ZoneInfo("Europe/Amsterdam")
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)


def hours(day: date, zone: ZoneInfo = ZONE) -> list[datetime]:
    start = datetime.combine(day, time.min, zone).astimezone(UTC)
    end = datetime.combine(day + DAY, time.min, zone).astimezone(UTC)
    return [start + i * HOUR for i in range((end - start) // HOUR)]


def row(at: datetime, value: Any = 1, quality: str = "measured", **fields: Any) -> dict[str, Any]:
    return {
        "at": at.isoformat(),
        "role": "grid",
        "device": "testmeter A",
        "meter_id": str(uuid5(NAMESPACE_DNS, fields.get("device", "testmeter A"))),
        "metric": "energy_import_kwh",
        "unit": "kWh",
        "value": value,
        "quality": quality,
        "notes": "",
        **fields,
    }


@pytest.fixture
def source(linked, auth):
    fake = MyHouseEnergy()
    assert configure(linked, auth, fake).status_code == 201
    return fake


@pytest.fixture
def sync(linked, source, monkeypatch, fake_hub):
    transport = httpx.MockTransport(lambda r: source.handle(r) if r.url.host == "woning.test" else fake_hub.handler(r))
    worker = Worker(linked.app.state.settings, transport)
    ticks = monotonic()

    def run(day: date, *, full: bool = False, zone: ZoneInfo = ZONE):
        nonlocal ticks
        ticks += 3600
        now = datetime.combine(day + DAY, time(0, 5), zone).astimezone(UTC)
        monkeypatch.setattr("integrations.worker.utcnow", lambda: now)
        if full:
            worker.run_once()
        else:
            worker.energy_step(ticks)

    yield run
    worker.db.dispose()


def report(client, auth, day, period="day", direction="import"):
    r = client.get(
        ENERGY + "/usage",
        headers=auth("viewer"),
        params={
            "period": period,
            "date": day.isoformat(),
            "direction": direction,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def test_energiestoring_blijft_in_hartslag_tot_nieuwe_meting(linked, source, fake_hub):
    transport = httpx.MockTransport(lambda r: source.handle(r) if r.url.host == "woning.test" else fake_hub.handler(r))
    worker = Worker(linked.app.state.settings, transport)
    try:
        source.summary_status = 403
        worker.run_once()

        def mislukt():
            with linked.app.state.db.sessions() as db:
                return db.get(ServiceState, HEARTBEAT_KEY).value["mislukte_stappen"]

        assert "energie" in mislukt()
        source.summary_status = 200
        worker.run_once()
        assert "energie" in mislukt()
        worker.state.next_energy_sync = 0
        worker.run_once()
        assert "energie" not in mislukt()
    finally:
        worker.db.dispose()


def test_onbekend_queryveld_geweigerd_voor_bronverzoek(linked, auth, source, sync):
    day = date(2026, 4, 8)
    sync(day)
    assert report(linked, auth, day)["role"] == "p1_net"
    checks = list(source.checks)
    url = ENERGY + "/usage?rol=airco_outdoor"
    assert linked.get(url).status_code == 401
    assert linked.get(url, headers=auth("kind")).status_code == 403
    response = linked.get(url, headers=auth("viewer"))
    assert (response.status_code, response.json()["code"]) == (422, "validation_error")
    assert source.checks == checks


def test_onbereikbaar_archief_geeft_503_zonder_bronverzoek(linked, auth, source, monkeypatch):
    def offline(*args, **kwargs):
        raise OperationalError(None, None, OSError("proefarchief offline"))

    checks = list(source.checks)
    monkeypatch.setattr(Session, "scalar", offline)
    with TestClient(linked.app, raise_server_exceptions=False) as client:
        response = client.get(ENERGY + "/usage", headers=auth("viewer"))
    assert (response.status_code, response.json()["code"]) == (503, "dependency_unavailable")
    assert int(response.headers["Retry-After"]) > 0 and source.checks == checks


@pytest.mark.parametrize(("day", "count"), [(date(2026, 3, 29), 23), (date(2026, 10, 25), 25)])
def test_lokale_dag_en_herhaling(linked, auth, source, sync, day, count):
    stamps = hours(day)
    source.hour_rows[day] = [row(t, i + 0.1234) for i, t in enumerate(stamps)]
    sync(day, full=True)
    first = report(linked, auth, day)
    assert first["timezone"] == ZONE.key and first["status"] == "volledig"
    assert first["usage"]["value"] == pytest.approx(sum(range(count)) + count * 0.1234)
    assert first["usage"]["quality"] == "gemeten" and first["usage"]["source"]
    slots = first["days"][0]["hours"]
    assert len(slots) == count
    assert [datetime.fromisoformat(s["start_utc"]) for s in slots] == stamps
    assert all(s["usage"]["source"] and s["usage"]["quality"] == "gemeten" for s in slots)
    assert first["cost"]["value"] is None and first["cost"]["quality"] == "onbekend"
    sync(day)
    with linked.app.state.db.sessions() as db:
        stored = db.scalars(
            select(EnergyUsageInterval).where(
                EnergyUsageInterval.direction == "import",
                EnergyUsageInterval.start_utc >= stamps[0],
                EnergyUsageInterval.start_utc < stamps[-1] + HOUR,
            )
        ).all()
        assert len(stored) == count and len({i.start_utc.astimezone(UTC) for i in stored}) == count
        assert all(i.source_ref and i.counter_start is None and i.counter_end is None for i in stored)
    assert report(linked, auth, day) == first


def test_gat_reset_correctie_en_ontbrekende_waarde(linked, auth, source, sync):
    day = date(2026, 4, 8)
    stamps = hours(day)
    rows = [row(t) for t in stamps]
    rows[0] = row(stamps[0], 0)
    rows[4] = row(stamps[4], 2, notes="tellerreset gedetecteerd")
    rows[6] = row(stamps[6], 0, notes="tellerreset; interval overgeslagen")
    rows[7] = row(stamps[7], -3)
    del rows[8]["value"]
    rows[9] = row(stamps[9], None)
    rows[10] = row(stamps[10], 3, quality="missing")
    rows[11] = row(stamps[11], 1, quality="estimated")
    rows[12] = row(stamps[12], False)
    rows[13] = row(stamps[13], 2, notes="ontbrekende metingen")
    rows[14] = row(stamps[14], 2, notes="deels geschat")
    del rows[3]
    source.hour_rows[day] = [*rows, rows[0]]
    sync(day)
    result = report(linked, auth, day)
    assert result["status"] == result["days"][0]["status"] == "onvolledig"
    assert result["usage"]["value"] is None and result["usage"]["quality"] == "onbekend"
    slots = result["days"][0]["hours"]
    assert slots[0]["usage"]["value"] == 0
    assert slots[4]["counter_reset"] and slots[4]["usage"]["value"] == 2
    assert slots[6]["counter_reset"] and slots[11]["usage"]["quality"] == "geschat"
    assert slots[14]["usage"]["quality"] == "geschat"
    for i in (3, 6, 7, 8, 9, 10, 12, 13):
        assert slots[i]["usage"]["value"] is None and slots[i]["usage"]["quality"] == "onbekend"
    with linked.app.state.db.sessions() as db:
        gap = db.scalars(
            select(EnergyUsageInterval).where(
                EnergyUsageInterval.start_utc == stamps[3],
                EnergyUsageInterval.direction == "import",
            )
        ).one()
        assert gap.delta is None and gap.quality == "onbekend" and gap.meter_id is None
    source.hour_rows[day] = [row(t, 0.5, "estimated" if i == 11 else "measured") for i, t in enumerate(stamps)]
    sync(day)
    result = report(linked, auth, day)
    assert result["usage"]["value"] == 12 and result["usage"]["quality"] == "geschat"


def test_meterwissel_maand_teruglevering_en_weekgrenzen(linked, auth, source, sync):
    first = date(2026, 2, 1)
    for offset in range(28):
        day = first + offset * DAY
        device = "testmeter A" if offset < 14 else "testmeter B"
        source.hour_rows[day] = [row(t, device=device) for t in hours(day)]
        source.hour_rows[day] += [row(t, 0.25, device=device, metric="energy_export_kwh") for t in hours(day)]
    # De nieuwe meter komt het eerst binnen. Middagen opnieuw ophalen mag de keten niet omkeren.
    for offset in [*range(14, 28), *range(14)]:
        sync(first + offset * DAY)
    data = report(linked, auth, first, "month")
    assert data["usage"]["value"] == 28 * 24 and len(data["days"]) == 28
    assert report(linked, auth, first, "month", "export")["usage"]["value"] == 28 * 6
    week = report(linked, auth, first + 10 * DAY, "week")
    assert week["days"][0]["date"] == "2026-02-09" and week["usage"]["value"] == 7 * 24
    old_id = data["days"][0]["hours"][0]["meter_id"]
    new_id = data["days"][-1]["hours"][0]["meter_id"]
    assert old_id and new_id and old_id != new_id
    with linked.app.state.db.sessions() as db:
        new = db.get(EnergyMeter, new_id)
        assert str(new.replaced_meter_id) == old_id
    # De export geeft bij een wissel binnen hetzelfde uur geen exacte bindingsgrens.
    switch = first + DAY * 14
    source.hour_rows[switch].append(row(hours(switch)[0], 1, device="testmeter A"))
    sync(switch)
    mixed = report(linked, auth, switch)["days"][0]["hours"][0]
    assert mixed["usage"]["value"] is None and mixed["usage"]["quality"] == "onbekend"


def test_tarieven_per_richting_en_tijdvak(linked, auth, source, sync):
    day = date(2026, 3, 6)
    stamps = hours(day)
    source.hour_rows[day] = [row(t, 2) for t in stamps] + [row(t, 1, metric="energy_export_kwh") for t in stamps]
    source.tariffs = [
        {
            "id": str(uuid4()),
            "valid_from": day.isoformat(),
            "import_per_kwh": 0.25,
            "export_per_kwh": 0.05,
            "source": "handmatig",
        }
    ]
    sync(day)
    assert report(linked, auth, day)["cost"]["value"] == 12
    assert report(linked, auth, day, direction="export")["cost"]["value"] == 1.2
    source.tariffs.append(
        {
            "id": str(uuid4()),
            "valid_from": stamps[12].isoformat(),
            "valid_to": stamps[-1].isoformat(),
            "source": "dynamisch",
            "import_per_kwh": 0.5,
            "export_per_kwh": None,
        }
    )
    sync(day)
    data = report(linked, auth, day)
    assert data["usage"]["value"] == 48 and data["cost"]["value"] is None
    slots = data["days"][0]["hours"]
    assert slots[12]["cost"]["value"] == 1 and slots[12]["cost"]["source"]
    assert slots[-1]["cost"]["quality"] == "onbekend"
    with linked.app.state.db.sessions() as db:
        assert set(db.scalars(select(EnergyTariff.kind))) == {"vast", "dynamisch"}
    source.tariffs.clear()
    sync(day)
    assert all(h["cost"]["value"] is None for h in report(linked, auth, day)["days"][0]["hours"])


def test_willekeurige_reeksen_blijven_volgordeonafhankelijk(linked, auth, source, sync):
    rng = random.Random(310)
    for offset in range(8):
        day = date(2026, 3, 24) + offset * DAY
        switch = rng.randrange(4, 19)
        rows = []
        oracle = []
        for i, t in enumerate(hours(day)):
            state = rng.choice(("gemeten", "geschat", "reset", "gat", "strijdig"))
            value = rng.randrange(1, 90) / 10
            if state == "gat":
                oracle.append((None, "onbekend", False))
                continue
            r = row(
                t,
                value,
                "estimated" if state == "geschat" else "measured",
                notes="tellerreset gedetecteerd" if state == "reset" else "",
                device="testmeter A" if i < switch else "testmeter B",
            )
            rows.extend([r, r.copy()])
            if state == "strijdig":
                rows.append({**r, "value": value + 1})
            oracle.append(
                (
                    None if state == "strijdig" else value,
                    "onbekend" if state == "strijdig" else "geschat" if state == "geschat" else "gemeten",
                    state == "reset",
                )
            )
        source.hour_rows[day] = rows
        for _ in range(2):
            rng.shuffle(rows)
            sync(day)
            slots = report(linked, auth, day)["days"][0]["hours"]
            assert [(s["usage"]["value"], s["usage"]["quality"], s["counter_reset"]) for s in slots] == oracle


def test_leesrecht_en_actuele_koppeling(linked, auth, source, sync):
    day = date(2026, 5, 1)
    source.hour_rows[day] = [row(t) for t in hours(day)]
    sync(day)
    assert report(linked, auth, day)["usage"]["value"] == 24
    checks = list(source.checks)
    assert linked.get(ENERGY + "/usage").status_code == 401
    assert linked.get(ENERGY + "/usage", headers=auth("kind")).status_code == 403
    assert source.checks == checks
    source.role = "admin"
    assert linked.get(ENERGY + "/usage", headers=auth("viewer")).status_code == 503
    source.role = "viewer"
    source.summary["timezone"] = "ongeldige_woningzone"
    sync(day)
    assert linked.get(ENERGY + "/usage", headers=auth("viewer")).status_code != 200


def test_woningzone_bronwissel_en_alleen_uurcijfers(linked, auth, source, sync):
    day = date(2026, 11, 1)
    zone = ZoneInfo("America/New_York")
    source.summary["timezone"] = zone.key
    stamps = hours(day, zone)
    source.hour_rows[day] = [row(t, 0.03) for t in stamps]
    source.hour_rows[day] += [row(t, 5, metric=m) for t in stamps for m in ("power_w", "energy_import_t1_kwh")]
    sync(day, zone=zone)
    result = report(linked, auth, day)
    assert result["usage"]["value"] == 0.75 and result["timezone"] == zone.key
    assert len(result["days"][0]["hours"]) == 25
    assert linked.get(ENERGY + "/usage", params={"timezone": "UTC"}, headers=auth("viewer")).status_code == 422
    assert linked.get(ENERGY + "/usage", params={"period": "year"}, headers=auth("viewer")).status_code == 422
    assert not any(path.endswith("/live") for _, path in source.calls)
    replacement = MyHouseEnergy()
    assert configure(linked, auth, replacement).status_code in (200, 201)
    reply = linked.get(ENERGY + "/usage", headers=auth("viewer"))
    assert reply.status_code == 501 and "days" not in reply.json()


def test_terugmigratie_zonder_precisieverlies(linked, source, sync):
    from integrations.migrations import BackupError, downgrade

    day = date(2026, 5, 5)
    # Beide richtingen en beide afgesloten dagen volledig gemeten. Alleen de vierde decimaal blokkeert.
    for d in (day - DAY, day):
        source.hour_rows[d] = [
            row(t, 0.0001, metric=metric) for t in hours(d) for metric in ("energy_import_kwh", "energy_export_kwh")
        ]
    sync(day)
    with pytest.raises(BackupError, match="zonder verlies"):
        downgrade(linked.app.state.settings, "0008")
    assert linked.app.state.db.current_revision() == "0009"
    with linked.app.state.db.sessions() as db:
        stored = db.scalars(select(EnergyUsageInterval)).all()
        assert len(stored) == 96
        assert all(r.meter_id and r.quality == "gemeten" and str(r.delta) == "0.0001" for r in stored)


@pytest.mark.parametrize("mixed", [False, True])
def test_gelijknamige_meters_behouden_bron_id_en_voorganger(linked, auth, source, sync, mixed):
    day = date(2026, 4, 8)
    old, new = str(uuid4()), str(uuid4())
    stamps = hours(day)
    rows = [row(t, 1 if i < 12 or mixed else 2, meter_id=old if i < 12 else new) for i, t in enumerate(stamps)]
    if mixed:
        rows[12] = row(stamps[12], 0.5, "estimated", meter_id=old)
        rows.append(row(stamps[12], 0.5, "estimated", meter_id=new))
    source.hour_rows[day] = rows
    for delivery in range(2):
        if delivery:
            rows.reverse()
            for item in rows:
                item["device"] = "Hernoemd"
        sync(day)
        data = report(linked, auth, day)
        slots = data["days"][0]["hours"]
        first, last = slots[0]["meter_id"], slots[-1]["meter_id"]
        assert first and last and first != last
        with linked.app.state.db.sessions() as db:
            assert str(db.get(EnergyMeter, last).replaced_meter_id) == first
        if mixed:
            assert slots[12]["usage"]["value"] is None and slots[12]["usage"]["quality"] == "onbekend"
            assert data["usage"]["value"] is None and data["status"] == "onvolledig"
        else:
            assert data["usage"]["value"] == 36
        if delivery == 0:
            original = (first, last)
        else:
            assert (first, last) == original


def test_resetkenmerk_zonder_vrije_tekst(linked, auth, source, sync):
    day = date(2026, 4, 8)
    source.hour_rows[day] = [row(t, 1) for t in hours(day)]
    source.hour_rows[day][12].update(value=0.75, reset_skipped=True)
    sync(day)
    data = report(linked, auth, day)
    slot = data["days"][0]["hours"][12]
    assert slot["counter_reset"] and slot["usage"]["value"] is None and slot["usage"]["quality"] == "onbekend"
    assert data["status"] == "onvolledig" and data["usage"]["value"] is None


def test_oude_en_ongeldige_meteridentiteit_geven_geen_gemeten_uur(linked, auth, source, sync):
    day = date(2026, 4, 8)
    rows = [row(t, 1) for t in hours(day)]
    source.hour_rows[day] = rows
    del rows[0]["meter_id"]
    rows[1]["meter_id"] = "ongeldig"
    sync(day)
    data = report(linked, auth, day)
    slots = data["days"][0]["hours"]
    assert all(s["meter_id"] is None and s["usage"]["value"] is None for s in slots[:2])
    assert slots[2]["usage"]["quality"] == "gemeten"
    assert data["status"] == "onvolledig"


def test_terugleververgoeding_met_oud_nulveld_en_bekendheid(linked, auth, source, sync):
    day = date(2026, 4, 8)
    source.hour_rows[day] = [row(t, 1, metric="energy_export_kwh") for t in hours(day)]
    tariff = {"valid_from": day.isoformat(), "export_per_kwh": 0}
    source.tariffs = [tariff]
    for known, expected in ((False, None), (True, 0)):
        tariff["export_price_known"] = known
        sync(day)
        data = report(linked, auth, day, direction="export")
        assert data["usage"]["value"] == 24
        assert data["cost"]["value"] == expected and data["cost"]["quality"] == ("gemeten" if known else "onbekend")


def test_archief_met_oude_naambinding_tot_herlevering(linked, auth, source, sync):
    day = date(2026, 4, 8)
    source.hour_rows[day] = [row(t) for t in hours(day)]
    sync(day)
    first = report(linked, auth, day)
    key = first["days"][0]["hours"][0]["meter_id"]
    # Een oudere worker archiveerde op naam en gaf het uur ten onrechte als gemeten door.
    with linked.app.state.db.sessions() as db:
        role = db.get(EnergyMeterRole, (key, "p1_net"))
        role.confirmed_by = "my_house:energy/export"
        db.commit()
    assert report(linked, auth, day)["usage"]["value"] is None
    replacement = str(uuid4())
    for item in source.hour_rows[day]:
        item["meter_id"] = replacement
    sync(day)
    assert report(linked, auth, day)["usage"] == first["usage"]
