"""B14-004. Van een gesimuleerde viewer-export en Hub-events naar een herleidbaar kostenadvies."""

from datetime import UTC, date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from integrations.domains.energy.load_history import cpu_readings
from integrations.domains.energy.models import EnergyEstimateProvenance, EnergyUsageInterval
from tests.conftest import idem
from tests.integration.test_b14_001_dekkingsmatrix import ENERGY
from tests.integration.test_b14_002_tijdreeks import hours, row
from tests.integration.test_b14_002_tijdreeks import source as source
from tests.integration.test_b14_002_tijdreeks import sync as sync
from tests.integration.test_b14_005_meldingen import cpu

ZONE = ZoneInfo("Europe/Amsterdam")
MON = date(2026, 2, 2)
DAY = timedelta(days=1)
HOUR = timedelta(hours=1)
ADVICE = ENERGY + "/advice"
NO_METER = {"items": [], "comparable_days": 0, "reason_nl": "geen meter, geen bedrag"}


def instant(day, hour):
    return datetime.combine(day, time(hour), ZONE).astimezone(UTC)


@pytest.fixture
def history(linked, auth, source, sync, fake_hub, monkeypatch):
    since = instant(MON - 40 * DAY, 0).isoformat()
    linked.app.state.hublink_store.update(lambda state: state.model_copy(update={"linked_at": since}))
    monkeypatch.setattr("integrations.domains.energy.router.utcnow", lambda: instant(MON + 7 * DAY, 10))

    def add_day(
        day,
        busy_kwh=4,
        quiet_kwh=1,
        *,
        role="grid",
        quality="measured",
        device="testmeter A",
        busy_load=75,
        quiet_load=20,
        quarters=(0, 15, 30, 45),
        prices=(0.4, 0.1),
        quiet_hour=23,
    ):
        source.hour_rows[day] = []
        readings = {18: (busy_kwh, busy_load, prices[0]), quiet_hour: (quiet_kwh, quiet_load, prices[1])}
        for start in hours(day):
            clock_hour = start.astimezone(ZONE).hour
            if clock_hour not in readings:
                continue
            kwh, load, price = readings[clock_hour]
            source.hour_rows[day].append(row(start, kwh, role=role, quality=quality, device=device))
            if price is not None:
                source.tariffs.append(
                    {
                        "valid_from": start.isoformat(),
                        "valid_to": (start + HOUR).isoformat(),
                        "import_per_kwh": price,
                    }
                )
            for minute in quarters:
                event = cpu(start + timedelta(minutes=minute), load)
                response = linked.post(
                    "/integrations/v1/automation/events", json=event, headers=idem(fake_hub.service_auth())
                )
                assert response.status_code == 201 and response.json()["catalog_status"] == "geldig"
        sync(day)

    return add_day


def get(client, auth, day=MON + 4 * DAY, **params):
    response = client.get(ADVICE, params={"date": day.isoformat(), **params}, headers=auth("viewer"))
    assert response.status_code == 200, response.status_code
    return response.json()


def test_zonder_meter_ook_geen_bedrag_bij_verkeerde_rol_meter_of_tijdvak(linked, auth, history):
    assert get(linked, auth) == NO_METER
    history(MON - 28 * DAY)  # Wel gemeten, buiten de gekozen 28 dagen.
    history(MON, role="boiler", device="deelmeting")
    history(MON + DAY, quality="estimated")
    assert get(linked, auth) == NO_METER
    history(MON + 2 * DAY)
    assert get(linked, auth, meter_id=str(uuid4())) == NO_METER
    assert get(linked, auth)["comparable_days"] == 1


def test_database_weigert_schatting_zonder_herkomst_en_cpu_zonder_kalibratie(linked, auth, history):
    history(MON, quality="estimated")
    with linked.app.state.db.sessions() as db:
        interval = db.scalars(select(EnergyUsageInterval).where(EnergyUsageInterval.quality == "geschat")).first()
        assert db.get(EnergyEstimateProvenance, interval.provenance_id).method == "bronaggregatie"
        with pytest.raises(IntegrityError) as missing:
            interval.provenance_id = None
            db.flush()
        assert missing.value.orig.diag.constraint_name.endswith("estimate_requires_provenance")
        db.rollback()
        with pytest.raises(IntegrityError) as cpu_without_meter:
            db.add(EnergyEstimateProvenance(method="cpu_model", confidence=Decimal("0.60"), created_at=instant(MON, 0)))
            db.flush()
        assert cpu_without_meter.value.orig.diag.constraint_name.endswith("cpu_model_requires_calibration")
        db.rollback()
    assert get(linked, auth) == NO_METER


def test_minimum_negeert_weekend_ander_profiel_en_onvolledige_belasting(linked, auth, history):
    history(MON - DAY)
    history(MON)
    history(MON + DAY)
    history(MON + 2 * DAY, quiet_load=65)
    history(MON + 3 * DAY, quarters=(0, 15, 45))
    body = get(linked, auth)
    assert body["items"] == [] and body["comparable_days"] == 2
    assert "Te weinig vergelijkbare dagen" in body["reason_nl"]


def test_bandbreedte_bron_zekerheid_en_alleen_een_planningsadvies(linked, auth, history, source, fake_hub):
    history(MON, busy_kwh=4, quiet_kwh=1)
    history(MON + DAY, busy_kwh=2, quiet_kwh=0)
    history(MON + 2 * DAY, busy_kwh=0.5, quiet_kwh=1)
    seen = list(fake_hub.requests), list(source.calls)

    def snapshot(db):
        return db.execute(
            select(EnergyUsageInterval.id, EnergyUsageInterval.delta, EnergyUsageInterval.provenance_id).order_by(
                EnergyUsageInterval.id
            )
        ).all()

    with linked.app.state.db.sessions() as db:
        before = snapshot(db)
    assert len(before) >= 6
    body = get(linked, auth)
    assert body["comparable_days"] == 3 and body["reason_nl"] is None
    (item,) = body["items"]
    assert get(linked, auth, meter_id=item["meter_id"]) == body
    assert item["savings"] == {
        "low": 0.0,
        "high": 0.9,
        "currency": "EUR",
        "unit_nl": "per verplaatst werkuur",
        "measurement_quality": "geschat",
        "source": "vergelijkbare_dag",
    }
    assert 0 <= item["confidence"] == 0.27 <= 1
    assert item["method"] == "vergelijkbare_dag" and item["disclaimer_nl"] == "De besparing is niet gegarandeerd."
    assert [d["date"] for d in item["days"]] == [(MON + i * DAY).isoformat() for i in range(3)]
    assert [d["busy_kwh"] for d in item["days"]] == [4, 2, 0.5]
    assert all(
        d["measurement_quality"] == "gemeten"
        and d["usage_source"] == "my_house:energy/export"
        and d["tariff_source"] == "my_house:tariffs"
        for d in item["days"]
    )
    assert item["sources"] == ["my_house:energy/export", "my_house:tariffs", "monitoring.metric.recorded/cpu.gebruik"]
    assert "P1-meter" in " ".join(item["assumptions_nl"]) and "AV1" in item["advice_nl"]
    assert "boiler" not in str(body).lower() and "action_id" not in item and "target" not in item
    assert source.token not in str(body) and "testonderwerp" not in str(body)
    assert set(linked.app.openapi()["paths"][ADVICE]) == {"get"}
    assert linked.post(ADVICE, headers=auth("admin")).status_code == 405
    with linked.app.state.db.sessions() as db:
        method = db.get(EnergyEstimateProvenance, UUID(item["provenance_id"]))
        assert method.method == item["method"] and method.assumptions["aannames_nl"] == item["assumptions_nl"]
        assert snapshot(db) == before
    assert (fake_hub.requests, source.calls) == seen


@pytest.mark.parametrize("end", [date(2026, 3, 29), date(2026, 10, 25)])
def test_ontbrekend_of_dubbel_lokaal_uur_telt_niet_mee(linked, auth, history, monkeypatch, end):
    monkeypatch.setattr("integrations.domains.energy.router.utcnow", lambda: instant(end + DAY, 12))
    ordinary = [end - i * DAY for i in (21, 14, 7)]
    for day in [*ordinary, end]:
        history(day, quiet_hour=2)
    result = get(linked, auth, day=end, quiet_hour=2)
    assert result["comparable_days"] == 3
    (item,) = result["items"]
    assert [d["date"] for d in item["days"]] == [d.isoformat() for d in ordinary]
    assert item["savings"]["low"] == item["savings"]["high"] == 0.9
    assert item["disclaimer_nl"] == "De besparing is niet gegarandeerd."


def test_verschillende_utc_metingen_bij_hetzelfde_databaseklokuur(linked, fake_hub):
    first = datetime(2026, 10, 25, 0, 15, tzinfo=UTC)
    second = first + HOUR
    for at, value in [(first, 75), (second, 20)]:
        received = linked.post(
            "/integrations/v1/automation/events", json=cpu(at, value), headers=idem(fake_hub.service_auth())
        )
        assert received.status_code == 201
    with linked.app.state.db.sessions() as db:
        db.execute(text("SET LOCAL TIME ZONE 'Europe/Amsterdam'"))
        samples = list(cpu_readings(db, datetime(2000, 1, 1, tzinfo=UTC), first, second))
    assert samples == [(first, Decimal(75)), (second, Decimal(20))]


def test_een_ontbrekende_prijs_of_valuta_sluit_het_bedrag_uit(linked, auth, source, history, sync):
    history(MON)
    history(MON + DAY)
    history(MON + 2 * DAY)
    history(MON + 3 * DAY, prices=(0.4, None))
    body = get(linked, auth)
    assert body["items"] == [] and body["comparable_days"] == 4 and "tarief" in body["reason_nl"]
    source.summary.pop("currency")
    sync(MON + 3 * DAY)
    assert get(linked, auth, day=MON + 2 * DAY)["items"] == []


@pytest.mark.parametrize(("busy", "quiet", "prices"), [(1, 3, (0.4, 0.1)), (3, 1, (0.2, 0.2))])
def test_zonder_verband_of_prijsvoordeel_geen_advies(linked, auth, history, busy, quiet, prices):
    for i in range(3):
        history(MON + i * DAY, busy_kwh=busy, quiet_kwh=quiet, prices=prices)
    body = get(linked, auth)
    assert body["items"] == [] and body["comparable_days"] == 3 and "kostenvoordeel" in body["reason_nl"]


def test_meterwissel_en_ingetrokken_viewer(linked, auth, history, source):
    for i in range(3):
        history(MON + i * DAY)
    old = get(linked, auth)["items"][0]["meter_id"]
    history(MON + 3 * DAY, device="testmeter B")
    body = get(linked, auth)
    assert body["items"] == [] and body["comparable_days"] == 1
    assert get(linked, auth, meter_id=old)["comparable_days"] == 3
    source.role = "admin"
    response = linked.get(ADVICE, params={"date": MON.isoformat(), "meter_id": old}, headers=auth("viewer"))
    assert response.status_code == 503 and int(response.headers["Retry-After"]) > 0
    assert "savings" not in response.json() and source.token not in response.text


def test_conflicterende_meting_en_eerdere_hubkoppeling_tellen_niet_mee(linked, auth, history, fake_hub):
    for i in range(3):
        history(MON + i * DAY)
    assert len(get(linked, auth)["items"]) == 1
    conflict = cpu(instant(MON, 18), 80)
    assert (
        linked.post(
            "/integrations/v1/automation/events", json=conflict, headers=idem(fake_hub.service_auth())
        ).status_code
        == 201
    )
    assert get(linked, auth)["comparable_days"] == 2
    linked.app.state.hublink_store.update(
        lambda s: s.model_copy(update={"linked_at": instant(MON + 2 * DAY, 0).isoformat()})
    )
    assert get(linked, auth)["comparable_days"] == 1


def test_bestaand_archief_krijgt_alleen_de_adviesherkomst(linked, auth, history, sync):
    for i in range(3):
        history(MON + i * DAY)
    initial = get(linked, auth)["items"][0]
    key = UUID(initial["provenance_id"])
    with linked.app.state.db.sessions() as db:
        method = db.get(EnergyEstimateProvenance, key)
        method.assumptions = {}
        db.commit()
        assert get(linked, auth)["items"] == []
        db.delete(method)
        db.commit()  # Archief van vóór de adviesmethode.
        stmt = (
            select(EnergyUsageInterval.id, EnergyUsageInterval.delta)
            .where(EnergyUsageInterval.quality == "gemeten")
            .order_by(EnergyUsageInterval.id)
        )
        before = db.execute(stmt).all()
    assert len(before) == 6
    body = get(linked, auth)
    assert body["items"] == [] and "herkomst" in body["reason_nl"]
    sync(MON + 2 * DAY)
    sync(MON + 2 * DAY)
    assert get(linked, auth)["items"] == [initial]
    with linked.app.state.db.sessions() as db:
        assert db.execute(stmt).all() == before
        assert db.scalars(
            select(EnergyEstimateProvenance.id).where(EnergyEstimateProvenance.method == "vergelijkbare_dag")
        ).all() == [key]


def test_rechten_en_invoer_voor_de_bronlezing(linked, auth, source):
    checks = list(source.checks)
    assert linked.get(ADVICE).status_code == 401
    assert linked.get(ADVICE, headers=auth("kind")).status_code == 403
    for query in (
        "role=boiler_socket",
        "busy_hour=23",
        "quiet_hour=24",
        "busy_hour=1&busy_hour=2",
        "meter_id=ongeldig",
    ):
        assert linked.get(ADVICE + "?" + query, headers=auth("viewer")).status_code == 422
    assert source.checks == checks
