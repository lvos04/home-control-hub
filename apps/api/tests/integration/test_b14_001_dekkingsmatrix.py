"""B14-001. De bron bepaalt per rol of er een actuele meting is."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from integrations.domains.energy.models import EnergyMeter, EnergyMeterRole
from tests.conftest import idem
from tests.fakes.my_house_energy import MyHouseEnergy

ENERGY = "/integrations/v1/energy"
SOURCE = "/integrations/v1/sources/my_house"
CONNECTOR = "/connector/v1/items?type=energy.coverage"


@pytest.fixture
def bron(linked: Any, auth: Any) -> MyHouseEnergy:
    fake = MyHouseEnergy()
    result = linked.put(
        SOURCE,
        headers=idem(auth("admin")),
        json={"base_url": fake.address, "enabled": True, "credential": fake.token},
    )
    assert result.status_code == 201 and fake.token not in result.text
    linked.app.state.http_transport = httpx.MockTransport(fake.handle)
    return fake


def rows(linked: Any, auth: Any, path: str) -> dict[str, Any]:
    response = linked.get(path, headers=auth("viewer"))
    assert response.status_code == 200
    return {item["role"]: item for item in response.json()["items"]}


def test_meters_rollen_en_herkomst(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    meters = rows(linked, auth, ENERGY + "/meters")
    assert set(meters) == {"p1_net", "boiler_socket", "airco_outdoor"}
    for role, watts in (("p1_net", -42.5), ("boiler_socket", 0), ("airco_outdoor", 74)):
        item = meters[role]
        assert (item["last_measurement"], item["unit"], item["source"]) == (watts, "W", "my_house")
        assert item["measurement_quality"] == "gemeten" and item["last_updated"] == bron.at
    for path in (ENERGY + "/coverage", CONNECTOR):
        matrix = rows(linked, auth, path)
        assert set(matrix) == {*meters, "nas_host"}
        assert matrix["nas_host"]["quality"] == "onbekend" and matrix["nas_host"]["why_unknown_nl"]
        for role in meters:
            assert matrix[role]["measurement_status"] == "gemeten"
            assert matrix[role]["last_updated"] == bron.at
            assert matrix[role]["source"] == "my_house" and matrix[role]["reason_nl"]
    assert rows(linked, auth, ENERGY + "/meters") == meters
    with linked.app.state.db.sessions() as s:
        pairs = s.execute(select(EnergyMeter, EnergyMeterRole).join(EnergyMeterRole)).all()
        assert {(str(m.id), r.role) for m, r in pairs} == {(m["id"], r) for r, m in meters.items()}
        assert all(m.read_only and r.confirmed_at is not None for m, r in pairs)


@pytest.mark.parametrize("path", [ENERGY + "/meters", ENERGY + "/coverage", CONNECTOR])
def test_leesrecht_voor_bronverzoek(linked: Any, auth: Any, bron: MyHouseEnergy, path: str) -> None:
    assert linked.get(path).status_code == 401
    assert linked.get(path, headers=auth("kind")).status_code == 403
    assert not bron.calls


def test_geen_naam_cpu_binnenunit_of_huistotaal_als_rol(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    bron.summary = {"meters": []}
    part = bron.live["parts"][0]
    bron.live["parts"] = [
        {**part, "role": role, "label": "Boiler", "cpu_percent": 50}
        for role in (None, "", False, "airco_indoor", "nas_host", "cpu", "rest")
    ] + [{"label": "P1", "watts": 20, "at": bron.at}]
    assert all(r["quality"] == "onbekend" for r in rows(linked, auth, ENERGY + "/coverage").values())
    assert rows(linked, auth, ENERGY + "/meters") == {}
    with linked.app.state.db.sessions() as s:
        assert s.scalars(select(EnergyMeterRole)).all() == []


def test_uitval_en_herstel_zonder_oude_waarde(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    goede = rows(linked, auth, ENERGY + "/meters")["boiler_socket"]
    bron.reachable = False
    matrix = rows(linked, auth, CONNECTOR)
    assert all(r["quality"] == "onbekend" and r["why_unknown_nl"] for r in matrix.values())
    assert matrix["boiler_socket"]["last_updated"] == bron.at
    assert all(m["last_measurement"] is None for m in rows(linked, auth, ENERGY + "/meters").values())
    bron.reachable = True
    bron.live["parts"][1]["watts"] = 30
    nieuw = rows(linked, auth, ENERGY + "/meters")["boiler_socket"]
    assert nieuw["last_measurement"] == 30 and nieuw["id"] == goede["id"]
    bron.live["parts"] = []
    assert rows(linked, auth, ENERGY + "/coverage")["boiler_socket"]["quality"] == "onbekend"


@pytest.mark.parametrize(
    ("patch", "quality"),
    [
        ({"watts": 0}, "gemeten"),
        ({"watts": None}, "onbekend"),
        ({"watts": ""}, "onbekend"),
        ({"watts": False}, "onbekend"),
        ({"stale": True}, "onbekend"),
        ({"stale": 0}, "onbekend"),
        ({"quality": "missing"}, "onbekend"),
        ({"quality": "estimated"}, "geschat"),
        ({"at": None}, "onbekend"),
        ({"at": "2030-01-01T12:00:00"}, "onbekend"),
    ],
)
def test_toestand_per_meter(linked: Any, auth: Any, bron: MyHouseEnergy, patch: Any, quality: str) -> None:
    bron.live["parts"][1].update(patch)
    m = rows(linked, auth, ENERGY + "/meters")["boiler_socket"]
    assert m["measurement_quality"] == quality
    assert m["last_measurement"] == (None if quality == "onbekend" else 0)
    matrix = rows(linked, auth, ENERGY + "/coverage")
    assert matrix["boiler_socket"]["quality"] == quality
    assert matrix["airco_outdoor"]["quality"] == "gemeten"


def test_geen_gedeelde_meettijd_of_dubbele_rol(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    oud = (datetime.now(UTC) - timedelta(hours=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    bron.live["parts"][0]["at"] = oud
    bron.live["parts"].append(dict(bron.live["parts"][1]))
    m = rows(linked, auth, ENERGY + "/meters")
    assert m["airco_outdoor"]["last_measurement"] is None and m["airco_outdoor"]["last_updated"] == oud
    assert m["boiler_socket"]["last_measurement"] is None
    assert m["p1_net"]["last_measurement"] == -42.5


@pytest.mark.parametrize("status", [200, 302, 401, 403, 503])
def test_geheim_blijft_in_de_kluis(linked: Any, auth: Any, bron: MyHouseEnergy, caplog: Any, status: int) -> None:
    caplog.set_level("DEBUG")
    bron.status = status
    bron.live["note"] = bron.token
    bron.live["parts"][0]["label"] = bron.token
    for path in (SOURCE, ENERGY + "/meters", ENERGY + "/coverage", CONNECTOR):
        response = linked.get(path, headers=auth("viewer"))
        assert response.status_code == 200 and bron.token not in response.text
        if status != 200 and path == CONNECTOR:
            assert all(r["quality"] == "onbekend" for r in response.json()["items"])
    assert bron.token not in caplog.text


def test_client_heeft_alleen_vijf_vaste_gets(make_settings: Any) -> None:
    from integrations.domains.energy.client import EnergyClient, EnergyRoute

    bron = MyHouseEnergy()
    client = EnergyClient(bron.address, bron.token, make_settings(), httpx.MockTransport(bron.handle))
    for route in EnergyRoute:
        client.read(route, day=date.today())
    assert {path for _, path in bron.calls} == {
        f"{bron.path}/energy/summary",
        f"{bron.path}/energy/live",
        f"{bron.path}/energy/export",
        f"{bron.path}/tariffs",
        "/api/v1/energy/limits",
    }
    for word in ("POST", "PUT", "PATCH", "DELETE", "request"):
        assert not hasattr(client, word.lower())
        with pytest.raises(TypeError):
            client.read(EnergyRoute.LIVE, method=word)  # type: ignore[call-arg]
        with pytest.raises(ValueError):
            client.read(word)  # type: ignore[arg-type]
    assert len(bron.calls) == 5 and bron.token not in repr(client)


def test_ouderdom_op_de_grens() -> None:
    from integrations.domains.energy.readings import LIVE_MAX_AGE, read_part

    now = datetime.now(UTC)
    limit = int(LIVE_MAX_AGE.total_seconds())
    for age in (-1, 0, 1, limit - 1, limit, limit + 1, 901):
        part = {"watts": 0, "stale": False, "quality": "measured", "at": (now - timedelta(seconds=age)).isoformat()}
        reading = read_part(part, now)
        assert (reading.value == 0) is (0 <= age <= LIVE_MAX_AGE.total_seconds())
    for field in ("watts", "stale", "quality", "at"):
        assert read_part({k: v for k, v in {**part, "at": now.isoformat()}.items() if k != field}, now).value is None


def test_wisseling_bronadres_stuurt_geen_oud_geheim(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    rows(linked, auth, ENERGY + "/meters")
    result = linked.put(
        SOURCE,
        headers=idem(auth("admin"), **{"If-Match": "*"}),
        json={"base_url": bron.address.replace("woning.test", "andere.test"), "enabled": True},
    )
    assert result.status_code == 200 and result.json()["runtime"]["credential_present"] is False
    bron.calls.clear()
    assert all(r["quality"] == "onbekend" and r["last_updated"] is None for r in rows(linked, auth, CONNECTOR).values())
    assert not bron.calls


@pytest.mark.parametrize("summary_status", [404, 503])
def test_deelmeters_houden_eigen_bewijs_bij_ontbrekend_dagoverzicht(
    linked: Any, auth: Any, bron: MyHouseEnergy, summary_status: int
) -> None:
    bron.summary_status = summary_status
    matrix = rows(linked, auth, ENERGY + "/coverage")
    assert matrix["p1_net"]["quality"] == "onbekend"
    assert matrix["boiler_socket"]["quality"] == "gemeten" and matrix["airco_outdoor"]["quality"] == "gemeten"


def test_geweigerd_token_bij_tweede_get_maakt_alles_onbekend(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    bron.summary_status = 403
    assert all(r["quality"] == "onbekend" for r in rows(linked, auth, ENERGY + "/coverage").values())


def test_onjuiste_broninhoud_geeft_reden(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    for body in (b"ongeldig", b"x" * (1024 * 1024 + 1), b'{"parts":{}}'):

        def antwoord(request: httpx.Request, data: bytes = body) -> httpx.Response:
            return httpx.Response(200, content=data) if request.url.path.endswith("/live") else bron.handle(request)

        linked.app.state.http_transport = httpx.MockTransport(antwoord)
        assert all(r["quality"] == "onbekend" and r["why_unknown_nl"] for r in rows(linked, auth, CONNECTOR).values())


def test_woning_ontbreekt_of_bron_staat_uit(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    for address, enabled in (("https://woning.test", True), (bron.address, False)):
        result = linked.put(
            SOURCE,
            headers=idem(auth("admin"), **{"If-Match": "*"}),
            json={"base_url": address, "enabled": enabled, "credential": bron.token},
        )
        assert result.status_code == 200
        matrix = rows(linked, auth, CONNECTOR)
        assert all(m["quality"] == "onbekend" and m["last_updated"] is None for m in matrix.values())
    assert not bron.calls


def test_p1_zonder_waarde_krijgt_geen_tijd_van_deelmeter(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    bron.live["total_w"] = None
    matrix = rows(linked, auth, ENERGY + "/coverage")
    assert matrix["p1_net"]["quality"] == "onbekend" and matrix["p1_net"]["last_updated"] is None
    assert matrix["boiler_socket"]["last_updated"] == bron.at


def test_oude_bronreactie_overschrijft_geen_latere_meting(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    rows(linked, auth, ENERGY + "/meters")
    bron.live["parts"][1]["at"] = (datetime.fromisoformat(bron.at) - timedelta(seconds=1)).isoformat()
    bron.live["parts"][1]["watts"] = 12
    meter = rows(linked, auth, ENERGY + "/meters")["boiler_socket"]
    assert meter["last_measurement"] is None and meter["last_updated"] == bron.at


def test_token_uit_een_ander_formaat_wordt_niet_verstuurd() -> None:
    from integrations.config import Settings
    from integrations.domains.energy.client import EnergyClient, EnergyReadError

    bron = MyHouseEnergy()
    with pytest.raises(EnergyReadError):
        EnergyClient(bron.address, "ander-tokenformaat", Settings(), httpx.MockTransport(bron.handle))
    assert not bron.calls


def test_alleen_de_eigen_kluisverwijzing(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    from integrations.models import IntegrationSource
    from integrations.sources import source_ref

    with linked.app.state.db.sessions.begin() as session:
        vreemde_ref = source_ref("authentik")
        linked.app.state.vault.put(session, vreemde_ref, bron.token)
        session.get(IntegrationSource, "my_house").credential_ref = vreemde_ref
    assert all(r["quality"] == "onbekend" for r in rows(linked, auth, CONNECTOR).values())
    assert not bron.calls
