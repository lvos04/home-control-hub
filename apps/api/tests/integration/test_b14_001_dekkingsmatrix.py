"""B14-001. De bron bepaalt per rol of er een actuele meting is."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import event, select

from integrations.domains.energy.client import BoundViewer, ViewerPairing
from integrations.domains.energy.meters import STATUS_KEY
from integrations.domains.energy.models import EnergyMeter, EnergyMeterRole
from integrations.models import ServiceState
from integrations.worker import Worker
from tests.conftest import idem
from tests.fakes.my_house_energy import MyHouseEnergy
from tests.unit.test_authentik_execution_transport import TlsAuthentik
from tests.unit.test_authentik_execution_transport import tls_authentik as tls_authentik

ENERGY = "/integrations/v1/energy"
SOURCE = "/integrations/v1/sources/my_house"
CONNECTOR = "/connector/v1/items?type=energy.coverage"


def configure(linked: Any, auth: Any, fake: MyHouseEnergy, **changes: Any) -> Any:
    linked.app.state.http_transport = httpx.MockTransport(fake.handle)
    return linked.put(
        SOURCE,
        headers=idem(auth("admin"), **{"If-Match": "*"}),
        json={
            "base_url": fake.address,
            "enabled": True,
            "credential": fake.token,
            "my_house_pairing": fake.pairing,
            **changes,
        },
    )


def viewer(fake: MyHouseEnergy, token: str | None = None) -> BoundViewer:
    return BoundViewer(address=fake.address, token=token or fake.token, pairing=ViewerPairing(**fake.pairing))


@pytest.fixture
def bron(linked: Any, auth: Any) -> MyHouseEnergy:
    fake = MyHouseEnergy()
    result = configure(linked, auth, fake)
    assert result.status_code == 201 and fake.token not in result.text
    assert result.json()["runtime"]["credential_last4"] == fake.token[-4:]
    return fake


def rows(linked: Any, auth: Any, path: str) -> dict[str, Any]:
    response = linked.get(path, headers=auth("viewer"))
    assert response.status_code == 200
    return {item["role"]: item for item in response.json()["items"]}


def energieblok(client: Any) -> str:
    response = client.get("/")
    assert response.status_code == 200
    return response.text.split('<section class="blok" aria-labelledby="h-energie">', 1)[1].split("</section>", 1)[0]


def test_statuspagina_van_eerste_meting_tot_bronwissel(linked, auth, monkeypatch):
    assert "Er is geen actieve woningbron." in energieblok(linked)
    bron = MyHouseEnergy()
    bron.live["parts"][0]["source_quality"] = "estimated"
    assert configure(linked, auth, bron).status_code == 201
    assert "De dienst wacht op de eerste meting." in energieblok(linked)
    worker = Worker(linked.app.state.settings, linked.app.state.http_transport)
    try:
        worker.meter_step(0)
    finally:
        worker.db.dispose()
    verzoeken = (list(bron.calls), list(bron.checks))
    sql = []

    def registreer(_conn, _cursor, statement, *_):
        sql.append(statement.lstrip().split()[0].upper())

    engine = linked.app.state.db.engine
    event.listen(engine, "before_cursor_execute", registreer)
    try:
        # Beoordeel op de echte grens, ook als de worker na het opslaan stilvalt.
        meettijd = datetime.fromisoformat(bron.at)

        class Klok(datetime):
            @classmethod
            def now(cls, tz=None):
                return tijdstip

        tijdstip = meettijd + timedelta(seconds=300)
        monkeypatch.setattr("integrations.status_page.datetime", Klok)
        blok = energieblok(linked)
        assert "Gemeten</span>" in blok and "-42,5 W." in blok and "0 W." in blok
        assert "Geschat</span>" in blok and "74 W." in blok
        assert "my_house meldt geen losse vermogensmeter" in blok
        assert bron.address not in blok and bron.token not in blok and str(bron.home) not in blok
        tijdstip += timedelta(seconds=1)
        oud = energieblok(linked)
        assert oud.count("Verouderd</span>") == 3 and "Huidig vermogen onbekend" in oud
        assert " W." not in oud and "Laatste meting van my_house op" in oud
    finally:
        event.remove(engine, "before_cursor_execute", registreer)
    assert sql and set(sql) == {"SELECT"}
    assert verzoeken == (bron.calls, bron.checks)

    bron.reachable = False
    rows(linked, auth, ENERGY + "/coverage")
    storing = energieblok(linked)
    assert "Storing</span>" in storing and " W." not in storing
    vervanger = MyHouseEnergy()
    assert configure(linked, auth, vervanger).status_code == 200
    nieuw = energieblok(linked)
    assert "De dienst wacht op de eerste meting." in nieuw
    assert "Laatste meting van my_house op" not in nieuw and " W." not in nieuw


def test_statuspagina_leest_bestaande_meettijden_zonder_watt_te_verzinnen(linked, auth, bron):
    rows(linked, auth, ENERGY + "/meters")
    with linked.app.state.db.sessions() as db:
        db.delete(db.get_one(ServiceState, STATUS_KEY))
        db.commit()  # oude opslagvorm met uitsluitend de bevestigde roltijden
    blok = energieblok(linked)
    assert blok.count("Laatste meting van my_house op") == 3 and blok.count("Onbekend</span>") == 4
    assert " W." not in blok
    bron.live["parts"][0]["stale"] = True
    rows(linked, auth, ENERGY + "/coverage")
    blok = energieblok(linked)
    assert blok.count("Verouderd</span>") == 1 and "74 W." not in blok and "-42,5 W." in blok


def test_statuspagina_laat_ongeldige_opgeslagen_hublink_weg(linked):
    store = linked.app.state.hublink_store
    store.update(lambda stand: stand.model_copy(update={"hub_url": "https://hub.test/ongeldig"}))
    pagina = linked.get("/")
    assert pagina.status_code == 200 and 'id="h-energie"' in pagina.text
    assert "Hub openen</a>" not in pagina.text and 'href=""' not in pagina.text
    assert "hub.test/ongeldig" not in pagina.text


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
    checks = list(bron.checks)
    assert linked.get(path).status_code == 401
    assert linked.get(path, headers=auth("kind")).status_code == 403
    assert not bron.calls and bron.checks == checks


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
        ({"source_quality": "missing"}, "onbekend"),
        ({"source_quality": "estimated"}, "geschat"),
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
    client = EnergyClient(bron.address, viewer(bron), make_settings(), httpx.MockTransport(bron.handle))
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
    assert len(bron.calls) == len(set(bron.nonces)) == 5 and bron.token not in repr(client)


def test_ouderdom_op_de_grens() -> None:
    from integrations.domains.energy.readings import LIVE_MAX_AGE, read_part

    now = datetime.now(UTC)
    limit = int(LIVE_MAX_AGE.total_seconds())
    for age in (-1, 0, 1, limit - 1, limit, limit + 1, 901):
        part = {
            "watts": 0,
            "stale": False,
            "source_quality": "measured",
            "at": (now - timedelta(seconds=age)).isoformat(),
        }
        reading = read_part(part, now)
        assert (reading.value == 0) is (0 <= age <= LIVE_MAX_AGE.total_seconds())
    for field in ("watts", "stale", "source_quality", "at"):
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
    assert configure(linked, auth, bron, base_url="https://woning.test").status_code == 422
    assert configure(linked, auth, bron, enabled=False).status_code == 200
    matrix = rows(linked, auth, CONNECTOR)
    assert all(m["quality"] == "onbekend" and m["last_updated"] is None for m in matrix.values())
    assert not bron.calls


def test_p1_zonder_waarde_krijgt_geen_tijd_van_deelmeter(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    bron.live.update(total_w=None, total_observed_at=None)
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
        EnergyClient(bron.address, viewer(bron, "ander-tokenformaat"), Settings(), httpx.MockTransport(bron.handle))
    with pytest.raises(EnergyReadError):
        EnergyClient(bron.address, bron.token, Settings(), httpx.MockTransport(bron.handle))
    assert not bron.calls and not bron.checks


def test_alleen_de_eigen_kluisverwijzing(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    from integrations.models import IntegrationSource
    from integrations.sources import source_ref

    with linked.app.state.db.sessions.begin() as session:
        vreemde_ref = source_ref("authentik")
        linked.app.state.vault.put(session, vreemde_ref, bron.token)
        session.get(IntegrationSource, "my_house").credential_ref = vreemde_ref
    assert all(r["quality"] == "onbekend" for r in rows(linked, auth, CONNECTOR).values())
    assert not bron.calls


def test_andere_instantie_op_hetzelfde_adres(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    first = rows(linked, auth, ENERGY + "/meters")["boiler_socket"]
    assert first["last_measurement"] == 0
    # Hetzelfde adres, dezelfde woning en hetzelfde testtoken. Alleen de server-ID verandert.
    bron.server_id = uuid4()
    bron.live["parts"][1]["watts"] = 71
    bron.calls.clear()
    bron.checks.clear()
    assert all(row["quality"] == "onbekend" for row in rows(linked, auth, CONNECTOR).values())
    assert not bron.calls and bron.checks == ["/api/v1/pairing/identity"]
    assert configure(linked, auth, bron).status_code == 200
    new = rows(linked, auth, ENERGY + "/meters")["boiler_socket"]
    assert new["id"] != first["id"] and new["last_measurement"] == 71


@pytest.mark.parametrize(
    ("role", "purpose"),
    [
        ("viewer", "hub"),
        ("viewer", "phone"),
        ("control", "phone"),
        ("admin", "phone"),
        ("control", "hub"),
        ("admin", "hub"),
        ("", "hub"),
        ("viewer", ""),
    ],
)
def test_koppelrecht(linked: Any, auth: Any, role: str, purpose: str) -> None:
    from integrations.models import IntegrationSource, VaultSecret

    fake = MyHouseEnergy()
    fake.role, fake.purpose = role, purpose
    allowed = (role, purpose) == ("viewer", "hub")
    result = configure(linked, auth, fake)
    assert result.status_code == (201 if allowed else 422)
    assert fake.token not in result.text and not fake.calls
    with linked.app.state.db.sessions() as s:
        assert (s.get(IntegrationSource, "my_house") is not None) is allowed
        assert (s.get(VaultSecret, "vault://source/my-house") is not None) is allowed
    assert rows(linked, auth, CONNECTOR)["boiler_socket"]["quality"] == ("gemeten" if allowed else "onbekend")
    assert bool(fake.calls) is allowed
    if not allowed:
        fake.role, fake.purpose = "viewer", "hub"
        assert configure(linked, auth, fake).status_code == 201
        fake.role, fake.purpose = role, purpose
        assert all(m["quality"] == "onbekend" for m in rows(linked, auth, CONNECTOR).values())
        assert not fake.calls


def test_transport_zonder_tls(linked: Any, auth: Any) -> None:
    from integrations.models import IntegrationSource

    fake = MyHouseEnergy()
    address = fake.address.replace("https:", "http:")
    assert configure(linked, auth, fake, base_url=address).status_code == 422
    assert linked.get(SOURCE, headers=auth("viewer")).json()["runtime"]["credential_present"] is False
    assert not fake.checks and not fake.calls
    assert configure(linked, auth, fake).status_code == 201
    with linked.app.state.db.sessions.begin() as s:
        source = s.get(IntegrationSource, "my_house")
        source.base_url = address
        # Ook een intern consistente oude HTTP-koppeling hoort bij gebruik te stranden op het transport.
        old = viewer(fake).model_copy(update={"address": address})
        linked.app.state.vault.put(s, source.credential_ref, old.model_dump_json(), last4=fake.token[-4:])
    fake.checks.clear()
    assert all(m["quality"] == "onbekend" for m in rows(linked, auth, CONNECTOR).values())
    assert not fake.checks and not fake.calls


@pytest.mark.parametrize("state", ["oude_kluiswaarde", "andere_client", "woning_ontbreekt", "ander_woningadres"])
def test_koppelbewijs_bij_gebruik(linked: Any, auth: Any, bron: MyHouseEnergy, state: str) -> None:
    from integrations.models import IntegrationSource

    with linked.app.state.db.sessions.begin() as s:
        source = s.get(IntegrationSource, "my_house")
        if state == "oude_kluiswaarde":
            linked.app.state.vault.put(s, source.credential_ref, bron.token)
        elif state == "andere_client":
            bron.client_id = uuid4()
        elif state == "woning_ontbreekt":
            bron.homes = []
        else:
            source.base_url = bron.address.replace(str(bron.home), str(uuid4()))
    bron.checks.clear()
    assert all(m["quality"] == "onbekend" for m in rows(linked, auth, CONNECTOR).values())
    assert not bron.calls
    if state in ("oude_kluiswaarde", "ander_woningadres"):
        assert not bron.checks


@pytest.mark.parametrize("first_status", [200, 503])
def test_recht_opnieuw_voor_volgende_get_en_herpoging(
    linked: Any, auth: Any, bron: MyHouseEnergy, first_status: int
) -> None:
    def changed(request: httpx.Request) -> httpx.Response:
        result = bron.handle(request)
        if request.url.path.endswith("/energy/live"):
            bron.purpose = "phone"
            return result if first_status == 200 else httpx.Response(first_status)
        return result

    linked.app.state.http_transport = httpx.MockTransport(changed)
    assert all(m["quality"] == "onbekend" for m in rows(linked, auth, CONNECTOR).values())
    assert bron.calls == [("GET", bron.path + "/energy/live")]
    assert len(set(bron.nonces)) == 3


@pytest.mark.parametrize(
    ("source_quality", "quality"),
    [
        ("measured", "gemeten"),
        ("estimated", "geschat"),
        ("derived", "onbekend"),
        (None, "onbekend"),
    ],
)
def test_bronkwaliteit(linked: Any, auth: Any, bron: MyHouseEnergy, source_quality: str | None, quality: str) -> None:
    if source_quality is None:
        del bron.live["total_source_quality"]
        del bron.live["parts"][1]["source_quality"]
    else:
        bron.live["total_source_quality"] = bron.live["parts"][1]["source_quality"] = source_quality
    meters = rows(linked, auth, ENERGY + "/meters")
    for role, value in (("p1_net", -42.5), ("boiler_socket", 0)):
        assert meters[role]["measurement_quality"] == quality
        assert meters[role]["last_measurement"] == (None if quality == "onbekend" else value)


def test_connector_versheidscontract(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    now = datetime.now(UTC)
    fresh, stale = (
        (now - timedelta(seconds=s)).isoformat(timespec="seconds").replace("+00:00", "Z") for s in (240, 310)
    )
    bron.live["total_observed_at"] = stale
    bron.live["parts"][0]["at"] = stale
    bron.live["parts"][1]["at"] = fresh
    discover = linked.get("/connector/v1/discover", headers=auth("viewer")).json()
    assert discover["limits"]["max_age_s"]["energy.coverage"] == 300
    assert linked.get(ENERGY + "/coverage", headers=auth("viewer")).json()["max_age_s"] == 300
    for path in (ENERGY + "/coverage", CONNECTOR):
        matrix = rows(linked, auth, path)
        for role, at, quality, code in [
            ("p1_net", stale, "onbekend", "meting_verouderd"),
            ("airco_outdoor", stale, "onbekend", "meting_verouderd"),
            ("boiler_socket", fresh, "gemeten", None),
            ("nas_host", None, "onbekend", None),
        ]:
            item = matrix[role]
            assert (item["observed_at"], item["last_updated"], item["quality"], item["reason_code"]) == (
                at,
                at,
                quality,
                code,
            )


def test_onvertrouwd_tls_certificaat(tls_authentik: TlsAuthentik) -> None:
    from integrations.config import Settings
    from integrations.domains.energy.client import EnergyClient, EnergyRoute, ViewerDenied

    server, url, _cert, _heads = tls_authentik
    source = MyHouseEnergy()
    source.address = url + source.path
    client = EnergyClient(source.address, viewer(source), Settings(allow_loopback_hub=True), None)
    with pytest.raises(ViewerDenied):
        client.verify()
    with pytest.raises(ViewerDenied):
        client.read(EnergyRoute.LIVE)
    assert not server.calls


@pytest.mark.parametrize(
    "invalid", ["bewijs_ontbreekt", "fout_bewijs", "ander_algoritme", "andere_client", "andere_woning"]
)
def test_geen_opslag_zonder_bewijs(linked: Any, auth: Any, invalid: str) -> None:
    from integrations.models import IntegrationSource, VaultSecret

    fake = MyHouseEnergy()
    authorised = []

    def invalid_proof(request: httpx.Request) -> httpx.Response:
        result = fake.handle(request)
        if "Authorization" in request.headers:
            authorised.append(request.url.path)
        data = result.json()
        if request.url.path.endswith("/identity"):
            if invalid == "bewijs_ontbreekt":
                del data["proof"]
            elif invalid == "fout_bewijs":
                data["proof"] = "0" * 64
            elif invalid == "ander_algoritme":
                data["proof_alg"] = None
        elif invalid == "andere_client" and request.url.path.endswith("/self"):
            data["id"] = str(uuid4())
        elif invalid == "andere_woning" and request.url.path.endswith("/homes"):
            data = [{"id": str(uuid4())}]
        return httpx.Response(200, json=data)

    linked.app.state.http_transport = httpx.MockTransport(invalid_proof)
    result = linked.put(
        SOURCE,
        headers=idem(auth("admin")),
        json={
            "base_url": fake.address,
            "enabled": True,
            "credential": fake.token,
            "my_house_pairing": fake.pairing,
        },
    )
    assert result.status_code == 422 and fake.token not in result.text
    assert all(m["quality"] == "onbekend" for m in rows(linked, auth, CONNECTOR).values())
    assert not fake.calls
    if invalid in ("bewijs_ontbreekt", "fout_bewijs", "ander_algoritme"):
        assert not authorised
    with linked.app.state.db.sessions() as s:
        assert s.get(IntegrationSource, "my_house") is None and s.get(VaultSecret, "vault://source/my-house") is None


def test_herconfiguratie_bewaart_geen_onbevestigde_wijziging(linked: Any, auth: Any, bron: MyHouseEnergy) -> None:
    before = linked.get(SOURCE, headers=auth("viewer")).json()["runtime"]
    bron.purpose = "phone"
    assert configure(linked, auth, bron, credential=None, my_house_pairing=None).status_code == 422
    after = linked.get(SOURCE, headers=auth("viewer")).json()["runtime"]
    assert before == after
    assert all(m["quality"] == "onbekend" for m in rows(linked, auth, CONNECTOR).values())
    assert not bron.calls
