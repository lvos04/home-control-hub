"""Regressieproeven voor de Authentik-export in de lokale simulator."""

from __future__ import annotations

import secrets
import uuid
from copy import deepcopy
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select

from integrations.domains.sso import authaudit
from integrations.domains.sso.models import SsoAnomaly, SsoAuthentikSnapshot
from tests.conftest import idem
from tests.fakes.authentik_fake import AuthentikFake
from tests.integration.test_b13_p1_authentik import BASE, _outbox, _source

pytestmark = pytest.mark.integration
EXPORTS = f"{BASE}/authentik/config-exports"


def _export(client: Any, headers: Any, key: str | None = None) -> dict[str, Any]:
    response = client.post(EXPORTS, headers=idem(headers, key=key))
    assert response.status_code == 201
    return response.json()


def _export_check(client: Any, headers: Any) -> dict[str, Any]:
    response = client.post(f"{BASE}/authentik/upgrade-gate", json={"target_version": "2026.8.5"}, headers=idem(headers))
    assert response.status_code == 200
    result = response.json()
    assert result["outcome"] in {"rood", "onbekend"}
    return next(check for check in result["checks"] if check["name"] == "configuratie_export")


def test_opruimen_bewaart_de_laatste_bruikbare_configuratie_export(
    paired_client: Any, auth: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    geldig = _export(client, admin)
    # Een oudere opslagversie kon een ontbrekende flow met complete=True bewaren.
    monkeypatch.setitem(authaudit.KEEP_SNAPSHOTS, "config_export", 2)
    with client.app.state.db.sessions() as session:
        bron = session.get(SsoAuthentikSnapshot, uuid.UUID(geldig["id"]))
        inhoud = deepcopy(bron.content)
        inhoud["format"] = "hch-authentik-config-export/1"
        inhoud["parts"]["providers"][0].pop("authorization_flow")
        afgekeurd = [
            authaudit.store_snapshot(
                session, bron.kind, inhoud, True, bron.authentik_version, ("service", bron.taken_by), str(bron.trace_id)
            ).id
            for _ in range(2)
        ]
        session.commit()

    controle = _export_check(client, admin)
    assert controle["status"] == "ok" and controle["detail"]["export_id"] == geldig["id"]
    with client.app.state.db.sessions() as session:
        assert authaudit.latest_snapshot(session, "config_export").id == uuid.UUID(geldig["id"])
        authaudit.purge_old_events(session)
        session.commit()
        assert all(session.get(SsoAuthentikSnapshot, row_id) is not None for row_id in afgekeurd)
    detail = client.get(f"{EXPORTS}/{geldig['id']}", headers=admin)
    assert detail.status_code == 200 and detail.json()["complete"] is True
    assert _export_check(client, admin)["detail"]["export_id"] == geldig["id"]


def test_upgradegate_negeert_een_export_van_een_andere_versie(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    huidig = _export(client, admin)
    authentik_fake.version = "2026.8.4"
    assert _export(client, admin)["complete"] is True
    authentik_fake.version = "2026.8.5"
    controle = _export_check(client, admin)
    assert controle["status"] == "ok" and controle["detail"]["export_id"] == huidig["id"]
    with client.app.state.db.sessions() as session:
        bron = session.get(SsoAuthentikSnapshot, uuid.UUID(huidig["id"]))
        bron.taken_at -= timedelta(hours=25)
        session.commit()
    assert _export_check(client, admin)["status"] == "fout"


def test_oude_lege_redirectlijst_is_geen_bewijs_voor_een_herstelbasis(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    authentik_fake.providers[-1]["redirect_uris"] = []
    nieuw = _export(client, admin)
    with client.app.state.db.sessions() as session:
        bron = session.get(SsoAuthentikSnapshot, uuid.UUID(nieuw["id"]))
        inhoud = deepcopy(bron.content)
        inhoud["format"] = "hch-authentik-config-export/1"
        oud = authaudit.store_snapshot(
            session, bron.kind, inhoud, True, bron.authentik_version, ("service", bron.taken_by), str(bron.trace_id)
        )
        oud_id, oude_hash = oud.id, oud.content_sha256
        session.commit()
    detail = client.get(f"{EXPORTS}/{oud_id}", headers=admin)
    assert detail.status_code == 200 and detail.json()["complete"] is False
    assert detail.json()["content_sha256"] == oude_hash
    assert _export_check(client, admin)["detail"]["export_id"] == nieuw["id"]

    def herstel(export_id: str) -> Any:
        return client.post(f"{BASE}/authentik/restore-check", json={"export_id": export_id}, headers=idem(admin))

    geweigerd = herstel(str(oud_id))
    assert geweigerd.status_code == 409 and geweigerd.json()["code"] == "export_onvolledig"
    bruikbaar = herstel(nieuw["id"])
    assert bruikbaar.status_code == 200 and bruikbaar.json()["outcome"] == "ok"
    with client.app.state.db.sessions() as session:
        bewaard = session.get(SsoAuthentikSnapshot, oud_id)
        assert bewaard.complete is True and bewaard.content == inhoud and bewaard.content_sha256 == oude_hash


@pytest.mark.parametrize("volledig", [True, False])
def test_herhaling_geeft_het_oorspronkelijke_antwoord_ook_na_opruiming(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, volledig: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    sleutel = str(uuid.uuid4())
    provider = authentik_fake.providers[-1]
    flow = provider.pop("authorization_flow") if not volledig else provider["authorization_flow"]
    gemaakt = _export(client, admin, sleutel)
    assert gemaakt["complete"] is volledig
    assert _export(client, admin, sleutel) == gemaakt
    provider["authorization_flow"] = flow
    assert _export(client, admin)["complete"] is True
    monkeypatch.setitem(authaudit.KEEP_SNAPSHOTS, "config_export", 1)
    with client.app.state.db.sessions() as session:
        authaudit.purge_old_events(session)
        session.commit()
    events = _outbox(client)
    assert client.get(f"{EXPORTS}/{gemaakt['id']}", headers=admin).status_code == 404
    replay = client.post(EXPORTS, headers=idem(admin, key=sleutel))
    assert replay.status_code == 201 and replay.headers["Idempotent-Replay"] == "true"
    assert replay.json() == gemaakt
    assert _outbox(client) == events
    with client.app.state.db.sessions() as session:
        assert session.scalar(select(func.count()).select_from(SsoAuthentikSnapshot)) == 1


def test_opruimen_bewaart_per_versie_de_laatste_bruikbare_export(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    huidig = _export(client, admin)
    authentik_fake.version = "2026.8.4"
    ander = _export(client, admin)
    authentik_fake.version = "2026.8.5"
    monkeypatch.setitem(authaudit.KEEP_SNAPSHOTS, "config_export", 1)
    with client.app.state.db.sessions() as session:
        bron = session.get(SsoAuthentikSnapshot, uuid.UUID(huidig["id"]))
        for _ in range(3):  # nieuwere rijen, onvolledig: tellen mee voor de bewaartermijn, niet als bruikbare export
            authaudit.store_snapshot(
                session,
                bron.kind,
                bron.content,
                False,
                bron.authentik_version,
                ("service", bron.taken_by),
                str(bron.trace_id),
            )
        session.commit()
        authaudit.purge_old_events(session)
        session.commit()
    assert client.get(f"{EXPORTS}/{huidig['id']}", headers=admin).status_code == 200
    assert client.get(f"{EXPORTS}/{ander['id']}", headers=admin).status_code == 200
    assert _export_check(client, admin)["detail"]["export_id"] == huidig["id"]


def test_upgradegate_gebruikt_alleen_een_export_van_de_ingestelde_bron(paired_client: Any, auth: Any) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    export = _export(client, admin)
    assert _export_check(client, admin)["status"] == "ok"
    for bron in ("een-andere-bron", None):  # een andere Authentik-instantie, of een export van vóór de bronvastlegging
        with client.app.state.db.sessions() as session:
            rij = session.get(SsoAuthentikSnapshot, uuid.UUID(export["id"]))
            inhoud = deepcopy(rij.content)
            inhoud.pop("source", None)
            if bron:
                inhoud["source"] = bron
            rij.content = inhoud
            session.commit()
        assert _export_check(client, admin)["status"] == "fout"
    assert _export_check(client, admin)["detail"]["export_id"] is None
    nieuw = _export(client, admin)
    assert _export_check(client, admin)["detail"]["export_id"] == nieuw["id"]


SOURCE = "/integrations/v1/sources/authentik"


def _herkoppel(client: Any, admin: Any, fake: AuthentikFake) -> None:
    huidig = client.get(SOURCE, headers=admin).json()["runtime"]
    antwoord = client.put(
        SOURCE,
        json={"base_url": huidig["base_url"], "enabled": True, "credential": fake.token},
        headers=idem(admin, **{"If-Match": huidig["etag"]}),
    )
    assert antwoord.status_code == 200


def test_upgradegate_weigert_een_export_van_de_vorige_installatie_op_hetzelfde_adres(
    paired_client: Any, auth: Any, fake_hub: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, admin = paired_client, auth("admin")
    oud, vervanger = fake_hub.authentik, AuthentikFake(host=fake_hub.authentik.host, token=secrets.token_urlsafe(24))
    bronnen = {"actief": oud}
    monkeypatch.setattr(
        client.app.state, "http_transport", httpx.MockTransport(lambda verzoek: bronnen["actief"].handle(verzoek))
    )
    _source(client, admin)
    export = _export(client, admin)
    assert _export_check(client, admin)["detail"]["export_id"] == export["id"]
    bronnen["actief"] = vervanger
    _herkoppel(client, admin, vervanger)
    controle = _export_check(client, admin)
    assert controle["status"] == "fout" and controle["detail"]["export_id"] is None
    nieuw = _export(client, admin)
    assert _export_check(client, admin)["detail"]["export_id"] == nieuw["id"]


@pytest.mark.parametrize("situatie", ["eigen", "herkoppeld", "zonder_herkomst"])
def test_herstelcheck_toetst_eerst_de_herkomst(
    paired_client: Any, auth: Any, fake_hub: Any, monkeypatch: pytest.MonkeyPatch, situatie: str
) -> None:
    client, admin = paired_client, auth("admin")
    oud, vervanger = fake_hub.authentik, AuthentikFake(host=fake_hub.authentik.host, token=secrets.token_urlsafe(24))
    bronnen = {"actief": oud}
    monkeypatch.setattr(
        client.app.state, "http_transport", httpx.MockTransport(lambda verzoek: bronnen["actief"].handle(verzoek))
    )
    _source(client, admin)
    export = _export(client, admin)
    if situatie == "herkoppeld":
        bronnen["actief"] = vervanger
        _herkoppel(client, admin, vervanger)
    if situatie == "zonder_herkomst":
        with client.app.state.db.sessions() as session:
            rij = session.get(SsoAuthentikSnapshot, uuid.UUID(export["id"]))
            inhoud = deepcopy(rij.content)
            inhoud.pop("source")
            rij.content = inhoud
            session.commit()
    antwoord = client.post(f"{BASE}/authentik/restore-check", json={"export_id": export["id"]}, headers=idem(admin))
    assert antwoord.status_code == 200
    uitkomst = antwoord.json()["outcome"]
    with client.app.state.db.sessions() as session:
        assert session.scalar(select(func.count()).select_from(SsoAnomaly)) == 0
    if situatie == "eigen":
        assert uitkomst == "ok"
    else:
        assert uitkomst == "onbekend" and [c["name"] for c in antwoord.json()["checks"]] == ["herkomst"]


def test_opruimen_houdt_de_nieuwste_rechtenkaarten(
    paired_client: Any, auth: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    monkeypatch.setitem(authaudit.KEEP_SNAPSHOTS, "rechten", 2)
    with client.app.state.db.sessions() as session:
        ids = [
            authaudit.store_snapshot(
                session, "rechten", {"rights": {}}, True, version, ("service", "t"), str(uuid.uuid4())
            ).id
            for version in ("2026.8.4", "2026.8.5", "2026.8.5")
        ]
        session.commit()
        authaudit.purge_old_events(session)
        session.commit()
        bewaard = set(session.scalars(select(SsoAuthentikSnapshot.id).where(SsoAuthentikSnapshot.kind == "rechten")))
    assert bewaard == set(ids[1:])


def _zet_bron(client: Any, admin: Any, **velden: Any) -> None:
    huidig = client.get(SOURCE, headers=admin).json()["runtime"]
    antwoord = client.put(SOURCE, json=velden, headers=idem(admin, **{"If-Match": huidig["etag"]}))
    assert antwoord.status_code == 200


def test_opruimen_begrenst_exports_van_vervallen_koppelrevisies(
    paired_client: Any, auth: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    adres = client.get(SOURCE, headers=admin).json()["runtime"]["base_url"]
    monkeypatch.setitem(authaudit.KEEP_SNAPSHOTS, "config_export", 3)
    exports = []
    for _ in range(5):
        _zet_bron(client, admin, base_url=adres, enabled=True)
        gemaakt = _export(client, admin)
        assert gemaakt["complete"]
        exports.append(uuid.UUID(gemaakt["id"]))

    with client.app.state.db.sessions() as session:
        authaudit.purge_old_events(session)
        session.commit()
        bewaard = set(
            session.scalars(select(SsoAuthentikSnapshot.id).where(SsoAuthentikSnapshot.kind == "config_export"))
        )
    assert bewaard == set(exports[-3:])
    assert _export_check(client, admin)["detail"]["export_id"] == str(exports[-1])


@pytest.mark.parametrize("onvolledig", ["ander", "zelfde", "dubbel", "dubbel_id", "dubbel_id_onvolledig"])
def test_herstelcheck_onderscheidt_bevestigde_en_onbekende_providervelden(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, onvolledig: str
) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    authentik_fake.add_hub_app()
    export = _export(client, admin)
    assert export["complete"]
    immich, hub = authentik_fake.providers
    hub["client_id"] = "gewijzigde-testclient"
    if onvolledig == "ander":
        immich.pop("authorization_flow")
    elif onvolledig == "zelfde":
        hub.pop("redirect_uris")
    elif onvolledig == "dubbel":
        authentik_fake.providers.append({**hub, "client_id": "dubbele-testclient"})
    else:
        hub["pk"] = immich["pk"]
        if onvolledig == "dubbel_id_onvolledig":
            hub.pop("authorization_flow")

    antwoord = client.post(f"{BASE}/authentik/restore-check", json={"export_id": export["id"]}, headers=idem(admin))
    assert antwoord.status_code == 200
    data = antwoord.json()
    providers = next(check for check in data["checks"] if check["name"] == "providers")
    with client.app.state.db.sessions() as session:
        alarmen = session.scalar(
            select(func.count()).select_from(SsoAnomaly).where(SsoAnomaly.rule_id == "herstel_afwijking")
        )
    if onvolledig.startswith("dubbel"):
        assert data["outcome"] == providers["status"] == "onbekend"
        assert not providers["detail"].get("missing")
        assert alarmen == 0
    else:
        assert data["outcome"] == providers["status"] == "afwijking"
        assert providers["detail"]["missing"] == []
        assert providers["detail"]["changed"] == [{"key": "Hub", "fields": ["client_id"]}]
        assert alarmen == 1
    assert not authentik_fake.writes


def test_oude_koppeling_komt_niet_terug_na_verwijderen_en_opnieuw_instellen(paired_client: Any, auth: Any) -> None:
    client, admin = paired_client, auth("admin")
    _source(client, admin)
    adres = client.get(SOURCE, headers=admin).json()["runtime"]["base_url"]
    export = _export(client, admin)
    assert _export_check(client, admin)["detail"]["export_id"] == export["id"]
    _zet_bron(client, admin, base_url=None, enabled=False)  # de kluisrij blijft behouden
    _zet_bron(client, admin, base_url=adres, enabled=True)
    controle = _export_check(client, admin)
    assert controle["status"] == "fout" and controle["detail"]["export_id"] is None
    nieuw = _export(client, admin)
    assert _export_check(client, admin)["detail"]["export_id"] == nieuw["id"]


def test_export_krijgt_de_revisie_van_de_client_ook_als_de_bron_daarna_wijzigt(paired_client: Any, auth: Any) -> None:
    from integrations.domains.sso import backup
    from integrations.domains.sso.authentik.client import client_from_source

    client, admin = paired_client, auth("admin")
    _source(client, admin)
    state = client.app.state
    with state.db.sessions() as session:
        gelezen = client_from_source(session, state.settings, state.vault, state.http_transport)
        session.commit()
    adres = client.get(SOURCE, headers=admin).json()["runtime"]["base_url"]
    _zet_bron(client, admin, base_url=adres, enabled=True)  # overlappende wijziging na de lezing van de client
    with state.db.sessions() as session:
        rij = backup.create_export(session, gelezen, ("service", "test"), str(uuid.uuid4()))
        session.commit()
        assert rij.content["source"] == gelezen.link_revision
    assert _export_check(client, admin)["detail"]["export_id"] is None
