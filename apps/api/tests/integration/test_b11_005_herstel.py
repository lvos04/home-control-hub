"""B11-005 — herstel en versiebeheer van flows.

Acceptatie: "Undo herstelt oude flows inclusief credentials zonder secrets te loggen." De hele keten hier: momentopname
(versleuteld, mét het door Node-RED versleutelde credentials-bestand) → verschil zonder waarden → herstelvoorstel →
door de Hub ondertekend ExecutionRequest met een menselijke goedkeuring → eigen hercontrole → schrijven → readback.
Sim-getest (nep-Node-RED met dezelfde API-vorm, nep-Hub die ondertekent zoals docs/EXECUTION_REQUEST.md van de Hub).
Dat de echte Hub dit verzoek uitgeeft en een echte Node-RED op de NAS het aanneemt: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest import mock

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text, update

from integrations import idempotency
from integrations.domains.automation import nodered, restore, snapshots
from integrations.domains.automation.models import AutomationExecutionNonce, AutomationRestore, AutomationSnapshot
from integrations.models import AuditEvent, IdempotencyRecord, OutboxEvent
from integrations.timeutil import utcnow
from integrations.worker import Worker
from tests import b11
from tests.b11 import CONNECTOR, RESTORE, A
from tests.conftest import BROWSER_HEADERS, SimKey, idem, pair, setup_node_red
from tests.fakes.node_red_fake import exec_flow, node, simple_flow

TAB = "tab0000000000001"
BROKER = "broker0000000001"
PW1 = "Eerste-broker-wachtwoord-9431"
PW2 = "Tweede-broker-wachtwoord-7702"


def broker() -> dict[str, Any]:
    """Een configuratienode met inloggegevens (die staan alleen in flows_cred.json, versleuteld door Node-RED)."""
    return {"id": BROKER, "type": "mqtt-broker", "name": "Huisbroker", "broker": "mqtt.invalid", "port": "1883"}


def flows_v1() -> list[dict[str, Any]]:
    return [*simple_flow(), broker()]


def flows_v2() -> list[dict[str, Any]]:
    flows = flows_v1()
    for n in flows:
        if n["type"] == "function":
            n["func"] = "msg.payload = 'stiekem-aangepast'; return msg;"
    flows.append(node("tab00000debug002", "debug", TAB, active=False))
    return flows


CREDS_V1 = {BROKER: {"user": "nas", "password": PW1}}
CREDS_V2 = {BROKER: {"user": "nas", "password": PW2}}


@pytest.fixture
def read_only_mount() -> Iterator[None]:
    """Doet alsof de datamap van Node-RED alleen-lezen is gekoppeld. Een echte alleen-lezen-koppeling kan een test
    zonder root niet maken; daarom wordt alleen de meting daarvan (``snapshots._mounted_read_only``) vervangen, buiten
    ``monkeypatch`` om (een ``monkeypatch.undo()`` in een test haalt dit dus niet weg). Dat een beschrijfbare map nooit
    telt: ``test_a_writable_data_dir_never_counts_as_linked``."""
    with mock.patch.object(snapshots, "_mounted_read_only", lambda _dir_fd: True):
        yield


@pytest.fixture
def client(app_factory: Any, node_red_fake: Any, read_only_mount: None) -> Any:
    """De dienst met de datamap van Node-RED alleen-lezen gekoppeld (zoals in het formulier van de Custom App)."""
    return app_factory(node_red_data_dir=node_red_fake.data_dir)


def cred_blob(node_red_fake: Any) -> str:
    return str(json.loads((node_red_fake.data_dir / "flows_cred.json").read_text(encoding="utf-8"))["$"])


def define(profile: dict[str, Any], key: str) -> str:
    for arg in profile["arguments"]:
        if arg.startswith(f"--define={key}="):
            return str(arg.split("=", 2)[2])
    raise AssertionError(key)


class Scene:
    """Twee toestanden: v1 (momentopname) en daarna een wijziging in de editor naar v2 (ook een momentopname)."""

    def __init__(self, linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
        self.linked, self.fake_hub, self.auth, self.nr = linked, fake_hub, auth, node_red_fake
        self.profile = setup_node_red(linked, fake_hub, auth, flows=flows_v1(), credentials=CREDS_V1)
        self.blob1 = cred_blob(node_red_fake)
        self.snap1 = b11.snapshot(linked, auth)["snapshot"]
        node_red_fake.deploy(flows_v2(), CREDS_V2)
        self.blob2 = cred_blob(node_red_fake)
        self.snap2 = b11.snapshot(linked, auth)["snapshot"]
        assert node_red_fake.writes == [], "tot hier heeft deze dienst alleen gelezen"

    def propose(self, snapshot_id: str | None = None) -> dict[str, Any]:
        r = b11.propose_restore(self.linked, self.auth, snapshot_id or self.snap1["id"])
        assert r.status_code == 201, r.text
        view: dict[str, Any] = r.json()
        return view

    def sign(self, view: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return b11.signed_restore(self.fake_hub, view, **kwargs)

    def apply(self, request: dict[str, Any], key: str | None = None) -> Any:
        return b11.apply(self.linked, self.fake_hub, request, key=key)

    def restore_row(self, proposal_id: str) -> dict[str, Any]:
        r = self.linked.get(f"{A}/restores/{proposal_id}", headers=self.auth("viewer"))
        assert r.status_code == 200, r.text
        body: dict[str, Any] = r.json()
        return body

    def secrets(self) -> list[str]:
        return [
            PW1,
            PW2,
            self.blob1,
            self.blob2,
            self.profile["beheerwachtwoord"],
            define(self.profile, "credentialSecret"),
        ]


@pytest.fixture
def scene(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> Scene:
    return Scene(linked, fake_hub, auth, node_red_fake)


def snapshot_rows(linked: Any) -> list[AutomationSnapshot]:
    with linked.app.state.db.sessions() as s:
        return list(s.scalars(select(AutomationSnapshot).order_by(AutomationSnapshot.seq)))


# ------------------------------------------------------------------------------------------- momentopnamen en versies
def test_snapshot_holds_flows_and_the_encrypted_credentials_file(scene: Scene, linked: Any, auth: Any) -> None:
    snap = scene.snap1
    assert snap["credentials_present"] is True and snap["credentials_status"] == "meegenomen"
    assert snap["versleuteld"].startswith("AES-256-GCM") and snap["reason"] == "handmatig"
    assert snap["flow_count"] == 1 and snap["node_count"] == len(flows_v1())
    assert snap["checksum_sha256"] != scene.snap2["checksum_sha256"]
    # de inhoud staat versleuteld in de database: geen functiecode, geen credentials-bestand, geen wachtwoord
    rows = snapshot_rows(linked)
    assert len(rows) == 2
    for row in rows:
        stored = bytes(row.ciphertext)
        for needle in ("return msg;", "stiekem-aangepast", scene.blob1, scene.blob2, PW1, PW2, "Huisbroker"):
            assert needle.encode() not in stored
    # en de API geeft alleen kenmerken terug
    r = linked.get(f"{A}/snapshots/{snap['id']}", headers=auth("viewer"))
    assert r.status_code == 200 and "flows" not in r.json() and "credentials" not in r.json()
    assert scene.blob1 not in r.text
    listed = linked.get(f"{A}/snapshots", headers=auth("viewer")).json()["items"]
    assert [x["id"] for x in listed] == [scene.snap2["id"], snap["id"]]
    assert linked.post(f"{A}/snapshots", headers=idem(auth("viewer"))).status_code == 403


def test_worker_snapshots_only_when_something_changed(
    scene: Scene, linked: Any, fake_hub: Any, make_settings: Any, node_red_fake: Any
) -> None:
    settings = make_settings(node_red_data_dir=node_red_fake.data_dir, node_red_sync_interval_s=60)
    worker = Worker(settings, transport=fake_hub.transport)
    worker.automation_step(1000.0)
    assert worker.state.stats["node_red_syncs"] == 1
    assert len(snapshot_rows(linked)) == 2, "niets gewijzigd: geen nieuwe momentopname"
    worker.automation_step(1030.0)
    assert worker.state.stats["node_red_syncs"] == 1, "binnen het interval wordt Node-RED niet opnieuw uitgelezen"
    # een wijziging in de editor: bij de volgende ronde een nieuwe versie
    changed = flows_v2()
    changed.append(node("tab00000debug003", "debug", TAB, active=True))
    node_red_fake.deploy(changed)
    worker.automation_step(1100.0)
    rows = snapshot_rows(linked)
    assert len(rows) == 3 and rows[-1].reason == "gepland" and rows[-1].has_credentials is True
    detail = b11.flow_by_tab(linked, scene.auth, TAB)
    assert detail["current_version"]["snapshot_id"] == str(rows[-1].id)
    versions = linked.get(f"{A}/flows/{detail['id']}/versions", headers=scene.auth("viewer")).json()["items"]
    assert len(versions) == 3 and len({v["checksum_sha256"] for v in versions}) == 3
    # alleen andere inloggegevens (zelfde flows): ook dat is een nieuwe momentopname
    node_red_fake.deploy(changed, {BROKER: {"user": "nas", "password": "nog-een-ander"}})
    worker.automation_step(1200.0)
    rows = snapshot_rows(linked)
    assert len(rows) == 4 and rows[-1].checksum_sha256 == rows[-2].checksum_sha256
    assert rows[-1].credentials_sha256 != rows[-2].credentials_sha256
    assert node_red_fake.writes == [], "de worker schrijft nooit naar Node-RED"


def test_diff_shows_nodes_and_field_names_but_never_values(scene: Scene, linked: Any, auth: Any) -> None:
    r = linked.get(f"{A}/snapshots/{scene.snap2['id']}/diff", headers=auth("operator"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["van"]["id"] == scene.snap1["id"] and body["naar"]["id"] == scene.snap2["id"]
    diff = body["diff"]
    assert diff["waarden_getoond"] is False and diff["gelijk"] is False
    assert diff["aantallen"] == {"toegevoegd": 1, "verwijderd": 0, "gewijzigd": 1, "ongewijzigd": 4}
    assert [n["id"] for n in diff["toegevoegd"]] == ["tab00000debug002"]
    assert diff["gewijzigd"][0]["type"] == "function" and diff["gewijzigd"][0]["velden"] == ["func"]
    assert body["credentials_gewijzigd"] is True
    for needle in ("stiekem-aangepast", "return msg", PW1, PW2, scene.blob1, scene.blob2):
        assert needle not in r.text
    assert linked.get(f"{A}/snapshots/{scene.snap2['id']}/diff", headers=auth("viewer")).status_code == 403
    r = linked.get(f"{A}/snapshots/{scene.snap1['id']}/diff", headers=auth("admin"))
    assert r.status_code == 409 and r.json()["code"] == "geen_eerdere_momentopname"


def test_unencrypted_credentials_file_is_never_taken(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    """Een leesbaar credentials-bestand (Node-RED zonder credentialSecret) neemt deze dienst bewust niet mee."""
    setup_node_red(linked, fake_hub, auth, flows=flows_v1(), credentials=CREDS_V1)
    cred_file = node_red_fake.data_dir / "flows_cred.json"
    cred_file.write_text(json.dumps(CREDS_V1), encoding="utf-8")  # zoals Node-RED het zonder sleutel schrijft
    assert PW1 in cred_file.read_text(encoding="utf-8")
    snap = b11.snapshot(linked, auth)["snapshot"]
    assert snap["credentials_present"] is False and snap["credentials_status"] == "onleesbaar"
    assert PW1 not in b11.everything_stored(linked)
    assert PW1.encode() not in bytes(snapshot_rows(linked)[0].ciphertext)


def test_snapshot_without_linked_data_dir_says_so(
    app_factory: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    plain = app_factory()  # zonder HCH_NODE_RED_DATA_DIR
    assert pair(plain, fake_hub).ok
    setup_node_red(plain, fake_hub, auth, flows=flows_v1(), credentials=CREDS_V1)
    first = b11.snapshot(plain, auth)["snapshot"]
    assert first["credentials_present"] is False and first["credentials_status"] == "niet_gekoppeld"
    sync = plain.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["credentials_status"] == "niet_gekoppeld" and sync["credentials_reden"] is None, sync
    node_red_fake.deploy(flows_v2(), CREDS_V2)
    b11.snapshot(plain, auth)
    view = b11.propose_restore(plain, auth, first["id"]).json()
    assert view["credentials"] == {
        "credentials_present": False,
        "status": "niet_gekoppeld",
        "wijzigt": None,
        "terugzetten": False,
        "reden": None,
    }
    assert any("geen credentials-bestand" in w for w in view["warnings"])
    r = b11.apply(plain, fake_hub, b11.signed_restore(fake_hub, view))
    assert r.status_code == 200, r.text
    assert r.json()["credentials_teruggezet"] is False
    assert node_red_fake.flows == flows_v1()
    assert node_red_fake.credentials == CREDS_V2, "bestaande nodes houden hun (huidige) inloggegevens"
    assert node_red_fake.writes[-1]["met_credentials"] is False


def test_a_writable_data_dir_never_counts_as_linked(
    app_factory: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """S-P2-320, bouwpunt 1: credentials-herstel telt alleen als de datamap van Node-RED **alleen-lezen** is gekoppeld
    (``ST_RDONLY``, gemeten met ``fstatvfs`` op de geopende map). Een beschrijfbare koppeling (hier de tijdelijke map
    van de nep-Node-RED, met een geldig versleuteld bestand erin) is eerlijk ``niet_gekoppeld``: het bestand wordt niet
    gelezen, de momentopname heeft geen credentials en een herstel zet er geen terug. De synchronisatie noemt de reden
    ``niet_alleen_lezen`` (R-TECH-3), zodat de beheerder ziet waarom; zonder ingestelde map is er geen reden."""
    import os

    data_dir = node_red_fake.data_dir
    assert not os.statvfs(data_dir).f_flag & os.ST_RDONLY, "deze proef vraagt een beschrijfbare map"
    writable = app_factory(node_red_data_dir=data_dir)
    assert pair(writable, fake_hub).ok
    setup_node_red(writable, fake_hub, auth, flows=flows_v1(), credentials=CREDS_V1)
    assert (data_dir / "flows_cred.json").is_file(), "het bestand staat er wel"
    first = b11.snapshot(writable, auth)["snapshot"]
    assert first["credentials_present"] is False and first["credentials_status"] == "niet_gekoppeld"
    sync = writable.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["credentials_status"] == "niet_gekoppeld", sync
    assert sync["credentials_reden"] == "niet_alleen_lezen", sync
    node_red_fake.deploy(flows_v2(), CREDS_V2)
    b11.snapshot(writable, auth)
    view = b11.propose_restore(writable, auth, first["id"]).json()
    assert view["credentials"] == {
        "credentials_present": False,
        "status": "niet_gekoppeld",
        "wijzigt": None,
        "terugzetten": False,
        "reden": None,
    }
    r = b11.apply(writable, fake_hub, b11.signed_restore(fake_hub, view))
    assert r.status_code == 200, r.text
    assert r.json()["credentials_teruggezet"] is False
    assert node_red_fake.flows == flows_v1() and node_red_fake.credentials == CREDS_V2
    assert node_red_fake.writes[-1]["met_credentials"] is False


# ------------------------------------------------------------------------------------------------------ het voorstel
def test_proposal_changes_nothing_and_needs_a_signed_request(
    scene: Scene, linked: Any, auth: Any, fake_hub: Any
) -> None:
    r = b11.propose_restore(linked, auth, scene.snap1["id"])
    assert r.status_code == 201, r.text
    view = r.json()
    assert view["action_id"] == RESTORE and view["target"] == {"type": "source", "id": "node_red"}
    assert view["parameters"] == {"snapshot_id": scene.snap1["id"]}
    assert view["status"] == "voorgesteld" and view["apply_status"] == "vereist_execution_request"
    assert view["risk_class_min"] == "R2" and view["requires_backup"] is False
    assert view["preview_hash"].startswith("sha256:") and len(view["preview_hash"]) == 71
    assert view["resource_etag"] == "sha256:" + scene.snap2["checksum_sha256"]
    assert view["diff"]["aantallen"] == {"toegevoegd": 0, "verwijderd": 1, "gewijzigd": 1, "ongewijzigd": 4}
    assert view["diff"]["waarden_getoond"] is False
    assert view["credentials"] == {
        "credentials_present": True,
        "status": "meegenomen",
        "wijzigt": True,
        "terugzetten": True,
        "reden": None,
    }
    assert view["rollback_recipe"]["automatisch"] is False
    assert r.headers["ETag"]
    assert scene.nr.writes == [] and scene.nr.flows == flows_v2()
    for secret in scene.secrets():
        assert secret not in r.text
    # zichtbaar voor de beheerder en voor de Hub
    assert scene.restore_row(view["proposal_id"])["status"] == "voorgesteld"
    listed = linked.get(f"{A}/restores", params={"status": "voorgesteld"}, headers=auth("viewer")).json()["items"]
    assert [x["proposal_id"] for x in listed] == [view["proposal_id"]]
    r = linked.get(f"{CONNECTOR}/items", params={"type": "automation.restore"}, headers=fake_hub.service_auth())
    assert r.status_code == 200 and [x["proposal_id"] for x in r.json()["items"]] == [view["proposal_id"]]
    assert len(b11.outbox(linked, "automation.restore.proposed")) == 1


def test_proposal_refusals(scene: Scene, linked: Any, auth: Any, fake_hub: Any) -> None:
    for role in ("operator", "viewer", "family"):
        assert b11.propose_restore(linked, auth, scene.snap1["id"], role=role).status_code == 403
    r = b11.propose_restore(linked, auth, str(uuid.uuid4()))
    assert r.status_code == 404
    for parameters in ({}, {"snapshot_id": "geen-uuid"}, {"snapshot_id": scene.snap1["id"], "force": True}):
        r = linked.post(
            f"{CONNECTOR}/propose",
            json={"action_id": RESTORE, "target": b11.NODE_RED_TARGET, "parameters": parameters},
            headers=idem(auth("admin")),
        )
        assert r.status_code == 422 and r.json()["code"] == "parameters_ongeldig", r.text
    # de huidige toestand terugzetten heeft geen zin
    r = b11.propose_restore(linked, auth, scene.snap2["id"])
    assert r.status_code == 409 and r.json()["code"] == "niets_te_herstellen"
    # Node-RED niet bereikbaar: geen voorstel
    scene.nr.up = False
    r = b11.propose_restore(linked, auth, scene.snap1["id"])
    assert r.status_code == 503 and r.json()["code"] == "node_red_unavailable" and r.headers["Retry-After"] == "30"
    scene.nr.up = True
    assert linked.get(f"{A}/restores", headers=auth("viewer")).json()["items"] == []


def test_snapshot_with_a_now_forbidden_flow_cannot_be_restored(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    setup_node_red(linked, fake_hub, auth, flows=[*simple_flow(), *exec_flow()])
    bad = b11.snapshot(linked, auth)
    assert bad["geblokkeerd"] == ["tab0000000000001", "tabexec000000001"]  # grof blokkeren: de hele bron
    node_red_fake.deploy(simple_flow())
    b11.snapshot(linked, auth)
    r = b11.propose_restore(linked, auth, bad["snapshot"]["id"])
    assert r.status_code == 422, r.text
    assert r.json()["code"] == "momentopname_niet_toegestaan"
    assert r.json()["details"]["bevindingen"][0]["code"] == "verboden_node"
    assert node_red_fake.writes == []


def test_unreadable_snapshot_is_reported(scene: Scene, linked: Any, auth: Any) -> None:
    with linked.app.state.db.sessions() as s:
        s.execute(
            update(AutomationSnapshot)
            .where(AutomationSnapshot.id == uuid.UUID(scene.snap1["id"]))
            .values(ciphertext=b"\x00" * 64)
        )
        s.commit()
    r = b11.propose_restore(linked, auth, scene.snap1["id"])
    assert r.status_code == 409 and r.json()["code"] == "momentopname_onleesbaar"
    assert scene.nr.writes == []


# ------------------------------------------------------------------------------- acceptatie: undo, mét credentials
def test_undo_restores_flows_and_credentials_without_logging_secrets(
    scene: Scene, linked: Any, auth: Any, fake_hub: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    view = scene.propose()
    request = scene.sign(view)
    r = scene.apply(request)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "uitgevoerd" and body["action_id"] == RESTORE
    assert body["proposal_id"] == view["proposal_id"]
    assert body["before_hash"] == "sha256:" + scene.snap2["checksum_sha256"]
    assert body["after_hash"] == "sha256:" + scene.snap1["checksum_sha256"]
    assert body["readback"]["gelezen"] is True and body["readback"]["gelijk_aan_momentopname"] is True
    assert body["credentials_teruggezet"] is True
    assert "NIET GEVALIDEERD (echte NAS)" in body["validatie"]

    # Node-RED staat weer in de oude toestand, mét de oude inloggegevens
    assert scene.nr.flows == flows_v1()
    assert scene.nr.credentials == CREDS_V1
    assert len(scene.nr.writes) == 1
    write = scene.nr.writes[0]
    assert write["door"] == "hub-dienst" and write["met_credentials"] is True and write["deployment_type"] == "full"

    # vastgelegd: wie, wat, vóór en na — en de weg terug
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "uitgevoerd" and row["applied_at"]
    assert row["result"]["goedgekeurd_door"] == "beheerder-1"
    assert row["result"]["bevestigd_via"] == "antwoord_en_readback"
    snaps = {s["id"]: s for s in linked.get(f"{A}/snapshots", headers=auth("viewer")).json()["items"]}
    assert snaps[body["pre_snapshot_id"]]["reason"] == "voor_herstel"
    assert snaps[body["pre_snapshot_id"]]["checksum_sha256"] == scene.snap2["checksum_sha256"]
    assert snaps[body["post_snapshot_id"]]["reason"] == "na_herstel"
    assert snaps[body["post_snapshot_id"]]["checksum_sha256"] == scene.snap1["checksum_sha256"]
    assert body["rollback_recipe"] == {"action_id": RESTORE, "parameters": {"snapshot_id": body["pre_snapshot_id"]}}
    applied = b11.outbox(linked, "automation.restore.applied")
    assert len(applied) == 1 and applied[0]["payload"]["credentials_present"] is True
    audits = [a for a in b11.audit_rows(linked) if a["action"] == "automation.restore.applied"]
    assert len(audits) == 1 and audits[0]["details"]["goedgekeurd_door"] == "beheerder-1"
    detail = b11.flow_by_tab(linked, auth, TAB)
    assert detail["current_version"]["snapshot_id"] == body["post_snapshot_id"]

    # nergens een geheim: niet in antwoorden, audit, events, bewaarde antwoorden of het logboek
    stored = b11.everything_stored(linked)
    blob3 = cred_blob(scene.nr)
    for secret in [*scene.secrets(), blob3, request["signature"]]:
        assert secret not in r.text
        assert secret not in stored
        assert secret not in caplog.text
        assert secret not in json.dumps(row)
    evidence = linked.get(f"{CONNECTOR}/items", params={"type": "automation.restore"}, headers=fake_hub.service_auth())
    for secret in scene.secrets():
        assert secret not in evidence.text


def test_the_undo_can_itself_be_undone(scene: Scene, linked: Any, auth: Any) -> None:
    first = scene.apply(scene.sign(scene.propose())).json()
    assert scene.nr.flows == flows_v1()
    back = scene.propose(first["rollback_recipe"]["parameters"]["snapshot_id"])
    r = scene.apply(scene.sign(back))
    assert r.status_code == 200, r.text
    assert scene.nr.flows == flows_v2() and scene.nr.credentials == CREDS_V2
    assert len(scene.nr.writes) == 2
    # er is geen aparte terugdraai-route: dat zou een uitvoering zonder nieuwe goedkeuring zijn
    r = linked.post(f"{CONNECTOR}/rollback", json={}, headers=idem(auth("admin")))
    assert r.status_code == 501 and r.json()["code"] == "capability_unavailable"


def test_response_lost_after_writing_is_confirmed_by_readback(scene: Scene) -> None:
    view = scene.propose()
    scene.nr.drop_next_post_response = True
    r = scene.apply(scene.sign(view))
    assert r.status_code == 200, r.text
    assert r.json()["readback"]["gelijk_aan_momentopname"] is True
    assert scene.restore_row(view["proposal_id"])["result"]["bevestigd_via"] == "readback"
    assert scene.nr.flows == flows_v1() and len(scene.nr.writes) == 1


# ------------------------------------------------------------ R-VEILIG-9: herstel en worker tegelijk (één slot op het register)
def _waiting_on_a_lock(linked: Any) -> int:
    """Hoeveel databaseverbindingen van deze test nu op een slot wachten (pg_stat_activity; alleen lezen)."""
    with linked.app.state.db.engine.connect() as conn:
        found = conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'"
            )
        ).scalar_one()
    return int(found)


def test_a_restore_and_the_worker_at_the_same_time_block_nothing(
    scene: Scene,
    linked: Any,
    fake_hub: Any,
    auth: Any,
    node_red_fake: Any,
    make_settings: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R-VEILIG-9 (herreview 5 van S-P2-295): een geslaagd herstel van een schone configuratie en een gewone
    workerronde die tegelijk lopen, leggen niets stil. Het herstel houdt na zijn momentopname ``na_herstel`` (nog niet
    gecommit) stil tot de worker op de database wacht. Zonder één slot op het flowregister schreef de worker daarna
    dezelfde flowversie nog een keer: een uniekheidsfout, en daarmee (blokkeren bij mislukken) elke flow geblokkeerd
    met ``synchronisatie_mislukt`` tot een beheerder hem hervat."""
    worker = Worker(
        make_settings(node_red_sync_interval_s=60, node_red_data_dir=node_red_fake.data_dir),
        transport=fake_hub.transport,
    )
    worker.automation_step(100.0)
    flow, token = b11.ready_flow(linked, auth, TAB, "notification.send")
    assert flow["status"] == "actief"
    request = scene.sign(scene.propose())

    recorded, go = threading.Event(), threading.Event()
    original = snapshots.record_state

    def record_then_wait(*args: Any, **kwargs: Any) -> Any:
        out = original(*args, **kwargs)
        if kwargs.get("reason") == "na_herstel":
            recorded.set()
            go.wait(20)
        return out

    monkeypatch.setattr(snapshots, "record_state", record_then_wait)
    outcome: dict[str, Any] = {}

    def run_restore() -> None:
        outcome["herstel"] = scene.apply(request)

    def run_worker() -> None:
        try:
            worker.automation_step(200.0)
        except Exception as exc:  # de stap zelf mag niet mislukken; dan faalt de test hieronder
            outcome["worker"] = repr(exc)

    restoring = threading.Thread(target=run_restore)
    restoring.start()
    assert recorded.wait(20), "het herstel kwam niet tot de momentopname na_herstel"
    worker.state.next_node_red_sync = 0
    syncing = threading.Thread(target=run_worker)
    syncing.start()
    deadline = time.monotonic() + 20
    while not _waiting_on_a_lock(linked) and time.monotonic() < deadline:
        time.sleep(0.05)
    waited = _waiting_on_a_lock(linked) > 0
    go.set()
    restoring.join(30)
    syncing.join(30)
    monkeypatch.undo()

    assert waited, "de worker moet tijdens het herstel op de database wachten; anders toetst deze test de race niet"
    assert not restoring.is_alive() and not syncing.is_alive()
    assert outcome["herstel"].status_code == 200 and outcome["herstel"].json()["status"] == "uitgevoerd"
    assert "worker" not in outcome, outcome
    assert worker.state.stats["node_red_sync_failed"] == 0 and worker.state.stats["node_red_syncs"] == 2
    states = {f["source_flow_id"]: (f["status"], f["blocked_reason"]) for f in b11.flows(linked, auth)}
    assert states == {TAB: ("actief", None)}, states
    sync = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["ok"] is True and sync["fout"] is None, sync
    assert b11.outbox(linked, "flow.policy.blocked") == []
    act = b11.request_action(
        linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
    )
    assert act.status_code == 202, act.text
    assert len(b11.outbox(linked, "flow.action.requested")) == 1


def _lock_waits(linked: Any) -> list[str]:
    """Het soort slot waarop databaseverbindingen van deze test nu wachten (pg_stat_activity; alleen lezen)."""
    with linked.app.state.db.engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT wait_event FROM pg_stat_activity "
                "WHERE datname = current_database() AND wait_event_type = 'Lock' ORDER BY wait_event"
            )
        ).all()
    return [str(row[0]) for row in rows]


def _wait_for_lock_waits(linked: Any, count: int, seconds: float = 15.0) -> list[str]:
    deadline = time.monotonic() + seconds
    while len(_lock_waits(linked)) < count and time.monotonic() < deadline:
        time.sleep(0.05)
    return _lock_waits(linked)


def _deadlocks(linked: Any, *workers: Worker) -> int:
    """Het aantal deadlocks in deze database. Eerst gaan de verbindingen dicht, zodat hun tellingen bij de server
    staan; een deadlock zou ook als fout in een van de uitkomsten van de test zelf zichtbaar zijn."""
    for engine in (linked.app.state.db.engine, *(w.db.engine for w in workers)):
        engine.dispose()
    time.sleep(1.0)
    with linked.app.state.db.engine.connect() as conn:
        conn.execute(text("SELECT pg_stat_clear_snapshot()"))
        found = conn.execute(
            text("SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()")
        ).scalar_one()
    return int(found)


def _in_thread(target: Any, out: dict[str, Any], name: str) -> threading.Thread:
    def body() -> None:
        try:
            out[name] = target()
        except Exception as exc:  # de test zelf beoordeelt de uitkomst
            out[name] = exc

    thread = threading.Thread(target=body, name=name)
    thread.start()
    return thread


def test_while_a_restore_holds_the_register_lock_the_worker_and_a_snapshot_wait(
    scene: Scene,
    linked: Any,
    fake_hub: Any,
    auth: Any,
    node_red_fake: Any,
    make_settings: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R-TECH-2 en R-VEILIG-1 (S-P2-300): het slot op het flowregister in ``restore.apply`` (vóór de goedkeuring, de
    readback en de momentopname ``voor_herstel``). Terwijl het herstel daar stilstaat, wachten de synchronisatie van
    de worker en ``POST …/snapshots`` op dat slot ('advisory'): ze lezen Node-RED pas na de commit van het herstel uit.
    De flow-API (actieverzoek, claim) en ``PUT …/state`` gebruiken het slot niet en lopen door. Daarna is alles
    geslaagd, zonder deadlock en zonder geblokkeerde flow. Zonder het slot in ``apply`` wacht niets: dan faalt deze
    test."""
    worker = Worker(
        make_settings(node_red_sync_interval_s=60, node_red_data_dir=node_red_fake.data_dir),
        transport=fake_hub.transport,
    )
    worker.automation_step(100.0)
    flow, token = b11.ready_flow(linked, auth, TAB, "notification.send")
    request = scene.sign(scene.propose())
    before = _deadlocks(linked, worker)

    holding, go = threading.Event(), threading.Event()
    find_proposal = restore._find_proposal

    def hold_then_find(*args: Any, **kwargs: Any) -> Any:
        # hier heeft apply het slot op het flowregister al genomen (snapshots.lock_register, vlak hiervoor)
        holding.set()
        go.wait(30)
        return find_proposal(*args, **kwargs)

    monkeypatch.setattr(restore, "_find_proposal", hold_then_find)
    out: dict[str, Any] = {}
    restoring = _in_thread(lambda: scene.apply(request), out, "herstel")
    assert holding.wait(20), "het herstel kwam niet bij de goedkeuring"
    worker.state.next_node_red_sync = 0
    syncing = _in_thread(lambda: worker.automation_step(200.0), out, "worker")
    snapping = _in_thread(lambda: linked.post(f"{A}/snapshots", headers=idem(auth("admin"))), out, "momentopname")
    waits = _wait_for_lock_waits(linked, 2)
    others: list[threading.Thread] = []
    for name, call in (
        (
            "actie",
            lambda: b11.request_action(
                linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
            ),
        ),
        ("claim", lambda: b11.claim(linked, token)),
        ("pauze", lambda: b11.put_flow(linked, auth, flow["id"], "state", {"status": "gepauzeerd", "reden": "proef"})),
    ):
        thread = _in_thread(call, out, name)
        thread.join(15)  # één voor één, terwijl het herstel het slot nog vasthoudt
        others.append(thread)
    through_while_held = {t.name: not t.is_alive() for t in others}
    still_waiting = {"worker": syncing.is_alive(), "momentopname": snapping.is_alive()}
    go.set()
    for thread in (restoring, syncing, snapping, *others):
        thread.join(40)
    monkeypatch.undo()

    assert waits == ["advisory", "advisory"], waits
    assert still_waiting == {"worker": True, "momentopname": True}, still_waiting
    assert through_while_held == {"actie": True, "claim": True, "pauze": True}, through_while_held
    assert out["herstel"].status_code == 200 and out["herstel"].json()["status"] == "uitgevoerd", out["herstel"]
    assert out["worker"] is None, out["worker"]
    assert worker.state.stats["node_red_sync_failed"] == 0 and worker.state.stats["node_red_syncs"] == 2
    assert out["momentopname"].status_code == 201, out["momentopname"].text
    assert out["actie"].status_code == 202, out["actie"].text
    assert out["claim"]["flow_status"] == "actief"
    assert out["pauze"].status_code == 200, out["pauze"].text
    states = {f["source_flow_id"]: (f["status"], f["blocked_reason"]) for f in b11.flows(linked, auth)}
    assert states == {TAB: ("gepauzeerd", None)}, states
    assert b11.outbox(linked, "flow.policy.blocked") == []
    assert _deadlocks(linked, worker) == before


def test_blocking_after_a_failed_sync_waits_for_a_restore_that_holds_the_register_lock(
    scene: Scene,
    linked: Any,
    fake_hub: Any,
    auth: Any,
    node_red_fake: Any,
    make_settings: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R-TECH-2 en R-VEILIG-1 (S-P2-300): het slot in ``snapshots._block_after_failure``. Een vastgelopen
    synchronisatie draait eerst terug (dat geeft het slot vrij) en blokkeert daarna in een aparte transactie alle
    flows. In dat venster kan een herstel het slot nemen. Hier staat het herstel stil na zijn momentopname
    ``na_herstel``: het heeft de flow (geblokkeerd met ``synchronisatie_mislukt``, de configuratie is nu schoon) op
    gepauzeerd gezet, nog niet gecommit. Het blokkeren (hier rechtstreeks aangeroepen, zoals na de rollback van de
    synchronisatie) wacht op het slot ('advisory') en leest daarna de nieuwe stand: de flow eindigt geblokkeerd. Zonder
    het slot las het blokkeren de oude stand (al geblokkeerd, dus niets te doen) en eindigde de flow na de commit van
    het herstel als gepauzeerd: open terwijl de synchronisatie vastliep."""
    worker = Worker(
        make_settings(node_red_sync_interval_s=60, node_red_data_dir=node_red_fake.data_dir),
        transport=fake_hub.transport,
    )
    worker.automation_step(100.0)
    flow, token = b11.ready_flow(linked, auth, TAB, "notification.send")

    def scan_fails(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("ingespoten fout")

    monkeypatch.setattr(snapshots, "apply_scan", scan_fails)
    worker.state.next_node_red_sync = 0
    worker.automation_step(200.0)
    monkeypatch.undo()
    assert worker.state.stats["node_red_sync_failed"] == 1
    blocked = b11.flow_detail(linked, auth, flow["id"])
    assert (blocked["status"], blocked["blocked_reason"]) == ("geblokkeerd", "synchronisatie_mislukt")
    request = scene.sign(scene.propose())
    before = _deadlocks(linked, worker)

    recorded, go = threading.Event(), threading.Event()
    record_state = snapshots.record_state

    def record_then_wait(*args: Any, **kwargs: Any) -> Any:
        result = record_state(*args, **kwargs)
        if kwargs.get("reason") == "na_herstel":
            recorded.set()
            go.wait(30)
        return result

    monkeypatch.setattr(snapshots, "record_state", record_then_wait)
    out: dict[str, Any] = {}
    restoring = _in_thread(lambda: scene.apply(request), out, "herstel")
    assert recorded.wait(20), "het herstel kwam niet tot de momentopname na_herstel"

    def block_like_a_failed_sync() -> Any:
        with linked.app.state.db.sessions() as session:
            return snapshots._block_after_failure(
                session, RuntimeError("ingespoten fout"), trace_id=str(uuid.uuid4()), now=utcnow()
            )

    blocking = _in_thread(block_like_a_failed_sync, out, "blokkeren")
    waits = _wait_for_lock_waits(linked, 1)
    still_waiting = blocking.is_alive()
    go.set()
    restoring.join(40)
    blocking.join(40)
    monkeypatch.undo()

    assert waits == ["advisory"], waits
    assert still_waiting, "het blokkeren moet op het slot van het herstel wachten"
    assert out["herstel"].status_code == 200 and out["herstel"].json()["status"] == "uitgevoerd", out["herstel"]
    assert isinstance(out["blokkeren"], snapshots.SyncResult) and out["blokkeren"].ok is False, out["blokkeren"]
    after = b11.flow_detail(linked, auth, flow["id"])
    assert (after["status"], after["blocked_reason"]) == ("geblokkeerd", "synchronisatie_mislukt"), after
    sync = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["ok"] is False and sync["fout"]["reason"] == "synchronisatie_mislukt", sync
    act = b11.request_action(
        linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
    )
    assert act.status_code == 403 and act.json()["details"]["reason"] == "flow_geblokkeerd", act.text
    assert b11.outbox(linked, "flow.action.requested") == []
    assert _deadlocks(linked, worker) == before


# ------------------------------------------------------------- weigeringen vóórdat er iets is vastgelegd (vorm, sleutel, tijd)
def _unsigned(request: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in request.items() if k != "signature"}


def _tampered(request: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(request)
    changed["proposal"]["reason"] = "iets anders dan ondertekend"
    return changed


@pytest.mark.parametrize(
    ("kind", "status", "code", "reason"),
    [
        ("geen_handtekening", 422, "execution_request_ongeldig", None),
        ("gewijzigd_na_ondertekenen", 403, "forbidden", "handtekening_ongeldig"),
        ("vreemde_sleutel", 403, "forbidden", "handtekening_ongeldig"),
        ("verlopen", 403, "forbidden", "verzoek_verlopen"),
        ("te_lang_geldig", 403, "forbidden", "verzoek_geldigheid_ongeldig"),
        ("uit_de_toekomst", 403, "forbidden", "verzoek_nog_niet_geldig"),
        ("geen_object", 422, "execution_request_ongeldig", None),
    ],
)
def test_invalid_requests_are_refused_and_leave_no_trace(
    scene: Scene, linked: Any, kind: str, status: int, code: str, reason: str | None
) -> None:
    view = scene.propose()
    now = datetime.now(UTC)
    request: dict[str, Any]
    if kind == "geen_handtekening":
        request = _unsigned(scene.sign(view))
    elif kind == "gewijzigd_na_ondertekenen":
        request = _tampered(scene.sign(view))
    elif kind == "vreemde_sleutel":
        request = scene.sign(view, key=SimKey())
    elif kind == "verlopen":
        request = scene.sign(view, now=now - timedelta(minutes=10))
    elif kind == "te_lang_geldig":
        request = scene.sign(view, ttl_s=3600)
    elif kind == "uit_de_toekomst":
        request = scene.sign(view, now=now + timedelta(minutes=10))
    else:
        request = {"proposal": "nee"}
    r = scene.apply(request)
    assert r.status_code == status, r.text
    assert r.json()["code"] == code
    if reason is not None:
        assert r.json()["details"]["reason"] == reason
    assert scene.nr.writes == [] and scene.nr.flows == flows_v2()
    assert scene.restore_row(view["proposal_id"])["status"] == "voorgesteld"
    # er is geen nonce opgemaakt: een geldig verzoek voor hetzelfde voorstel werkt daarna gewoon
    assert scene.apply(scene.sign(view)).status_code == 200
    assert scene.nr.flows == flows_v1()


# -------------------------------------------------------------------- weigeringen na de handtekening (eigen hercontrole)
@pytest.mark.parametrize(
    ("kind", "status", "code", "detail"),
    [
        ("zonder_goedkeuring", 403, "forbidden", {"reason": "goedkeuring_ontbreekt"}),
        ("risico_r1", 403, "forbidden", {"reason": "risicoklasse_te_laag"}),
        ("goedkeuring_voor_r1", 409, "goedkeuring_past_niet", {"gewijzigd": ["risk_class"]}),
        ("andere_preview", 409, "goedkeuring_past_niet", {"gewijzigd": ["preview_hash"]}),
        ("andere_versie", 409, "goedkeuring_past_niet", {"gewijzigd": ["resource_etag"]}),
        ("goedkeuring_andere_parameters", 409, "goedkeuring_past_niet", {"gewijzigd": ["action_scope"]}),
        ("goedkeuring_ander_beleid", 409, "goedkeuring_past_niet", {"gewijzigd": ["policy_hash"]}),
        ("goedkeuring_verlopen", 403, "forbidden", {"reason": "goedkeuring_verlopen"}),
        ("andere_actie", 403, "forbidden", {"reason": "actie_niet_toegestaan"}),
        ("ander_doel", 422, "parameters_ongeldig", {}),
        ("extra_parameter", 422, "parameters_ongeldig", {}),
    ],
)
def test_signed_but_wrong_requests_are_refused_and_recorded(
    scene: Scene, linked: Any, kind: str, status: int, code: str, detail: dict[str, Any]
) -> None:
    view = scene.propose()
    now = datetime.now(UTC).replace(microsecond=0)
    kwargs: dict[str, Any] = {}
    if kind == "zonder_goedkeuring":
        kwargs = {"approved_by": None}
    elif kind == "risico_r1":
        kwargs = {"risk_class": "R1"}
    elif kind == "goedkeuring_voor_r1":
        kwargs = {"approval_overrides": {"risk_class": "R1"}}
    elif kind == "andere_preview":
        kwargs = {"approval_overrides": {"preview_hash": "sha256:" + "0" * 64}}
    elif kind == "andere_versie":
        etag = "sha256:" + "1" * 64
        kwargs = {"approval_overrides": {"resource_etag": etag}, "proposal_overrides": {"expected_version": etag}}
    elif kind == "goedkeuring_andere_parameters":
        scope = {"action_id": RESTORE, "target": b11.NODE_RED_TARGET, "parameters_sha256": "sha256:" + "2" * 64}
        kwargs = {"approval_overrides": {"action_scope": scope}}
    elif kind == "goedkeuring_ander_beleid":
        kwargs = {"approval_overrides": {"policy_hash": "sha256:" + "3" * 64}}
    elif kind == "goedkeuring_verlopen":
        past = now - timedelta(minutes=20)
        kwargs = {
            "approval_overrides": {
                "approved_at": past.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expires_at": (past + timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        }
    elif kind == "andere_actie":
        kwargs = {"proposal_overrides": {"action_id": "automation.flows.wissen"}}
    elif kind == "ander_doel":
        kwargs = {"proposal_overrides": {"target": {"type": "source", "id": "iets_anders"}}}
    elif kind == "extra_parameter":
        kwargs = {"proposal_overrides": {"parameters": {"snapshot_id": view["parameters"]["snapshot_id"], "x": 1}}}
    request = scene.sign(view, **kwargs)
    key = str(uuid.uuid4())
    r = scene.apply(request, key=key)
    assert r.status_code == status, r.text
    body = r.json()
    assert body["code"] == code
    for k, v in detail.items():
        assert body["details"][k] == v, body
    assert scene.nr.writes == [] and scene.nr.flows == flows_v2(), "er is niets geschreven"
    # dezelfde Idempotency-Key: precies hetzelfde antwoord; hetzelfde verzoek met een nieuwe key: de nonce is op
    again = scene.apply(request, key=key)
    assert again.status_code == status and again.json() == body
    replay = scene.apply(request)
    assert replay.status_code == 409 and replay.json()["code"] == "nonce_al_gebruikt"
    assert scene.nr.writes == []


def test_request_cannot_be_replayed_after_success(scene: Scene) -> None:
    view = scene.propose()
    request = scene.sign(view)
    key = str(uuid.uuid4())
    first = scene.apply(request, key=key)
    assert first.status_code == 200
    # netwerkherhaling met dezelfde key: hetzelfde antwoord, niet opnieuw uitgevoerd
    again = scene.apply(request, key=key)
    assert again.status_code == 200 and again.json() == first.json()
    # hetzelfde ondertekende verzoek met een nieuwe key: geweigerd
    replay = scene.apply(request)
    assert replay.status_code == 409 and replay.json()["code"] == "nonce_al_gebruikt"
    # een nieuw verzoek (nieuwe nonce, nieuwe goedkeuring) voor een al uitgevoerd voorstel: ook geweigerd
    r = scene.apply(scene.sign(view))
    assert r.status_code == 409 and r.json()["code"] == "voorstel_al_afgehandeld"
    assert len(scene.nr.writes) == 1


def test_who_may_apply(scene: Scene, linked: Any, auth: Any, fake_hub: Any) -> None:
    view = scene.propose()
    request = scene.sign(view)
    for role in ("operator", "viewer", "family"):
        assert linked.post(f"{CONNECTOR}/apply", json=request, headers=idem(auth(role))).status_code == 403
    assert linked.post(f"{CONNECTOR}/apply", json=request, headers=idem()).status_code == 401
    assert scene.nr.writes == []
    # zonder Idempotency-Key gebeurt er niets
    r = linked.post(f"{CONNECTOR}/apply", json=request, headers=fake_hub.service_auth())
    assert r.status_code in (400, 428) and scene.nr.writes == []
    # zonder koppeling met de Hub is er geen gepinde sleutel en dus geen uitvoering
    linked.app.state.hublink.unlink(trace_id=str(uuid.uuid4()), actor=("user", "user-1"))
    r = scene.apply(request)
    assert r.status_code == 401 and scene.nr.writes == []


def test_apply_without_pinned_key_is_refused_directly(scene: Scene, linked: Any) -> None:
    """De laag eronder: ook als de route bereikt zou worden, voert de dienst zonder gepinde sleutel niets uit."""
    from integrations.errors import ApiError
    from integrations.security.auth import Principal

    view = scene.propose()
    state = linked.app.state
    with state.db.sessions() as s, pytest.raises(ApiError) as caught:
        restore.apply(
            s,
            state.settings,
            state.vault,
            state.http_transport,
            request=scene.sign(view),
            keys=[],
            principal=Principal(subject="hub", roles=("service",), kind="service"),
            trace_id=str(uuid.uuid4()),
            now=utcnow(),
        )
    assert caught.value.status_code == 403 and caught.value.details["reason"] == "geen_gepinde_policy_sleutel"
    assert scene.nr.writes == []


# -------------------------------------------------------------------------------- precondities en fouten van Node-RED
def test_changed_flows_since_the_preview_stop_the_restore(scene: Scene, linked: Any) -> None:
    view = scene.propose()
    changed = flows_v2()
    changed.append(node("tab00000debug009", "debug", TAB, active=True))
    scene.nr.deploy(changed)  # iemand wijzigt de flows ná de preview
    r = scene.apply(scene.sign(view))
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "doel_gewijzigd" and r.json()["details"]["verwacht"] == view["resource_etag"]
    assert scene.nr.writes == [] and scene.nr.flows == changed
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "mislukt" and row["result"]["reden"] == "doel_gewijzigd"
    failed = b11.outbox(linked, "automation.restore.failed")
    assert len(failed) == 1 and failed[0]["payload"]["reden"] == "doel_gewijzigd"
    # het oude voorstel is afgehandeld; een nieuw voorstel (nieuwe preview) kan wel
    assert scene.apply(scene.sign(view)).json()["code"] == "voorstel_al_afgehandeld"
    assert scene.apply(scene.sign(scene.propose())).status_code == 200
    assert scene.nr.flows == flows_v1()


def test_changed_credential_secret_makes_node_red_refuse_and_nothing_changes(scene: Scene, linked: Any) -> None:
    scene.nr.credential_secret = "een-andere-credentialSecret"
    scene.nr._write_cred_file()
    view = scene.propose()
    r = scene.apply(scene.sign(view))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["code"] == "credentials_niet_te_ontsleutelen"
    assert body["details"]["readback"]["gelijk_aan_toestand_vooraf"] is True
    assert scene.nr.flows == flows_v2() and scene.nr.credentials == CREDS_V2
    assert scene.nr.writes == []
    assert scene.restore_row(view["proposal_id"])["status"] == "mislukt"


def test_node_red_error_while_writing_is_reported_honestly(scene: Scene, linked: Any, auth: Any) -> None:
    view = scene.propose()
    scene.nr.fail_next_post = 400
    request = scene.sign(view)
    key = str(uuid.uuid4())
    r = scene.apply(request, key=key)
    assert r.status_code == 502, r.text
    body = r.json()
    assert body["code"] == "node_red_fout" and body["details"]["readback"]["gelijk_aan_toestand_vooraf"] is True
    assert scene.nr.flows == flows_v2() and scene.nr.writes == []
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "mislukt" and row["pre_snapshot_id"] == body["details"]["pre_snapshot_id"]
    # de poging is vastgelegd: geen stille herhaling
    assert scene.apply(request, key=key).json() == body
    assert scene.apply(request).json()["code"] == "nonce_al_gebruikt"
    audits = [a for a in b11.audit_rows(linked) if a["action"] == "automation.restore.failed"]
    assert len(audits) == 1 and audits[0]["details"]["ongewijzigd"] is True


def test_node_red_5xx_while_writing_with_unchanged_flows(scene: Scene) -> None:
    view = scene.propose()
    scene.nr.fail_next_post = 500
    r = scene.apply(scene.sign(view))
    assert r.status_code == 503, r.text
    assert r.json()["code"] == "node_red_unavailable" and r.headers["Retry-After"] == "30"
    assert scene.nr.flows == flows_v2()
    assert scene.restore_row(view["proposal_id"])["status"] == "mislukt"


def test_node_red_down_before_writing_changes_nothing_and_can_be_retried(scene: Scene) -> None:
    view = scene.propose()
    request = scene.sign(view)
    scene.nr.up = False
    r = scene.apply(request)
    assert r.status_code == 503 and r.json()["code"] == "node_red_unavailable"
    assert scene.restore_row(view["proposal_id"])["status"] == "voorgesteld"
    scene.nr.up = True
    # er was nog niets vastgelegd: hetzelfde verzoek mag binnen zijn geldigheid opnieuw
    r = scene.apply(request)
    assert r.status_code == 200, r.text
    assert scene.nr.flows == flows_v1() and len(scene.nr.writes) == 1


def test_interrupted_restore_is_never_repeated_blindly(
    scene: Scene, linked: Any, fake_hub: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """De dienst valt weg nádat er geschreven is maar vóór de uitkomst is vastgelegd."""
    view = scene.propose()
    request = scene.sign(view)

    def crash(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("stroom weg")

    with monkeypatch.context() as m:
        m.setattr(restore, "_finish_apply", crash)
        with pytest.raises(RuntimeError):
            scene.apply(request)
    assert len(scene.nr.writes) == 1, "er is geschreven"
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "voorgesteld" and row["result"]["fase"] == "toepassen_gestart"
    assert row["pre_snapshot_id"], "de toestand van vóór het herstel is al vastgelegd"
    # het verzoek en de goedkeuring zijn opgemaakt
    assert scene.apply(request).json()["code"] == "nonce_al_gebruikt"
    reused = scene.sign(view, approval_overrides=dict(request["approval"]))
    r = scene.apply(reused)
    assert r.status_code == 409 and r.json()["code"] == "goedkeuring_al_gebruikt"
    assert len(scene.nr.writes) == 1
    # na de geldigheid sluit de worker het voorstel af als onderbroken, met een eerlijke uitkomst
    later = utcnow() + restore.PROPOSAL_TTL + timedelta(seconds=1)
    monkeypatch.setattr("integrations.worker.utcnow", lambda: later)
    Worker(make_settings(), transport=fake_hub.transport).automation_step(0.0)
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "mislukt"
    assert row["result"]["reden"] == "onderbroken" and row["result"]["uitkomst"] == "onbekend"


def test_expired_proposal_is_not_applied(
    scene: Scene, linked: Any, fake_hub: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    view = scene.propose()
    with linked.app.state.db.sessions() as s:
        s.execute(
            update(AutomationRestore)
            .where(AutomationRestore.id == uuid.UUID(view["proposal_id"]))
            .values(expires_at=utcnow() - timedelta(seconds=1))
        )
        s.commit()
    r = scene.apply(scene.sign(view))
    assert r.status_code == 409 and r.json()["code"] == "voorstel_verlopen"
    assert scene.nr.writes == []
    Worker(make_settings(), transport=fake_hub.transport).automation_step(0.0)
    assert scene.restore_row(view["proposal_id"])["status"] == "verlopen"


def test_restore_never_reactivates_a_flow_that_became_forbidden(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """Tussen voorstel en uitvoering verandert het flowbeleid (een module is niet meer toegestaan)."""
    extra = {
        "id": "node-red-contrib-voorbeeld/voorbeeld",
        "name": "voorbeeld",
        "types": ["voorbeeld"],
        "enabled": True,
        "local": True,
        "user": True,
        "module": "node-red-contrib-voorbeeld",
        "version": "1.0.0",
    }
    node_red_fake.extra_sets.append(extra)
    client2 = linked
    setup_node_red(client2, fake_hub, auth, flows=[*simple_flow(), node("tab00000voorb001", "voorbeeld", TAB)])
    first = b11.snapshot(client2, auth)
    node_red_fake.deploy(simple_flow())
    b11.snapshot(client2, auth)
    r = b11.propose_restore(client2, auth, first["snapshot"]["id"])
    assert r.status_code == 422 and r.json()["code"] == "momentopname_niet_toegestaan", r.text
    assert r.json()["details"]["bevindingen"][0]["code"] == "module_niet_toegestaan"
    assert node_red_fake.writes == []


# ------------------------------------------------------- S-P2-320: tekst die niet op te slaan is (NUL, losse surrogaat)
#: zo staan ze in de ruwe JSON (een geldige JSON-escape): json.loads maakt er een losse surrogaat en een NUL-teken van
UNSTORABLE = {"surrogaat": "\\ud800", "nul": "\\u0000"}
MARK = "@@teken@@"


def _raw(body: dict[str, Any], escape: str) -> bytes:
    raw = json.dumps(body)
    assert MARK in raw
    return raw.replace(MARK, escape).encode("ascii")


def _stored(linked: Any) -> tuple[int, ...]:
    """Wat een geweigerde invoer niet mag achterlaten: voorstellen, nonces, bewaarde antwoorden, audit en events."""
    with linked.app.state.db.sessions() as s:
        return tuple(
            int(s.scalar(select(func.count()).select_from(model)) or 0)
            for model in (AutomationRestore, AutomationExecutionNonce, IdempotencyRecord, AuditEvent, OutboxEvent)
        )


def _invalid_input(r: Any) -> None:
    """Een invoerfout (422 ``validation_error``) zonder het teken in het antwoord; nooit een serverfout."""
    assert r.status_code == 422, (r.status_code, r.text)
    assert r.json()["code"] == "validation_error", r.text
    assert "\ud800" not in r.text and "\x00" not in r.text and "\\u0000" not in r.text and "\\ud800" not in r.text


@pytest.mark.parametrize("bad", list(UNSTORABLE))
@pytest.mark.parametrize("where", ["parameter", "parameternaam", "actor", "actor_sa_sleutel"])
def test_unstorable_text_in_a_restore_proposal_is_a_422_and_stores_nothing(
    scene: Scene, linked: Any, auth: Any, bad: str, where: str
) -> None:
    """Vervolgpunt van S-P2-310: een losse surrogaat of een NUL-teken in ``POST /connector/v1/propose`` gaf een
    serverfout (de Idempotency-Key wordt als UTF-8 vastgelegd) of werd aangenomen. Nu weigert
    ``idempotency.run_idempotent`` zulke invoer centraal vóór er iets gebeurt: ``422 validation_error``, geen voorstel,
    geen audit, geen event en geen bewaard antwoord. Dezelfde Idempotency-Key met gewone tekst werkt daarna gewoon.
    Ook in een sleutel die met ``_sa`` begint (R-VEILIG-2 van S-P2-320): ``jsonable_encoder`` liet die standaard stil
    weg, zodat een voorstel mét zo'n teken werd bewaard (201)."""
    body: dict[str, Any] = {
        "action_id": RESTORE,
        "target": b11.NODE_RED_TARGET,
        "parameters": {"snapshot_id": scene.snap1["id"]},
    }
    marked = copy.deepcopy(body)
    if where == "parameter":
        marked["parameters"]["snapshot_id"] += MARK
    elif where == "parameternaam":
        marked["parameters"]["x" + MARK] = 1
    elif where == "actor":
        marked["actor"] = {"type": "user", "id": "beheerder" + MARK}
    else:
        marked["actor"] = {"type": "user", "id": "beheerder", "_sa" + MARK: 1}
    before = _stored(linked)
    key = str(uuid.uuid4())
    headers = {**idem(auth("admin"), key=key), "Content-Type": "application/json"}
    r = linked.post(f"{CONNECTOR}/propose", content=_raw(marked, UNSTORABLE[bad]), headers=headers)
    _invalid_input(r)
    assert _stored(linked) == before
    assert scene.nr.writes == [] and scene.nr.flows == flows_v2()
    ok = linked.post(f"{CONNECTOR}/propose", json=body, headers=idem(auth("admin"), key=key))
    assert ok.status_code == 201, ok.text


APPLY_CASES = [
    ("surrogaat", "reden"),
    ("surrogaat", "parameter"),
    ("surrogaat", "veldnaam"),
    ("surrogaat", "sa_sleutel"),
    ("nul", "reden"),
    ("nul", "parameter"),
    ("nul", "veldnaam"),
    ("nul", "sa_sleutel"),
    ("nul", "ondertekend"),
    ("nul", "ondertekend_sa_sleutel"),
]


@pytest.mark.parametrize(("bad", "where"), APPLY_CASES)
def test_unstorable_text_in_an_execution_request_is_a_422_and_uses_no_nonce(
    scene: Scene, linked: Any, fake_hub: Any, bad: str, where: str
) -> None:
    """Vervolgpunt van S-P2-310: een losse surrogaat in ``POST /connector/v1/apply`` gaf een serverfout vóór de
    handtekeningcontrole, en een NUL-teken in een door de Hub ondertekend verzoek (hier in de ``action_id``: de
    weigering zou het teken bewaren) gaf een databasefout. Nu is het centraal ``422 validation_error``: er wordt geen
    nonce verbruikt, niets bewaard en niets naar Node-RED geschreven. Het ondertekende verzoek zelf, met dezelfde nonce
    en dezelfde Idempotency-Key, wordt daarna gewoon uitgevoerd. Een losse surrogaat kan de Hub niet ondertekenen
    (canonieke JSON in UTF-8); daarom staat ``ondertekend`` alleen bij de NUL. Ook in een sleutel die met ``_sa``
    begint (R-VEILIG-2 van S-P2-320): daar gaf een losse surrogaat op het hoogste niveau een serverfout, en werd een
    ondertekend verzoek met een NUL in zo'n sleutel van ``actor`` uitgevoerd (200)."""
    view = scene.propose()
    request = scene.sign(view)
    if where == "ondertekend":
        bad_request = scene.sign(
            view, proposal_overrides={"action_id": RESTORE + "\x00"}, overrides={"nonce": request["nonce"]}
        )
        raw = json.dumps(bad_request).encode("ascii")
    elif where == "ondertekend_sa_sleutel":
        actor = {"type": "user", "id": "beheerder-1", "_sa_x\x00": "1"}
        bad_request = scene.sign(view, actor=actor, overrides={"nonce": request["nonce"]})
        raw = json.dumps(bad_request).encode("ascii")
    else:
        marked = copy.deepcopy(request)
        if where == "reden":
            marked["proposal"]["reason"] += MARK
        elif where == "parameter":
            marked["proposal"]["parameters"]["snapshot_id"] += MARK
        elif where == "sa_sleutel":
            marked["_sa" + MARK] = 1
        else:
            marked["x" + MARK] = 1
        raw = _raw(marked, UNSTORABLE[bad])
    before = _stored(linked)
    key = str(uuid.uuid4())
    headers = {**idem(fake_hub.service_auth(), key=key), "Content-Type": "application/json"}
    r = linked.post(f"{CONNECTOR}/apply", content=raw, headers=headers)
    _invalid_input(r)
    assert _stored(linked) == before, "geen nonce, geen bewaard antwoord, geen audit of event"
    assert scene.nr.writes == [] and scene.restore_row(view["proposal_id"])["status"] == "voorgesteld"
    ok = scene.apply(request, key=key)
    assert ok.status_code == 200, ok.text
    assert scene.nr.flows == flows_v1() and len(scene.nr.writes) == 1


# --------------------------------------------- S-P2-320: blokkeren bij mislukken ná het schrijven (vervolgpunt S-P2-300)
@pytest.mark.parametrize(
    "where", ["na_herstel", "na_het_schrijven", "bij_het_sluiten", "databasefout_bij_het_vastleggen"]
)
def test_a_failure_after_writing_blocks_every_flow(
    scene: Scene, linked: Any, auth: Any, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """Vervolgpunt (1) van S-P2-300: loopt een herstel vast nádat het naar Node-RED schreef (bij het vastleggen van de
    momentopname ``na_herstel``, of direct na het schrijven), dan klopt het flowregister niet meer met Node-RED. Dan
    blokkeert ``snapshots._block_after_failure`` in een eigen transactie elke flow met ``synchronisatie_mislukt``
    (blokkeren bij mislukken, besluit van de gebruiker 2026-11-12), in plaats van dat de oude stand blijft staan. Het
    antwoord is eerlijk ``500 herstel_niet_vastgelegd``; het verzoek wordt niet blind herhaald (de nonce is op) en
    pas na een geslaagde synchronisatie én een beheerder gaat de flow weer open. Ook (S-P2-320, herstel): een fout bij
    het sluiten van de client (het token intrekken) na het schrijven (R-VEILIG-3; vóór de reparatie een kale 500 en de
    flow bleef actief), en een databasefout bij het vastleggen die pas bij het wegschrijven valt (hier een rij die de
    controle ``applied_has_snapshots`` schendt; R-TECH-2: de ``flush`` aan het eind van ``_record_outcome`` haalt die
    binnen de blokkade, anders viel hij pas bij de commit in ``run_idempotent``)."""
    flow, token = b11.ready_flow(linked, auth, TAB, "notification.send")
    assert flow["status"] == "actief"
    view = scene.propose()
    request = scene.sign(view)
    blocked_before = len(b11.outbox(linked, "flow.policy.blocked"))
    if where == "na_herstel":
        record_state = snapshots.record_state

        def fails_after_writing(*args: Any, **kwargs: Any) -> Any:
            if kwargs.get("reason") == "na_herstel":
                raise RuntimeError("ingespoten fout")
            return record_state(*args, **kwargs)

        monkeypatch.setattr(snapshots, "record_state", fails_after_writing)
    elif where == "na_het_schrijven":
        post_flows = nodered.NodeRedClient.post_flows

        def writes_then_fails(self: Any, *args: Any, **kwargs: Any) -> Any:
            post_flows(self, *args, **kwargs)
            raise RecursionError("ingespoten fout")

        monkeypatch.setattr(nodered.NodeRedClient, "post_flows", writes_then_fails)
    elif where == "bij_het_sluiten":
        close = nodered.NodeRedClient.close

        def close_fails_after_writing(self: Any) -> None:
            if scene.nr.writes:
                raise RuntimeError("ingespoten fout bij het sluiten")
            close(self)

        monkeypatch.setattr(nodered.NodeRedClient, "close", close_fails_after_writing)
    else:
        record_state = snapshots.record_state

        def records_without_post_snapshot(*args: Any, **kwargs: Any) -> Any:
            # zonder momentopname na_herstel mag het voorstel niet op uitgevoerd: de database weigert de rij
            result = record_state(*args, **kwargs)
            return dataclasses.replace(result, snapshot_id=None) if kwargs.get("reason") == "na_herstel" else result

        monkeypatch.setattr(snapshots, "record_state", records_without_post_snapshot)
    r = scene.apply(request)
    monkeypatch.undo()

    assert r.status_code == 500, r.text
    body = r.json()
    assert body["code"] == "herstel_niet_vastgelegd", body
    assert body["details"]["flows_geblokkeerd"] is True and body["details"]["proposal_id"] == view["proposal_id"]
    assert body["details"]["pre_snapshot_id"], body
    assert len(scene.nr.writes) == 1 and scene.nr.flows == flows_v1(), "er is geschreven"
    detail = b11.flow_detail(linked, auth, flow["id"])
    assert (detail["status"], detail["blocked_reason"]) == ("geblokkeerd", "synchronisatie_mislukt"), detail
    assert len(b11.outbox(linked, "flow.policy.blocked")) == blocked_before + 1
    sync = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["ok"] is False and sync["fout"]["reason"] == "synchronisatie_mislukt", sync
    act = b11.request_action(
        linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
    )
    assert act.status_code == 403 and act.json()["details"]["reason"] == "flow_geblokkeerd", act.text
    # niets van een geslaagd herstel vastgelegd, en niet blind te herhalen
    assert b11.outbox(linked, "automation.restore.applied") == []
    assert [s.reason for s in snapshot_rows(linked)] == ["handmatig", "handmatig", "voor_herstel"]
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "voorgesteld" and row["result"]["fase"] == "toepassen_gestart", row
    assert scene.apply(request).json()["code"] == "nonce_al_gebruikt"
    assert len(scene.nr.writes) == 1
    # een synchronisatie die weer slaagt, legt de stand van Node-RED vast; de flow blijft dicht tot een beheerder hem
    # hervat (geen automatisch heropenen)
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == "gepauzeerd"


# ----------------------------------------------------- S-P2-320: wachten op het slot op het flowregister is begrensd
def test_waiting_for_the_register_lock_is_bounded_and_changes_nothing(
    scene: Scene,
    linked: Any,
    auth: Any,
    fake_hub: Any,
    node_red_fake: Any,
    make_settings: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vervolgpunt (2) van S-P2-300: wie het slot op het flowregister houdt, praat soms met Node-RED (lezen, met
    herhalingen). Wie erop wacht, wacht nu hooguit ``snapshots.REGISTER_LOCK_TIMEOUT_MS`` (hier 300 ms; anders 30 s)
    en krijgt dan ``409 flowregister_bezig``: ``POST …/snapshots``, een herstel (de nonce blijft ongebruikt) en de
    worker. Er is dan niets gewijzigd. Na het vrijgeven werkt alles weer, ook hetzelfde ondertekende verzoek. Zonder
    lock_timeout blijven ze wachten tot het slot vrij is: dan faalt deze test."""
    monkeypatch.setattr(snapshots, "REGISTER_LOCK_TIMEOUT_MS", 300)
    worker = Worker(
        make_settings(node_red_sync_interval_s=60, node_red_data_dir=node_red_fake.data_dir),
        transport=fake_hub.transport,
    )
    worker.automation_step(100.0)
    view = scene.propose()
    request = scene.sign(view)
    before = _stored(linked)
    snapshots_before = len(snapshot_rows(linked))
    worker.state.next_node_red_sync = 0
    out: dict[str, Any] = {}
    with linked.app.state.db.engine.connect() as holder:
        holder.execute(select(func.pg_advisory_xact_lock(snapshots.REGISTER_LOCK_KEY)))  # houdt het slot vast
        started = time.monotonic()
        threads = [
            _in_thread(lambda: linked.post(f"{A}/snapshots", headers=idem(auth("admin"))), out, "momentopname"),
            _in_thread(lambda: scene.apply(request), out, "herstel"),
            _in_thread(lambda: worker.automation_step(200.0), out, "worker"),
        ]
        for thread in threads:
            thread.join(10)
        done_while_held = {t.name: not t.is_alive() for t in threads}
        waited = time.monotonic() - started
        holder.rollback()  # geeft het slot vrij
    for thread in threads:
        thread.join(30)

    assert done_while_held == {"momentopname": True, "herstel": True, "worker": True}, done_while_held
    assert waited < 10, waited
    for name in ("momentopname", "herstel"):
        r = out[name]
        assert r.status_code == 409 and r.json()["code"] == "flowregister_bezig", (name, r.text)
        assert r.headers["Retry-After"] == "30"
    assert getattr(out["worker"], "code", None) == "flowregister_bezig", out["worker"]
    assert _stored(linked) == before, "geen nonce, geen bewaard antwoord, geen audit of event"
    assert len(snapshot_rows(linked)) == snapshots_before and scene.nr.writes == []
    assert scene.restore_row(view["proposal_id"])["status"] == "voorgesteld"
    # na het vrijgeven: hetzelfde verzoek (dezelfde nonce) wordt gewoon uitgevoerd
    r = scene.apply(request)
    assert r.status_code == 200, r.text
    assert scene.nr.flows == flows_v1()


def test_the_lock_timeout_only_applies_to_taking_the_register_lock(linked: Any) -> None:
    """De grens geldt alleen voor het wachten op het slot op het flowregister (``pg_advisory_xact_lock``), niet voor
    de rest van de transactie: daarna staat ``lock_timeout`` weer op de waarde van vóór het slot. Zo raakt hij de
    rijsloten in dezelfde transactie niet (bijvoorbeeld ``simulate.close_for_block``)."""
    with linked.app.state.db.sessions() as session:
        before = session.execute(text("SHOW lock_timeout")).scalar_one()
        snapshots.lock_register(session)
        assert session.execute(text("SHOW lock_timeout")).scalar_one() == before
        session.execute(text("SET LOCAL lock_timeout = '7s'"))
        snapshots.lock_register(session)  # tweede keer in dezelfde transactie: de eigen waarde blijft staan
        assert session.execute(text("SHOW lock_timeout")).scalar_one() == "7s"
        session.rollback()


# ------------------------------------- S-P2-320, herstel: een antwoord na het schrijven dat de dienst niet kan gebruiken
@pytest.mark.parametrize(
    ("case", "cause"),
    [
        ("teruglezen_ongeldig", "antwoord_ongeldig"),
        ("teruglezen_geen_rechten", "geen_rechten"),
        ("schrijfantwoord_ongeldig", "antwoord_ongeldig"),
    ],
)
def test_an_unusable_answer_after_writing_blocks_every_flow(
    scene: Scene, linked: Any, auth: Any, node_red_fake: Any, monkeypatch: pytest.MonkeyPatch, case: str, cause: str
) -> None:
    """R-VEILIG-4 van S-P2-320, keuze (a) van de regisseur: geeft Node-RED na het schrijven een antwoord dat de dienst
    niet kan gebruiken (``snapshots.UNUSABLE_ANSWER_REASONS``), op het teruglezen of als antwoord op ``POST /flows``,
    dan blokkeert het herstel alle flows (``_blocked_after_writing``), net als de synchronisatie bij zo'n antwoord.
    Vóór de reparatie bleef de flow actief en werkte zijn token (502 ``herstel_niet_bevestigd``). Er is geschreven, de
    uitkomst is niet vastgelegd; de oorzaak staat in het antwoord en in de synchronisatie."""
    flow, token = b11.ready_flow(linked, auth, TAB, "notification.send")
    view = scene.propose()
    request = scene.sign(view)
    original = node_red_fake.handle

    def handle(req: httpx.Request) -> httpx.Response:
        if case.startswith("teruglezen") and req.method == "GET" and req.url.path == "/flows" and node_red_fake.writes:
            status, body = (200, b"geen json") if case == "teruglezen_ongeldig" else (403, b"{}")
            return httpx.Response(status, content=body, headers={"content-type": "application/json"})
        resp = original(req)
        if case == "schrijfantwoord_ongeldig" and req.method == "POST" and req.url.path == "/flows":
            assert resp.status_code == 200, "Node-RED heeft het herstel aangenomen"
            return httpx.Response(200, content=b"<html>proxy</html>", headers={"content-type": "application/json"})
        return resp

    monkeypatch.setattr(node_red_fake, "handle", handle)
    r = scene.apply(request)
    monkeypatch.undo()

    assert r.status_code == 500, r.text
    body = r.json()
    assert body["code"] == "herstel_niet_vastgelegd", body
    assert body["details"]["flows_geblokkeerd"] is True and body["details"]["oorzaak"] == cause, body
    assert len(node_red_fake.writes) == 1 and node_red_fake.flows == flows_v1(), "er is geschreven"
    detail = b11.flow_detail(linked, auth, flow["id"])
    assert (detail["status"], detail["blocked_reason"]) == ("geblokkeerd", "synchronisatie_mislukt"), detail
    act = b11.request_action(
        linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
    )
    assert act.status_code == 403 and act.json()["details"]["reason"] == "flow_geblokkeerd", act.text
    assert b11.outbox(linked, "flow.action.requested") == []
    sync = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["ok"] is False and sync["fout"]["reason"] == "synchronisatie_mislukt", sync
    assert sync["fout"]["oorzaak"] == cause, sync
    assert scene.apply(request).json()["code"] == "nonce_al_gebruikt"
    assert len(node_red_fake.writes) == 1
    # een synchronisatie die weer slaagt, legt de stand vast; de flow blijft dicht tot een beheerder hem hervat
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == "gepauzeerd"


# ------------------------------- S-P2-320, herstel: credentials alleen terug als de huidige ook vast te leggen zijn
@pytest.mark.parametrize(
    ("at_proposal", "at_apply"),
    [("beschrijfbaar", "beschrijfbaar"), ("alleen_lezen", "beschrijfbaar"), ("beschrijfbaar", "alleen_lezen")],
)
def test_credentials_are_only_restored_when_the_current_ones_can_be_recorded(
    scene: Scene, linked: Any, at_proposal: str, at_apply: str
) -> None:
    """R-VEILIG-5 van S-P2-320: heeft de momentopname credentials, maar zijn de huidige inloggegevens niet vast te
    leggen (de koppeling is intussen beschrijfbaar: ``niet_gekoppeld``), dan zou de momentopname ``voor_herstel`` ze
    missen en kon terugdraaien ze nooit meer terugzetten (vóór de reparatie: Node-RED had daarna PW1 en het
    terugdraaien bracht PW2 niet terug). Nu gaan alleen de flows terug en zeggen het voorstel (``terugzetten: false``,
    reden en waarschuwing) en het antwoord (``credentials_niet_teruggezet``) dat uitdrukkelijk; Node-RED houdt PW2.
    Dat geldt als het bij het voorstel of vlak voor het schrijven zo is. De goedkeuring is aan die keuze gebonden: zei
    het voorstel "niet terugzetten", dan gaan ze ook niet mee als de koppeling bij het toepassen weer alleen-lezen is."""
    writable = mock.patch.object(snapshots, "_mounted_read_only", lambda _dir_fd: False)
    read_only = mock.patch.object(snapshots, "_mounted_read_only", lambda _dir_fd: True)
    mounts = {"beschrijfbaar": writable, "alleen_lezen": read_only}
    with mounts[at_proposal]:
        view = scene.propose()
    planned = at_proposal == "alleen_lezen"
    assert view["credentials"]["credentials_present"] is True
    assert view["credentials"]["terugzetten"] is planned, view["credentials"]
    if not planned:
        assert view["credentials"]["reden"] == "huidige_credentials_niet_vastgelegd", view["credentials"]
        assert any("wordt niet teruggezet" in w for w in view["warnings"]), view["warnings"]
    with mounts[at_apply]:
        r = scene.apply(scene.sign(view))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["credentials_teruggezet"] is False, body
    note = body["credentials_niet_teruggezet"]
    assert note["reden"] == "huidige_credentials_niet_vastgelegd", note
    expected_now = "niet_gekoppeld" if at_apply == "beschrijfbaar" else "meegenomen"
    assert note["huidige_status"] == expected_now and "niet teruggezet" in note["uitleg_nl"], note
    assert scene.restore_row(view["proposal_id"])["result"]["credentials_niet_teruggezet"] == note
    assert scene.nr.flows == flows_v1() and scene.nr.credentials == CREDS_V2, "alleen de flows gaan terug"
    assert scene.nr.writes[-1]["met_credentials"] is False
    for secret in scene.secrets():
        assert secret not in r.text
    # terugdraaien brengt de flows terug; de inloggegevens zijn nooit kwijtgeraakt
    with mounts[at_apply]:
        back = scene.propose(body["rollback_recipe"]["parameters"]["snapshot_id"])
        again = scene.apply(scene.sign(back))
    assert again.status_code == 200, again.text
    assert scene.nr.flows == flows_v2() and scene.nr.credentials == CREDS_V2


# -------------------------------------- S-P2-320, herstel: blokkeren bij mislukken geeft nooit op op een bezet slot
HOLD_S = 1.5


def _hold_the_register_lock(linked: Any, seconds: float, *, behind_the_holder: bool) -> tuple[threading.Thread, bool]:
    """Een tweede databaseverbinding neemt het slot op het flowregister en houdt het ``seconds`` vast. Met
    ``behind_the_holder`` houdt iemand anders het slot nu: deze verbinding wacht dan eerst (gaat pas terug als ze
    echt wacht) en krijgt het slot zodra die het vrijgeeft, vóór wie er daarna om vraagt. Geeft de draad terug en of
    het gelukt is (de test controleert dat, niet deze functie: die draait soms midden in de dienst)."""
    holding = threading.Event()

    def body() -> None:
        with linked.app.state.db.engine.connect() as conn:
            conn.execute(select(func.pg_advisory_xact_lock(snapshots.REGISTER_LOCK_KEY)))
            holding.set()
            time.sleep(seconds)
            conn.rollback()

    thread = threading.Thread(target=body, name="houder", daemon=True)
    thread.start()
    ok = _wait_for_lock_waits(linked, 1) == ["advisory"] if behind_the_holder else holding.wait(10)
    return thread, ok


@pytest.mark.parametrize("where", ["antwoord_ongeldig", "record_state", "na_het_schrijven"])
def test_blocking_after_a_failure_never_gives_up_on_a_busy_register_lock(
    scene: Scene, linked: Any, auth: Any, node_red_fake: Any, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """R-TECH-1 van S-P2-320: het blokkeren bij mislukken (``snapshots._block_after_failure``) draait eerst terug (dat
    geeft het slot vrij) en neemt het slot daarna opnieuw. Houdt een ander het slot dan langer dan
    ``REGISTER_LOCK_TIMEOUT_MS`` (hier 300 ms), dan gaf het blokkeren op met ``409 flowregister_bezig`` ("er is niets
    gewijzigd") en bleven alle flows open. Nu wacht het blokkeren onbegrensd: na het vrijgeven staan alle flows op
    geblokkeerd met ``synchronisatie_mislukt`` en het antwoord is nooit 409. Drie wegen: een synchronisatie
    (``POST …/snapshots``) met een onbruikbaar antwoord, een met een fout in ``record_state`` (in beide wacht de tweede
    verbinding al op het slot van de synchronisatie en krijgt het direct na de rollback), en een herstel dat na het
    schrijven op het slot vastloopt (de tweede verbinding nam het slot na het schrijven)."""
    monkeypatch.setattr(snapshots, "REGISTER_LOCK_TIMEOUT_MS", 300)
    flow, token = b11.ready_flow(linked, auth, TAB, "notification.send")
    held: list[tuple[threading.Thread, bool]] = []
    if where == "antwoord_ongeldig":
        original = node_red_fake.handle

        def handle(req: httpx.Request) -> httpx.Response:
            if req.method == "GET" and req.url.path == "/flows":
                held.append(_hold_the_register_lock(linked, HOLD_S, behind_the_holder=True))
                return httpx.Response(200, content=b"geen json", headers={"content-type": "application/json"})
            return original(req)

        monkeypatch.setattr(node_red_fake, "handle", handle)
    elif where == "record_state":

        def fails(*_args: Any, **_kwargs: Any) -> Any:
            held.append(_hold_the_register_lock(linked, HOLD_S, behind_the_holder=True))
            raise RuntimeError("ingespoten fout")

        monkeypatch.setattr(snapshots, "record_state", fails)
    else:
        request = scene.sign(scene.propose())
        post_flows = nodered.NodeRedClient.post_flows

        def writes_then_someone_holds(self: Any, *args: Any, **kwargs: Any) -> Any:
            out = post_flows(self, *args, **kwargs)
            held.append(_hold_the_register_lock(linked, HOLD_S, behind_the_holder=False))
            return out

        monkeypatch.setattr(nodered.NodeRedClient, "post_flows", writes_then_someone_holds)
    started = time.monotonic()
    if where == "na_het_schrijven":
        r = scene.apply(request)
    else:
        r = linked.post(f"{A}/snapshots", headers=idem(auth("admin")))
    waited = time.monotonic() - started
    for thread, _ok in held:
        thread.join(10)
    monkeypatch.undo()

    assert [ok for _thread, ok in held] == [True], "de tweede verbinding moet het slot gehouden hebben"
    assert r.status_code != 409 and r.json()["code"] != "flowregister_bezig", r.text
    if where == "na_het_schrijven":
        assert r.status_code == 500 and r.json()["code"] == "herstel_niet_vastgelegd", r.text
        assert r.json()["details"]["flows_geblokkeerd"] is True, r.text
    else:
        assert r.status_code == 502 and r.json()["code"] == "node_red_fout", r.text
        assert r.json()["details"]["reason"] == "synchronisatie_mislukt", r.text
    assert waited >= HOLD_S * 0.8, f"het blokkeren moet op het slot gewacht hebben ({waited:.2f} s)"
    detail = b11.flow_detail(linked, auth, flow["id"])
    assert (detail["status"], detail["blocked_reason"]) == ("geblokkeerd", "synchronisatie_mislukt"), detail
    act = b11.request_action(
        linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
    )
    assert act.status_code == 403 and act.json()["details"]["reason"] == "flow_geblokkeerd", act.text
    sync = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["ok"] is False and sync["fout"]["reason"] == "synchronisatie_mislukt", sync


# ------------------------------------------- S-P2-320, herstel: de grens van de blokkade na het schrijven (R-TECH-2)
def test_a_failing_commit_after_writing_is_outside_the_blockade_and_never_repeated_blindly(
    scene: Scene, linked: Any, auth: Any, fake_hub: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-TECH-2 van S-P2-320: de blokkade na het schrijven loopt tot en met de ``flush`` aan het eind van
    ``restore._record_outcome``. Het bewaren van het antwoord bij de Idempotency-Key en de commit in
    ``idempotency.run_idempotent`` vallen erbuiten (ADR-0016 kop 6, punt 4). Mislukt dat (hier: de database weigert
    het bewaren van het antwoord), dan is het een serverfout en is alles van na het schrijven teruggedraaid: het
    flowregister houdt zijn stand (de inhoud van het herstel is vóór het schrijven gescand), het voorstel blijft op
    ``toepassen_gestart`` en de nonce en de goedkeuring zijn al opgemaakt, dus het verzoek wordt nooit blind herhaald.
    De volgende synchronisatie legt de stand van Node-RED vast; na de geldigheid sluit de worker het voorstel af als
    onderbroken (uitkomst onbekend)."""
    flow, _token = b11.ready_flow(linked, auth, TAB, "notification.send")
    view = scene.propose()
    request = scene.sign(view)
    real_insert = idempotency.insert

    def storing_the_answer_fails(model: Any) -> Any:
        if model is IdempotencyRecord:
            raise RuntimeError("database weg bij het bewaren van het antwoord")
        return real_insert(model)

    with monkeypatch.context() as m:
        m.setattr(idempotency, "insert", storing_the_answer_fails)
        with pytest.raises(RuntimeError):
            scene.apply(request)
    assert len(scene.nr.writes) == 1 and scene.nr.flows == flows_v1(), "er is geschreven"
    assert [s.reason for s in snapshot_rows(linked)] == ["handmatig", "handmatig", "voor_herstel"]
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "voorgesteld" and row["result"]["fase"] == "toepassen_gestart", row
    assert b11.outbox(linked, "automation.restore.applied") == []
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == "actief", "buiten de blokkade: geen blokkade"
    assert scene.apply(request).json()["code"] == "nonce_al_gebruikt"
    reused = scene.sign(view, approval_overrides=dict(request["approval"]))
    assert scene.apply(reused).json()["code"] == "goedkeuring_al_gebruikt"
    assert len(scene.nr.writes) == 1
    snap = b11.snapshot(linked, auth)["snapshot"]
    assert snap["checksum_sha256"] == scene.snap1["checksum_sha256"], "de volgende synchronisatie ziet het herstel"
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == "actief"
    later = utcnow() + restore.PROPOSAL_TTL + timedelta(seconds=1)
    monkeypatch.setattr("integrations.worker.utcnow", lambda: later)
    Worker(make_settings(), transport=fake_hub.transport).automation_step(0.0)
    row = scene.restore_row(view["proposal_id"])
    assert row["status"] == "mislukt" and row["result"]["uitkomst"] == "onbekend", row


# ------------------------------------- S-P2-320, herstel: '_sa'-sleutels en te diep geneste verzoeken (R-VEILIG-2)
def test_the_same_key_with_other_sa_content_is_refused_not_replayed(scene: Scene, linked: Any, fake_hub: Any) -> None:
    """R-VEILIG-2 van S-P2-320: de verzoek-hash van de Idempotency-Key zag sleutels die met ``_sa`` beginnen niet
    (``jsonable_encoder`` liet ze stil weg), zodat een ander verzoek met dezelfde sleutel als herhaling gold (200,
    ``Idempotent-Replay: true``). Nu is dat ``422 idempotency_key_reused``, net als bij elke andere sleutel."""
    request = scene.sign(scene.propose())
    key = str(uuid.uuid4())
    assert scene.apply(request, key=key).status_code == 200
    for extra in ({"_sa_anders": "iets anders"}, {"anders": "iets anders"}):
        r = linked.post(f"{CONNECTOR}/apply", json={**request, **extra}, headers=idem(fake_hub.service_auth(), key=key))
        assert r.status_code == 422 and r.json()["code"] == "idempotency_key_reused", (extra, r.text)
        assert "Idempotent-Replay" not in r.headers
    assert len(scene.nr.writes) == 1


def _nested(levels: int) -> str:
    """Een object van ``levels`` niveaus diep, als ruwe JSON (``json.dumps`` kan dat bij duizenden niveaus niet)."""
    return '{"a":' * levels + "1" + "}" * levels


@pytest.mark.parametrize("route", ["propose", "apply"])
def test_a_too_deeply_nested_request_is_a_422_and_changes_nothing(
    scene: Scene, linked: Any, auth: Any, fake_hub: Any, route: str
) -> None:
    """R-VEILIG-2 van S-P2-320 (vervolgpunt): een verzoek dat dieper genest was dan ongeveer 990 niveaus gaf een
    serverfout (RecursionError in ``jsonable_encoder`` in ``run_idempotent``). Nu controleert ``run_idempotent`` de
    diepte eerst, zonder recursie: dieper dan ``idempotency.MAX_DEPTH`` niveaus (het verzoek zelf is niveau 1) is
    ``422 validation_error``, ook bij 5000 niveaus, en er wordt niets vastgelegd. Tot en met ``MAX_DEPTH`` niveaus gaat
    het verzoek door naar de eigen controle van de route (hier ``parameters_ongeldig`` en
    ``execution_request_ongeldig``)."""
    quiet = TestClient(linked.app, headers=BROWSER_HEADERS, raise_server_exceptions=False)
    view = scene.propose()

    def post(levels: int) -> Any:
        if route == "propose":  # het verzoek (1), parameters (2), daarin de diepe waarde
            raw = json.dumps({"action_id": RESTORE, "parameters": {"snapshot_id": view["parameters"]["snapshot_id"]}})
            raw = raw[:-2] + ', "x": ' + _nested(levels - 2) + "}}"
            headers = idem(auth("admin"))
        else:  # het verzoek (1), daarin proposal
            raw = '{"proposal":' + _nested(levels - 1) + "}"
            headers = idem(fake_hub.service_auth())
        return quiet.post(
            f"{CONNECTOR}/{route}", content=raw.encode(), headers={**headers, "Content-Type": "application/json"}
        )

    before = _stored(linked)
    at_limit = post(idempotency.MAX_DEPTH)
    own = "parameters_ongeldig" if route == "propose" else "execution_request_ongeldig"
    assert at_limit.status_code == 422 and at_limit.json()["code"] == own, at_limit.text
    for levels in (idempotency.MAX_DEPTH + 1, 1000, 5000):
        r = post(levels)
        assert r.status_code == 422, (levels, r.status_code, r.text[:300])
        body = r.json()
        assert body["code"] == "validation_error", body
        assert [f["probleem"] for f in body["details"]["fouten"]] == [idempotency.TOO_DEEP_NL], body
    assert _stored(linked) == before, "geen voorstel, nonce, bewaard antwoord, audit of event"
    assert scene.nr.writes == []


def test_no_route_with_run_idempotent_gives_a_server_error_on_a_too_deep_body(
    linked: Any, auth: Any, fake_hub: Any
) -> None:
    """R-VEILIG-2 van S-P2-320: de dieptecontrole zit centraal in ``run_idempotent``; deze test stuurt naar elke
    muterende route met een Idempotency-Key en een body (uit de app zelf gelezen) een body van ``MAX_DEPTH`` + 1 en van
    5000 niveaus, als beheerder en als de Hub. Geen enkele route geeft een serverfout; ``POST /connector/v1/apply``
    (een body zonder vaste vorm) komt tot de centrale controle en geeft ``422 validation_error``."""
    from fastapi.routing import APIRoute

    def routes(items: Any) -> Any:
        for item in items:
            if hasattr(item, "original_router"):
                yield from routes(item.original_router.routes)
            elif isinstance(item, APIRoute):
                yield item

    def uses(dependant: Any, call: Any) -> bool:
        return any(d.call is call or uses(d, call) for d in dependant.dependencies)

    quiet = TestClient(linked.app, headers=BROWSER_HEADERS, raise_server_exceptions=False)
    tried: list[str] = []
    central: set[str] = set()
    for route in routes(linked.app.routes):
        if route.body_field is None or not uses(route.dependant, idempotency.idempotency_key):
            continue
        path = route.path
        for name in route.param_convertors:
            path = path.replace("{" + name + "}", str(uuid.uuid4()))
        for method in sorted(set(route.methods) & {"POST", "PUT", "PATCH", "DELETE"}):
            tried.append(f"{method} {route.path}")
            for levels in (idempotency.MAX_DEPTH + 1, 5000):
                raw = ("{" + '"a":' + _nested(levels - 1) + "}").encode()
                for who in (auth("admin"), fake_hub.service_auth()):
                    headers = {**idem(who, **{"If-Match": "*"}), "Content-Type": "application/json"}
                    r = quiet.request(method, path, content=raw, headers=headers)
                    assert r.status_code < 500, (method, route.path, levels, r.status_code, r.text[:300])
                    if r.status_code == 422 and idempotency.TOO_DEEP_NL in r.text:
                        central.add(f"{method} {route.path}")
    assert len(tried) >= 20, tried
    assert f"POST {CONNECTOR}/apply" in central, central
