"""B11-005 — herstel en versiebeheer van flows.

Acceptatie: "Undo herstelt oude flows inclusief credentials zonder secrets te loggen." De hele keten hier: momentopname
(versleuteld, mét het door Node-RED versleutelde credentials-bestand) → verschil zonder waarden → herstelvoorstel →
door de Hub ondertekend ExecutionRequest met een menselijke goedkeuring → eigen hercontrole → schrijven → readback.
Sim-getest (nep-Node-RED met dezelfde API-vorm, nep-Hub die ondertekent zoals docs/EXECUTION_REQUEST.md van de Hub).
Dat de echte Hub dit verzoek uitgeeft en een echte Node-RED op de NAS het aanneemt: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import copy
import json
import logging
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import select, text, update

from integrations.domains.automation import restore, snapshots
from integrations.domains.automation.models import AutomationRestore, AutomationSnapshot
from integrations.timeutil import utcnow
from integrations.worker import Worker
from tests import b11
from tests.b11 import CONNECTOR, RESTORE, A
from tests.conftest import SimKey, idem, pair, setup_node_red
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
def client(app_factory: Any, node_red_fake: Any) -> Any:
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
    node_red_fake.deploy(flows_v2(), CREDS_V2)
    b11.snapshot(plain, auth)
    view = b11.propose_restore(plain, auth, first["id"]).json()
    assert view["credentials"] == {"credentials_present": False, "status": "niet_gekoppeld", "wijzigt": None}
    assert any("geen credentials-bestand" in w for w in view["warnings"])
    r = b11.apply(plain, fake_hub, b11.signed_restore(fake_hub, view))
    assert r.status_code == 200, r.text
    assert r.json()["credentials_teruggezet"] is False
    assert node_red_fake.flows == flows_v1()
    assert node_red_fake.credentials == CREDS_V2, "bestaande nodes houden hun (huidige) inloggegevens"
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
    assert view["credentials"] == {"credentials_present": True, "status": "meegenomen", "wijzigt": True}
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
