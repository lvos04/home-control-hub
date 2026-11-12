"""B11-004 — simulatie en testfixtures: een proefrun met vaste voorbeeld-events wijzigt niets.

Acceptatie: "Geen echte apparaten gewijzigd tijdens test." Wat hier aangetoond wordt: tijdens een proefrun komt er via
deze dienst geen enkel actieverzoek bij de Hub aan, wordt er niets naar Node-RED geschreven en blijven echte events
wachten. Sim-getest (flow = HTTP-client met flow-token, nep-Node-RED, nep-Hub).
Grens: een node die zelf naar buiten gaat (http request, mqtt out, function …) kan deze dienst niet tegenhouden; de
proefrun meldt dat en start alleen na een uitdrukkelijke bevestiging. Echte Node-RED: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest

from integrations.domains.automation import samples, simulate
from integrations.timeutil import utcnow
from integrations.worker import Worker
from tests import b11
from tests.b11 import FLOW_API, A
from tests.conftest import idem, setup_node_red
from tests.fakes.node_red_fake import exec_flow, node, simple_flow, tab

TAB = "tab0000000000001"
SAFE_TAB = "tabveilig0000001"
USER = {"type": "user", "id": "user-1"}
APP = {"type": "app", "id": "jellyfin"}
NOTIFY = {"titel": "Storing", "tekst": "De backup is mislukt."}
ALL_SAMPLES = [
    "energie-meting",
    "netwerk-nieuw-apparaat",
    "backup-mislukt",
    "app-gezondheid",
    "download-mislukt",
    "toegang-ingetrokken",
]


def safe_flow() -> list[dict[str, Any]]:
    """Een flow zonder nodes die zelf naar buiten gaan: inject → change → debug."""
    return [
        tab(SAFE_TAB, "Alleen kijken"),
        node("tabveiliinject01", "inject", SAFE_TAB, [["tabveilichange01"]]),
        node("tabveilichange01", "change", SAFE_TAB, [["tabveilidebug001"]], rules=[]),
        node("tabveilidebug001", "debug", SAFE_TAB, active=True),
    ]


@pytest.fixture
def flow(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> tuple[dict[str, Any], str]:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    return b11.ready_flow(linked, auth, TAB, "notification.send", "app.*", triggers=("energy.reading.recorded",))


def start(linked: Any, auth: Any, flow_id: str, role: str = "operator", key: str | None = None, **body: Any) -> Any:
    body.setdefault("bevestig_niet_afgeschermd", True)
    return linked.post(f"{A}/flows/{flow_id}/runs", json=body, headers=idem(auth(role), key=key))


def run_of(linked: Any, auth: Any, run_id: str) -> dict[str, Any]:
    r = linked.get(f"{A}/runs/{run_id}", headers=auth("viewer"))
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def drain(linked: Any, token: str, on_delivery: Any = None) -> list[dict[str, Any]]:
    """De flow haalt alles op wat hij krijgt en bevestigt het (per bron komt er één event tegelijk)."""
    seen: list[dict[str, Any]] = []
    for _ in range(20):
        if linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()["dry_run"] is None:
            break  # de proefrun is afgerond: wat nu nog wacht zijn echte events
        items = b11.claim(linked, token)["items"]
        if not items:
            break
        for item in items:
            seen.append(item)
            if on_delivery is not None:
                on_delivery(item)
            assert b11.ack(linked, token, item["id"]).status_code == 200
    return seen


# ------------------------------------------------------------------------------------------------ de vaste voorbeelden
def test_samples_are_fixed_and_marked_as_examples(linked: Any, auth: Any) -> None:
    r = linked.get(f"{A}/samples", headers=auth("viewer"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["checksum_sha256"] == samples.SAMPLES_SHA256 == samples.checksum()
    assert [s["id"] for s in body["items"]] == ALL_SAMPLES
    for sample in body["items"]:
        assert sample["envelope"]["payload"]["voorbeeld"] is True
        assert sample["envelope"]["actor"] == {"type": "system", "id": "voorbeeld"}
        assert sample["title_nl"]
    assert linked.get(f"{A}/samples").status_code == 401


def test_changed_samples_are_an_error_not_a_silent_success(
    linked: Any, auth: Any, flow: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    detail, _ = flow
    changed = [dict(s) for s in samples.SAMPLES]
    changed[0] = {**changed[0], "title_nl": "Stiekem aangepast"}
    monkeypatch.setattr(samples, "SAMPLES", tuple(changed))
    r = linked.get(f"{A}/samples", headers=auth("viewer"))
    assert r.status_code == 503 and r.json()["code"] == "simulation_unavailable"
    r = start(linked, auth, detail["id"])
    assert r.status_code == 503 and r.json()["code"] == "simulation_unavailable"
    assert linked.get(f"{A}/runs", headers=auth("viewer")).json()["items"] == []


def test_a_caller_cannot_change_the_samples() -> None:
    first = samples.verified()
    first["energie-meting"]["envelope"]["payload"]["vermogen_w"] = 999999
    assert samples.verified()["energie-meting"]["envelope"]["payload"]["vermogen_w"] == 420
    assert samples.checksum() == samples.SAMPLES_SHA256


# -------------------------------------------------------------------------------------------- de grens van een proefrun
def test_unshielded_nodes_need_an_explicit_confirmation(linked: Any, auth: Any, flow: Any) -> None:
    detail, _ = flow
    assert detail["niet_afgeschermde_typen"] == ["function"]
    r = start(linked, auth, detail["id"], bevestig_niet_afgeschermd=False)
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "proefrun_niet_afgeschermd"
    assert r.json()["details"]["niet_afgeschermd"] == ["function"]
    assert linked.get(f"{A}/runs", headers=auth("viewer")).json()["items"] == []
    r = start(linked, auth, detail["id"])
    assert r.status_code == 201, r.text
    first = r.json()["runlog"][0]
    assert first["soort"] == "start" and first["niet_afgeschermd"] == ["function"]
    assert first["niet_afgeschermd_bevestigd"] is True and "niet" in first["toelichting_nl"]


def test_flow_without_outbound_nodes_starts_without_confirmation(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    setup_node_red(linked, fake_hub, auth, flows=safe_flow())
    b11.snapshot(linked, auth)
    detail, _ = b11.ready_flow(linked, auth, SAFE_TAB, "notification.send")
    assert detail["niet_afgeschermde_typen"] == []
    r = start(linked, auth, detail["id"], bevestig_niet_afgeschermd=False, sample_ids=["energie-meting"])
    assert r.status_code == 201, r.text
    assert r.json()["runlog"][0]["niet_afgeschermd"] == []
    assert r.json()["runlog"][0]["niet_afgeschermd_bevestigd"] is False


# ---------------------------------------------------------------------------------- acceptatie: er verandert niets echt
def test_dry_run_requests_nothing_and_changes_nothing(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, node_red_fake: Any, make_settings: Any
) -> None:
    detail, token = flow
    writes_before = list(node_red_fake.writes)
    # een echt event dat al wacht: dat blijft staan zolang de proefrun loopt
    real = b11.envelope(source_event_id="meter-1:echt")
    assert b11.post_event(linked, fake_hub, real).json()["afleveringen"] == 1

    r = start(linked, auth, detail["id"])
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["status"] == "bezig" and run["mode"] == "dry_run" and run["sample_ids"] == ALL_SAMPLES
    me = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()
    assert me["dry_run"]["run_id"] == run["id"]

    answers: list[dict[str, Any]] = []

    def act(item: dict[str, Any]) -> None:
        # de flow doet wat hij in het echt ook zou doen: een melding, een herstart, en iets wat nooit mag
        assert item["dry_run"] is True and item["run_id"] == run["id"]
        assert item["event"]["payload"]["voorbeeld"] is True
        for action_id, target, params in (
            ("notification.send", USER, NOTIFY),
            ("app.restart", APP, {}),
            ("zfs.dataset.delete", {"type": "dataset", "id": "media"}, {}),
            ("energy.boiler.switch", {"type": "device", "id": "boiler"}, {"aan": True}),
        ):
            a = b11.request_action(
                linked, token, action_id, target=target, parameters=params, trigger_delivery_id=item["id"]
            )
            assert a.status_code == 200, a.text
            answers.append(a.json())

    seen = drain(linked, token, act)
    assert sorted(s["event"]["source_event_id"].rsplit(":", 1)[-1] for s in seen) == sorted(ALL_SAMPLES)
    assert real["event_id"] not in {s["event"]["event_id"] for s in seen}
    assert {a["status"] for a in answers} == {"gesimuleerd"} and all(a["dry_run"] is True for a in answers)
    assert [a["uitkomst"] for a in answers[:4]] == [
        "zou_worden_aangevraagd",
        "zou_worden_aangevraagd",
        "zou_worden_geweigerd",
        "zou_worden_geweigerd",
    ]
    assert [a["reden"] for a in answers[:4]] == [None, None, "destructief_verboden", "boiler_nooit"]
    assert all("id" not in a for a in answers), "er is geen actieverzoek aangemaakt"

    done = run_of(linked, auth, run["id"])
    assert done["status"] == "klaar" and done["error_code"] is None and done["finished_at"]
    assert done["result"]["afleveringen"] == {"verwerkt": 6, "mislukt": 0}
    assert done["result"]["actieverzoeken"] == 24
    assert done["result"]["zou_worden_aangevraagd"] == 12 and done["result"]["zou_worden_geweigerd"] == 12
    assert done["result"]["aangevraagd_bij_de_hub"] == 0
    assert done["result"]["echte_wijzigingen_via_deze_dienst"] == 0
    kinds = [e["soort"] for e in done["runlog"]]
    assert kinds[0] == "start" and kinds[-1] == "einde"
    assert kinds.count("aflevering") == 6 and kinds.count("actie") == 24
    actie = next(e for e in done["runlog"] if e["soort"] == "actie" and e["action_id"] == "notification.send")
    assert actie["parameter_namen"] == ["tekst", "titel"] and "De backup is mislukt." not in str(done["runlog"])

    # niets vastgelegd als verzoek, niets naar de Hub, niets naar Node-RED
    assert linked.get(f"{A}/action-requests", headers=auth("viewer")).json()["items"] == []
    assert b11.outbox(linked, "flow.action.requested") == []
    assert b11.outbox(linked, "flow.action.rejected") == []
    Worker(make_settings(), transport=fake_hub.transport).push_step()
    assert [e for e in fake_hub.inbox if e["event_type"].startswith("flow.action.")] == []
    assert node_red_fake.writes == writes_before == []
    # de voorbeeld-events zijn niet als afgekeurd gemeld en tellen niet mee in de wachtrij
    assert b11.outbox(linked, "automation.event.rejected") == []

    # daarna krijgt de flow het echte event alsnog
    after = b11.claim(linked, token)
    assert after["dry_run"] is False
    assert [i["event"]["event_id"] for i in after["items"]] == [real["event_id"]]
    assert after["items"][0]["dry_run"] is False
    assert linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()["dry_run"] is None


def test_dry_run_does_not_use_the_rate_limit_or_the_hub_link(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    r = b11.put_flow(
        linked,
        auth,
        detail["id"],
        "rate-limits",
        {"rate_limits": [{"action_id": "*", "max_per_hour": 1, "cooldown_s": 0}]},
    )
    assert r.status_code == 200, r.text
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    # zelfs zonder Hub-koppeling: er wordt toch niets aangevraagd
    linked.app.state.hublink.unlink(trace_id=str(uuid.uuid4()), actor=("user", "user-1"))
    for _ in range(3):
        a = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
        assert a.status_code == 200 and a.json()["status"] == "gesimuleerd", a.text
    assert a.json()["run_id"] == run["id"]


def test_failed_delivery_in_a_dry_run_is_logged_and_not_retried(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting", "backup-mislukt"]).json()
    items = b11.claim(linked, token)["items"]
    assert len(items) == 2
    assert b11.nack(linked, token, items[0]["id"], "kapot").status_code == 200
    assert b11.ack(linked, token, items[1]["id"]).status_code == 200
    assert b11.claim(linked, token)["items"] == [], "geen herhaling in een proefrun"
    done = run_of(linked, auth, run["id"])
    assert done["status"] == "mislukt" and done["error_code"] == "aflevering_mislukt"
    assert done["result"]["afleveringen"] == {"verwerkt": 1, "mislukt": 1}
    failed = [e for e in done["runlog"] if e["soort"] == "aflevering" and e["uitkomst"] == "mislukt"]
    assert len(failed) == 1 and failed[0]["fout"] == "kapot"
    # geen storingsmelding en niets om opnieuw in te plannen: het was een proef
    assert b11.outbox(linked, "automation.delivery.failed") == []
    r = linked.post(f"{A}/deliveries/{items[0]['id']}/requeue", headers=idem(auth("admin")))
    assert r.status_code == 409 and r.json()["code"] == "aflevering_niet_vastgelopen"


def test_a_dry_run_that_started_before_the_block_gives_nothing_and_simulates_nothing(
    linked: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """Vervolgpunt R-VEILIG-3 (S-P2-295): een proefrun die al liep voordat de flow geblokkeerd raakte. Daarna krijgt
    de flow geen voorbeeld-events meer en wordt een actieverzoek niet gesimuleerd maar geweigerd, zoals bij elke
    geblokkeerde flow (ADR-0016 kop 2): 403 ``flow_geblokkeerd``, niets naar de Hub en geen regel in het runlog."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting", "backup-mislukt"]).json()
    assert run["status"] == "bezig"
    assert linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()["dry_run"]["run_id"] == run["id"]

    # grof blokkeren: een verboden node in een ander tabblad blokkeert ook deze flow
    node_red_fake.deploy([*simple_flow(), *exec_flow()])
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "geblokkeerd"

    claimed = b11.claim(linked, token)
    assert claimed["items"] == [] and claimed["dry_run"] is False and claimed["flow_status"] == "geblokkeerd"
    me = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()
    assert me["dry_run"] is None and me["flow"]["status"] == "geblokkeerd"
    a = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert a.status_code == 403, a.text
    assert a.json()["code"] == "forbidden" and a.json()["details"]["reason"] == "flow_geblokkeerd"
    assert "dry_run" not in a.json()
    assert b11.outbox(linked, "flow.action.requested") == []
    log = run_of(linked, auth, run["id"])["runlog"]
    assert [e["soort"] for e in log] == ["start"], "geen aflevering en geen gesimuleerde actie na de blokkade"


def test_paused_flow_can_be_tried_before_it_is_resumed(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    assert b11.put_flow(linked, auth, detail["id"], "state", {"status": "gepauzeerd", "reden": "x"}).status_code == 200
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    seen = drain(linked, token)
    assert len(seen) == 1 and seen[0]["run_id"] == run["id"]
    assert run_of(linked, auth, run["id"])["status"] == "klaar"
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "gepauzeerd"


# -------------------------------------------------------------------------------------------- vergelijken met eerder
def test_comparison_with_an_earlier_run(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow

    def run_with(actions: list[str], **body: Any) -> dict[str, Any]:
        r = start(linked, auth, detail["id"], sample_ids=["energie-meting"], **body)
        assert r.status_code == 201, r.text
        drain(linked, token, lambda _i: [b11.request_action(linked, token, a, target=APP) for a in actions])
        return run_of(linked, auth, r.json()["id"])

    first = run_with(["app.restart"])
    assert "vergelijking" not in first["result"]
    same = run_with(["app.restart"], baseline_run_id=first["id"])
    assert same["baseline_run_id"] == first["id"]
    assert same["result"]["vergelijking"]["gelijk"] is True
    assert same["result"]["vergelijking"]["zelfde_voorbeelden"] is True
    different = run_with(["app.restart", "app.stop"], baseline_run_id=first["id"])
    comparison = different["result"]["vergelijking"]
    assert comparison["gelijk"] is False and comparison["alleen_eerder"] == []
    assert len(comparison["alleen_nu"]) == 1 and "app.stop" in comparison["alleen_nu"][0]
    assert comparison["baseline_version_id"] == first["version_id"]
    # vergelijken kan alleen met een afgeronde proefrun van dezelfde flow
    r = start(linked, auth, detail["id"], baseline_run_id=str(uuid.uuid4()))
    assert r.status_code == 422 and r.json()["code"] == "vergelijking_ongeldig"
    listed = linked.get(f"{A}/runs", params={"flow_id": detail["id"]}, headers=auth("viewer")).json()["items"]
    assert [x["id"] for x in listed] == [different["id"], same["id"], first["id"]]
    assert all("runlog" not in x for x in listed)


# --------------------------------------------------------------------------------------------------------- weigeringen
def test_one_dry_run_at_a_time_and_replay_gives_the_same_run(linked: Any, auth: Any, flow: Any) -> None:
    detail, _ = flow
    key = str(uuid.uuid4())
    first = start(linked, auth, detail["id"], key=key)
    assert first.status_code == 201
    again = start(linked, auth, detail["id"], key=key)
    assert again.status_code == 201 and again.json()["id"] == first.json()["id"]
    r = start(linked, auth, detail["id"])
    assert r.status_code == 409 and r.json()["code"] == "proefrun_loopt_al"
    assert r.json()["details"]["run_id"] == first.json()["id"]


def test_dry_run_refusals(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    good = b11.flow_by_tab(linked, auth, TAB)
    r = start(linked, auth, good["id"], sample_ids=["bestaat-niet", "energie-meting"])
    assert r.status_code == 422 and r.json()["code"] == "voorbeeld_onbekend"
    assert r.json()["details"]["onbekend"] == ["bestaat-niet"]
    r = start(linked, auth, good["id"], sample_ids=[f"s{i}" for i in range(21)])
    assert r.status_code == 422
    assert start(linked, auth, good["id"], role="viewer").status_code == 403
    assert start(linked, auth, good["id"], role="family").status_code == 403
    assert start(linked, auth, str(uuid.uuid4())).status_code == 404
    assert linked.post(f"{A}/flows/{good['id']}/runs", json={}).status_code == 401
    assert linked.get(f"{A}/runs/{uuid.uuid4()}", headers=auth("viewer")).status_code == 404
    # een verboden node in een ander tabblad: die flow, en (grof blokkeren) ook de schone flow, start geen proefrun
    node_red_fake.deploy([*simple_flow(), *exec_flow()])
    b11.snapshot(linked, auth)
    blocked = b11.flow_by_tab(linked, auth, "tabexec000000001")
    r = start(linked, auth, blocked["id"])
    assert r.status_code == 409 and r.json()["code"] == "flow_geblokkeerd"
    assert r.json()["details"]["reden"] == "verboden_node"
    r = start(linked, auth, good["id"])
    assert r.status_code == 409 and r.json()["code"] == "flow_geblokkeerd"
    assert r.json()["details"]["reden"] == "bron_geblokkeerd"
    assert linked.get(f"{A}/runs", headers=auth("viewer")).json()["items"] == []


def test_abandoned_dry_run_expires_and_real_events_flow_again(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    detail, token = flow
    real = b11.envelope(source_event_id="meter-1:na-de-proef")
    b11.post_event(linked, fake_hub, real)
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting", "backup-mislukt"]).json()
    assert len(b11.claim(linked, token)["items"]) == 2  # geclaimd en daarna nooit bevestigd
    worker = Worker(make_settings(), transport=fake_hub.transport)
    worker.automation_step(0.0)
    assert run_of(linked, auth, run["id"])["status"] == "bezig", "nog niet verlopen"
    later = utcnow() + simulate.RUN_TTL + timedelta(seconds=1)
    monkeypatch.setattr("integrations.worker.utcnow", lambda: later)
    worker.automation_step(0.0)
    done = run_of(linked, auth, run["id"])
    assert done["status"] == "mislukt" and done["error_code"] == "verlopen"
    assert done["runlog"][-1]["soort"] == "verlopen" and done["runlog"][-1]["niet_verwerkt"] == 2
    assert done["result"]["aangevraagd_bij_de_hub"] == 0
    assert b11.outbox(linked, "automation.delivery.failed") == []
    after = b11.claim(linked, token)
    assert after["dry_run"] is False and [i["event"]["event_id"] for i in after["items"]] == [real["event_id"]]


def test_dry_run_start_is_audited(linked: Any, auth: Any, flow: Any) -> None:
    detail, _ = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    rows = [a for a in b11.audit_rows(linked) if a["action"] == "automation.simulation.started"]
    assert len(rows) == 1 and rows[0]["details"] == {"run_id": run["id"], "voorbeelden": ["energie-meting"]}
