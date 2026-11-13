"""B11-004 — simulatie en testfixtures: een proefrun met vaste voorbeeld-events wijzigt niets.

Acceptatie: "Geen echte apparaten gewijzigd tijdens test." Wat hier aangetoond wordt: tijdens een proefrun komt er via
deze dienst geen enkel actieverzoek bij de Hub aan, wordt er niets naar Node-RED geschreven en blijven echte events
wachten. Sim-getest (flow = HTTP-client met flow-token, nep-Node-RED, nep-Hub).
Grens: een node die zelf naar buiten gaat (http request, mqtt out, function …) kan deze dienst niet tegenhouden; de
proefrun meldt dat en start alleen na een uitdrukkelijke bevestiging. Echte Node-RED: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text

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


def block_by_policy(linked: Any, auth: Any, node_red_fake: Any, flow_id: str) -> None:
    """Grof blokkeren: een verboden node in een ander tabblad blokkeert ook deze flow (ADR-0016 kop 2)."""
    node_red_fake.deploy([*simple_flow(), *exec_flow()])
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, flow_id)["status"] == "geblokkeerd"


def assert_closed_by_the_block(linked: Any, auth: Any, run_id: str, open_deliveries: int) -> dict[str, Any]:
    """De proefrun is bij het blokkeren direct afgesloten: mislukt met ``flow_geblokkeerd``, de open voorbeeld-
    afleveringen staan in dead_letter, en na de start komt in het runlog alleen nog de blokkade en het einde."""
    done = run_of(linked, auth, run_id)
    assert done["status"] == "mislukt" and done["error_code"] == "flow_geblokkeerd", done
    assert done["finished_at"]
    assert [e["soort"] for e in done["runlog"]] == ["start", "geblokkeerd", "einde"], done["runlog"]
    blocked = done["runlog"][1]
    assert blocked["niet_verwerkt"] == open_deliveries and blocked["reden"]
    assert done["result"]["afleveringen"] == {"verwerkt": 0, "mislukt": open_deliveries}
    assert done["result"]["aangevraagd_bij_de_hub"] == 0
    rows = linked.get(f"{A}/deliveries", params={"flow_id": done["flow_id"]}, headers=auth("viewer")).json()["items"]
    of_run = [d for d in rows if d["run_id"] == run_id]
    assert len(of_run) == open_deliveries
    assert {(d["status"], d["last_error"]) for d in of_run} == {("dead_letter", "flow_geblokkeerd")}
    return done


def test_a_dry_run_that_started_before_the_block_gives_nothing_and_simulates_nothing(
    linked: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """Vervolgpunt R-VEILIG-3 (S-P2-295): een proefrun die al liep voordat de flow geblokkeerd raakte. Daarna krijgt
    de flow geen voorbeeld-events meer en wordt een actieverzoek niet gesimuleerd maar geweigerd, zoals bij elke
    geblokkeerde flow (ADR-0016 kop 2): 403 ``flow_geblokkeerd``, niets naar de Hub. Het blokkeren sluit de proefrun
    direct af (R-TECH-1 en R-VEILIG-2 van S-P2-300): geen aflevering en geen gesimuleerde actie in het runlog."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting", "backup-mislukt"]).json()
    assert run["status"] == "bezig"
    assert linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()["dry_run"]["run_id"] == run["id"]

    block_by_policy(linked, auth, node_red_fake, detail["id"])

    claimed = b11.claim(linked, token)
    assert claimed["items"] == [] and claimed["dry_run"] is False and claimed["flow_status"] == "geblokkeerd"
    me = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()
    assert me["dry_run"] is None and me["flow"]["status"] == "geblokkeerd"
    a = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert a.status_code == 403, a.text
    assert a.json()["code"] == "forbidden" and a.json()["details"]["reason"] == "flow_geblokkeerd"
    assert "dry_run" not in a.json()
    assert b11.outbox(linked, "flow.action.requested") == []
    assert_closed_by_the_block(linked, auth, run["id"], open_deliveries=2)


def test_a_delivery_claimed_before_the_block_cannot_be_acked_after_it(
    linked: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """R-TECH-1 (S-P2-300): een voorbeeld-event dat vóór de blokkade geclaimd is en erna bevestigd wordt. De ack wordt
    geweigerd (409 ``proefrun_afgesloten``) en rondt de proefrun niet af: hij blijft mislukt met ``flow_geblokkeerd``,
    zonder aflevering in het runlog, en kan nooit als vergelijkingsrun dienen (422 ``vergelijking_ongeldig``)."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    claimed = b11.claim(linked, token)
    assert [i["dry_run"] for i in claimed["items"]] == [True]
    delivery_id = claimed["items"][0]["id"]

    block_by_policy(linked, auth, node_red_fake, detail["id"])
    before = assert_closed_by_the_block(linked, auth, run["id"], open_deliveries=1)

    a = b11.request_action(
        linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=delivery_id
    )
    assert a.status_code == 403 and a.json()["details"]["reason"] == "flow_geblokkeerd", a.text
    r = b11.ack(linked, token, delivery_id)
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "proefrun_afgesloten"
    assert r.json()["details"] == {"run_id": run["id"], "run_status": "mislukt", "flow_status": "geblokkeerd"}
    assert run_of(linked, auth, run["id"]) == before, "de geweigerde ack verandert de proefrun niet"
    assert linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()["dry_run"] is None
    assert b11.outbox(linked, "flow.action.requested") == []

    # zo'n proefrun is nooit een vergelijkingsrun, ook niet na het opheffen van de blokkade
    node_red_fake.deploy(simple_flow())
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "gepauzeerd"
    r = start(linked, auth, detail["id"], sample_ids=["energie-meting"], baseline_run_id=run["id"])
    assert r.status_code == 422 and r.json()["code"] == "vergelijking_ongeldig", r.text


def test_ack_and_nack_after_the_block_are_refused_and_change_nothing(
    linked: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """PROEF5 van R-VEILIG (S-P2-300): twee voorbeeld-events zijn vóór de blokkade geclaimd. Na de blokkade wordt een
    actieverzoek met een van die afleveringen als trigger geweigerd en vastgelegd (403), en worden ack en nack allebei
    geweigerd (409 ``proefrun_afgesloten``). Er komt geen regel meer in het runlog en niets gaat naar de Hub."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting", "backup-mislukt"]).json()
    items = b11.claim(linked, token)["items"]
    assert len(items) == 2
    block_by_policy(linked, auth, node_red_fake, detail["id"])

    a = b11.request_action(
        linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=items[0]["id"]
    )
    assert a.status_code == 403 and a.json()["details"]["reason"] == "flow_geblokkeerd", a.text
    ack = b11.ack(linked, token, items[0]["id"])
    nack = b11.nack(linked, token, items[1]["id"], "kapot")
    assert (ack.status_code, ack.json()["code"]) == (409, "proefrun_afgesloten"), ack.text
    assert (nack.status_code, nack.json()["code"]) == (409, "proefrun_afgesloten"), nack.text
    assert b11.claim(linked, token)["items"] == []
    assert_closed_by_the_block(linked, auth, run["id"], open_deliveries=2)
    assert b11.outbox(linked, "flow.action.requested") == []
    assert len(b11.outbox(linked, "flow.action.rejected")) == 1


def test_after_the_block_is_lifted_the_old_dry_run_does_not_count(
    linked: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """PROEF6 van R-VEILIG (S-P2-300): de verboden node verdwijnt weer en de flow wordt gepauzeerd (zonder beheerder).
    De oude proefrun telt dan niet meer: geen voorbeeld-events, een actieverzoek wordt niet gesimuleerd maar geweigerd
    (de flow is niet actief), en het runlog blijft zoals het bij de blokkade was. Een nieuwe proefrun kan wel."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    block_by_policy(linked, auth, node_red_fake, detail["id"])
    node_red_fake.deploy(simple_flow())
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "gepauzeerd"

    claimed = b11.claim(linked, token)
    assert claimed["items"] == [] and claimed["dry_run"] is False and claimed["run_id"] is None
    a = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert a.status_code == 403 and a.json()["details"]["reason"] == "flow_niet_actief", a.text
    assert "dry_run" not in a.json()
    assert linked.get(f"{FLOW_API}/me", headers=b11.bearer(token)).json()["dry_run"] is None
    assert_closed_by_the_block(linked, auth, run["id"], open_deliveries=1)
    assert b11.outbox(linked, "flow.action.requested") == []
    again = start(linked, auth, detail["id"], sample_ids=["energie-meting"])
    assert again.status_code == 201 and again.json()["id"] != run["id"], again.text


def assert_sample_trigger_refused(linked: Any, auth: Any, answer: Any) -> None:
    """R-VEILIG-3 (S-P2-300): een voorbeeld-aflevering is buiten haar eigen lopende proefrun geen trigger. Het verzoek
    wordt geweigerd en vastgelegd (403 ``voorbeeld_buiten_proefrun``): er komt geen rij ``aangevraagd`` en geen event
    ``flow.action.requested``, dus niets gaat naar de Hub."""
    assert answer.status_code == 403, answer.text
    body = answer.json()
    assert body["code"] == "forbidden" and body["details"]["reason"] == "voorbeeld_buiten_proefrun"
    assert "dry_run" not in body
    rows = linked.get(f"{A}/action-requests", headers=auth("viewer")).json()["items"]
    assert [(r["id"], r["status"], r["rejected_reason"]) for r in rows] == [
        (body["details"]["action_request_id"], "geweigerd", "voorbeeld_buiten_proefrun")
    ]
    assert b11.outbox(linked, "flow.action.requested") == []
    assert [e["payload"]["reden"] for e in b11.outbox(linked, "flow.action.rejected")] == ["voorbeeld_buiten_proefrun"]


def test_a_sample_of_a_closed_dry_run_is_no_trigger_after_the_flow_is_resumed(
    linked: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """PROEF-E van R-VEILIG (S-P2-300): een voorbeeld-event is vóór de blokkade geclaimd; de blokkade wordt opgeheven
    en een beheerder hervat de flow. Een actieverzoek met die voorbeeld-aflevering als trigger gaat niet als echt
    verzoek naar de Hub, maar wordt geweigerd en vastgelegd. De afgesloten proefrun verandert niet."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    delivery_id = b11.claim(linked, token)["items"][0]["id"]
    block_by_policy(linked, auth, node_red_fake, detail["id"])
    node_red_fake.deploy(simple_flow())
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "gepauzeerd"
    resumed = b11.put_flow(linked, auth, detail["id"], "state", {"status": "actief"})
    assert resumed.status_code == 200 and resumed.json()["status"] == "actief", resumed.text
    before = assert_closed_by_the_block(linked, auth, run["id"], open_deliveries=1)

    a = b11.request_action(
        linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=delivery_id
    )
    assert_sample_trigger_refused(linked, auth, a)
    assert run_of(linked, auth, run["id"]) == before


def test_a_sample_of_a_finished_dry_run_is_no_trigger_and_only_its_own_running_dry_run_simulates(
    linked: Any, auth: Any, flow: Any
) -> None:
    """PROEF-F van R-VEILIG (S-P2-300): een proefrun die gewoon klaar is. Een actieverzoek van de (actieve) flow met een
    voorbeeld-aflevering daarvan als trigger wordt geweigerd en vastgelegd, niet aangevraagd. Loopt er een nieuwe
    proefrun, dan wordt een verzoek gesimuleerd zoals elk verzoek in een proefrun: met een voorbeeld-aflevering van
    die run als ``zou_worden_aangevraagd``, met een van de oude run als ``zou_worden_geweigerd``."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    old = b11.claim(linked, token)["items"][0]["id"]
    assert b11.ack(linked, token, old).status_code == 200
    done = run_of(linked, auth, run["id"])
    assert done["status"] == "klaar" and b11.flow_detail(linked, auth, detail["id"])["status"] == "actief"

    a = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=old)
    assert_sample_trigger_refused(linked, auth, a)
    assert run_of(linked, auth, run["id"]) == done

    second = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    own = b11.claim(linked, token)["items"][0]["id"]
    answers = [
        b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=d)
        for d in (own, old)
    ]
    assert [(x.status_code, x.json()["status"], x.json()["run_id"]) for x in answers] == [
        (200, "gesimuleerd", second["id"]),
        (200, "gesimuleerd", second["id"]),
    ]
    assert [(x.json()["uitkomst"], x.json()["reden"]) for x in answers] == [
        ("zou_worden_aangevraagd", None),
        ("zou_worden_geweigerd", "voorbeeld_buiten_proefrun"),
    ]
    assert len(linked.get(f"{A}/action-requests", headers=auth("viewer")).json()["items"]) == 1
    assert b11.outbox(linked, "flow.action.requested") == []


def test_ack_of_a_sample_after_the_dry_run_finished_is_refused_and_a_replay_keeps_its_answer(
    linked: Any, auth: Any, flow: Any
) -> None:
    """R-TECH-4 (S-P2-300): een voorbeeld-aflevering van een proefrun die klaar is, terwijl de flow gewoon actief is.
    Dezelfde ``Idempotency-Key`` geeft het bewaarde antwoord (200); een nieuwe sleutel geeft 409
    ``proefrun_afgesloten`` (ook een nack), en de run verandert niet."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    delivery_id = b11.claim(linked, token)["items"][0]["id"]
    key = str(uuid.uuid4())
    url = f"{FLOW_API}/deliveries/{delivery_id}/ack"
    first = linked.post(url, headers=idem(b11.bearer(token), key=key))
    assert first.status_code == 200, first.text
    done = run_of(linked, auth, run["id"])
    assert done["status"] == "klaar" and b11.flow_detail(linked, auth, detail["id"])["status"] == "actief"

    replay = linked.post(url, headers=idem(b11.bearer(token), key=key))
    assert (replay.status_code, replay.json()) == (200, first.json())
    for again in (b11.ack(linked, token, delivery_id), b11.nack(linked, token, delivery_id, "kapot")):
        assert (again.status_code, again.json().get("code")) == (409, "proefrun_afgesloten"), again.text
        assert again.json()["details"] == {"run_id": run["id"], "run_status": "klaar", "flow_status": "actief"}
    assert run_of(linked, auth, run["id"]) == done


def test_ack_of_a_sample_after_the_dry_run_expired_is_refused_and_it_is_no_trigger(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-TECH-4 en R-VEILIG-3 (S-P2-300): een proefrun die verlopen is (``expire_runs``), terwijl de flow actief is.
    Een herhaalde ack met dezelfde sleutel geeft het bewaarde antwoord; elke nieuwe ack of nack van een voorbeeld-
    aflevering van die run geeft 409 ``proefrun_afgesloten`` en verandert de run niet; zo'n aflevering is ook geen
    trigger voor een echt actieverzoek."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting", "backup-mislukt"]).json()
    items = b11.claim(linked, token)["items"]
    assert len(items) == 2
    key = str(uuid.uuid4())
    url = f"{FLOW_API}/deliveries/{items[0]['id']}/ack"
    first = linked.post(url, headers=idem(b11.bearer(token), key=key))
    assert first.status_code == 200, first.text
    later = utcnow() + simulate.RUN_TTL + timedelta(seconds=1)
    monkeypatch.setattr("integrations.worker.utcnow", lambda: later)
    Worker(make_settings(), transport=fake_hub.transport).automation_step(0.0)
    done = run_of(linked, auth, run["id"])
    assert (done["status"], done["error_code"]) == ("mislukt", "verlopen")
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "actief"

    replay = linked.post(url, headers=idem(b11.bearer(token), key=key))
    assert (replay.status_code, replay.json()) == (200, first.json())
    for again in (
        b11.ack(linked, token, items[0]["id"]),
        b11.ack(linked, token, items[1]["id"]),
        b11.nack(linked, token, items[1]["id"], "kapot"),
    ):
        assert (again.status_code, again.json().get("code")) == (409, "proefrun_afgesloten"), again.text
        assert again.json()["details"] == {"run_id": run["id"], "run_status": "mislukt", "flow_status": "actief"}
    assert run_of(linked, auth, run["id"]) == done

    a = b11.request_action(
        linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=items[1]["id"]
    )
    assert_sample_trigger_refused(linked, auth, a)
    assert run_of(linked, auth, run["id"]) == done


def test_a_sample_is_no_trigger_once_its_dry_run_has_expired_even_before_the_worker_closes_it(
    linked: Any, auth: Any, flow: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vervolgpunt 3 van S-P2-300 (proef P1 van R-VEILIG-3), overgenomen in S-P2-310: het venster waarin ``expires_at``
    van de proefrun al voorbij is, maar ``simulate.expire_runs`` nog niet heeft gedraaid (de run staat nog op
    ``bezig``). Een actieverzoek met een voorbeeld-aflevering van die run als trigger telt dan niet als proefrun en ook
    niet als echt verzoek: het wordt geweigerd en vastgelegd (``403 voorbeeld_buiten_proefrun``), er gaat niets naar de
    Hub, en de run zelf verandert niet."""
    detail, token = flow
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting"]).json()
    delivery_id = b11.claim(linked, token)["items"][0]["id"]
    before = run_of(linked, auth, run["id"])
    later = utcnow() + simulate.RUN_TTL + timedelta(seconds=5)
    monkeypatch.setattr("integrations.domains.automation.flowapi.utcnow", lambda: later)
    a = b11.request_action(
        linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=delivery_id
    )
    assert run_of(linked, auth, run["id"]) == before and before["status"] == "bezig", "de worker heeft niet gedraaid"
    assert_sample_trigger_refused(linked, auth, a)


def test_a_failed_sync_that_blocks_every_flow_also_closes_the_dry_run(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, node_red_fake: Any, make_settings: Any, monkeypatch: Any
) -> None:
    """Blokkeren bij mislukken (``snapshots.block_every_flow``) sluit een lopende proefrun net zo af als het
    flowbeleid: mislukt met ``flow_geblokkeerd`` en de open voorbeeld-afleveringen in dead_letter."""
    from integrations.domains.automation import snapshots

    detail, token = flow
    worker = Worker(make_settings(node_red_sync_interval_s=60), transport=fake_hub.transport)
    worker.automation_step(100.0)
    run = start(linked, auth, detail["id"], sample_ids=["energie-meting", "backup-mislukt"]).json()
    assert len(b11.claim(linked, token)["items"]) == 2

    def fails(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("ingespoten fout")

    monkeypatch.setattr(snapshots, "apply_scan", fails)
    worker.automation_step(200.0)
    monkeypatch.undo()
    assert worker.state.stats["node_red_sync_failed"] == 1
    flow_now = b11.flow_detail(linked, auth, detail["id"])
    assert (flow_now["status"], flow_now["blocked_reason"]) == ("geblokkeerd", "synchronisatie_mislukt")
    done = assert_closed_by_the_block(linked, auth, run["id"], open_deliveries=2)
    assert done["runlog"][1]["reden"] == "synchronisatie_mislukt"


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


# ------------------------------------------------------- KLEIN-47: worker en claim tegelijk rond het verlopen van een proefrun
def _lock_waits(linked: Any) -> int:
    """Hoeveel databaseverbindingen van deze test nu op een slot wachten (pg_stat_activity; alleen lezen)."""
    with linked.app.state.db.engine.connect() as conn:
        found = conn.execute(
            text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'"
            )
        ).scalar_one()
    return int(found)


def _deadlocks(linked: Any, *workers: Worker) -> int:
    """Het aantal deadlocks in deze database. Eerst gaan de verbindingen dicht, zodat hun tellingen bij de server
    staan; een deadlock is ook zichtbaar als fout in een van de uitkomsten van de test zelf."""
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


def test_the_worker_and_a_claim_at_the_moment_a_dry_run_expires_do_not_deadlock(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """KLEIN-47 (vervolgpunt van R-VEILIG-2 uit S-P2-300): de worker en een claim van de flow, tegelijk op het moment
    dat de proefrun verloopt, met twee eigen databaseverbindingen.

    De worker (één transactie) vergrendelt eerst een voorbeeld-aflevering waarvan de lease voorbij is
    (``inbox.release_expired``, SKIP LOCKED) en daarna de verlopen proefrun (``simulate.expire_runs``). Daartussen komt
    de claim: hij ziet de proefrun nog als lopend (zijn ``now`` ligt net vóór ``expires_at``), vergrendelt de open
    aflevering met het laagste volgnummer en wacht dan op de aflevering die de worker al heeft. De worker wil daarna de
    open aflevering van de verlopen run bijwerken die de claim heeft. Vóór KLEIN-47 was dat een deadlock (PostgreSQL
    breekt een van beide af). Nu slaat de worker een run over waarvan een open aflevering door een ander vergrendeld
    is, net als een vergrendelde run (SKIP LOCKED), en sluit hem in de volgende ronde. Uitkomst: geen fout, geen
    deadlock, de claim geeft niets dubbel uit en de run eindigt als ``verlopen``."""
    detail, token = flow
    run = start(
        linked, auth, detail["id"], sample_ids=["energie-meting", "netwerk-nieuw-apparaat", "backup-mislukt"]
    ).json()
    expires = datetime.fromisoformat(run["expires_at"])

    def claim_at(moment: datetime) -> Any:
        monkeypatch.setattr("integrations.domains.automation.flowapi.utcnow", lambda: moment)
        return linked.post(f"{FLOW_API}/deliveries/claim", json={"limit": 5}, headers=idem(b11.bearer(token)))

    # vlak voor het einde van de run: per bron het oudste voorbeeld (energie-meting en backup-mislukt)
    first = claim_at(expires - timedelta(seconds=150)).json()["items"]
    assert [i["event"]["source_app"] for i in first] == ["home-control-hub", "ai-server-manager"], first
    assert b11.ack(linked, token, first[0]["id"]).status_code == 200
    # daarna het volgende voorbeeld van dezelfde bron; backup-mislukt wordt nooit bevestigd (lease tot expires - 30 s)
    second = claim_at(expires - timedelta(seconds=60)).json()["items"]
    assert [i["event"]["source_app"] for i in second] == ["home-control-hub"], second

    worker = Worker(make_settings(), transport=fake_hub.transport)
    before = _deadlocks(linked, worker)
    monkeypatch.setattr("integrations.worker.utcnow", lambda: expires + timedelta(seconds=1))
    holding, go = threading.Event(), threading.Event()
    expire_runs = simulate.expire_runs

    def hold_then_expire(*args: Any, **kwargs: Any) -> Any:
        # hier heeft de worker de verlopen claim van backup-mislukt al vergrendeld (release_expired, vlak hiervoor)
        holding.set()
        go.wait(30)
        return expire_runs(*args, **kwargs)

    monkeypatch.setattr(simulate, "expire_runs", hold_then_expire)
    out: dict[str, Any] = {}
    working = _in_thread(lambda: worker.automation_step(0.0), out, "worker")
    assert holding.wait(20), "de worker kwam niet bij expire_runs"
    claiming = _in_thread(lambda: claim_at(expires - timedelta(seconds=1)), out, "claim")
    deadline = time.monotonic() + 15
    while _lock_waits(linked) < 1 and time.monotonic() < deadline:
        time.sleep(0.05)
    claim_waited = _lock_waits(linked) >= 1
    go.set()
    for thread in (working, claiming):
        thread.join(40)
    monkeypatch.setattr(simulate, "expire_runs", expire_runs)

    assert claim_waited, "de claim wachtte niet op de aflevering die de worker vasthield"
    assert not working.is_alive() and not claiming.is_alive()
    assert out["worker"] is None, out["worker"]
    assert not isinstance(out["claim"], Exception), out["claim"]
    assert out["claim"].status_code == 200, out["claim"].text
    assert out["claim"].json()["items"] == [], "niets dubbel uitgegeven"
    worker.automation_step(0.0)  # de volgende ronde sluit de verlopen run (als hij nog liep)
    done = run_of(linked, auth, run["id"])
    assert (done["status"], done["error_code"]) == ("mislukt", "verlopen"), done
    assert done["result"]["afleveringen"] == {"verwerkt": 1, "mislukt": 2}, done["result"]
    assert _deadlocks(linked, worker) == before
