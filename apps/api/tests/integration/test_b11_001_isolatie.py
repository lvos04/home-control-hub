"""B11-001 — flow-netwerkisolatie: de editor is alleen voor de beheerder en een exec-node wordt geblokkeerd.

Acceptatie: "Viewer kan editor niet bereiken en custom exec-node is geblokkeerd." Sim-getest met de nep-Node-RED
(het gedrag van de nep is gemeten tegen de vastgezette image, zie docs/b11/node-red-verificatie.json).
Echte Node-RED op de NAS: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from integrations.worker import Worker
from tests import b11
from tests.b11 import A
from tests.conftest import NODE_RED_URL, idem, setup_node_red
from tests.fakes.node_red_fake import bypass_scenarios, clean_tab_id, exec_flow, node, simple_flow, tab


# ------------------------------------------------------------------------------------------------ toegang tot de editor
@pytest.mark.parametrize("role", ["viewer", "operator", "child", "family"])
def test_only_an_admin_gets_the_editor_address(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, role: str
) -> None:
    setup_node_red(linked, fake_hub, auth)
    r = linked.get(f"{A}/editor", headers=auth(role))
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "forbidden"
    assert NODE_RED_URL not in r.text


def test_admin_gets_the_editor_address(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    setup_node_red(linked, fake_hub, auth)
    r = linked.get(f"{A}/editor", headers=auth("admin"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["url"] == NODE_RED_URL
    assert body["aanmelden_als"] == "beheerder"


def test_editor_needs_a_login(linked: Any) -> None:
    assert linked.get(f"{A}/editor").status_code == 401


def test_editor_address_unknown_until_the_source_is_configured(linked: Any, auth: Any) -> None:
    r = linked.get(f"{A}/editor", headers=auth("admin"))
    assert r.status_code == 409
    assert r.json()["code"] == "node_red_niet_ingesteld"


def test_node_red_itself_refuses_anonymous_and_read_only_writes(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """De tweede laag: wie het adres tóch kent, komt zonder aanmelding nergens (Node-RED zelf, adminAuth)."""
    import httpx

    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    with httpx.Client(transport=fake_hub.transport, base_url=NODE_RED_URL) as nr:
        for path in ("/flows", "/nodes", "/settings"):
            assert nr.get(path).status_code == 401, path
        assert nr.post("/flows", json={"flows": []}).status_code == 401
    assert node_red_fake.writes == []


# ------------------------------------------------------------------------------------------------------------ isolatie
def test_isolation_is_measured_in_order_with_the_profile(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    r = linked.post(f"{A}/isolation/check", headers=idem(auth("operator")))
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["status"] == "gemeten_in_orde", report
    assert report["afwijkingen"] == []
    assert report["niet_meetbaar"], "wat niet via de API te meten is, staat er eerlijk bij"
    assert "NIET GEVALIDEERD" in report["validatie"]
    got = linked.get(f"{A}/isolation", headers=auth("viewer")).json()
    assert got["isolatie"]["status"] == "gemeten_in_orde"
    assert got["ingesteld"] is True


def test_unhardened_node_red_is_a_deviation_and_raises_an_event(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    setup_node_red(linked, fake_hub, auth, harden=False, flows=simple_flow())
    r = linked.post(f"{A}/isolation/check", headers=idem(auth("admin")))
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["status"] == "afwijking"
    assert report["afwijkingen"], report
    assert [e["payload"]["ernst"] for e in b11.outbox(linked, "automation.isolation.degraded")] == ["hoog"]
    # een tweede meting met dezelfde uitkomst meldt het niet opnieuw
    linked.post(f"{A}/isolation/check", headers=idem(auth("admin")))
    assert len(b11.outbox(linked, "automation.isolation.degraded")) == 1
    # na het toepassen van het profiel: herstel wordt gemeld
    profile = linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("admin"))).json()
    node_red_fake.apply_arguments(profile["arguments"])
    report = linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()
    assert report["status"] == "gemeten_in_orde", report
    assert len(b11.outbox(linked, "automation.isolation.recovered")) == 1


def test_isolation_is_unknown_when_not_measured_or_unreachable(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    assert linked.get(f"{A}/isolation", headers=auth("viewer")).json()["isolatie"]["status"] == "onbekend"
    setup_node_red(linked, fake_hub, auth)
    node_red_fake.up = False
    report = linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()
    assert report["status"] == "onbekend"
    assert report["status"] != "gemeten_in_orde"


def test_isolation_without_a_service_account_is_unknown_not_measured(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """Zo staat het bij een Node-RED volgens het manifest van jelly-leon-platform tot de voorziening van besluit C-12
    er is: alleen het adres, geen dienstaccount (deploy/truenas/NODE_RED_CUSTOM_APP.md, kop "Wat je in Home Control
    Hub instelt"). Dan wordt er niets gemeten, ook `anoniem_geweigerd` niet: de stand is `onbekend` met de fout
    `geen_aanmelding`, en andere routes geven `409 node_red_niet_ingesteld`."""
    r = linked.put(
        "/integrations/v1/sources/node_red",
        json={"base_url": NODE_RED_URL, "enabled": True},
        headers=idem(auth("admin"), **{"If-Match": "*"}),
    )
    assert r.status_code == 201, r.text  # nieuwe bron, zonder profiel en zonder credential
    assert r.json()["runtime"]["credential_present"] is False
    r = linked.post(f"{A}/isolation/check", headers=idem(auth("admin")))
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["status"] == "onbekend", report
    assert report["fout"]["reason"] == "geen_aanmelding", report
    assert report["checks"] == [] and report["afwijkingen"] == []
    assert not any(c.get("id") == "anoniem_geweigerd" for c in report["checks"])
    r = linked.post(f"{A}/snapshots", headers=idem(auth("admin")))
    assert r.status_code == 409, r.text
    assert r.json()["code"] == "node_red_niet_ingesteld"
    assert r.json()["details"]["reason"] == "geen_aanmelding"
    assert node_red_fake.writes == []


def test_viewer_cannot_measure_isolation_or_get_a_profile(linked: Any, auth: Any) -> None:
    assert linked.post(f"{A}/isolation/check", headers=idem(auth("viewer"))).status_code == 403
    assert linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("operator"))).status_code == 403


# ----------------------------------------------------------------------------------------------------------- exec-node
def test_exec_node_is_blocked_and_the_flow_can_do_nothing(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    flow, token = b11.ready_flow(linked, auth, "tab0000000000001", "notification.send")
    assert flow["status"] == "actief"
    assert linked.get(f"{b11.FLOW_API}/me", headers=b11.bearer(token)).status_code == 200

    # iemand zet (buiten het palet om) een exec-node in dezelfde flow; Node-RED accepteert dat zelf (gemeten)
    node_red_fake.deploy(exec_flow(tab_id="tab0000000000001", label="Melding bij storing"))
    result = b11.snapshot(linked, auth)
    assert result["geblokkeerd"] == ["tab0000000000001"]

    flow = b11.flow_detail(linked, auth, flow["id"])
    assert flow["status"] == "geblokkeerd"
    assert flow["blocked_reason"] == "verboden_node"
    assert flow["current_version"]["policy_status"] == "geblokkeerd"
    assert any(
        f.get("node_type") == "exec" and f.get("code") == "verboden_node" for f in flow["current_version"]["findings"]
    ), flow["current_version"]

    blocked = b11.outbox(linked, "flow.policy.blocked")
    assert len(blocked) == 1 and blocked[0]["payload"]["ernst"] == "hoog"

    # een geblokkeerde flow mag niets aanvragen en krijgt geen events
    r = b11.request_action(linked, token, "notification.send", target={"type": "user", "id": "user-1"})
    assert r.status_code == 403, r.text
    assert r.json()["details"]["reason"] == "flow_geblokkeerd"
    # en kan niet hervat worden zolang de node erin zit
    r = b11.put_flow(linked, auth, flow["id"], "state", {"status": "actief", "reden": "toch"}, role="admin")
    assert r.status_code == 409
    assert r.json()["code"] == "flow_status_conflict"


def test_clean_tab_linked_to_an_exec_tab_is_blocked_too(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """R-VEILIG-3: een tabblad zonder verboden node dat via een link-node berichten naar een tabblad met een
    exec-node stuurt, krijgt de bevinding ook: anders zou het token van het schone tabblad de exec-node bereiken."""
    clean = "tabschoon0000001"
    setup_node_red(linked, fake_hub, auth, flows=simple_flow(tab_id=clean, label="Schoon"))
    b11.snapshot(linked, auth)
    flow, token = b11.ready_flow(linked, auth, clean, "notification.send")
    assert flow["status"] == "actief"

    link_out = node("tabschoolink0001", "link out", clean, links=["tabexec0linkin01"])
    link_in = node("tabexec0linkin01", "link in", "tabexec000000001", [["tabexec0exec0001"]], links=[link_out["id"]])
    node_red_fake.deploy([*simple_flow(tab_id=clean, label="Schoon"), link_out, *exec_flow(), link_in])
    result = b11.snapshot(linked, auth)
    assert sorted(result["geblokkeerd"]) == ["tabexec000000001", clean]

    flow = b11.flow_detail(linked, auth, flow["id"])
    assert flow["status"] == "geblokkeerd" and flow["blocked_reason"] == "verboden_node"
    assert flow["current_version"]["policy_status"] == "geblokkeerd"
    assert any(f.get("via_link") == "tabexec000000001" for f in flow["current_version"]["findings"]), flow
    r = b11.request_action(linked, token, "notification.send", target={"type": "user", "id": "user-1"})
    assert r.status_code == 403 and r.json()["details"]["reason"] == "flow_geblokkeerd"
    r = linked.post(
        f"{A}/flows/{flow['id']}/tokens",
        json={"label": "nog een", "allowed_actions": ["notification.send"]},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 409 and r.json()["code"] == "flow_status_conflict"


def test_clean_tab_wired_to_an_exec_tab_is_blocked_too(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """R-VEILIG-3 (herreview): ook zonder link-node levert Node-RED af via een gewone draad naar een node in een
    ander tabblad (gemeten op de gepinde image). Het schone tabblad deelt dan de bevinding van het exec-tabblad."""
    clean = "tabschoon0000001"
    setup_node_red(linked, fake_hub, auth, flows=simple_flow(tab_id=clean, label="Schoon"))
    b11.snapshot(linked, auth)
    flow, token = b11.ready_flow(linked, auth, clean, "notification.send")
    assert flow["status"] == "actief"

    wired = [
        *simple_flow(tab_id=clean, label="Schoon"),
        node("tabschooinject02", "inject", clean, [["tabexec0exec0001"]]),  # draad naar de exec-node, ander tabblad
        *exec_flow(),
    ]
    wired[-1]["wires"] = [["tabschoodebug001"], [], []]  # en terug: de uitvoer van exec naar het schone tabblad
    node_red_fake.deploy(wired)
    result = b11.snapshot(linked, auth)
    assert sorted(result["geblokkeerd"]) == ["tabexec000000001", clean]

    flow = b11.flow_detail(linked, auth, flow["id"])
    assert flow["status"] == "geblokkeerd" and flow["blocked_reason"] == "verboden_node"
    assert any(f.get("via_link") == "tabexec000000001" for f in flow["current_version"]["findings"]), flow
    r = b11.request_action(linked, token, "notification.send", target={"type": "user", "id": "user-1"})
    assert r.status_code == 403 and r.json()["details"]["reason"] == "flow_geblokkeerd"
    r = linked.post(
        f"{A}/flows/{flow['id']}/tokens",
        json={"label": "nog een", "allowed_actions": ["notification.send"]},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 409 and r.json()["code"] == "flow_status_conflict"


def test_wire_to_a_node_that_does_not_exist_blocks_until_it_is_gone(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """Fail-closed: een draad naar een id die niet in de configuratie staat (bv. een node in een subflow-instantie,
    die Node-RED pas tijdens het draaien een id geeft) blokkeert; weg draad = gepauzeerd, zoals bij elke bevinding."""
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    flow = b11.flow_by_tab(linked, auth, "tab0000000000001")
    dangling = [*simple_flow(), node("tab00000inject02", "inject", "tab0000000000001", [["bestaatniet00001"]])]
    node_red_fake.deploy(dangling)
    assert b11.snapshot(linked, auth)["geblokkeerd"] == ["tab0000000000001"]
    flow = b11.flow_detail(linked, auth, flow["id"])
    assert flow["status"] == "geblokkeerd" and flow["blocked_reason"] == "verwijzing_onbekend"
    assert flow["current_version"]["findings"][0]["ref"] == "bestaatniet00001"
    node_red_fake.deploy(simple_flow())
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == "gepauzeerd"


def _every_flow_blocked(linked: Any, auth: Any, result: dict[str, Any]) -> None:
    listed = [f for f in b11.flows(linked, auth) if f["status"] != "verwijderd"]
    assert listed and all(f["status"] == "geblokkeerd" for f in listed), listed
    assert sorted(result["geblokkeerd"]) == sorted(f["source_flow_id"] for f in listed)


def _blocked_and_asks_nothing(linked: Any, auth: Any, flow_id: str, token: str, reason: str, cause: str) -> None:
    """Geblokkeerd met deze reden en oorzaak (bij ``bron_geblokkeerd``: de oorzaak elders); geen nieuw token, geen
    actie, niets naar de Hub."""
    flow = b11.flow_detail(linked, auth, flow_id)
    assert flow["status"] == "geblokkeerd" and flow["blocked_reason"] == reason, flow
    assert flow["current_version"]["policy_status"] == "geblokkeerd"
    found = {f.get("oorzaak", f["code"]) for f in flow["current_version"]["findings"]}
    assert cause in found, flow["current_version"]
    r = b11.request_action(
        linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
    )
    assert r.status_code == 403 and r.json()["details"]["reason"] == "flow_geblokkeerd", r.text
    r = linked.post(
        f"{A}/flows/{flow_id}/tokens",
        json={"label": "nog een", "allowed_actions": ["notification.send"]},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 409 and r.json()["code"] == "flow_status_conflict", r.text
    assert b11.outbox(linked, "flow.action.requested") == []


@pytest.mark.parametrize("name", ["sc1", "sc2", "sc3", "sc4", "sc5", "sc6"])
def test_something_wrong_anywhere_blocks_every_flow_of_the_source(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, name: str
) -> None:
    """R-VEILIG-3 (herreview 3), besluit van de gebruiker "grof blokkeren": langs deze zes routes levert de echte
    Node-RED 5.0.9 een bericht uit de bron af in het schone tabblad. Nu is elke flow van de bron geblokkeerd tot het
    weg is; daarna gepauzeerd (een beheerder hervat zelf), zoals bij elke bevinding."""
    clean = clean_tab_id(int(name[2]))
    setup_node_red(linked, fake_hub, auth, flows=simple_flow(tab_id=clean, label="Schoon"))
    b11.snapshot(linked, auth)
    flow, token = b11.ready_flow(linked, auth, clean, "notification.send")
    assert flow["status"] == "actief"

    node_red_fake.deploy(bypass_scenarios("exec")[name])
    _every_flow_blocked(linked, auth, b11.snapshot(linked, auth))
    if name == "sc5":  # de tweede node met dezelfde id staat in het schone tabblad zelf
        _blocked_and_asks_nothing(linked, auth, flow["id"], token, "dubbele_id", "dubbele_id")
    else:
        _blocked_and_asks_nothing(linked, auth, flow["id"], token, "bron_geblokkeerd", "verboden_node")

    node_red_fake.deploy(simple_flow(tab_id=clean, label="Schoon"))
    assert b11.snapshot(linked, auth)["geblokkeerd"] == []
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == "gepauzeerd"


@pytest.mark.parametrize(
    "odd",
    [
        pytest.param({"id": 5, "type": "inject", "z": "tab0000000000001", "wires": []}, id="id als getal"),
        pytest.param({"id": "los00000exec0001", "type": ["exec"], "z": "tab0000000000001"}, id="type als lijst"),
        pytest.param(5, id="geen object"),
    ],
)
def test_a_node_of_the_wrong_shape_blocks_every_flow_instead_of_stopping_the_sync(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, odd: Any
) -> None:
    """Vormfout in id of type, of een element dat geen object is: de dienst leest de configuratie toch en blokkeert
    alles (vóór dit herstel mislukte de synchronisatie en bleven de flows zoals ze waren)."""
    two = [*simple_flow(), *simple_flow(tab_id="tabander00000002", label="Ander")]
    setup_node_red(linked, fake_hub, auth, flows=two)
    b11.snapshot(linked, auth)
    flow, token = b11.ready_flow(linked, auth, "tabander00000002", "notification.send")
    node_red_fake.deploy([*two, odd])
    _every_flow_blocked(linked, auth, b11.snapshot(linked, auth))
    _blocked_and_asks_nothing(linked, auth, flow["id"], token, "bron_geblokkeerd", "vorm_ongeldig")


# --------------------------------------------- R-VEILIG-8 (herreview 4): nooit de oude stand als het uitlezen vastloopt
T = "tab0000000000001"
LONG = "t" * 121  # één teken langer dan automation_flow.source_flow_id (String(120))
#: (vooraf, daarna): vormen die de echte Node-RED 5.0.9 aanneemt, bewaart en op GET /flows teruggeeft (NUL en een losse
#: surrogaat als \u-escape, zoals JSON.stringify); daarna staat er ook een exec-node. Vóór het herstel liep elke
#: synchronisatie vanaf "daarna" vast en bleef T actief, met token, afleveringen en actieverzoeken naar de Hub.
ODD_FORMS: dict[str, tuple[list[Any], list[Any]]] = {
    "lange_tab_id": (
        [*simple_flow(), tab(LONG, "Lang"), node("lang0000inject01", "inject", LONG)],
        [*simple_flow(), tab(LONG, "Lang"), node("lang0000inject01", "inject", LONG), *exec_flow()],
    ),
    "nul_in_id": (
        simple_flow(),
        [*simple_flow(), tab("tabexec000000001", "Shell"), node("exec\x00x", "exec", "tabexec000000001")],
    ),
    "nul_in_label": (simple_flow(), [*simple_flow(), *exec_flow(), tab("tablabel00000001", "a\x00b")]),
    "surrogaat_in_naam": (
        simple_flow(),
        [*simple_flow(), *exec_flow(), node("naam0000inject01", "inject", T, name="\ud800")],
    ),
}


def _owner_and_token(linked: Any, auth: Any, flow_id: str) -> Any:
    b11.set_owner(linked, auth, flow_id)
    return linked.post(
        f"{A}/flows/{flow_id}/tokens",
        json={"label": "test", "allowed_actions": ["notification.send"]},
        headers=idem(auth("admin")),
    )


def _nothing_gets_through(linked: Any, auth: Any, flow_id: str, token: str | None, reason: str) -> None:
    """Elke flow die nog bestaat is geblokkeerd; deze flow vraagt niets aan, krijgt geen nieuw token en er gaat geen
    actieverzoek naar de Hub."""
    listed = [f for f in b11.flows(linked, auth) if f["status"] != "verwijderd"]
    assert listed and all(f["status"] == "geblokkeerd" for f in listed), listed
    flow = b11.flow_detail(linked, auth, flow_id)
    assert flow["status"] == "geblokkeerd" and flow["blocked_reason"] == reason, flow
    if token is not None:
        r = b11.request_action(
            linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
        )
        assert r.status_code == 403 and r.json()["details"]["reason"] == "flow_geblokkeerd", r.text
    r = _owner_and_token(linked, auth, flow_id)
    assert r.status_code == 409 and r.json()["code"] == "flow_status_conflict", r.text
    assert b11.outbox(linked, "flow.action.requested") == []


@pytest.mark.parametrize("case", list(ODD_FORMS))
def test_a_form_that_stopped_the_sync_is_a_finding_that_blocks_every_flow(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, make_settings: Any, case: str
) -> None:
    """R-VEILIG-8 (herreview 4, besluit van de gebruiker: vorm A): een id of z langer dan 120 tekens, een NUL of een
    losse surrogaat in een tekst is een gewone bevinding ``vorm_ongeldig``: de synchronisatie slaagt en blokkeert
    (grof) alle flows. Staat de vorm er al vóór het token (lange_tab_id), dan krijgt T geen token."""
    before, after = ODD_FORMS[case]
    setup_node_red(linked, fake_hub, auth, flows=before)
    worker = Worker(make_settings(node_red_sync_interval_s=60), transport=fake_hub.transport)
    worker.automation_step(100.0)
    flow = b11.flow_by_tab(linked, auth, T)
    issued = _owner_and_token(linked, auth, flow["id"])
    assert issued.status_code == (409 if case == "lange_tab_id" else 201), issued.text
    token = issued.json()["flow_token"] if issued.status_code == 201 else None

    node_red_fake.deploy(after)
    worker.automation_step(200.0)
    worker.automation_step(300.0)
    assert worker.state.stats["node_red_sync_failed"] == 0, "een gewone bevinding, geen mislukte synchronisatie"
    # de node met de losse surrogaat staat in T zelf: T heeft dan de bevinding zelf, de andere vormen staan elders
    own = case == "surrogaat_in_naam"
    _nothing_gets_through(linked, auth, flow["id"], token, "vorm_ongeldig" if own else "bron_geblokkeerd")
    found = b11.flow_detail(linked, auth, flow["id"])["current_version"]["findings"]
    assert "vorm_ongeldig" in {f.get("oorzaak", f["code"]) for f in found}, found
    sync = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    assert sync["ok"] is True and sync["fout"] is None, sync


def _deep_flows_body() -> bytes:
    """GET /flows met een eigenschap die 100000 keer genest is: ``json.loads`` geeft dan RecursionError (geen
    ValueError, dus geen ``antwoord_ongeldig``). Zo'n antwoord kan json.dumps zelf niet maken: ruwe bytes."""
    deep = b'{"id":"diep0000comment1","type":"comment","z":"' + T.encode() + b'","info":'
    deep += b"[" * 100_000 + b"]" * 100_000 + b"}"
    flows = json.dumps([*simple_flow(), *simple_flow(tab_id="tabander00000002", label="Ander")]).encode()
    return b'{"flows":' + flows[:-1] + b"," + deep + b'],"rev":"' + b"0" * 64 + b'"}'


def _fail_in(where: str, monkeypatch: pytest.MonkeyPatch, node_red_fake: Any) -> None:
    """Laat de synchronisatie om een andere reden vastlopen: in de opslag (een echte databasefout), het flowregister,
    de scan, of bij het lezen (RecursionError uit ``NodeRedClient._json``)."""
    from sqlalchemy import text

    from integrations.domains.automation import policy, snapshots

    def storage_fails(session: Any, *_args: Any, **_kwargs: Any) -> Any:
        session.execute(text("SELECT 1/0"))  # de transactie is daarna afgebroken: alleen een rollback helpt

    def fails(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("ingespoten fout")

    if where == "opslag":
        monkeypatch.setattr(snapshots, "create_snapshot", storage_fails)
    elif where == "register":
        monkeypatch.setattr(snapshots, "apply_scan", fails)
    elif where == "scan":
        monkeypatch.setattr(policy, "scan", fails)
    else:
        node_red_fake.flows_body = _deep_flows_body()


@pytest.mark.parametrize("where", ["opslag", "register", "scan", "lezen"])
def test_a_sync_that_fails_blocks_every_flow_until_an_admin_resumes(
    linked: Any,
    fake_hub: Any,
    auth: Any,
    node_red_fake: Any,
    make_settings: Any,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
) -> None:
    """R-VEILIG-8, vorm A ("blokkeren bij mislukken"): loopt de synchronisatie vast, dan zet een aparte transactie
    elke flow van de bron die nog bestaat op geblokkeerd met reden ``synchronisatie_mislukt`` en de stand op
    ``ok: false``; de check ``automatisering`` is dan degraded. Een verwijderde flow blijft verwijderd. Slaagt een
    synchronisatie daarna weer, dan blijven de flows gepauzeerd tot een beheerder ze hervat (geen automatisch
    heropenen)."""
    three = [
        *simple_flow(),
        *simple_flow(tab_id="tabander00000002", label="Ander"),
        *simple_flow(tab_id="tabweg0000000003", label="Weg"),
    ]
    setup_node_red(linked, fake_hub, auth, flows=three)
    worker = Worker(make_settings(node_red_sync_interval_s=60), transport=fake_hub.transport)
    worker.automation_step(100.0)
    node_red_fake.deploy(three[:-4])
    worker.automation_step(160.0)
    assert b11.flow_by_tab(linked, auth, "tabweg0000000003")["status"] == "verwijderd"
    flow, token = b11.ready_flow(linked, auth, T, "notification.send")
    assert flow["status"] == "actief"
    before = len(b11.outbox(linked, "flow.policy.blocked"))

    _fail_in(where, monkeypatch, node_red_fake)
    node_red_fake.deploy([*three[:-4], node("tab00000inject02", "inject", T)])  # een wijziging: alles wordt gelezen
    worker.automation_step(220.0)  # mag zelf niet mislukken: de fout is vastgelegd en dichtgezet
    assert worker.state.stats["node_red_sync_failed"] == 1
    _nothing_gets_through(linked, auth, flow["id"], token, "synchronisatie_mislukt")
    assert b11.flow_by_tab(linked, auth, "tabweg0000000003")["status"] == "verwijderd"
    blocked = b11.outbox(linked, "flow.policy.blocked")[before:]
    assert sorted(e["payload"]["reden"] for e in blocked) == ["synchronisatie_mislukt"] * 2, blocked
    state = linked.get(f"{A}/isolation", headers=auth("viewer")).json()
    assert state["synchronisatie"]["ok"] is False, state
    assert state["synchronisatie"]["fout"]["reason"] == "synchronisatie_mislukt", state
    check = {c["name"]: c for c in linked.get("/connector/v1/health", headers=fake_hub.service_auth()).json()["checks"]}
    assert check["automatisering"]["status"] == "degraded", check["automatisering"]
    assert check["automatisering"]["reason_code"] == "synchronisatie_mislukt", check["automatisering"]
    worker.automation_step(280.0)  # blijft het vastlopen: blijft dicht, zonder nieuwe events
    assert len(b11.outbox(linked, "flow.policy.blocked")) == before + 2
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == "geblokkeerd"

    monkeypatch.undo()
    node_red_fake.flows_body = None
    worker.automation_step(340.0)
    assert worker.state.stats["node_red_syncs"] == 3
    for tab_id in (T, "tabander00000002"):
        assert b11.flow_by_tab(linked, auth, tab_id)["status"] == "gepauzeerd", "nooit vanzelf weer actief"
    r = b11.put_flow(linked, auth, flow["id"], "state", {"status": "actief", "reden": "nagekeken"})
    assert r.status_code == 200 and r.json()["status"] == "actief", r.text


@pytest.mark.parametrize("where", ["register", "lezen"])
def test_a_sync_that_fails_also_blocks_paused_and_disabled_flows(
    linked: Any,
    fake_hub: Any,
    auth: Any,
    node_red_fake: Any,
    make_settings: Any,
    monkeypatch: pytest.MonkeyPatch,
    where: str,
) -> None:
    """R-VEILIG-10 (herreview 5 van S-P2-295): "elke flow van de bron die nog bestaat" (ADR-0016 kop 2) geldt ook voor
    een flow die vóór het vastlopen gepauzeerd was en voor een flow die in Node-RED uit staat (uitgeschakeld). Beide
    staan daarna op geblokkeerd met ``synchronisatie_mislukt``: hervatten geeft 409, hun token 403 en er gaat geen
    actieverzoek naar de Hub. Zou alleen een actieve flow geblokkeerd worden, dan kon een beheerder de gepauzeerde
    flow hervatten terwijl de synchronisatie blijft vastlopen."""
    paused, disabled = "tabpauze00000003", "tabuit0000000004"
    flows = [
        *simple_flow(),
        *simple_flow(tab_id=paused, label="Pauze"),
        tab(disabled, "Uit", disabled=True),
        node("tabuit00inject01", "inject", disabled),
    ]
    setup_node_red(linked, fake_hub, auth, flows=flows)
    worker = Worker(make_settings(node_red_sync_interval_s=60), transport=fake_hub.transport)
    worker.automation_step(100.0)
    p_flow, p_token = b11.ready_flow(linked, auth, paused, "notification.send")
    d_flow, d_token = b11.ready_flow(linked, auth, disabled, "notification.send")
    r = b11.put_flow(linked, auth, p_flow["id"], "state", {"status": "gepauzeerd", "reden": "onderhoud"})
    assert r.status_code == 200 and r.json()["status"] == "gepauzeerd", r.text
    assert b11.flow_detail(linked, auth, d_flow["id"])["status"] == "uitgeschakeld"
    before = len(b11.outbox(linked, "flow.policy.blocked"))

    _fail_in(where, monkeypatch, node_red_fake)
    node_red_fake.deploy([*flows, node("tab00000inject02", "inject", T)])  # een wijziging: alles wordt gelezen
    worker.automation_step(200.0)
    assert worker.state.stats["node_red_sync_failed"] == 1
    for flow_id, token in ((p_flow["id"], p_token), (d_flow["id"], d_token)):
        detail = b11.flow_detail(linked, auth, flow_id)
        assert detail["status"] == "geblokkeerd" and detail["blocked_reason"] == "synchronisatie_mislukt", detail
        r = b11.put_flow(linked, auth, flow_id, "state", {"status": "actief", "reden": "toch hervatten"})
        assert r.status_code == 409 and r.json()["code"] == "flow_status_conflict", r.text
        r = b11.request_action(
            linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
        )
        assert r.status_code == 403 and r.json()["details"]["reason"] == "flow_geblokkeerd", r.text
    blocked = b11.outbox(linked, "flow.policy.blocked")[before:]
    assert {e["entity"]["id"] for e in blocked} >= {p_flow["id"], d_flow["id"]}, blocked
    assert b11.outbox(linked, "flow.action.requested") == []


def test_a_manual_snapshot_that_fails_blocks_every_flow_too(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dezelfde synchronisatie via ``POST …/snapshots``: 502 met reden ``synchronisatie_mislukt``, geen momentopname,
    en de blokkade blijft staan (aparte transactie), ook al wordt de rest van het verzoek teruggedraaid."""
    setup_node_red(linked, fake_hub, auth, flows=[*simple_flow(), *simple_flow(tab_id="tabander00000002")])
    first = b11.snapshot(linked, auth)
    flow, token = b11.ready_flow(linked, auth, T, "notification.send")
    _fail_in("opslag", monkeypatch, node_red_fake)
    r = linked.post(f"{A}/snapshots", headers=idem(auth("admin")))
    assert r.status_code == 502 and r.json()["code"] == "node_red_fout", r.text
    assert r.json()["details"]["reason"] == "synchronisatie_mislukt", r.text
    _nothing_gets_through(linked, auth, flow["id"], token, "synchronisatie_mislukt")
    listed = linked.get(f"{A}/snapshots", headers=auth("viewer")).json()["items"]
    assert [s["id"] for s in listed] == [first["snapshot_id"]], listed


def test_a_clean_configuration_with_long_ids_and_any_text_stays_active(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, make_settings: Any
) -> None:
    """Geen vals blokkeren (R-VEILIG-8): een tabblad-id van precies 120 tekens en tekst met accenten, een emoji en
    andere schriften worden opgeslagen; de flow is actief en mag aanvragen."""
    long_tab = "w" * 120
    clean = [
        tab(long_tab, "Wóónkamer ☕ 😀 中文"),
        node("w" * 112 + "inject01", "inject", long_tab, [["w" * 112 + "debug001"]], name="ïnject"),
        node("w" * 112 + "debug001", "debug", long_tab, info="é\tß\n\U0001f600"),
    ]
    setup_node_red(linked, fake_hub, auth, flows=clean)
    worker = Worker(make_settings(node_red_sync_interval_s=60), transport=fake_hub.transport)
    worker.automation_step(100.0)
    assert worker.state.stats["node_red_syncs"] == 1
    flow, token = b11.ready_flow(linked, auth, long_tab, "notification.send")
    assert flow["status"] == "actief" and flow["label"] == "Wóónkamer ☕ 😀 中文", flow
    r = b11.request_action(
        linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
    )
    assert r.status_code == 202, r.text
    assert len(b11.outbox(linked, "flow.action.requested")) == 1


def test_blocked_flow_stays_paused_after_the_node_is_removed(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    setup_node_red(linked, fake_hub, auth, flows=exec_flow())
    b11.snapshot(linked, auth)
    flow = b11.flow_by_tab(linked, auth, "tabexec000000001")
    assert flow["status"] == "geblokkeerd"
    node_red_fake.deploy(simple_flow(tab_id="tabexec000000001", label="Zonder shell"))
    b11.snapshot(linked, auth)
    flow = b11.flow_detail(linked, auth, flow["id"])
    assert flow["status"] == "gepauzeerd", "niet vanzelf weer actief: een beheerder hervat bewust"
    assert len(b11.outbox(linked, "flow.policy.resolved")) == 1
    r = b11.put_flow(linked, auth, flow["id"], "state", {"status": "actief", "reden": "nagekeken"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "actief"


def test_policy_lists_the_forbidden_nodes(linked: Any, auth: Any) -> None:
    body = linked.get(f"{A}/policy", headers=auth("viewer")).json()
    assert "exec" in body["forbidden_node_types"]
    assert body["node_red_image"]["digest"].startswith("sha256:")
    assert ":latest" not in str(body["node_red_image"])
    # R-TECH-8: de teksten volgen de strenge lezing van ADR-0016 kop 4 (nooit via een flow, ook niet met goedkeuring)
    from integrations.domains.automation.catalog import SOURCES

    texts = [*body["never_nl"], *(t for src in SOURCES for t in src.forbidden_nl)]
    assert any("kan nooit via een flow, ook niet met goedkeuring" in t for t in body["never_nl"])
    assert not any("zonder admin-goedkeuring" in t for t in texts), texts


# ------------------------------------------------------------------------------------------------- geheimen blijven weg
def test_profile_secrets_are_shown_once_and_stored_nowhere(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    herhaalsleutel = "7d0c7f0e-4b1f-4a55-9d53-0c7d5c0f6a01"  # vaste Idempotency-Key van deze test (geen geheim)
    r = linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("admin"), key=herhaalsleutel))
    assert r.status_code == 201, r.text
    profile = r.json()
    password = profile["beheerwachtwoord"]
    assert password and len(password) >= 20
    secrets = [password, *[a for a in profile["arguments"] if "credentialSecret" in a or "$2" in a]]
    assert len(secrets) >= 3, "wachtwoord, credentialSecret en minstens één wachtwoordhash"

    # dezelfde Idempotency-Key: het bewaarde antwoord bevat het wachtwoord en de argumenten niet meer
    again = linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("admin"), key=herhaalsleutel))
    assert again.status_code == 201
    assert again.json()["beheerwachtwoord"] is None
    assert again.json()["arguments"] is None
    assert "herhaling_nl" in again.json()

    # een nieuw verzoek toont de argumenten opnieuw (nodig voor het formulier) maar het wachtwoord nooit meer
    second = linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("admin")))
    assert second.status_code == 200
    assert second.json()["beheerwachtwoord"] is None
    assert second.json()["arguments"] == profile["arguments"]

    stored = b11.everything_stored(linked)
    for secret in secrets:
        assert secret not in stored
        assert secret not in caplog.text
    for value in profile["arguments"]:
        tail = value.split("=", 1)[-1]
        if len(tail) >= 24:
            assert tail not in stored


def test_new_admin_password_replaces_the_old_one(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    first = setup_node_red(linked, fake_hub, auth)
    r = linked.post(f"{A}/hardening-profile", json={"nieuw_beheerwachtwoord": True}, headers=idem(auth("admin")))
    assert r.status_code == 200, r.text
    second = r.json()
    assert second["beheerwachtwoord_vervangen"] is True
    assert second["beheerwachtwoord"] and second["beheerwachtwoord"] != first["beheerwachtwoord"]
    assert second["arguments"] != first["arguments"]
