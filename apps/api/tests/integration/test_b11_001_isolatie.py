"""B11-001 — flow-netwerkisolatie: de editor is alleen voor de beheerder en een exec-node wordt geblokkeerd.

Acceptatie: "Viewer kan editor niet bereiken en custom exec-node is geblokkeerd." Sim-getest met de nep-Node-RED
(het gedrag van de nep is gemeten tegen de vastgezette image, zie docs/b11/node-red-verificatie.json).
Echte Node-RED op de NAS: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import pytest

from integrations.domains.automation import policy
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
    # C-12: de beheerder kiest zijn naam zelf in Node-RED; deze dienst noemt geen accountnaam meer
    assert "aanmelden_als" not in body


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
def test_isolation_is_measured_in_order_when_node_red_is_hardened(
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
    profile = setup_node_red(linked, fake_hub, auth, harden=False, flows=simple_flow())
    r = linked.post(f"{A}/isolation/check", headers=idem(auth("admin")))
    assert r.status_code == 200, r.text
    report = r.json()
    assert report["status"] == "afwijking"
    assert report["afwijkingen"], report
    assert [e["payload"]["ernst"] for e in b11.outbox(linked, "automation.isolation.degraded")] == ["hoog"]
    # een tweede meting met dezelfde uitkomst meldt het niet opnieuw
    linked.post(f"{A}/isolation/check", headers=idem(auth("admin")))
    assert len(b11.outbox(linked, "automation.isolation.degraded")) == 1
    # nadat de beheerder Node-RED zelf beveiligd heeft: herstel wordt gemeld
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
    `geen_aanmelding`. Wat Node-RED moet uitlezen (een momentopname maken) geeft `409 node_red_niet_ingesteld`;
    de routes die alleen de eigen stand tonen (`GET /editor`, `/flows`, `/isolation`) geven 200 (A-12 van KLEIN-48)."""
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
    for path in ("/editor", "/flows", "/isolation"):
        r = linked.get(f"{A}{path}", headers=auth("admin"))
        assert r.status_code == 200, (path, r.text)
    isolation = linked.get(f"{A}/isolation", headers=auth("admin")).json()["isolatie"]
    assert isolation["status"] == "onbekend", isolation
    assert node_red_fake.writes == []


def test_viewer_cannot_measure_isolation(linked: Any, auth: Any) -> None:
    assert linked.post(f"{A}/isolation/check", headers=idem(auth("viewer"))).status_code == 403


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


#: de statussen waarmee ``GET /flows`` antwoordt bij een geweigerde aanmelding, ontbrekende rechten, een onbekend pad
#: en een doorverwijzing (R-VEILIG-1 van S-P2-320)
REFUSED_ANSWERS = {"aanmelding_geweigerd": 401, "geen_rechten": 403, "niet_gevonden": 404, "redirect": 302}
#: een exec-node in de flow met het token (iemand zet hem erin terwijl Node-RED zonder aanmelding draait)
EXEC_IN_T = node("tab00000exec0001", "exec", T, [[], [], []], command="id")


def _flows_answer(node_red_fake: Any, monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    """``GET /flows`` antwoordt zoals in ``case``: onbruikbaar of niet te lezen (Node-RED antwoordde wel) of helemaal
    niet. Bij ``niet_beveiligd`` draait Node-RED opnieuw zonder aanmelding (``adminAuth`` weg, C-11 geschonden) en zet
    iemand een exec-node in de flow met het token; zonder aanmelding leest de dienst niets, dus scant hij die ook niet."""
    import httpx

    original = node_red_fake.handle

    def answer(status: int, body: bytes, headers: dict[str, str] | None = None) -> Any:
        def handle(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/flows":
                return httpx.Response(
                    status, content=body, headers={"content-type": "application/json", **(headers or {})}
                )
            return original(request)

        return handle

    def times_out(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/flows":
            raise httpx.ReadTimeout("nep-time-out", request=request)
        return original(request)

    if case == "antwoord_ongeldig":
        monkeypatch.setattr(node_red_fake, "handle", answer(200, b"geen json"))
    elif case == "antwoord_te_groot":
        # meer dan 16 MiB aangekondigd: de client leest het antwoord dan niet eens
        monkeypatch.setattr(node_red_fake, "handle", answer(200, b"{}", {"content-length": str(17 * 1024 * 1024)}))
    elif case == "onverwacht_antwoord":
        monkeypatch.setattr(node_red_fake, "handle", answer(418, b'{"fout": "theepot"}'))
    elif case in REFUSED_ANSWERS:
        location = {"location": "/elders"} if case == "redirect" else {}
        monkeypatch.setattr(node_red_fake, "handle", answer(REFUSED_ANSWERS[case], b"{}", location))
    elif case == "niet_beveiligd":
        monkeypatch.setattr(node_red_fake, "admin_auth", None)
        node_red_fake.deploy([*simple_flow(), *simple_flow(tab_id="tabander00000002", label="Ander"), EXEC_IN_T])
    elif case == "http_5xx":
        monkeypatch.setattr(node_red_fake, "handle", answer(500, b'{"fout": "intern"}'))
    elif case == "timeout":
        monkeypatch.setattr(node_red_fake, "handle", times_out)
    else:
        node_red_fake.up = False


UNUSABLE_ANSWERS = ["antwoord_ongeldig", "antwoord_te_groot", "onverwacht_antwoord", "niet_beveiligd", *REFUSED_ANSWERS]


@pytest.mark.parametrize("case", [*UNUSABLE_ANSWERS, "onbereikbaar", "timeout", "http_5xx"])
def test_an_unusable_answer_from_node_red_blocks_every_flow_but_no_answer_does_not(
    linked: Any,
    fake_hub: Any,
    auth: Any,
    node_red_fake: Any,
    make_settings: Any,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """S-P2-320, keuze B1 (b) (uitwerking van het besluit van de gebruiker "blokkeren bij mislukken", ADR-0016 kop 2),
    aangescherpt door de regisseur (R-VEILIG-1 = (b), uit "grof blokkeren" en C-11): antwoordde Node-RED wel, maar kan
    de dienst het antwoord niet gebruiken (``antwoord_ongeldig``, ``antwoord_te_groot``, ``onverwacht_antwoord``, een
    Node-RED zonder aanmelding ``niet_beveiligd``, ``aanmelding_geweigerd`` (401), ``geen_rechten`` (403),
    ``niet_gevonden`` (404) of ``redirect`` (3xx)), dan blokkeert de synchronisatie elke flow met
    ``synchronisatie_mislukt``; de meting van de bron noemt de oorzaak. Bij ``niet_beveiligd`` staat er ook een
    exec-node in de flow met het token: die flow is dicht, zijn token geeft 403 en er gaat geen actieverzoek naar de
    Hub (vóór S-P2-320 bleef hij actief: 202). Antwoordde Node-RED niet (``onbereikbaar``, ``timeout``) of met een
    serverfout (``http_5xx``), dan blijft de stand van de flows staan en zegt alleen de synchronisatie eerlijk
    ``ok: false``."""
    flows = [*simple_flow(), *simple_flow(tab_id="tabander00000002", label="Ander")]
    setup_node_red(linked, fake_hub, auth, flows=flows)
    worker = Worker(make_settings(node_red_sync_interval_s=60, http_max_attempts=1), transport=fake_hub.transport)
    worker.automation_step(100.0)
    flow, token = b11.ready_flow(linked, auth, T, "notification.send")
    assert flow["status"] == "actief"
    before = len(b11.outbox(linked, "flow.policy.blocked"))

    _flows_answer(node_red_fake, monkeypatch, case)
    worker.state.next_node_red_sync = 0
    worker.automation_step(200.0)
    assert worker.state.stats["node_red_sync_failed"] == 1
    state = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["synchronisatie"]
    health = linked.get("/integrations/v1/sources/node_red", headers=auth("viewer")).json()["runtime"]["health"]
    assert state["ok"] is False and health["reason_code"] == case, (state, health)
    if case in UNUSABLE_ANSWERS:
        _nothing_gets_through(linked, auth, flow["id"], token, "synchronisatie_mislukt")
        blocked = b11.outbox(linked, "flow.policy.blocked")[before:]
        assert sorted(e["payload"]["reden"] for e in blocked) == ["synchronisatie_mislukt"] * 2, blocked
        assert state["fout"]["reason"] == "synchronisatie_mislukt" and state["fout"]["oorzaak"] == case, state
        assert health["status"] == "degraded", health
    else:
        assert b11.flow_detail(linked, auth, flow["id"])["status"] == "actief"
        assert b11.outbox(linked, "flow.policy.blocked")[before:] == []
        assert state["fout"]["reason"] == case, state
        assert health["status"] == "down", health
        r = b11.request_action(
            linked, token, "notification.send", target={"type": "user", "id": "user-1"}, parameters={"tekst": "x"}
        )
        assert r.status_code == 202, r.text

    monkeypatch.undo()
    node_red_fake.up = True
    if case == "niet_beveiligd":
        node_red_fake.deploy(flows)  # Node-RED weer met aanmelding; de beheerder haalt de exec-node weg
    worker.state.next_node_red_sync = 0
    worker.automation_step(300.0)
    assert worker.state.stats["node_red_syncs"] == 2
    expected = "gepauzeerd" if case in UNUSABLE_ANSWERS else "actief"
    assert b11.flow_detail(linked, auth, flow["id"])["status"] == expected, "nooit vanzelf weer actief"


def test_a_manual_snapshot_with_an_unusable_answer_blocks_every_flow_too(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dezelfde keuze B1 (b) via ``POST …/snapshots``: ``502 node_red_fout`` met reden ``synchronisatie_mislukt`` en
    de oorzaak in de meting van de bron; geen momentopname; de blokkade blijft staan (aparte transactie)."""
    setup_node_red(linked, fake_hub, auth, flows=[*simple_flow(), *simple_flow(tab_id="tabander00000002")])
    first = b11.snapshot(linked, auth)
    flow, token = b11.ready_flow(linked, auth, T, "notification.send")
    _flows_answer(node_red_fake, monkeypatch, "antwoord_ongeldig")
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


# -------------------------------------------------------------------------- besluit C-12: het profiel is vervallen (S-P3-360)
@pytest.mark.parametrize("role", ["admin", "operator", "viewer"])
@pytest.mark.parametrize("body", [{}, {"nieuw_beheerwachtwoord": True}])
def test_c12_a_the_hardening_profile_route_is_gone(linked: Any, auth: Any, role: str, body: dict[str, Any]) -> None:
    """Negatief (a): de oude route geeft 404, voor elke rol, en legt niets vast."""
    r = linked.post(f"{A}/hardening-profile", json=body, headers=idem(auth(role)))
    assert r.status_code == 404, r.text
    assert not any("hardening" in path for path in linked.app.openapi()["paths"])
    assert not any(row["action"] == "automation.hardening_profile.issued" for row in b11.audit_rows(linked))


def test_c12_a_no_answer_contains_a_hash_password_or_credential_secret(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """Negatief (a): na het instellen (beheerder en dienstaccount in Node-RED, aanmelding via de bron) bevat geen
    antwoord, audit, event of idempotentie-opslag een testwachtwoord, een bcrypt-hash, een ``--define`` of een
    ``credentialSecret`` als formulierargument."""
    caplog.set_level(logging.DEBUG)
    profile = setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    hashes = next(json.loads(a.split("=", 2)[2])["users"] for a in profile["arguments"] if "adminAuth=" in a)
    secrets = [profile["dienstwachtwoord"], profile["beheerwachtwoord"], *(u["password"] for u in hashes)]
    assert all(len(v) >= 20 for v in secrets)
    answers = [
        linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))),
        linked.post(f"{A}/snapshots", headers=idem(auth("admin"))),
        *(
            linked.get(path, headers=auth("admin"))
            for path in (
                "/integrations/v1/sources",
                "/integrations/v1/sources/node_red",
                f"{A}/editor",
                f"{A}/isolation",
                f"{A}/policy",
                f"{A}/flows",
            )
        ),
    ]
    assert all(r.status_code in (200, 201) for r in answers), [r.text for r in answers]
    texts = [r.text for r in answers] + [b11.everything_stored(linked), caplog.text]
    for text in texts:
        for value in secrets:
            assert value not in text
        assert "$2b$" not in text and "--define" not in text
        assert "credentialSecret=" not in text and '"credentialSecret":' not in text


@pytest.mark.parametrize(
    ("credential", "status"),
    [
        ("hub-dienst:" + "k" * 31, 422),  # te kort (ADR-0016 van appstore-en-fork, punt 3: minstens 32)
        ("k" * 40, 422),  # geen '<gebruiker>:<wachtwoord>'
        (":" + "k" * 40, 422),  # geen gebruiker
        ("hub-dienst:" + "k" * 32, 200),
    ],
)
def test_c12_service_login_needs_a_secret_of_at_least_32_characters(
    linked: Any, auth: Any, credential: str, status: int
) -> None:
    r = linked.put(
        "/integrations/v1/sources/node_red",
        json={"base_url": NODE_RED_URL, "enabled": True, "credential": credential},
        headers=idem(auth("admin"), **{"If-Match": "*"}),
    )
    assert r.status_code in ((200, 201) if status == 200 else (status,)), r.text
    if status == 422:
        assert r.json()["details"] == {"veld": "credential"} and credential not in r.text
        assert (
            linked.get("/integrations/v1/sources/node_red", headers=auth("admin")).json()["runtime"][
                "credential_present"
            ]
            is False
        )


def test_c12_b_anonymous_access_is_still_reported(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    """Negatief (b), besluit C-11: met een dienstaccount meet de controle ``anoniem_geweigerd`` 401 op ``/flows``,
    ``/nodes`` en ``/settings``; zonder ``adminAuth`` (anoniem leesbaar) is het een afwijking."""
    profile = setup_node_red(linked, fake_hub, auth, harden=False)
    report = linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()
    row = next(c for c in report["checks"] if c["id"] == "anoniem_geweigerd")
    assert row["status"] == "afwijking" and set(row["detail"]["http"].values()) == {200}, row
    node_red_fake.apply_arguments(profile["arguments"])
    report = linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()
    row = next(c for c in report["checks"] if c["id"] == "anoniem_geweigerd")
    assert row["status"] == "ok" and row["detail"]["http"] == {"/flows": 401, "/nodes": 401, "/settings": 401}


@pytest.mark.parametrize(
    "rechten", ["*", [*policy.SERVICE_PERMISSIONS, "nodes.write"], [*policy.SERVICE_PERMISSIONS, "flows.write"]]
)
def test_c12_c_a_service_account_with_more_rights_is_a_deviation(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, rechten: Any
) -> None:
    """Negatief (c): meer rechten dan ``SERVICE_PERMISSIONS`` (alle rechten, of ``nodes.write``) meldt de
    isolatiecontrole als ``dienstaccount_minimaal``."""
    setup_node_red(linked, fake_hub, auth)
    assert node_red_fake.admin_auth is not None
    node_red_fake.admin_auth["users"][0]["permissions"] = rechten
    node_red_fake.tokens.clear()
    report = linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()
    assert report["status"] == "afwijking" and report["afwijkingen"] == ["dienstaccount_minimaal"], report


def test_c12_d_existing_vault_items_and_credential_secret_stay_byte_equal(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """Negatief (d): een installatie van vóór C-12 (profiel in de kluis, Node-RED met een ``credentialSecret`` uit het
    formulier) blijft na de wijziging byte-gelijk: het kluisitem wordt niet gelezen, vervangen of verwijderd, de
    sleutel en het credentials-bestand van Node-RED veranderen niet. De isolatiecontrole meldt de ``credentialSecret``
    wel eerlijk als afwijking (C-12); hem weghalen zou de credentials onleesbaar maken, dus deze dienst doet niets."""
    from sqlalchemy import select

    from integrations.models import VaultSecret

    old_ref = "vault://automation/node-red-profiel"
    with linked.app.state.db.sessions() as session:
        linked.app.state.vault.put(session, old_ref, '{"dienst_hash":"x","credential_secret":"oud-geheim","v":1}')
        session.commit()
    profile = setup_node_red(linked, fake_hub, auth, harden=False, flows=simple_flow(), credentials={"n": {"p": "q"}})
    node_red_fake.apply_arguments([*profile["arguments"], "--define=credentialSecret=oude-sleutel-uit-het-formulier"])
    cred_file = node_red_fake.data_dir / "flows_cred.json"

    def vault_rows() -> dict[str, tuple[bytes, bytes, int]]:
        with linked.app.state.db.sessions() as session:
            return {
                r.ref: (bytes(r.nonce), bytes(r.ciphertext), r.version) for r in session.scalars(select(VaultSecret))
            }

    before = (vault_rows(), cred_file.read_bytes(), node_red_fake.credential_secret)
    report = linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()
    assert report["afwijkingen"] == ["credentials_versleuteld"], report
    b11.snapshot(linked, auth)
    for path in ("/integrations/v1/sources/node_red", f"{A}/editor", f"{A}/isolation"):
        assert linked.get(path, headers=auth("admin")).status_code == 200
    assert linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("admin"))).status_code == 404
    after = (vault_rows(), cred_file.read_bytes(), node_red_fake.credential_secret)
    assert old_ref in before[0] and after == before
    assert node_red_fake.writes == []


# --------------------------------------------------------------------- aanmelding van het dienstaccount (S-P3-360)
SOURCE = "/integrations/v1/sources/node_red"


def _put_source(client: Any, auth: Any, url: str, credential: str | None = None, key: str | None = None) -> Any:
    body: dict[str, Any] = {"base_url": url, "enabled": True}
    if credential is not None:
        body["credential"] = credential
    return client.put(SOURCE, json=body, headers=idem(auth("admin"), key=key, **{"If-Match": "*"}))


def _stored_login(client: Any) -> str | None:
    from integrations.sources import source_ref

    with client.app.state.db.sessions() as session:
        try:
            return client.app.state.vault.get(session, source_ref("node_red"))  # type: ignore[no-any-return]
        except KeyError:
            return None


def test_an_address_change_drops_the_stored_login(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    """R-VEILIG-1: de aanmelding hoort bij de bevestigde bestemming; een nieuw adres krijgt het oude wachtwoord niet."""
    from tests.fakes.node_red_fake import TEST_SERVICE_USER

    profile = setup_node_red(linked, fake_hub, auth)
    login = f"{TEST_SERVICE_USER}:{profile['dienstwachtwoord']}"
    same = _put_source(linked, auth, NODE_RED_URL)  # zelfde adres: de kluiswaarde blijft
    assert same.status_code == 200 and same.json()["runtime"]["credential_present"] is True
    assert _stored_login(linked) == login
    before = len(fake_hub.requests)
    moved = _put_source(linked, auth, "http://tweede-node.test:1880")
    assert moved.status_code == 200, moved.text
    assert moved.json()["runtime"]["credential_present"] is False and _stored_login(linked) is None
    assert len(fake_hub.requests) == before  # niets naar de nieuwe bestemming gestuurd
    again = _put_source(linked, auth, NODE_RED_URL, credential=login)  # pas na expliciete invoer weer een aanmelding
    assert again.json()["runtime"]["credential_present"] is True and _stored_login(linked) == login


def test_a_reused_key_with_another_password_is_refused(linked: Any, auth: Any) -> None:
    """R-VEILIG-2: zelfde Idempotency-Key met een ander wachtwoord is 422, niet een herhaling van het eerste."""
    from tests.fakes.node_red_fake import TEST_SERVICE_USER

    first, second = f"{TEST_SERVICE_USER}:{'a' * 32}", f"{TEST_SERVICE_USER}:{'b' * 32}"
    key = str(uuid.uuid4())
    created = _put_source(linked, auth, NODE_RED_URL, credential=first, key=key)
    replay = _put_source(linked, auth, NODE_RED_URL, credential=first, key=key)
    assert created.status_code == replay.status_code == 201 and replay.headers.get("Idempotent-Replay") == "true"
    other = _put_source(linked, auth, NODE_RED_URL, credential=second, key=key)
    assert other.status_code == 422 and other.json()["code"] == "idempotency_key_reused", other.text
    assert second not in other.text and _stored_login(linked) == first
    rotated = _put_source(linked, auth, NODE_RED_URL, credential=second)
    assert rotated.status_code == 200 and _stored_login(linked) == second


def test_the_simulators_keep_no_password(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    """R-VEILIG-3 (V-094): de verzoekhistorie van de testdubbels bewaart geen wachtwoord, wel aantal en uitkomst."""
    profile = setup_node_red(linked, fake_hub, auth)
    secret = profile["dienstwachtwoord"]
    r = linked.post(f"{A}/isolation/check", headers=idem(auth("admin")))
    assert r.status_code == 200 and r.json()["status"] == "gemeten_in_orde", r.text
    logins = [req for req in fake_hub.requests if req.url.path == "/auth/token"]
    assert logins and all(secret.encode() not in req.content for req in logins)
    assert secret not in repr(vars(node_red_fake))
    assert node_red_fake.logins == ["ok"] * len(logins)
