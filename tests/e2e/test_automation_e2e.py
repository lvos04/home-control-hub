"""Dienst-E2E voor B11 (Sim-getest): echte processen (API + worker) tegen de Hub-simulator en een nep-Node-RED.

De flow is hier een klein Python-programma dat doet wat een Node-RED-flow met een flow-token doet: events ophalen,
acties **aanvragen** en bevestigen. De rol van de Hub (een aangevraagde actie na zijn eigen beleid uitvoeren) speelt de
test zelf, tegen een register van apparaten en apps in het testproces. Zo is de hele keten zichtbaar: de enige weg naar
een wijziging loopt via de Hub, en tijdens een proefrun komt er over die weg niets.

- B11-001: editor alleen voor de beheerder, Node-RED weigert anoniem, een exec-flow wordt geblokkeerd;
- B11-002: een event met een onbekende schema-versie verdwijnt niet stil (bewaard, zichtbaar, gemeld aan de Hub);
- B11-003: een actie gaat als ``flow.action.requested`` naar de Hub; dataset verwijderen, de boiler en een actie die
  niet op de vaste lijst van contract §8 staat (een stekker schakelen) nooit;
- B11-004: een proefrun wijzigt geen apparaat;
- B11-005: herstel naar een eerdere momentopname met een door de Hub ondertekend verzoek, zonder geheimen in de logs.

Echte Node-RED, echte Hub en echte apparaten: NIET GEVALIDEERD (echte NAS). Volgorde van de tests is bewust
(module-scope stack)."""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx

from tests.e2e.conftest import Stack, TokenHeaders

A = "/integrations/v1/automation"
FLOW_API = A + "/flow-api"
TAB = "tab0000000000001"
EXEC_TAB = "tabexec000000001"
BROKER = "broker0000000001"
PW1 = "E2E-eerste-broker-wachtwoord-5521"
PW2 = "E2E-tweede-broker-wachtwoord-8804"
PLUG = {"type": "device", "id": "stekker-3"}
APP_DOEL = {"type": "app", "id": "uptime-kuma"}
STATE: dict[str, Any] = {}


class Apparaten:
    """Register van apparaten en apps in het testproces: alleen de Hub-rol in deze test mag hier iets uitvoeren."""

    def __init__(self) -> None:
        self.stand: dict[str, bool] = {"stekker-3": False, "boiler": False}
        self.mutaties: list[dict[str, Any]] = []

    def uitvoeren(self, action_id: str, doel: str, door: str) -> None:
        self.mutaties.append({"actie": action_id, "doel": doel, "door": door})


APPARATEN = Apparaten()
VERWERKT: set[str] = set()


def _idem(h: dict[str, str], key: str | None = None, **extra: str) -> dict[str, str]:
    base = h.fresh() if isinstance(h, TokenHeaders) else h  # één JWT per wijziging (replaybescherming)
    return {**base, "Idempotency-Key": key or str(uuid.uuid4()), **extra}


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _wait(cond: Any, timeout: float = 30, step: float = 0.5) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False


def _flows_v1() -> list[dict[str, Any]]:
    return [
        {"id": TAB, "type": "tab", "label": "Stekker bij zonnestroom", "disabled": False, "info": ""},
        {"id": "tab00000inject01", "type": "inject", "z": TAB, "name": "", "wires": [["tab00000functi01"]]},
        {"id": "tab00000functi01", "type": "function", "z": TAB, "name": "", "wires": [[]], "func": "return msg;"},
        {"id": BROKER, "type": "mqtt-broker", "name": "Huisbroker", "broker": "mqtt.invalid", "port": "1883"},
    ]


def _flows_v2() -> list[dict[str, Any]]:
    flows = _flows_v1()
    flows[2]["func"] = "msg.payload = 'in de editor aangepast'; return msg;"
    return flows


def _exec_flow() -> list[dict[str, Any]]:
    return [
        {"id": EXEC_TAB, "type": "tab", "label": "Shell (verboden)", "disabled": False, "info": ""},
        {"id": "tabexec0exec0001", "type": "exec", "z": EXEC_TAB, "name": "", "wires": [[], [], []], "command": "id"},
    ]


def _nr_state(stack: Stack) -> dict[str, Any]:
    return dict(httpx.get(f"{stack.node_red}/sim/state").json())


def _hub_inbox(stack: Stack, event_type: str) -> list[dict[str, Any]]:
    events = httpx.get(f"{stack.hub}/sim/inbox").json()
    return [e for e in events if e["event_type"] == event_type]


def _envelope(source_event_id: str, schema_version: str = "1.0") -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "event_id": str(uuid.uuid4()),
        "source_app": "home-control-hub",
        "source_event_id": source_event_id,
        "event_type": "energy.reading.recorded",
        "entity": {"type": "meter", "id": "meter-1"},
        "timestamp_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "trace_id": str(uuid.uuid4()),
        "correlation_id": None,
        "actor": {"type": "system", "id": "e2e"},
        "classification": "internal",
        "payload": {"vermogen_w": -1800, "eenheid": "W"},
        "payload_ref": None,
    }


def _flow(stack: Stack, tab_id: str) -> dict[str, Any]:
    items = httpx.get(f"{stack.hch}{A}/flows", headers=stack.token("viewer")).json()["items"]
    return next(dict(i) for i in items if i["source_flow_id"] == tab_id)


def _snapshot(stack: Stack) -> dict[str, Any]:
    r = httpx.post(f"{stack.hch}{A}/snapshots", headers=_idem(stack.token("admin")))
    assert r.status_code == 201, r.text
    return dict(r.json()["snapshot"])


def _de_flow_draait(stack: Stack, token: str) -> list[dict[str, Any]]:
    """Het 'programma' van de flow: bij elk event een app-herstart aanvragen én drie dingen proberen die nooit mogen."""
    antwoorden: list[dict[str, Any]] = []
    for _ in range(20):
        claimed = httpx.post(
            f"{stack.hch}{FLOW_API}/deliveries/claim", json={"limit": 5}, headers=_idem(_bearer(token))
        ).json()
        if not claimed["items"]:
            break
        for item in claimed["items"]:
            for action_id, target, params in (
                ("app.restart", APP_DOEL, {}),
                ("zfs.dataset.delete", {"type": "dataset", "id": "media"}, {}),
                ("energy.device.switch", {"type": "device", "id": "boiler"}, {"aan": True}),
                ("energy.device.switch", PLUG, {"aan": True}),
            ):
                r = httpx.post(
                    f"{stack.hch}{FLOW_API}/actions",
                    json={
                        "action_id": action_id,
                        "target": target,
                        "parameters": params,
                        "reason": "Er is zonnestroom over",
                        "trigger_delivery_id": item["id"],
                        "risk_claim": "R0",
                    },
                    headers=_idem(_bearer(token)),
                )
                antwoorden.append({"http": r.status_code, "action_id": action_id, "target": target, **r.json()})
            ack = httpx.post(f"{stack.hch}{FLOW_API}/deliveries/{item['id']}/ack", headers=_idem(_bearer(token)))
            assert ack.status_code == 200, ack.text
    return antwoorden


def _de_hub_voert_uit(stack: Stack) -> int:
    """De rol van de Hub: elk aangevraagd actieverzoek één keer uitvoeren (hier: een app herstarten)."""
    done = 0
    for event in _hub_inbox(stack, "flow.action.requested"):
        payload = event["payload"]
        if payload["action_request_id"] in VERWERKT:
            continue
        VERWERKT.add(payload["action_request_id"])
        if payload["action_id"] == "app.restart":
            APPARATEN.uitvoeren(payload["action_id"], payload["target"]["id"], door="hub")
            done += 1
    return done


def test_01_editor_alleen_beheerder_en_exec_flow_geblokkeerd(stack: Stack) -> None:
    """B11-001: viewer bereikt de editor niet, Node-RED weigert anoniem en een exec-flow wordt geblokkeerd."""

    def linked() -> bool:
        return bool(httpx.get(f"{stack.hch}/readyz").json()["hub_link"]["state"] == "gekoppeld")

    assert _wait(linked), "worker koppelde niet"
    admin = stack.token("admin")
    r = httpx.post(f"{stack.hch}{A}/hardening-profile", json={}, headers=_idem(admin))
    assert r.status_code == 201, r.text
    profile = r.json()
    STATE["profile"] = profile
    # de beheerder zet de argumenten in het formulier van de Custom App en herstart Node-RED
    assert httpx.post(f"{stack.node_red}/sim/arguments", json={"arguments": profile["arguments"]}).json()["beveiligd"]
    creds = {BROKER: {"user": "nas", "password": PW1}}
    httpx.post(f"{stack.node_red}/sim/deploy", json={"flows": [*_flows_v1(), *_exec_flow()], "credentials": creds})
    r = httpx.put(
        f"{stack.hch}/integrations/v1/sources/node_red",
        json={"base_url": stack.node_red, "enabled": True},
        headers=_idem(admin, **{"If-Match": "*"}),
    )
    assert r.status_code in (200, 201), r.text

    for role in ("viewer", "operator"):
        editor = httpx.get(f"{stack.hch}{A}/editor", headers=stack.token(role))
        assert editor.status_code == 403 and stack.node_red not in editor.text
    assert httpx.get(f"{stack.hch}{A}/editor", headers=admin).json()["url"] == stack.node_red
    for path in ("/flows", "/nodes", "/settings"):
        assert httpx.get(f"{stack.node_red}{path}").status_code == 401, path
    assert _nr_state(stack)["exec_geladen"] is False

    report = httpx.post(f"{stack.hch}{A}/isolation/check", headers=_idem(stack.token("operator"))).json()
    assert report["status"] == "gemeten_in_orde", report
    assert report["niet_meetbaar"] and "NIET GEVALIDEERD" in report["validatie"]

    STATE["snap_exec"] = _snapshot(stack)
    blocked = _flow(stack, EXEC_TAB)
    assert blocked["status"] == "geblokkeerd", blocked
    assert _flow(stack, TAB)["status"] != "geblokkeerd"
    # de worker meldt de geblokkeerde flow aan de Hub
    assert _wait(lambda: len(_hub_inbox(stack, "flow.policy.blocked")) == 1), "blokkade niet bij de Hub gemeld"
    # een geblokkeerde flow krijgt geen token
    r = httpx.put(
        f"{stack.hch}{A}/flows/{blocked['id']}/owner",
        json={"owner": "user-1", "eigenaren": []},
        headers=_idem(admin, **{"If-Match": "*"}),
    )
    assert r.status_code == 200, r.text
    r = httpx.post(
        f"{stack.hch}{A}/flows/{blocked['id']}/tokens",
        json={"label": "e2e", "allowed_actions": ["notification.send"]},
        headers=_idem(admin),
    )
    assert r.status_code in (403, 409), r.text
    # de beheerder haalt de exec-flow weer weg in de editor
    httpx.post(f"{stack.node_red}/sim/deploy", json={"flows": _flows_v1(), "credentials": creds})
    STATE["snap1"] = _snapshot(stack)
    assert STATE["snap1"]["credentials_status"] == "meegenomen"
    assert _nr_state(stack)["writes"] == [], "tot hier heeft de dienst alleen gelezen"


def test_02_onbekende_schema_versie_verdwijnt_niet_stil(stack: Stack) -> None:
    """B11-002: bewaard, zichtbaar voor de beheerder, niet afgeleverd en gemeld aan de Hub."""
    env = _envelope("meter-1:e2e-onbekend", schema_version="9.9")
    r = httpx.post(f"{stack.hch}{A}/events", json=env, headers=_idem(stack.service()))
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["catalog_status"] == "onbekende_schema_versie" and body["afleveringen"] == 0
    seen = httpx.get(f"{stack.hch}{A}/events", headers=stack.token("viewer")).json()["items"]
    assert [e["catalog_status"] for e in seen if e["event_id"] == env["event_id"]] == ["onbekende_schema_versie"]

    def reported() -> bool:
        seen_by_hub = _hub_inbox(stack, "automation.event.rejected")
        return any(e["entity"]["id"] == env["event_id"] for e in seen_by_hub)

    assert _wait(reported), "de afkeuring is niet bij de Hub gemeld"
    assert httpx.get(f"{stack.hub}/sim/rejected").json() == [], "de Hub accepteert alle envelopes (contract §7)"
    # een flow-token of een gebruiker mag geen events aanbieden: alleen de Hub
    assert httpx.post(f"{stack.hch}{A}/events", json=env, headers=_idem(stack.token("admin"))).status_code == 403


def test_03_flow_vraagt_aan_en_de_hub_voert_uit(stack: Stack) -> None:
    """B11-003: het verzoek gaat naar de Hub; dataset verwijderen en de boiler worden nooit doorgestuurd."""
    admin = stack.token("admin")
    flow = _flow(stack, TAB)
    STATE["flow_id"] = flow["id"]
    put = {"If-Match": "*"}
    r = httpx.put(
        f"{stack.hch}{A}/flows/{flow['id']}/owner",
        json={"owner": "user-1", "eigenaren": []},
        headers=_idem(admin, **put),
    )
    assert r.status_code == 200, r.text
    r = httpx.put(
        f"{stack.hch}{A}/flows/{flow['id']}/triggers",
        json={"triggers": [{"event_type": "energy.reading.recorded", "schema_version": "1.0", "filter": {}}]},
        headers=_idem(admin, **put),
    )
    assert r.status_code == 200, r.text
    # een token dat de boiler, een dataset of een actie buiten de vaste lijst mag aanvragen bestaat niet
    for scope in (["energy.boiler.switch"], ["zfs.dataset.delete"], ["*"], ["energy.device.switch"], ["energy.*"]):
        r = httpx.post(
            f"{stack.hch}{A}/flows/{flow['id']}/tokens",
            json={"label": "te ruim", "allowed_actions": scope},
            headers=_idem(admin),
        )
        assert r.status_code == 422, (scope, r.text)
    r = httpx.post(
        f"{stack.hch}{A}/flows/{flow['id']}/tokens",
        json={"label": "e2e", "allowed_actions": ["app.restart", "zfs.*"]},
        headers=_idem(admin),
    )
    assert r.status_code == 201, r.text
    token = STATE["token"] = r.json()["flow_token"]
    # het flow-token opent niets anders dan de flow-API
    assert httpx.get(f"{stack.hch}{A}/flows", headers=_bearer(token)).status_code == 401
    assert httpx.get(f"{stack.hch}/connector/v1/discover", headers=_bearer(token)).status_code == 401

    env = _envelope("meter-1:e2e-zon")
    offered = [  # EX46: de Hub biedt hetzelfde event vijf keer aan
        httpx.post(f"{stack.hch}{A}/events", json=env, headers=_idem(stack.service())) for _ in range(5)
    ]
    assert all(r.status_code in (200, 201) for r in offered), [r.text for r in offered]
    assert sum(r.json()["afleveringen"] for r in offered if not r.json().get("duplicaat")) == 1, offered[1].text
    answers = _de_flow_draait(stack, token)
    assert [(a["http"], a.get("status")) for a in answers] == [
        (202, "aangevraagd"),
        (403, None),
        (403, None),
        (403, None),
    ], answers
    assert answers[0]["risk_preview"]["risk_claim_genegeerd"] is True  # EX18
    assert [a["details"]["reason"] for a in answers[1:]] == ["destructief_verboden", "boiler_nooit", "onbekende_actie"]

    assert _wait(lambda: len(_hub_inbox(stack, "flow.action.requested")) == 1), "verzoek kwam niet bij de Hub aan"
    assert _wait(lambda: len(_hub_inbox(stack, "flow.action.rejected")) == 3), "weigeringen niet bij de Hub gemeld"
    requested = _hub_inbox(stack, "flow.action.requested")[0]
    assert requested["actor"] == {"type": "flow", "id": f"flow:{flow['id']}"}
    assert requested["payload"]["action_id"] == "app.restart" and requested["payload"]["target"] == APP_DOEL
    assert "risk_claim" not in requested["payload"]
    # tot de Hub iets doet is er niets gewijzigd: deze dienst voert zelf niets uit
    assert APPARATEN.mutaties == []
    assert _de_hub_voert_uit(stack) == 1
    assert APPARATEN.mutaties == [{"actie": "app.restart", "doel": "uptime-kuma", "door": "hub"}]
    assert APPARATEN.stand == {"stekker-3": False, "boiler": False}
    # de Hub meldt de uitkomst terug; de flow kan die lezen
    r = httpx.post(
        f"{stack.hch}{A}/action-requests/{answers[0]['id']}/result",
        json={"status": "uitgevoerd", "hub_proposal_id": "prop-e2e-1", "hub_risk_class": "R1"},
        headers=_idem(stack.service()),
    )
    assert r.status_code == 200, r.text
    got = httpx.get(f"{stack.hch}{FLOW_API}/actions/{answers[0]['id']}", headers=_bearer(token)).json()
    assert got["status"] == "uitgevoerd" and got["hub_risk_class"] == "R1"
    listed = httpx.get(f"{stack.hch}{A}/action-requests", headers=stack.token("viewer")).json()["items"]
    assert sorted(i["status"] for i in listed) == ["geweigerd", "geweigerd", "geweigerd", "uitgevoerd"]
    assert httpx.get(f"{stack.hub}/sim/rejected").json() == []


def test_04_proefrun_wijzigt_geen_apparaat(stack: Stack) -> None:
    """B11-004: dezelfde flow, nu als proefrun met de vaste voorbeeld-events: er komt niets bij de Hub of een apparaat."""
    token = STATE["token"]
    before = {
        "mutaties": list(APPARATEN.mutaties),
        "stand": dict(APPARATEN.stand),
        "requested": len(_hub_inbox(stack, "flow.action.requested")),
        "rejected": len(_hub_inbox(stack, "flow.action.rejected")),
        "writes": _nr_state(stack)["writes"],
    }
    r = httpx.post(
        f"{stack.hch}{A}/flows/{STATE['flow_id']}/runs",
        json={"bevestig_niet_afgeschermd": True},
        headers=_idem(stack.token("operator")),
    )
    assert r.status_code == 201, r.text
    run = r.json()
    assert run["mode"] == "dry_run" and run["status"] == "bezig"
    me = httpx.get(f"{stack.hch}{FLOW_API}/me", headers=_bearer(token)).json()
    assert me["dry_run"]["run_id"] == run["id"]

    answers: list[dict[str, Any]] = []
    for _ in range(10):
        if httpx.get(f"{stack.hch}{FLOW_API}/me", headers=_bearer(token)).json()["dry_run"] is None:
            break
        answers += _de_flow_draait(stack, token)
    assert answers and {a["http"] for a in answers} == {200}
    assert {a["status"] for a in answers} == {"gesimuleerd"} and all("id" not in a for a in answers)
    assert {a["uitkomst"] for a in answers if a["target"] == APP_DOEL} == {"zou_worden_aangevraagd"}
    assert {a["reden"] for a in answers if a["target"] != APP_DOEL} == {
        "destructief_verboden",
        "boiler_nooit",
        "onbekende_actie",
    }
    done = httpx.get(f"{stack.hch}{A}/runs/{run['id']}", headers=stack.token("viewer")).json()
    assert done["status"] == "klaar", done
    assert done["result"]["aangevraagd_bij_de_hub"] == 0 and done["result"]["echte_wijzigingen_via_deze_dienst"] == 0
    assert done["result"]["actieverzoeken"] == len(answers)

    time.sleep(4)  # de worker heeft ruim de tijd gehad om iets door te sturen (interval 1 s)
    assert _de_hub_voert_uit(stack) == 0, "de Hub heeft na de proefrun niets uit te voeren"
    assert len(_hub_inbox(stack, "flow.action.requested")) == before["requested"]
    assert len(_hub_inbox(stack, "flow.action.rejected")) == before["rejected"]
    assert APPARATEN.mutaties == before["mutaties"] and APPARATEN.stand == before["stand"]
    assert _nr_state(stack)["writes"] == before["writes"] == []
    listed = httpx.get(f"{stack.hch}{A}/action-requests", headers=stack.token("viewer")).json()["items"]
    assert len(listed) == 4, "de proefrun heeft geen actieverzoek aangemaakt"


def test_05_herstel_met_door_de_hub_ondertekend_verzoek(stack: Stack) -> None:
    """B11-005: undo naar de eerdere momentopname, mét credentials, alleen met een ondertekend verzoek van de Hub."""
    admin = stack.token("admin")
    snap1 = STATE["snap1"]
    # iemand past de flow en het broker-wachtwoord aan in de editor
    httpx.post(
        f"{stack.node_red}/sim/deploy",
        json={"flows": _flows_v2(), "credentials": {BROKER: {"user": "nas", "password": PW2}}},
    )

    def versioned() -> bool:  # de worker legt de wijziging zelf vast (geplande momentopname)
        items = httpx.get(f"{stack.hch}{A}/snapshots", headers=stack.token("viewer")).json()["items"]
        return bool(items[0]["reason"] == "gepland" and items[0]["checksum_sha256"] != snap1["checksum_sha256"])

    assert _wait(versioned), "de worker legde de wijziging niet vast"
    body = {
        "action_id": "automation.flows.restore",
        "target": {"type": "source", "id": "node_red"},
        "parameters": {"snapshot_id": snap1["id"]},
    }
    assert (
        httpx.post(f"{stack.hch}/connector/v1/propose", json=body, headers=_idem(stack.token("operator"))).status_code
        == 403
    )
    r = httpx.post(f"{stack.hch}/connector/v1/propose", json=body, headers=_idem(admin))
    assert r.status_code == 201, r.text
    view = r.json()
    assert _nr_state(stack)["flows"] == _flows_v2(), "een voorstel wijzigt niets"

    signed = httpx.post(
        f"{stack.hub}/sim/execution-request",
        json={
            "action_id": body["action_id"],
            "target": body["target"],
            "parameters": view["parameters"],
            "preview_hash": view["preview_hash"],
            "resource_etag": view["resource_etag"],
        },
    ).json()
    # wie geen beheerder of Hub is, kan zelfs een geldig ondertekend verzoek niet indienen
    r = httpx.post(f"{stack.hch}/connector/v1/apply", json=signed, headers=_idem(stack.token("operator")))
    assert r.status_code == 403, r.text
    # zonder handtekening van de Hub gaat het niet, ook niet voor de beheerder
    unsigned = {k: v for k, v in signed.items() if k != "signature"}
    r = httpx.post(f"{stack.hch}/connector/v1/apply", json=unsigned, headers=_idem(admin))
    assert r.status_code in (403, 422), r.text
    # en een verzoek waar na het ondertekenen aan gezeten is, wordt geweigerd zonder iets te wijzigen
    tampered = {**signed, "proposal": {**signed["proposal"], "parameters": {"snapshot_id": STATE["snap_exec"]["id"]}}}
    r = httpx.post(f"{stack.hch}/connector/v1/apply", json=tampered, headers=_idem(stack.service()))
    assert r.status_code == 403, r.text
    assert _nr_state(stack)["flows"] == _flows_v2() and _nr_state(stack)["writes"] == []

    key = str(uuid.uuid4())
    r = httpx.post(f"{stack.hch}/connector/v1/apply", json=signed, headers=_idem(stack.service(), key=key))
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["status"] == "uitgevoerd" and result["credentials_teruggezet"] is True
    assert result["readback"]["gelijk_aan_momentopname"] is True
    assert "NIET GEVALIDEERD (echte NAS)" in result["validatie"]
    state = _nr_state(stack)
    assert state["flows"] == _flows_v1()
    assert state["credentials"] == {BROKER: {"user": "nas", "password": PW1}}
    assert len(state["writes"]) == 1 and state["writes"][0]["met_credentials"] is True
    # hetzelfde verzoek nog eens: zelfde antwoord, geen tweede schrijfactie; met een nieuwe sleutel: geweigerd
    again = httpx.post(f"{stack.hch}/connector/v1/apply", json=signed, headers=_idem(stack.service(), key=key))
    assert again.status_code == 200 and again.json() == result
    replay = httpx.post(f"{stack.hch}/connector/v1/apply", json=signed, headers=_idem(stack.service()))
    assert replay.status_code == 409 and replay.json()["code"] == "nonce_al_gebruikt", replay.text
    assert len(_nr_state(stack)["writes"]) == 1
    assert _wait(lambda: len(_hub_inbox(stack, "automation.restore.applied")) == 1), "herstel niet bij de Hub gemeld"
    assert httpx.post(f"{stack.hch}/connector/v1/rollback", json={}, headers=_idem(stack.service())).status_code == 501
    assert APPARATEN.mutaties == [{"actie": "app.restart", "doel": "uptime-kuma", "door": "hub"}]
    STATE["signature"] = signed["signature"]


def test_06_health_volgt_node_red_en_geen_geheimen_in_de_logs(stack: Stack) -> None:
    def check() -> dict[str, Any] | None:
        body = httpx.get(f"{stack.hch}/connector/v1/health", headers=stack.service()).json()
        return next((dict(c) for c in body["checks"] if c["name"] == "automatisering"), None)

    assert _wait(lambda: (check() or {}).get("status") == "healthy"), check()
    httpx.post(f"{stack.node_red}/sim/state", json={"up": False})
    assert _wait(lambda: (check() or {}).get("reason_code") == "synchronisatie_mislukt"), check()
    assert (check() or {})["status"] != "healthy"
    httpx.post(f"{stack.node_red}/sim/state", json={"up": True})
    assert _wait(lambda: (check() or {}).get("status") == "healthy"), check()

    assert stack.logs is not None
    profile = STATE["profile"]
    secret_args = [a.split("=", 2)[2] for a in profile["arguments"] if a.startswith("--define=credentialSecret=")]
    secrets = [PW1, PW2, profile["beheerwachtwoord"], STATE["token"], STATE["signature"], *secret_args]
    assert len(secret_args) == 1 and all(len(s) >= 16 for s in secrets)
    for name in ("api.log", "worker.log"):
        for p in stack.procs:
            assert p.poll() is None, f"{name}: proces is onverwacht gestopt"
        text = (stack.logs / name).read_text(encoding="utf-8", errors="replace")
        assert text.strip(), f"{name} is leeg; de controle zou niets bewijzen"
        for secret in secrets:
            assert secret not in text, f"geheim in {name}"
