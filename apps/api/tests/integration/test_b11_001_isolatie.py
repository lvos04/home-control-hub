"""B11-001 — flow-netwerkisolatie: de editor is alleen voor de beheerder en een exec-node wordt geblokkeerd.

Acceptatie: "Viewer kan editor niet bereiken en custom exec-node is geblokkeerd." Sim-getest met de nep-Node-RED
(het gedrag van de nep is gemeten tegen de vastgezette image, zie docs/b11/node-red-verificatie.json).
Echte Node-RED op de NAS: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from tests import b11
from tests.b11 import A
from tests.conftest import NODE_RED_URL, idem, setup_node_red
from tests.fakes.node_red_fake import exec_flow, simple_flow


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


# ------------------------------------------------------------------------------------------------- geheimen blijven weg
def test_profile_secrets_are_shown_once_and_stored_nowhere(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    key = "7d0c7f0e-4b1f-4a55-9d53-0c7d5c0f6a01"
    r = linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("admin"), key=key))
    assert r.status_code == 201, r.text
    profile = r.json()
    password = profile["beheerwachtwoord"]
    assert password and len(password) >= 20
    secrets = [password, *[a for a in profile["arguments"] if "credentialSecret" in a or "$2" in a]]
    assert len(secrets) >= 3, "wachtwoord, credentialSecret en minstens één wachtwoordhash"

    # dezelfde Idempotency-Key: het bewaarde antwoord bevat het wachtwoord en de argumenten niet meer
    again = linked.post(f"{A}/hardening-profile", json={}, headers=idem(auth("admin"), key=key))
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
