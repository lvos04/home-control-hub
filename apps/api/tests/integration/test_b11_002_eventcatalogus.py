"""B11-002 — eventtypen-catalogus met schema-versies, en de inbox die events aan flows aflevert.

Acceptatie: "Een event met onbekende schema-versie verdwijnt niet stil." Sim-getest (nep-Hub als afzender, de flow is
een HTTP-client met een flow-token). Het doorsturen van events door de echte Hub: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests import b11
from tests.b11 import A
from tests.conftest import idem, setup_node_red
from tests.fakes.node_red_fake import simple_flow

TAB = "tab0000000000001"


@pytest.fixture
def flow(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> tuple[dict[str, Any], str]:
    """Een actieve flow met eigenaar, een trigger op energiemetingen en een flow-token."""
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    return b11.ready_flow(
        linked, auth, TAB, "notification.send", triggers=("energy.reading.recorded", "backup.run.failed")
    )


def _events(linked: Any, auth: Any, status: str | None = None) -> dict[str, Any]:
    r = linked.get(f"{A}/events", params={"status": status} if status else None, headers=auth("viewer"))
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


# ------------------------------------------------------------------------------------------------------- de catalogus
def test_catalogue_lists_types_with_schema_versions(linked: Any, auth: Any) -> None:
    r = linked.get(f"{A}/event-types", headers=auth("viewer"))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["envelope"]["schema_versions"] == ["1.0"]
    types = {i["event_type"]: i for i in body["items"]}
    assert {"energy.reading.recorded", "backup.run.failed", "flow.action.requested", "app.health.changed"} <= set(types)
    assert all(i["schema_versions"] == ["1.0"] for i in body["items"])
    assert types["flow.action.requested"]["sources"] == ["home-control-hub"]
    assert "ai-server-manager" in body["owners"] and "energy" in body["owners"]["home-control-hub"]


def test_catalogue_needs_a_login(linked: Any) -> None:
    assert linked.get(f"{A}/event-types").status_code == 401


# ------------------------------------------------------------------------------------------- wie mag events aanbieden
def test_only_the_hub_service_may_offer_events(linked: Any, auth: Any, flow: Any) -> None:
    for role in ("admin", "operator", "viewer"):
        r = linked.post(f"{A}/events", json=b11.envelope(), headers=idem(auth(role)))
        assert r.status_code == 403, role
    _, token = flow
    r = linked.post(f"{A}/events", json=b11.envelope(), headers=idem(b11.bearer(token)))
    assert r.status_code == 401, "een flow-token geeft geen toegang buiten de flow-API"
    assert _events(linked, auth)["items"] == []


# ----------------------------------------------------------------------------------------------------- geldig event
def test_valid_event_is_stored_and_delivered_to_the_matching_flow(
    linked: Any, fake_hub: Any, auth: Any, flow: Any
) -> None:
    _, token = flow
    env = b11.envelope()
    r = b11.post_event(linked, fake_hub, env)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["catalog_status"] == "geldig" and body["bewaard"] is True
    assert body["afleveringen"] == 1

    claimed = b11.claim(linked, token)
    assert [i["event"]["event_id"] for i in claimed["items"]] == [env["event_id"]]
    item = claimed["items"][0]
    assert item["event"]["payload"] == env["payload"]
    assert item["attempt"] == 1 and item["dry_run"] is False
    assert b11.ack(linked, token, item["id"]).json()["status"] == "verwerkt"
    assert b11.claim(linked, token)["items"] == []
    # nog een keer bevestigen is veilig
    assert b11.ack(linked, token, item["id"]).status_code == 200


def test_event_without_matching_trigger_is_stored_but_not_delivered(
    linked: Any, fake_hub: Any, auth: Any, flow: Any
) -> None:
    env = b11.envelope("network.device.discovered", entity={"type": "device", "id": "d-1"}, payload={"mac": "x"})
    r = b11.post_event(linked, fake_hub, env)
    assert r.status_code == 201, r.text
    assert r.json()["afleveringen"] == 0
    assert [e["event_id"] for e in _events(linked, auth)["items"]] == [env["event_id"]]


# ------------------------------------------------------------------------------ onbekende schema-versie: nooit stil weg
def test_unknown_schema_version_is_kept_visible_and_reported(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    env = b11.envelope(schema_version="2.0")
    r = b11.post_event(linked, fake_hub, env)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["catalog_status"] == "onbekende_schema_versie"
    assert body["catalog_detail"] == {"schema_version": "2.0", "ondersteund": ["1.0"]}
    assert body["bewaard"] is True and body["afleveringen"] == 0

    # 1. zichtbaar in de lijst, met een filter erop
    listed = _events(linked, auth, "onbekende_schema_versie")
    assert [(e["event_id"], e["schema_version"]) for e in listed["items"]] == [(env["event_id"], "2.0")]
    assert listed["wachtrij"]["niet_afgeleverd_24u"] == {"onbekende_schema_versie": 1}
    # 2. gemeld als eigen event (voor de Hub en de beheerder)
    rejected = b11.outbox(linked, "automation.event.rejected")
    assert len(rejected) == 1
    assert rejected[0]["payload"]["catalog_status"] == "onbekende_schema_versie"
    assert rejected[0]["payload"]["event_type"] == "energy.reading.recorded"
    # 3. niet aan de flow gegeven: die kent de vorm niet
    assert b11.claim(linked, token)["items"] == []
    # een tweede binnen het uur wordt wél bewaard maar niet opnieuw gemeld (geen meldingsstorm)
    assert b11.post_event(linked, fake_hub, b11.envelope(schema_version="2.0")).status_code == 202
    assert len(_events(linked, auth, "onbekende_schema_versie")["items"]) == 2
    assert len(b11.outbox(linked, "automation.event.rejected")) == 1


def test_trigger_on_unknown_schema_version_is_refused(linked: Any, auth: Any, flow: Any) -> None:
    detail, _ = flow
    r = b11.put_flow(
        linked,
        auth,
        detail["id"],
        "triggers",
        {"triggers": [{"event_type": "energy.reading.recorded", "schema_version": "2.0", "filter": {}}]},
    )
    assert r.status_code == 422, r.text
    assert r.json()["code"] == "trigger_ongeldig"
    r = b11.put_flow(
        linked, auth, detail["id"], "triggers", {"triggers": [{"event_type": "bestaat.niet.echt", "filter": {}}]}
    )
    assert r.status_code == 422


@pytest.mark.parametrize(
    ("overrides", "status"),
    [
        (
            {"event_type": "service.iets.onbekends", "entity": {"type": "service", "id": "home-control-hub"}},
            "onbekend_type",
        ),
        ({"event_type": "tuin.sproeier.gestart"}, "onbekend_type"),
        ({"source_app": "mediaguard"}, "buiten_domein"),
        ({"source_app": "onbekende-app"}, "buiten_domein"),
        (
            {
                "event_type": "app.health.changed",
                "entity": {"type": "app", "id": "home-control-hub"},
                "payload": {"status": "paars"},
            },
            "ongeldige_payload",
        ),
        ({"event_type": "app.health.changed", "payload": {"status": "down"}}, "buiten_domein"),
    ],
)
def test_events_outside_the_catalogue_are_stored_but_never_delivered(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, overrides: dict[str, Any], status: str
) -> None:
    _, token = flow
    env = b11.envelope(**{"event_type": "energy.reading.recorded", **overrides})
    r = b11.post_event(linked, fake_hub, env)
    assert r.status_code == 202, r.text
    assert r.json()["catalog_status"] == status
    assert [e["event_id"] for e in _events(linked, auth, status)["items"]] == [env["event_id"]]
    assert b11.claim(linked, token)["items"] == []
    assert len(b11.outbox(linked, "automation.event.rejected")) == 1


def test_broken_envelope_is_refused_and_not_stored(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    """Zonder identiteit (event_id, bron) of met een vorm buiten §7 is er niets te bewaren: 422, met de reden."""
    without_id = b11.envelope()
    del without_id["event_id"]
    extra_field = {**b11.envelope(), "onbekend_veld": 1}
    bad_actor = {**b11.envelope(), "actor": {"type": "robot", "id": "x"}}
    for env, veld in ((without_id, "event_id"), (extra_field, "onbekend_veld"), (bad_actor, "actor.type")):
        r = b11.post_event(linked, fake_hub, env)
        assert r.status_code == 422, r.text
        assert r.json()["code"] == "event_ongeldig"
        assert veld in {f["veld"] for f in r.json()["details"]["fouten"]}, r.text
    assert _events(linked, auth)["items"] == []


def test_list_refuses_an_unknown_status_filter(linked: Any, auth: Any) -> None:
    r = linked.get(f"{A}/events", params={"status": "weg"}, headers=auth("viewer"))
    assert r.status_code == 422
    assert r.json()["code"] == "validation_error"


# ------------------------------------------------------------------------------------------------------ ontdubbelen
def test_duplicate_events_are_delivered_once(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    env = b11.envelope(source_event_id="meter-1:42")
    assert b11.post_event(linked, fake_hub, env).status_code == 201
    # zelfde event opnieuw (nieuwe Idempotency-Key, zoals bij een herstart van de afzender)
    again = b11.post_event(linked, fake_hub, env)
    assert again.status_code == 200 and again.json()["duplicaat"] is True
    # zelfde bron-event onder een nieuw event_id
    twin = b11.post_event(linked, fake_hub, {**env, "event_id": str(uuid.uuid4())})
    assert twin.status_code == 200 and twin.json()["duplicaat"] is True
    assert len(_events(linked, auth)["items"]) == 1
    assert len(b11.claim(linked, token)["items"]) == 1


# ------------------------------------------------------------------------------------- volgorde, herhalen, dead-letter
def test_order_per_source_is_kept(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    first, second = b11.envelope(), b11.envelope()
    other = b11.envelope(
        "backup.run.failed", source_app="ai-server-manager", entity={"type": "backup", "id": "b"}, payload={}
    )
    for env in (first, second, other):
        assert b11.post_event(linked, fake_hub, env).status_code == 201, env
    claimed = b11.claim(linked, token, limit=10)["items"]
    # per bron alleen het oudste; het tweede van dezelfde bron wacht op de bevestiging van het eerste
    assert [i["event"]["event_id"] for i in claimed] == [first["event_id"], other["event_id"]]
    assert b11.claim(linked, token, limit=10)["items"] == []
    for item in claimed:
        assert b11.ack(linked, token, item["id"]).status_code == 200
    assert [i["event"]["event_id"] for i in b11.claim(linked, token)["items"]] == [second["event_id"]]


def test_failed_delivery_waits_and_blocks_later_events_of_that_source(
    linked: Any, fake_hub: Any, auth: Any, flow: Any
) -> None:
    detail, token = flow
    first, second = b11.envelope(), b11.envelope()
    for env in (first, second):
        b11.post_event(linked, fake_hub, env)
    item = b11.claim(linked, token)["items"][0]
    r = b11.nack(linked, token, item["id"], "apparaat_onbereikbaar")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "wachtend" and r.json()["attempts"] == 1
    assert r.json()["last_error"] == "apparaat_onbereikbaar"
    # de wachttijd loopt: er komt nu niets, ook niet het latere event van dezelfde bron
    assert b11.claim(linked, token)["items"] == []
    # een aflevering die niet geclaimd is, kan niet bevestigd of afgewezen worden
    assert b11.nack(linked, token, item["id"]).status_code == 409
    assert b11.ack(linked, token, item["id"]).json()["code"] == "aflevering_niet_geclaimd"
    assert b11.ack(linked, token, str(uuid.uuid4())).status_code == 404
    listed = linked.get(f"{A}/deliveries", params={"flow_id": detail["id"]}, headers=auth("viewer")).json()["items"]
    assert sorted(d["status"] for d in listed) == ["wachtend", "wachtend"]


def test_delivery_ends_in_dead_letter_and_can_be_requeued(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    from integrations.domains.automation import inbox
    from integrations.domains.automation.models import AutomationFlow
    from integrations.timeutil import utcnow

    detail, token = flow
    env = b11.envelope()
    b11.post_event(linked, fake_hub, env)
    tid = str(uuid.uuid4())
    with linked.app.state.db.sessions() as s:
        row = s.get(AutomationFlow, uuid.UUID(detail["id"]))
        now = utcnow()
        for attempt in range(1, inbox.MAX_ATTEMPTS + 1):
            items, _ = inbox.claim(s, row, limit=5, now=now, trace_id=tid)
            assert len(items) == 1 and items[0]["attempt"] == attempt
            d = inbox.get_delivery(s, row.id, uuid.UUID(items[0]["id"]))
            assert d is not None and inbox.nack(s, d, "kapot", now, tid)
            s.flush()
            if attempt < inbox.MAX_ATTEMPTS:
                assert d.status == "wachtend"
                assert d.next_attempt_at == now + inbox.backoff(attempt), "oplopende wachttijd"
                assert inbox.claim(s, row, limit=5, now=now, trace_id=tid)[0] == []
                now = d.next_attempt_at
        assert d.status == "dead_letter"
        delivery_id = str(d.id)
        s.commit()

    failed = b11.outbox(linked, "automation.delivery.failed")
    assert len(failed) == 1 and failed[0]["payload"]["pogingen"] == inbox.MAX_ATTEMPTS
    dead = linked.get(f"{A}/deliveries", params={"status": "dead_letter"}, headers=auth("viewer")).json()["items"]
    assert [d["id"] for d in dead] == [delivery_id]
    assert b11.claim(linked, token)["items"] == []

    assert linked.post(f"{A}/deliveries/{delivery_id}/requeue", headers=idem(auth("viewer"))).status_code == 403
    r = linked.post(f"{A}/deliveries/{delivery_id}/requeue", headers=idem(auth("operator")))
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "wachtend" and r.json()["attempts"] == 0
    assert linked.post(f"{A}/deliveries/{delivery_id}/requeue", headers=idem(auth("operator"))).status_code == 409
    assert [i["id"] for i in b11.claim(linked, token)["items"]] == [delivery_id]


def test_expired_claim_counts_as_a_failed_attempt(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    from integrations.domains.automation import inbox
    from integrations.domains.automation.models import AutomationDelivery
    from integrations.timeutil import utcnow

    _, token = flow
    b11.post_event(linked, fake_hub, b11.envelope())
    item = b11.claim(linked, token)["items"][0]
    with linked.app.state.db.sessions() as s:
        later = utcnow() + inbox.LEASE + inbox.LEASE
        assert inbox.release_expired(s, later, str(uuid.uuid4())) == 1
        d = s.get(AutomationDelivery, uuid.UUID(item["id"]))
        assert d is not None and d.status == "wachtend" and d.attempts == 1 and d.last_error == "claim_verlopen"
        s.commit()


# ----------------------------------------------------------------------------------- gevoelig en gepauzeerd: niet afleveren
def test_sensitive_events_are_never_handed_to_a_flow(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    r = b11.post_event(linked, fake_hub, b11.envelope(classification="sensitive"))
    assert r.status_code == 201, r.text
    assert r.json()["afleveringen"] == 0
    assert r.json()["catalog_detail"]["niet_afgeleverd_reden"] == "classificatie_sensitive"
    assert b11.claim(linked, token)["items"] == []


def test_paused_flow_gets_nothing_until_resumed(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    r = b11.put_flow(
        linked, auth, detail["id"], "state", {"status": "gepauzeerd", "reden": "onderhoud"}, role="operator"
    )
    assert r.status_code == 200, r.text
    r = b11.post_event(linked, fake_hub, b11.envelope())
    assert r.status_code == 201
    assert r.json()["afleveringen"] == 0
    assert r.json()["niet_afgeleverd"][0]["reden"] == "flow_gepauzeerd"
    claimed = b11.claim(linked, token)
    assert claimed["items"] == [] and claimed["flow_status"] == "gepauzeerd"


def _deliveries(linked: Any, auth: Any, flow_id: str) -> list[dict[str, Any]]:
    r = linked.get(f"{A}/deliveries", params={"flow_id": flow_id}, headers=auth("viewer"))
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["items"]
    return items


def test_waiting_delivery_is_held_back_while_the_flow_is_paused(
    linked: Any, fake_hub: Any, auth: Any, flow: Any
) -> None:
    """R-TECH-3: een aflevering die al wachtte toen de flow werd gepauzeerd, gaat pas na het hervatten naar de flow."""
    detail, token = flow
    assert b11.post_event(linked, fake_hub, b11.envelope()).json()["afleveringen"] == 1
    r = b11.put_flow(
        linked, auth, detail["id"], "state", {"status": "gepauzeerd", "reden": "onderhoud"}, role="operator"
    )
    assert r.status_code == 200, r.text
    claimed = b11.claim(linked, token)
    assert claimed["items"] == [] and claimed["flow_status"] == "gepauzeerd"
    assert [d["status"] for d in _deliveries(linked, auth, detail["id"])] == ["wachtend"]
    r = b11.put_flow(linked, auth, detail["id"], "state", {"status": "actief", "reden": "klaar"}, role="operator")
    assert r.status_code == 200, r.text
    items = b11.claim(linked, token)["items"]
    assert len(items) == 1 and items[0]["status"] == "geclaimd"


def test_blocked_flow_keeps_its_token_but_gets_nothing_and_may_request_nothing(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """R-TECH-3 en R-VEILIG-5 (ADR-0016 kop 2): een flow die geblokkeerd raakt terwijl er al afleveringen wachten,
    houdt zijn token, maar krijgt niets meer en mag niets aanvragen. Wat de flow nog wel kan: zijn eigen stand lezen
    (/me, met de reden) en een eerder opgehaalde aflevering bevestigen; die wordt niet opnieuw afgeleverd."""
    from tests.fakes.node_red_fake import exec_flow

    detail, token = flow
    assert b11.post_event(linked, fake_hub, b11.envelope()).json()["afleveringen"] == 1
    earlier = b11.claim(linked, token)["items"]
    assert len(earlier) == 1
    assert b11.post_event(linked, fake_hub, b11.envelope()).json()["afleveringen"] == 1  # wacht nog
    node_red_fake.deploy(exec_flow(tab_id=TAB, label="Nu met shell"))
    assert b11.snapshot(linked, auth)["geblokkeerd"] == [TAB]

    me = linked.get(f"{b11.FLOW_API}/me", headers=b11.bearer(token))
    assert me.status_code == 200, me.text
    assert me.json()["flow"]["status"] == "geblokkeerd" and me.json()["flow"]["blocked_reason"] == "verboden_node"
    claimed = b11.claim(linked, token)
    assert claimed["items"] == [] and claimed["flow_status"] == "geblokkeerd"
    assert sorted(d["status"] for d in _deliveries(linked, auth, detail["id"])) == ["geclaimd", "wachtend"]
    r = b11.request_action(linked, token, "notification.send", target={"type": "user", "id": "user-1"})
    assert r.status_code == 403 and r.json()["details"]["reason"] == "flow_geblokkeerd"
    # R-VEILIG-6: een verzoek dat ook om een andere reden niet mag, houdt die eigen reden (ADR-0016 kop 2)
    r = b11.request_action(linked, token, "energy.device.switch", target={"type": "device", "id": "lamp-1"})
    assert r.status_code == 403 and r.json()["details"]["reason"] == "onbekende_actie"
    assert b11.ack(linked, token, earlier[0]["id"]).status_code == 200
    assert b11.claim(linked, token)["items"] == []
    r = b11.post_event(linked, fake_hub, b11.envelope())
    assert r.json()["afleveringen"] == 0 and r.json()["niet_afgeleverd"][0]["reden"] == "flow_geblokkeerd"
    assert b11.outbox(linked, "flow.action.requested") == []


def test_too_long_chain_is_not_delivered_and_cannot_lead_to_a_request(
    linked: Any, fake_hub: Any, auth: Any, flow: Any
) -> None:
    """R-TECH-5 (ADR-0016 kop 3): een keten van herkomst van 8 of meer flows wordt niet afgeleverd, en een
    actieverzoek op een aflevering met zo'n keten wordt geweigerd (tweede laag)."""
    from sqlalchemy import update

    from integrations.domains.automation import inbox
    from integrations.domains.automation.models import AutomationEvent

    detail, token = flow
    others = [inbox.chain_entry(uuid.uuid4()) for _ in range(inbox.MAX_CHAIN)]
    r = b11.post_event(linked, fake_hub, b11.envelope(payload={"vermogen_w": 1, "origin_chain": others}))
    assert r.status_code == 201, r.text
    assert r.json()["afleveringen"] == 0
    assert r.json()["niet_afgeleverd"] == [{"flow_id": detail["id"], "reden": "keten_te_lang"}]
    # één korter: wel afgeleverd
    r = b11.post_event(linked, fake_hub, b11.envelope(payload={"vermogen_w": 1, "origin_chain": others[:-1]}))
    assert r.json()["afleveringen"] == 1, r.text
    item = b11.claim(linked, token)["items"][0]
    assert len(item["origin_chain"]) == inbox.MAX_CHAIN - 1
    with linked.app.state.db.sessions() as s:  # de keten van dat event is intussen te lang (bv. een oudere rij)
        s.execute(update(AutomationEvent).where(AutomationEvent.seq == item["event_seq"]).values(origin_chain=others))
        s.commit()
    r = b11.request_action(
        linked,
        token,
        "notification.send",
        target={"type": "user", "id": "user-1"},
        parameters={"tekst": "x"},
        trigger_delivery_id=item["id"],
    )
    assert r.status_code == 403 and r.json()["details"]["reason"] == "keten_te_lang", r.text
    assert b11.outbox(linked, "flow.action.requested") == []


def test_trigger_filter_limits_what_a_flow_gets(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    r = b11.put_flow(
        linked,
        auth,
        detail["id"],
        "triggers",
        {"triggers": [{"event_type": "app.health.changed", "filter": {"source_app": "mediaguard"}}]},
    )
    assert r.status_code == 200, r.text

    def health(app_id: str, about: str | None = None) -> dict[str, Any]:
        entity = {"type": "app", "id": about or app_id}
        return b11.envelope("app.health.changed", source_app=app_id, entity=entity, payload={"status": "down"})

    mine = health("mediaguard")
    assert b11.post_event(linked, fake_hub, health("jelly-leon")).json()["afleveringen"] == 0
    # §7: een app meldt alleen zijn eigen gezondheid; "mediaguard zegt dat jelly-leon down is" wordt niet afgeleverd
    spoofed = b11.post_event(linked, fake_hub, health("mediaguard", about="jelly-leon")).json()
    assert spoofed["afleveringen"] == 0 and spoofed["catalog_status"] == "buiten_domein"
    assert b11.post_event(linked, fake_hub, mine).json()["afleveringen"] == 1
    assert [i["event"]["event_id"] for i in b11.claim(linked, token)["items"]] == [mine["event_id"]]
