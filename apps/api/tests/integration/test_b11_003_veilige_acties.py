"""B11-003 — veilige acties: een flow vraagt een actie aan bij de Hub en voert zelf nooit iets uit.

Acceptatie: "Flow mag zonder admin geen dataset delete uitvoeren." Hier strenger uitgelegd (ADR-0016): een destructieve
actie kan via een flow helemaal niet worden aangevraagd; de boiler nooit, langs geen enkele route. Ook EX18 (risk_claim
telt niet), EX27 (boiler), EX45 (flow zonder admin) en EX46 (vijf keer hetzelfde event geeft één actie).
Sim-getest: de flow is een HTTP-client met een flow-token, de Hub is de nep-Hub. Dat de echte Hub het event
flow.action.requested omzet in een ActionProposal: NIET GEVALIDEERD (echte NAS; de Hub heeft daar nog geen afnemer voor).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from tests import b11
from tests.b11 import FLOW_API, A
from tests.conftest import idem, setup_node_red
from tests.fakes.node_red_fake import simple_flow

TAB = "tab0000000000001"
USER = {"type": "user", "id": "user-1"}
APP = {"type": "app", "id": "jellyfin"}
NOTIFY = {"titel": "Storing", "tekst": "De backup is mislukt."}


@pytest.fixture
def flow(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> tuple[dict[str, Any], str]:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    return b11.ready_flow(
        linked, auth, TAB, "notification.send", "app.*", triggers=("energy.reading.recorded", "action.run.executed")
    )


def _requests(linked: Any, auth: Any, **params: str) -> list[dict[str, Any]]:
    r = linked.get(f"{A}/action-requests", params=params or None, headers=auth("viewer"))
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["items"]
    return items


# --------------------------------------------------------------------------------------------- het flow-token (auth eerst)
def test_flow_api_refuses_before_reading_anything(linked: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    cases = [
        ({}, "flow_token_ontbreekt"),
        ({"Authorization": "Bearer flw_" + "x" * 43}, "flow_token_ongeldig"),
        ({"Authorization": "Bearer " + auth("admin")["Authorization"].split(" ", 1)[1]}, "flow_token_ongeldig"),
        ({"Authorization": f"Basic {token}"}, "flow_token_ontbreekt"),
    ]
    for headers, reason in cases:
        # ongeldige body én geen Idempotency-Key: toch 401 (authenticatie gaat voor alles)
        r = linked.post(
            f"{FLOW_API}/actions", content=b"{geen json", headers={**headers, "Content-Type": "application/json"}
        )
        assert r.status_code == 401, (reason, r.text)
        assert r.json()["code"] == "unauthorized" and r.json()["details"]["reason"] == reason
        assert r.headers["WWW-Authenticate"].startswith("Bearer")
        assert linked.get(f"{FLOW_API}/me", headers=headers).status_code == 401
    assert _requests(linked, auth) == []


def test_flow_api_mutations_need_an_idempotency_key(linked: Any, auth: Any, flow: Any) -> None:
    """Met een geldig flow-token maar zonder Idempotency-Key gebeurt er niets (contract §5)."""
    _, token = flow
    some_id = str(uuid.uuid4())
    for path in ("actions", "deliveries/claim", f"deliveries/{some_id}/ack", f"deliveries/{some_id}/nack"):
        r = linked.post(f"{FLOW_API}/{path}", json={}, headers=b11.bearer(token))
        assert r.status_code == 400 and r.json()["code"] == "idempotency_key_required", (path, r.text)
    assert _requests(linked, auth) == []


def test_flow_token_opens_nothing_but_the_flow_api(linked: Any, flow: Any) -> None:
    detail, token = flow
    h = b11.bearer(token)
    for method, path in [
        ("GET", f"{A}/flows"),
        ("GET", f"{A}/editor"),
        ("GET", f"{A}/snapshots"),
        ("GET", "/integrations/v1/sources"),
        ("GET", "/connector/v1/discover"),
        ("POST", "/connector/v1/propose"),
        ("POST", "/connector/v1/apply"),
        ("POST", f"{A}/flows/{detail['id']}/tokens"),
        ("PUT", f"{A}/flows/{detail['id']}/state"),
    ]:
        r = linked.request(method, path, json={}, headers=idem(h))
        assert r.status_code == 401, (method, path, r.status_code)


def test_me_shows_what_the_flow_may_do(linked: Any, flow: Any) -> None:
    detail, token = flow
    r = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["flow"]["id"] == detail["id"] and body["flow"]["status"] == "actief"
    assert body["token"]["allowed_actions"] == ["notification.send", "app.*"]
    assert "boiler_nooit" in body["nooit"] and "destructief_verboden" in body["nooit"]
    assert token not in r.text


def test_token_is_shown_once_and_only_its_hash_is_kept(linked: Any, auth: Any, flow: Any) -> None:
    detail, _ = flow
    key = str(uuid.uuid4())
    body = {"label": "tweede", "allowed_actions": ["notification.send"]}
    first = linked.post(f"{A}/flows/{detail['id']}/tokens", json=body, headers=idem(auth("admin"), key=key))
    assert first.status_code == 201, first.text
    token = first.json()["flow_token"]
    assert token.startswith("flw_")
    again = linked.post(f"{A}/flows/{detail['id']}/tokens", json=body, headers=idem(auth("admin"), key=key))
    assert again.status_code == 201 and again.json()["flow_token"] is None and "herhaling_nl" in again.json()
    listed = linked.get(f"{A}/flows/{detail['id']}/tokens", headers=auth("operator")).json()["items"]
    assert {t["last4"] for t in listed} >= {token[-4:]}
    assert token not in b11.everything_stored(linked)
    assert linked.get(f"{A}/flows/{detail['id']}/tokens", headers=auth("viewer")).status_code == 403


def test_revoked_token_stops_working_at_once(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    token_id = linked.get(f"{A}/flows/{detail['id']}/tokens", headers=auth("admin")).json()["items"][0]["id"]
    r = linked.post(f"{A}/flows/{detail['id']}/tokens/{token_id}/revoke", headers=idem(auth("admin")))
    assert r.status_code == 200, r.text
    r = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token))
    assert r.status_code == 401 and r.json()["details"]["reason"] == "flow_token_ingetrokken"
    assert len(b11.outbox(linked, "flow.access.revoked")) == 1


def test_token_scope_cannot_contain_forbidden_actions(linked: Any, auth: Any, flow: Any) -> None:
    detail, _ = flow
    for scope in (
        ["*"],
        ["zfs.dataset.delete"],
        ["energy.boiler.switch"],
        ["system.shell.exec"],
        ["Niet Goed"],
        # fail-closed (R-VEILIG-1): alleen acties van de vaste lijst, of een patroon dat er minstens één dekt
        ["energy.*"],
        ["media.*"],
        ["energy.device.switch"],
        ["zfs.dataset.rm"],
    ):
        r = linked.post(
            f"{A}/flows/{detail['id']}/tokens",
            json={"label": "x", "allowed_actions": scope},
            headers=idem(auth("admin")),
        )
        assert r.status_code == 422, (scope, r.text)
        assert r.json()["code"] == "scope_ongeldig", scope


def test_flow_without_owner_gets_no_token(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    detail = b11.flow_by_tab(linked, auth, TAB)
    r = linked.post(
        f"{A}/flows/{detail['id']}/tokens",
        json={"label": "x", "allowed_actions": ["notification.send"]},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 409 and r.json()["code"] == "flow_zonder_eigenaar"
    for role in ("operator", "viewer"):
        r = linked.post(f"{A}/flows/{detail['id']}/tokens", json={}, headers=idem(auth(role)))
        assert r.status_code == 403


# ------------------------------------------------------------------------------------------------ een actie aanvragen
def test_action_is_requested_at_the_hub_and_never_executed_here(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    detail, token = flow
    key = str(uuid.uuid4())
    r = b11.request_action(
        linked, token, "app.restart", target=APP, reason="Jellyfin reageert niet", key=key, risk_claim="R0"
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["status"] == "aangevraagd" and body["ontdubbeld"] is False
    assert body["owner"] == "user-1"
    # EX18: wat de flow zelf over het risico zegt, telt niet
    assert body["risk_claim"] == "R0"
    assert body["risk_preview"]["klasse_min"] == "R1" and body["risk_preview"]["risk_claim_genegeerd"] is True
    assert "deze dienst voert niets uit" in body["uitvoering"]

    requested = b11.outbox(linked, "flow.action.requested")
    assert len(requested) == 1
    env = requested[0]
    assert env["actor"] == {"type": "flow", "id": f"flow:{detail['id']}"}
    assert env["correlation_id"] == body["id"]
    payload = env["payload"]
    assert payload["action_id"] == "app.restart" and payload["target"] == APP
    assert payload["idempotency_key"] == key and payload["action_request_id"] == body["id"]
    assert payload["actor"] == env["actor"] and payload["owner"] == "user-1"
    assert payload["origin_chain"] == [f"flow:{detail['id']}"]
    assert payload["risk_claim_genegeerd"] is True and "risk_claim" not in payload
    # dezelfde Idempotency-Key: hetzelfde antwoord, geen tweede verzoek
    again = b11.request_action(
        linked, token, "app.restart", target=APP, reason="Jellyfin reageert niet", key=key, risk_claim="R0"
    )
    assert again.status_code == 202 and again.json()["id"] == body["id"]
    assert len(b11.outbox(linked, "flow.action.requested")) == 1
    # er is niets naar Node-RED geschreven en geen enkele andere bron aangeraakt
    assert node_red_fake.writes == []
    assert linked.get(f"{FLOW_API}/actions/{body['id']}", headers=b11.bearer(token)).json()["status"] == "aangevraagd"


def test_requested_action_reaches_the_hub_inbox(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, make_settings: Any
) -> None:
    from integrations.worker import Worker

    _, token = flow
    r = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert r.status_code == 202, r.text
    Worker(make_settings(), transport=fake_hub.transport).push_step()
    received = [e for e in fake_hub.inbox if e["event_type"] == "flow.action.requested"]
    assert len(received) == 1 and received[0]["payload"]["action_request_id"] == r.json()["id"]
    assert fake_hub.rejected == [], "de Hub accepteert de envelope (contract §7)"


# ------------------------------------------------------------------------------------------- wat een flow nooit mag
@pytest.mark.parametrize(
    ("action_id", "target", "parameters", "reason"),
    [
        ("zfs.dataset.delete", {"type": "dataset", "id": "media/films"}, {}, "destructief_verboden"),
        ("zfs.dataset.destroy", {"type": "dataset", "id": "media/films"}, {"recursive": True}, "destructief_verboden"),
        ("app.uninstall_data", APP, {}, "destructief_verboden"),
        ("media.library.purge", {"type": "library", "id": "films"}, {}, "destructief_verboden"),
        ("energy.boiler.switch", {"type": "device", "id": "b1"}, {"aan": True}, "boiler_nooit"),
        ("energy.device.switch", {"type": "device", "id": "boiler"}, {"aan": True}, "boiler_nooit"),
        ("energy.device.switch", {"type": "device", "id": "stekker-3"}, {"naam": "Warmwater"}, "boiler_nooit"),
        ("system.shell.exec", {"type": "host", "id": "nas"}, {"cmd": "id"}, "shell_verboden"),
        ("app.exec.run", APP, {}, "shell_verboden"),
        # fail-closed (R-VEILIG-1): onder een andere naam verwijderen, terugdraaien of schakelen kan ook niet
        ("zfs.dataset.rm", {"type": "dataset", "id": "media/films"}, {}, "onbekende_actie"),
        ("zfs.dataset.destroyrecursive", {"type": "dataset", "id": "media"}, {}, "onbekende_actie"),
        ("zfs.snapshot.rollback", {"type": "dataset", "id": "media"}, {}, "onbekende_actie"),
        ("media.file.trash", {"type": "file", "id": "film-1"}, {}, "onbekende_actie"),
        ("energy.device.switch", {"type": "device", "id": "shelly-plug-3"}, {"aan": True}, "onbekende_actie"),
        ("energy.device.switch", {"type": "device", "id": "boi\u200bler"}, {"aan": True}, "ongeldige_tekens"),
        ("app.restart", APP, {"apparaat": "boi\u200bler"}, "boiler_nooit"),
        # HARDE EIS (R-HARDE-EIS-3): Emby wordt door het platform nooit gestopt, bijgewerkt of verwijderd
        ("app.stop", {"type": "app", "id": "emby"}, {}, "emby_nooit_door_platform"),
        ("app.uninstall", {"type": "app", "id": "embyserver"}, {}, "emby_nooit_door_platform"),
    ],
)
def test_forbidden_actions_are_refused_and_recorded(
    linked: Any, auth: Any, flow: Any, action_id: str, target: dict[str, Any], parameters: dict[str, Any], reason: str
) -> None:
    _, token = flow
    r = b11.request_action(linked, token, action_id, target=target, parameters=parameters)
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["code"] == "forbidden" and body["details"]["reason"] == reason
    assert uuid.UUID(body["trace_id"])
    # vastgelegd, zichtbaar voor de beheerder, en gemeld — maar nooit aangevraagd bij de Hub
    rows = _requests(linked, auth, status="geweigerd")
    assert [(x["action_id"], x["rejected_reason"]) for x in rows] == [(action_id, reason)]
    assert rows[0]["id"] == body["details"]["action_request_id"]
    assert b11.outbox(linked, "flow.action.requested") == []
    rejected = b11.outbox(linked, "flow.action.rejected")
    assert (
        len(rejected) == 1 and rejected[0]["payload"]["reden"] == reason and rejected[0]["payload"]["ernst"] == "hoog"
    )
    assert any(
        a["action"] == "automation.action.rejected" and a["details"]["reden"] == reason for a in b11.audit_rows(linked)
    )


def test_dataset_delete_is_refused_even_with_admin_issued_wide_scope(linked: Any, auth: Any, flow: Any) -> None:
    """De acceptatie-eis letterlijk: ook een door de beheerder ruim ingesteld token maakt een dataset delete niet mogelijk."""
    detail, _ = flow
    r = linked.post(
        f"{A}/flows/{detail['id']}/tokens",
        json={"label": "ruim", "allowed_actions": ["zfs.*", "app.*", "notification.send"]},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 201, r.text
    wide = r.json()["flow_token"]
    r = b11.request_action(linked, wide, "zfs.dataset.delete", target={"type": "dataset", "id": "media"})
    assert r.status_code == 403 and r.json()["details"]["reason"] == "destructief_verboden"
    # een niet-destructieve actie binnen dezelfde scope kan wel worden aangevraagd (de Hub beslist dan verder)
    r = b11.request_action(linked, wide, "zfs.snapshot.create", target={"type": "dataset", "id": "media"})
    assert r.status_code == 202, r.text
    assert r.json()["risk_preview"]["klasse_min"] == "R1"


def test_renamed_destructive_actions_never_reach_the_hub_even_with_a_wide_scope(
    linked: Any, auth: Any, flow: Any
) -> None:
    """R-VEILIG-1: met de ruimste scope die uit te geven is, gaat geen actie buiten de vaste lijst naar de Hub."""
    detail, _ = flow
    r = linked.post(
        f"{A}/flows/{detail['id']}/tokens",
        json={"label": "ruim", "allowed_actions": ["zfs.*", "app.*", "notification.send"]},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 201, r.text
    wide = r.json()["flow_token"]
    attempts = {
        "zfs.dataset.rm": {"type": "dataset", "id": "media"},
        "zfs.dataset.destroyrecursive": {"type": "dataset", "id": "media"},
        "zfs.snapshot.rollback": {"type": "dataset", "id": "media"},
        "app.uninstall_everything": APP,
        "app.stop": {"type": "app", "id": "emby"},
    }
    answers = {a: b11.request_action(linked, wide, a, target=t) for a, t in attempts.items()}
    assert {a: (r.status_code, r.json()["details"]["reason"]) for a, r in answers.items()} == {
        "zfs.dataset.rm": (403, "onbekende_actie"),
        "zfs.dataset.destroyrecursive": (403, "onbekende_actie"),
        "zfs.snapshot.rollback": (403, "onbekende_actie"),
        "app.uninstall_everything": (403, "onbekende_actie"),
        "app.stop": (403, "emby_nooit_door_platform"),
    }
    assert b11.outbox(linked, "flow.action.requested") == []
    assert len(b11.outbox(linked, "flow.action.rejected")) == len(attempts)
    # wat wél op de lijst staat kan binnen dezelfde scope nog steeds worden aangevraagd (de Hub beslist verder)
    assert (
        b11.request_action(linked, wide, "zfs.snapshot.create", target={"type": "dataset", "id": "m"}).status_code
        == 202
    )


def test_boiler_word_in_a_notification_text_is_allowed(linked: Any, flow: Any) -> None:
    """Een melding óver de boiler schakelt niets; alleen de vrije tekst van notification.send wordt niet gescand."""
    _, token = flow
    r = b11.request_action(
        linked, token, "notification.send", target=USER, parameters={"titel": "Boiler", "tekst": "De boiler staat aan."}
    )
    assert r.status_code == 202, r.text
    r = b11.request_action(
        linked, token, "notification.send", target={"type": "device", "id": "boiler"}, parameters=NOTIFY
    )
    assert r.status_code == 403 and r.json()["details"]["reason"] == "boiler_nooit"


def test_action_outside_the_token_scope_is_refused(linked: Any, flow: Any) -> None:
    _, token = flow
    r = b11.request_action(linked, token, "zfs.snapshot.create", target={"type": "dataset", "id": "media"})
    assert r.status_code == 403 and r.json()["details"]["reason"] == "buiten_scope"


def test_secret_in_parameters_is_refused_and_not_stored(linked: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    secret = "sk-live-" + "a1B2c3D4" * 5
    r = b11.request_action(
        linked, token, "notification.send", target=USER, parameters={"api_key": secret, "tekst": "x"}
    )
    assert r.status_code == 403, r.text
    assert r.json()["details"]["reason"] == "geheim_in_parameters"
    assert secret not in b11.everything_stored(linked)
    row = _requests(linked, auth)[0]
    assert row["parameters"] == {} and row["target"] == {}


def test_blocked_or_paused_flow_cannot_request_actions(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    r = b11.put_flow(linked, auth, detail["id"], "state", {"status": "gepauzeerd", "reden": "test"})
    assert r.status_code == 200
    r = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert r.status_code == 403 and r.json()["details"]["reason"] == "flow_niet_actief"


def test_too_large_parameters_are_refused(linked: Any, flow: Any) -> None:
    _, token = flow
    r = b11.request_action(linked, token, "notification.send", target=USER, parameters={"tekst": "x" * 9000})
    assert r.status_code == 422 and r.json()["code"] == "parameters_te_groot"


@pytest.mark.parametrize(
    ("field", "raw"),
    [
        ("target", '{"type":"user","id":"user-1\\ud800"}'),
        ("target", '{"type":"user","\\udfff":"user-1"}'),
        ("parameters", '{"tekst":"x\\ud800"}'),
        ("parameters", '{"lijst":[{"diep":"\\udc00"}]}'),
    ],
)
def test_lone_surrogate_in_target_or_parameters_is_a_422(
    linked: Any, auth: Any, flow: Any, field: str, raw: str
) -> None:
    """Vervolgpunt R-VEILIG-5 (S-P2-295): een losse surrogaat (geldige JSON-escape, maar geen tekst die in UTF-8 kan)
    in het doel of de parameters gaf bij de groottecontrole een serverfout (500). Nu is het een invoerfout (422
    ``validation_error`` met het veld); er wordt niets vastgelegd en niets naar de Hub gestuurd."""
    _, token = flow
    body = {"target": '{"type":"user","id":"user-1"}', "parameters": '{"tekst":"x"}'}
    body[field] = raw
    target, parameters = body["target"], body["parameters"]
    content = f'{{"action_id":"notification.send","target":{target},"parameters":{parameters},"reason":"test"}}'
    r = linked.post(
        f"{FLOW_API}/actions",
        content=content,
        headers={**idem(b11.bearer(token)), "Content-Type": "application/json"},
    )
    assert r.status_code == 422, r.text
    assert r.json()["code"] == "validation_error"
    assert [f["veld"] for f in r.json()["details"]["fouten"]] == [field], r.text
    assert _requests(linked, auth) == []
    assert b11.outbox(linked, "flow.action.requested") == [] and b11.outbox(linked, "flow.action.rejected") == []
    ok = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert ok.status_code == 202, ok.text


def test_reason_is_required(linked: Any, flow: Any) -> None:
    _, token = flow
    r = linked.post(
        f"{FLOW_API}/actions",
        json={"action_id": "notification.send", "target": USER, "parameters": NOTIFY},
        headers=idem(b11.bearer(token)),
    )
    assert r.status_code == 422


# ------------------------------------------------------------------------------- EX46: vijf events, één actie; en grenzen
def test_same_event_five_times_gives_one_action(linked: Any, fake_hub: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    env = b11.envelope(source_event_id="meter-1:piek-7")
    statuses = [b11.post_event(linked, fake_hub, env).status_code for _ in range(5)]
    assert statuses == [201, 200, 200, 200, 200]
    stored = linked.get(f"{A}/events", headers=auth("viewer")).json()["items"]
    assert [e["event_id"] for e in stored] == [env["event_id"]], "vijf keer hetzelfde event: één rij"
    items = b11.claim(linked, token)["items"]
    assert len(items) == 1
    answers = [
        b11.request_action(
            linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=items[0]["id"]
        )
        for _ in range(5)
    ]
    assert [a.status_code for a in answers] == [202, 200, 200, 200, 200]
    assert {a.json()["id"] for a in answers} == {answers[0].json()["id"]}
    assert [a.json()["ontdubbeld"] for a in answers] == [False, True, True, True, True]
    assert len(b11.outbox(linked, "flow.action.requested")) == 1
    assert len(_requests(linked, auth)) == 1
    assert b11.outbox(linked, "flow.action.requested")[0]["payload"]["evidence_ids"] == [env["event_id"]]


def test_trigger_of_another_flow_is_refused(linked: Any, flow: Any) -> None:
    _, token = flow
    r = b11.request_action(
        linked, token, "notification.send", target=USER, parameters=NOTIFY, trigger_delivery_id=str(uuid.uuid4())
    )
    assert r.status_code == 422 and r.json()["code"] == "trigger_ongeldig"


def test_rate_limit_per_flow_and_action(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    r = b11.put_flow(
        linked,
        auth,
        detail["id"],
        "rate-limits",
        {"rate_limits": [{"action_id": "notification.send", "max_per_hour": 2, "cooldown_s": 0}]},
    )
    assert r.status_code == 200, r.text
    for _ in range(2):
        assert b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY).status_code == 202
    r = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert r.status_code == 429, r.text
    assert r.json()["code"] == "rate_limited" and int(r.headers["Retry-After"]) >= 1
    assert len(_requests(linked, auth)) == 2, "een afgeremd verzoek wordt niet vastgelegd"
    # een andere actie heeft haar eigen teller
    assert b11.request_action(linked, token, "app.restart", target=APP).status_code == 202
    # ruimer dan de standaard kan niet
    r = b11.put_flow(
        linked,
        auth,
        detail["id"],
        "rate-limits",
        {"rate_limits": [{"action_id": "*", "max_per_hour": 31, "cooldown_s": 0}]},
    )
    assert r.status_code == 422


def test_star_limit_counts_all_actions_of_the_flow_together(linked: Any, auth: Any, flow: Any) -> None:
    """R-VEILIG-2: ``*`` is een grens voor de hele flow, niet een terugval per actie."""
    detail, token = flow
    r = b11.put_flow(
        linked,
        auth,
        detail["id"],
        "rate-limits",
        {"rate_limits": [{"action_id": "*", "max_per_hour": 1, "cooldown_s": 0}]},
    )
    assert r.status_code == 200, r.text
    assert b11.request_action(linked, token, "app.restart", target=APP).status_code == 202
    for other in ("app.stop", "app.start", "notification.send"):
        r = b11.request_action(linked, token, other, target=APP if other != "notification.send" else USER)
        assert r.status_code == 429, (other, r.text)
        assert r.json()["details"]["limiet"]["geldt_voor"] == "*"
    assert len(_requests(linked, auth)) == 1
    assert len(b11.outbox(linked, "flow.action.requested")) == 1


def test_a_flow_has_a_fixed_limit_over_all_its_requests(linked: Any, auth: Any, flow: Any) -> None:
    """R-VEILIG-2: ook zonder eigen grens geeft een ruime scope geen onbegrensde stroom verzoeken (en events) naar de
    Hub: na FLOW_MAX_PER_HOUR verzoeken per uur, ook geweigerde en met steeds een andere actie, volgt 429."""
    from integrations.domains.automation import actions

    detail, _ = flow
    r = linked.post(
        f"{A}/flows/{detail['id']}/tokens",
        json={"label": "ruim", "allowed_actions": ["zfs.*", "app.*", "notification.send"]},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 201, r.text
    wide = r.json()["flow_token"]
    allowed = sorted(actions.FLOW_ACTIONS)
    unknown = [f"onbekend.actie.n{i}" for i in range(actions.FLOW_MAX_PER_HOUR - len(allowed))]
    statuses = []
    for action_id in [*allowed, *unknown]:
        target = USER if action_id == "notification.send" else APP
        params = NOTIFY if action_id == "notification.send" else {}
        statuses.append(b11.request_action(linked, wide, action_id, target=target, parameters=params).status_code)
    assert statuses.count(202) == len(allowed) and statuses.count(403) == len(unknown), statuses
    assert len(statuses) == actions.FLOW_MAX_PER_HOUR == 30
    r = b11.request_action(linked, wide, "app.restart", target=APP)
    assert r.status_code == 429, r.text
    assert r.json()["details"]["limiet"] == {"max_per_uur": 30, "wachttijd_s": 0, "geldt_voor": "*"}
    assert int(r.headers["Retry-After"]) >= 1
    sent = len(b11.outbox(linked, "flow.action.requested")) + len(b11.outbox(linked, "flow.action.rejected"))
    assert sent == actions.FLOW_MAX_PER_HOUR, "na de grens gaat er niets meer naar de Hub"


def test_cooldown_between_requests(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    r = b11.put_flow(
        linked,
        auth,
        detail["id"],
        "rate-limits",
        {"rate_limits": [{"action_id": "*", "max_per_hour": 30, "cooldown_s": 60}]},
    )
    assert r.status_code == 200, r.text
    assert b11.request_action(linked, token, "app.restart", target=APP).status_code == 202
    r = b11.request_action(linked, token, "app.restart", target=APP)
    assert r.status_code == 429 and 1 <= int(r.headers["Retry-After"]) <= 60


def test_no_request_without_a_hub_link(linked: Any, auth: Any, flow: Any) -> None:
    _, token = flow
    linked.app.state.hublink.unlink(trace_id=str(uuid.uuid4()), actor=("user", "user-1"))
    r = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert r.status_code == 503, r.text
    assert r.json()["code"] == "hub_unavailable" and r.json()["details"]["reason"] == "niet_gekoppeld"
    assert r.headers["Retry-After"] == "60"
    assert b11.outbox(linked, "flow.action.requested") == []


# --------------------------------------------------------------------------------- lussen: een flow triggert zichzelf niet
def test_event_caused_by_a_flows_own_action_is_not_delivered_back(
    linked: Any, fake_hub: Any, auth: Any, flow: Any
) -> None:
    detail, token = flow
    first = b11.request_action(linked, token, "app.restart", target=APP).json()
    # de Hub voert uit en stuurt het resultaat als event terug, met de correlation_id van het verzoek
    env = b11.envelope(
        "action.run.executed",
        source_app="ai-server-manager",
        entity={"type": "action_run", "id": "run-1"},
        payload={"action_id": "app.restart"},
        correlation_id=first["id"],
    )
    r = b11.post_event(linked, fake_hub, env)
    assert r.status_code == 201, r.text
    assert r.json()["afleveringen"] == 0
    assert r.json()["niet_afgeleverd"] == [{"flow_id": detail["id"], "reden": "lus_gedetecteerd"}]
    assert b11.claim(linked, token)["items"] == []
    # hetzelfde event zonder die herkomst wordt wel afgeleverd
    r = b11.post_event(
        linked, fake_hub, {**env, "event_id": str(uuid.uuid4()), "source_event_id": "run-2", "correlation_id": None}
    )
    assert r.json()["afleveringen"] == 1


# ------------------------------------------------------------------------------------------- wat de Hub terugmeldt
def test_hub_reports_the_outcome_and_final_states_do_not_change(
    linked: Any, fake_hub: Any, auth: Any, flow: Any
) -> None:
    _, token = flow
    row = b11.request_action(linked, token, "app.update", target=APP, risk_claim="R0").json()
    assert row["risk_preview"]["klasse_min"] == "R2" and row["risk_preview"]["goedkeuring_vereist"] is True
    url = f"{A}/action-requests/{row['id']}/result"
    waiting = {"status": "wacht_op_goedkeuring", "hub_proposal_id": "prop-1", "hub_risk_class": "R2"}
    # alleen de Hub (dienst-JWT) mag dit melden
    assert linked.post(url, json=waiting, headers=idem(auth("admin"))).status_code == 403
    assert linked.post(url, json=waiting, headers=idem(b11.bearer(token))).status_code == 401
    r = linked.post(url, json=waiting, headers=idem(fake_hub.service_auth()))
    assert r.status_code == 200, r.text
    seen = linked.get(f"{FLOW_API}/actions/{row['id']}", headers=b11.bearer(token)).json()
    assert seen["status"] == "wacht_op_goedkeuring" and seen["hub_risk_class"] == "R2"
    refused = {"status": "geweigerd", "reason": "beheerder_weigert", "result": {"api_key": "sk-live-" + "Z9" * 20}}
    r = linked.post(url, json=refused, headers=idem(fake_hub.service_auth()))
    assert r.status_code == 200 and r.json()["rejected_reason"] == "beheerder_weigert"
    assert "sk-live-" not in r.text, "een geheim in het resultaat wordt gemaskeerd bewaard"
    r = linked.post(url, json={"status": "uitgevoerd"}, headers=idem(fake_hub.service_auth()))
    assert r.status_code == 409 and r.json()["code"] == "actieverzoek_afgerond"
    assert (
        linked.post(
            f"{A}/action-requests/{uuid.uuid4()}/result", json=waiting, headers=idem(fake_hub.service_auth())
        ).status_code
        == 404
    )


def test_flow_cannot_read_requests_of_another_flow(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    other_tab = "tabtwee000000002"
    setup_node_red(linked, fake_hub, auth, flows=[*simple_flow(), *simple_flow(tab_id=other_tab, label="Tweede flow")])
    b11.snapshot(linked, auth)
    _, token_a = b11.ready_flow(linked, auth, TAB, "notification.send")
    _, token_b = b11.ready_flow(linked, auth, other_tab, "notification.send")
    row = b11.request_action(linked, token_a, "notification.send", target=USER, parameters=NOTIFY).json()
    assert linked.get(f"{FLOW_API}/actions/{row['id']}", headers=b11.bearer(token_a)).status_code == 200
    assert linked.get(f"{FLOW_API}/actions/{row['id']}", headers=b11.bearer(token_b)).status_code == 404


def test_removing_the_owner_revokes_the_tokens(linked: Any, auth: Any, flow: Any) -> None:
    detail, token = flow
    r = b11.put_flow(linked, auth, detail["id"], "owner", {"owner": "", "eigenaren": []})
    assert r.status_code == 200, r.text
    r = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token))
    assert r.status_code == 401 and r.json()["details"]["reason"] == "flow_token_ingetrokken"


def test_tokens_of_a_flow_that_disappears_from_node_red_are_revoked_for_good(
    linked: Any, auth: Any, flow: Any, node_red_fake: Any
) -> None:
    """R-TECH-4: verdwijnt het tabblad uit Node-RED, dan worden de tokens ingetrokken; komt een tabblad met hetzelfde
    id terug (de flow wordt dan weer actief), dan werken de oude tokens niet weer."""
    detail, token = flow
    node_red_fake.deploy(simple_flow(tab_id="tabander00000001", label="Ander"))
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "verwijderd"
    tokens = linked.get(f"{A}/flows/{detail['id']}/tokens", headers=auth("admin")).json()["items"]
    assert [(t["status"], t["revoked_reason"]) for t in tokens] == [("ingetrokken", "flow_verwijderd")]
    r = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token))
    assert r.status_code == 401 and r.json()["details"]["reason"] == "flow_token_ingetrokken"

    node_red_fake.deploy(simple_flow())  # hetzelfde tabblad komt terug
    b11.snapshot(linked, auth)
    assert b11.flow_detail(linked, auth, detail["id"])["status"] == "actief"
    r = linked.get(f"{FLOW_API}/me", headers=b11.bearer(token))
    assert r.status_code == 401 and r.json()["details"]["reason"] == "flow_token_ingetrokken"
    r = b11.request_action(linked, token, "notification.send", target=USER, parameters=NOTIFY)
    assert r.status_code == 401


def test_flow_settings_need_if_match(linked: Any, auth: Any, flow: Any) -> None:
    detail, _ = flow
    body = {"status": "gepauzeerd", "reden": "x"}
    url = f"{A}/flows/{detail['id']}/state"
    assert linked.put(url, json=body, headers=idem(auth("admin"))).status_code == 428
    r = linked.put(url, json=body, headers=idem(auth("admin"), **{"If-Match": 'W/"cfg-0000000000000000"'}))
    assert r.status_code == 412
    r = linked.put(url, json=body, headers=idem(auth("admin"), **{"If-Match": detail["etag"]}))
    assert r.status_code == 200 and r.headers["ETag"] != detail["etag"]
    assert linked.put(url, json=body, headers=idem(auth("viewer"), **{"If-Match": "*"})).status_code == 403
