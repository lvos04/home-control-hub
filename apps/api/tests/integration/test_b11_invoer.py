"""B11 — tekst die niet op te slaan is, geeft nooit een serverfout (vervolgpunt 5 van S-P2-300, stap S-P2-310).

Een losse surrogaat (een geldige JSON-escape zoals ``\\ud800``, maar geen tekst die in UTF-8 kan) of een NUL-teken
(``\\u0000``, dat PostgreSQL niet opslaat) in een tekstveld van de beheer-API (eigenaar, notitie, reden, label,
triggers, toegestane acties, voorbeelden), in een actieverzoek van een flow, in een onbekende veldnaam of in wat de
Hub aanbiedt (een event, de uitkomst van een actieverzoek), is een invoerfout: ``422``, nooit ``500``. Er wordt dan
niets vastgelegd: geen auditregel, geen event, geen wijziging aan de flow en geen actieverzoek. Dezelfde route met
gewone tekst werkt gewoon, zodat vaststaat dat de ``422`` door dat ene teken komt. Een losse surrogaat in het doel of de
parameters van een actieverzoek staat ook in
``test_b11_003_veilige_acties.py::test_lone_surrogate_in_target_or_parameters_is_a_422``.

Eén uitzondering (R-VEILIG-3 van S-P2-310, ADR-0016 kop 4): vraagt een flow een actie aan die op de harde weigerlijst
staat (zoals een dataset verwijderen of de boiler schakelen), dan is het antwoord de vastgelegde weigering (``403``,
rij, audit, ``flow.action.rejected``), zonder doel, parameters en reden; het teken staat nergens. Een cursor met zo'n
teken is ``400 invalid_cursor`` (R-VEILIG-2 en R-TECH-2 van S-P2-310).
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

import pytest

from tests import b11
from tests.b11 import FLOW_API, A
from tests.conftest import idem, setup_node_red
from tests.fakes.node_red_fake import simple_flow

TAB = "tab0000000000001"
#: zo staan ze in de ruwe JSON: json.loads maakt er een losse surrogaat en een NUL-teken van
SURROGATE = "\\ud800"
NUL = "\\u0000"
BAD = {"surrogaat": SURROGATE, "nul": NUL}
CODES = {"validation_error", "trigger_ongeldig"}


@pytest.fixture
def flow(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> tuple[dict[str, Any], str]:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    return b11.ready_flow(linked, auth, TAB, "notification.send", triggers=("energy.reading.recorded",))


def _send(linked: Any, method: str, path: str, raw: str, headers: dict[str, str]) -> Any:
    return linked.request(
        method, path, content=raw.encode("ascii"), headers={**headers, "Content-Type": "application/json"}
    )


def _state(linked: Any, auth: Any, flow_id: str) -> tuple[Any, ...]:
    """Wat er niet mag veranderen: auditregels, eigen events, de flow (ETag), tokens, proefruns en actieverzoeken."""
    detail = b11.flow_detail(linked, auth, flow_id)
    tokens = linked.get(f"{A}/flows/{flow_id}/tokens", headers=auth("admin")).json()["items"]
    runs = linked.get(f"{A}/runs", headers=auth("viewer")).json()["items"]
    requests = linked.get(f"{A}/action-requests", headers=auth("viewer")).json()["items"]
    return len(b11.audit_rows(linked)), len(b11.outbox(linked)), detail["etag"], len(tokens), len(runs), requests


def _refused(r: Any, codes: set[str]) -> None:
    """Een invoerfout (422) met een vaste foutcode en een leesbaar antwoord; nooit een serverfout."""
    assert r.status_code == 422, (r.status_code, r.text)
    body = r.json()
    assert body["code"] in codes, body
    assert "\ud800" not in r.text and "\x00" not in r.text


def _admin_cases(flow_id: str, s: str) -> dict[str, tuple[str, str, str, str]]:
    """``naam -> (methode, pad, ruwe body met het teken, dezelfde body zonder)``; elke body is verder geldig."""
    f = f"{A}/flows/{flow_id}"
    owner = '{"owner":"user-2","eigenaren":[]}'
    trigger = '{"event_type":"energy.reading.recorded","schema_version":"1.0","filter":{}}'
    cases = {
        "eigenaar": ("PUT", f"{f}/owner", owner.replace("user-2", f"user-2{s}")),
        "notitie": (
            "PUT",
            f"{f}/owner",
            f'{{"owner":"user-2","eigenaren":[{{"principal":"user-3","role":"lezer","note":"x{s}"}}]}}',
        ),
        "reden": ("PUT", f"{f}/state", f'{{"status":"gepauzeerd","reden":"onderhoud {s}"}}'),
        "label": ("POST", f"{f}/tokens", f'{{"label":"tweede {s}","allowed_actions":["notification.send"]}}'),
        "toegestane_actie": ("POST", f"{f}/tokens", f'{{"label":"tweede","allowed_actions":["notification.send{s}"]}}'),
        "trigger_type": ("PUT", f"{f}/triggers", '{"triggers":[' + trigger.replace("recorded", f"recorded{s}") + "]}"),
        "trigger_versie": ("PUT", f"{f}/triggers", '{"triggers":[' + trigger.replace('"1.0"', f'"1.0{s}"') + "]}"),
        "trigger_filter": (
            "PUT",
            f"{f}/triggers",
            '{"triggers":[' + trigger.replace("{}", f'{{"source_app":"home-control-hub{s}"}}') + "]}",
        ),
        "grens": ("PUT", f"{f}/rate-limits", f'{{"rate_limits":[{{"action_id":"app.restart{s}","max_per_hour":1}}]}}'),
        "voorbeeld": ("POST", f"{f}/runs", f'{{"sample_ids":["energie-meting{s}"],"bevestig_niet_afgeschermd":true}}'),
    }
    out = {name: (m, p, raw, raw.replace(s, "")) for name, (m, p, raw) in cases.items()}
    # een onbekende veldnaam met het teken; zonder dat veld is de body geldig
    out["onbekende_veldnaam"] = ("PUT", f"{f}/owner", owner[:-1] + f',"x{s}":1}}', owner)
    out["profiel_veldnaam"] = ("POST", f"{A}/hardening-profile", f'{{"x{s}":true}}', "{}")
    return out


ADMIN_CASES = list(_admin_cases("x", SURROGATE))


@pytest.mark.parametrize("bad", list(BAD))
@pytest.mark.parametrize("case", ADMIN_CASES)
def test_unstorable_text_in_a_management_route_is_a_422_and_changes_nothing(
    linked: Any, auth: Any, flow: Any, case: str, bad: str
) -> None:
    detail, _ = flow
    method, path, raw, valid = _admin_cases(detail["id"], BAD[bad])[case]
    before = _state(linked, auth, detail["id"])
    r = _send(linked, method, path, raw, idem(auth("admin"), **{"If-Match": "*"}))
    _refused(r, CODES | ({"voorbeeld_onbekend"} if case == "voorbeeld" else set()))
    assert _state(linked, auth, detail["id"]) == before, case
    # dezelfde route met gewone tekst werkt: de 422 komt door dat ene teken
    ok = _send(linked, method, path, valid, idem(auth("admin"), **{"If-Match": "*"}))
    assert ok.status_code in (200, 201), (case, ok.status_code, ok.text)


@pytest.mark.parametrize("bad", list(BAD))
@pytest.mark.parametrize("field", ["reason", "target", "parameters", "veldnaam"])
def test_unstorable_text_in_an_action_request_is_a_422_and_records_nothing(
    linked: Any, auth: Any, flow: Any, field: str, bad: str
) -> None:
    detail, token = flow
    s = BAD[bad]
    parts = {"target": '{"type":"user","id":"user-1"}', "parameters": '{"tekst":"x"}', "reason": '"test"'}
    if field == "veldnaam":
        parts["reason"] = f'"test","y{s}":1'
    elif field == "reason":
        parts["reason"] = f'"test {s}"'
    else:
        parts[field] = parts[field].replace('"}', f'{s}"}}')
    raw = (
        f'{{"action_id":"notification.send","target":{parts["target"]},"parameters":{parts["parameters"]},'
        f'"reason":{parts["reason"]}}}'
    )
    before = _state(linked, auth, detail["id"])
    r = _send(linked, "POST", f"{FLOW_API}/actions", raw, idem(b11.bearer(token)))
    _refused(r, {"validation_error"})
    assert _state(linked, auth, detail["id"]) == before
    assert b11.outbox(linked, "flow.action.requested") == [] and b11.outbox(linked, "flow.action.rejected") == []
    ok = _send(linked, "POST", f"{FLOW_API}/actions", raw.replace(s, ""), idem(b11.bearer(token)))
    assert ok.status_code == (202 if field != "veldnaam" else 422), ok.text


FORBIDDEN = {
    "dataset_verwijderen": ("zfs.dataset.delete", '{"type":"dataset","id":"data-x"}', "destructief_verboden"),
    "boiler": ("energy.boiler.switch", '{"type":"device","id":"boiler"}', "boiler_nooit"),
}


@pytest.mark.parametrize("bad", list(BAD))
@pytest.mark.parametrize("field", ["reason", "target", "parameters"])
@pytest.mark.parametrize("case", list(FORBIDDEN))
def test_forbidden_action_with_unstorable_text_is_refused_and_recorded_without_the_text(
    linked: Any, auth: Any, flow: Any, case: str, field: str, bad: str
) -> None:
    """R-VEILIG-3 van S-P2-310 (EX45, EX27): een flow die een verboden actie aanvraagt en er een NUL of een losse
    surrogaat bij zet, ontloopt de vastlegging niet. Het antwoord is de weigering (``403`` met de weigerreden), er is
    één rij ``geweigerd`` zonder doel en parameters en met de weigerreden als reden, één auditregel en één event
    ``flow.action.rejected``; niets gaat naar de Hub en het teken staat nergens."""
    _, token = flow
    s = BAD[bad]
    action_id, target, reason_code = FORBIDDEN[case]
    parts = {"target": target, "parameters": '{"stand":"aan"}', "reason": '"test"'}
    if field == "reason":
        parts["reason"] = f'"test {s}"'
    else:
        parts[field] = parts[field].replace('"}', f'{s}"}}')
    raw = (
        f'{{"action_id":"{action_id}","target":{parts["target"]},"parameters":{parts["parameters"]},'
        f'"reason":{parts["reason"]}}}'
    )
    audit_before = len(b11.audit_rows(linked))
    headers = idem(b11.bearer(token))
    r = _send(linked, "POST", f"{FLOW_API}/actions", raw, headers)
    assert r.status_code == 403, r.text
    assert r.json()["code"] == "forbidden" and r.json()["details"]["reason"] == reason_code, r.text
    assert "\ud800" not in r.text and "\x00" not in r.text
    rows = linked.get(f"{A}/action-requests", headers=auth("viewer")).json()["items"]
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["id"] == r.json()["details"]["action_request_id"]
    assert (row["action_id"], row["status"], row["rejected_reason"]) == (action_id, "geweigerd", reason_code)
    assert (row["target"], row["parameters"], row["reason"]) == ({}, {}, reason_code), row
    new_audit = b11.audit_rows(linked)[audit_before:]
    assert [a["action"] for a in new_audit] == ["automation.action.rejected"], new_audit
    rejected = b11.outbox(linked, "flow.action.rejected")
    assert len(rejected) == 1 and rejected[0]["payload"]["reden"] == reason_code, rejected
    assert rejected[0]["payload"]["ernst"] == "hoog"
    assert b11.outbox(linked, "flow.action.requested") == []
    stored = b11.everything_stored(linked)
    assert "\x00" not in stored and "\ud800" not in stored
    # dezelfde Idempotency-Key geeft hetzelfde antwoord en legt niets opnieuw vast
    again = _send(linked, "POST", f"{FLOW_API}/actions", raw, headers)
    assert again.status_code == 403 and again.json()["details"] == r.json()["details"], again.text
    assert len(linked.get(f"{A}/action-requests", headers=auth("viewer")).json()["items"]) == 1
    assert len(b11.outbox(linked, "flow.action.rejected")) == 1


@pytest.mark.parametrize("bad", list(BAD))
@pytest.mark.parametrize("shape", ["label_en_id", "tijdstip_en_id", "genest"])
def test_a_cursor_with_unstorable_text_is_a_400_invalid_cursor(
    linked: Any, auth: Any, flow: Any, shape: str, bad: str
) -> None:
    """R-VEILIG-2 en R-TECH-2 van S-P2-310: een zelfgemaakte cursor met een NUL of een losse surrogaat is als viewer
    op ``GET …/automation/flows`` een ongeldige cursor (``400 invalid_cursor``), geen serverfout. Dezelfde cursor zonder
    het teken werkt."""
    s = BAD[bad]
    fid = str(uuid.uuid4())
    values = {
        "label_en_id": f'["a{s}","{fid}"]',
        "tijdstip_en_id": f'["2026-01-01T00:00:00{s}","{fid}"]',
        "genest": f'[{{"x":["a{s}"]}},"{fid}"]',
    }

    def cursor(raw: str) -> str:
        return base64.urlsafe_b64encode(f'{{"k":{raw}}}'.encode("ascii")).rstrip(b"=").decode("ascii")

    r = linked.get(f"{A}/flows", params={"cursor": cursor(values[shape])}, headers=auth("viewer"))
    assert r.status_code == 400, (r.status_code, r.text)
    assert r.json()["code"] == "invalid_cursor", r.text
    assert "\ud800" not in r.text and "\x00" not in r.text
    ok = linked.get(f"{A}/flows", params={"cursor": cursor(values[shape].replace(s, ""))}, headers=auth("viewer"))
    assert ok.status_code == 200, ok.text


@pytest.mark.parametrize("bad", list(BAD))
def test_unstorable_text_in_a_nack_is_a_422(linked: Any, fake_hub: Any, auth: Any, flow: Any, bad: str) -> None:
    detail, token = flow
    assert b11.post_event(linked, fake_hub, b11.envelope()).status_code == 201
    delivery = b11.claim(linked, token)["items"][0]["id"]
    before = _state(linked, auth, detail["id"])
    raw = f'{{"error":"kapot{BAD[bad]}"}}'
    r = _send(linked, "POST", f"{FLOW_API}/deliveries/{delivery}/nack", raw, idem(b11.bearer(token)))
    _refused(r, {"validation_error"})
    assert _state(linked, auth, detail["id"]) == before


@pytest.mark.parametrize("bad", list(BAD))
@pytest.mark.parametrize("where", ["payload", "source_event_id", "veldnaam"])
def test_unstorable_text_in_an_event_from_the_hub_is_refused_and_not_stored(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, where: str, bad: str
) -> None:
    """De Hub biedt een event aan met zo'n teken: ``422 event_ongeldig``, niets bewaard, niets afgeleverd."""
    detail, _ = flow
    s = BAD[bad]
    raw = json.dumps(b11.envelope(source_event_id="test:tekens"))
    if where == "payload":
        raw = raw.replace('"W"', f'"W{s}"')
    elif where == "source_event_id":
        raw = raw.replace('"test:tekens"', f'"test:tekens{s}"')
    else:
        raw = raw[:-1] + f', "x{s}": 1}}'
    before = _state(linked, auth, detail["id"])
    r = _send(linked, "POST", f"{A}/events", raw, idem(fake_hub.service_auth()))
    _refused(r, {"event_ongeldig"})
    assert linked.get(f"{A}/events", headers=auth("viewer")).json()["items"] == []
    assert _state(linked, auth, detail["id"]) == before
    if where != "veldnaam":
        ok = _send(linked, "POST", f"{A}/events", raw.replace(s, ""), idem(fake_hub.service_auth()))
        assert ok.status_code == 201, ok.text


@pytest.mark.parametrize("bad", list(BAD))
def test_unstorable_text_in_a_result_from_the_hub_is_a_422_and_changes_nothing(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, bad: str
) -> None:
    detail, token = flow
    asked = b11.request_action(linked, token, "notification.send", target={"type": "user", "id": "user-1"})
    assert asked.status_code == 202, asked.text
    request_id = asked.json()["id"]
    before = _state(linked, auth, detail["id"])
    raw = f'{{"status":"uitgevoerd","result":{{"melding":"klaar{BAD[bad]}"}}}}'
    path = f"{A}/action-requests/{request_id}/result"
    r = _send(linked, "POST", path, raw, idem(fake_hub.service_auth()))
    _refused(r, {"validation_error"})
    assert _state(linked, auth, detail["id"]) == before
    ok = _send(linked, "POST", path, raw.replace(BAD[bad], ""), idem(fake_hub.service_auth()))
    assert ok.status_code == 200, ok.text
    assert ok.json()["status"] == "uitgevoerd" and uuid.UUID(ok.json()["id"])
