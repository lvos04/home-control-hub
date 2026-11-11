"""B11: de Node-RED-client en de isolatiecontrole tegen de nep-Node-RED (Sim-getest).

De nep-Node-RED volgt het gedrag dat met ``tools/node_red_verify.py`` tegen de gepinde image is gemeten
(``docs/b11/node-red-verificatie.json``); een Node-RED op de echte NAS is NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from integrations.config import Settings
from integrations.domains.automation import policy
from integrations.domains.automation.catalog import NODE_RED_DIGEST, NODE_RED_TAG
from integrations.domains.automation.nodered import (
    CONFIG_REASONS,
    UNREACHABLE_REASONS,
    NodeRedClient,
    NodeRedError,
    api_error,
)
from tests.fakes.node_red_fake import NodeRedFake, exec_flow, simple_flow

BASE = "http://nodered.test:1880"
SERVICE_PW = "dienst-wachtwoord-voor-de-test"
ADMIN_PW = "beheer-wachtwoord-voor-de-test"
SECRET = "credential-secret-voor-de-test"
SETTINGS = Settings()
REPO_ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture(scope="module")
def hashes() -> tuple[str, str]:
    return policy.hash_password(SERVICE_PW), policy.hash_password(ADMIN_PW)


@pytest.fixture
def fake(hashes: tuple[str, str], tmp_path: Path) -> NodeRedFake:
    f = NodeRedFake(data_dir=tmp_path / "nr")
    f.apply_arguments(policy.define_arguments(hashes[0], hashes[1], SECRET))
    return f


def client_for(
    fake: NodeRedFake, password: str = SERVICE_PW, user: str = policy.SERVICE_USER, **kw: Any
) -> NodeRedClient:
    return NodeRedClient(
        BASE, user, password, SETTINGS, transport=httpx.MockTransport(fake.handle), sleep=lambda _s: None, **kw
    )


# ------------------------------------------------------------------------------------------------- de simulator zelf
def test_fake_matches_the_verified_image_facts() -> None:
    """De simulator hoort bij dezelfde image en dezelfde feiten als het verificatierapport (geen eigen aannames)."""
    report = json.loads((REPO_ROOT / "docs/b11/node-red-verificatie.json").read_text(encoding="utf-8"))
    assert report["all_ok"] is True
    assert report["image"]["tag"] == NODE_RED_TAG == NodeRedFake().version
    assert report["image"]["digest"] == NODE_RED_DIGEST
    assert report["validatie_echte_nas"] == "NIET GEVALIDEERD (echte NAS)"
    ids = {c["id"] for c in report["checks"]}
    # elk gedrag dat de simulator nabootst, is tegen de echte image gemeten
    assert {
        "kaal_geen_aanmelding",
        "kaal_anoniem_leesbaar",
        "kaal_exec_geladen",
        "profiel_anoniem_401",
        "fout_wachtwoord_403",
        "dienstaccount_scope_ster_geweigerd",
        "flows_zonder_credentials",
        "credentials_bestand_versleuteld",
        "verouderde_rev_geweigerd",
        "herstel_credentials_terug",
        "exec_flow_aangenomen_maar_gescand",
        "andere_sleutel_geweigerd",
        "palette_installatie_uit",
        "token_ingetrokken",
    } <= ids


def test_unhardened_fake_is_open_like_a_fresh_install() -> None:
    fake = NodeRedFake()
    t = httpx.Client(transport=httpx.MockTransport(fake.handle), base_url=BASE)
    assert t.get("/auth/login").json() == {}
    assert [t.get(p).status_code for p in ("/flows", "/nodes", "/settings")] == [200, 200, 200]
    assert "exec" in policy.type_modules(t.get("/nodes").json())
    s = t.get("/settings").json()
    assert s["functionExternalModules"] is True and s["flowEncryptionType"] == "system" and s["externalModules"] == {}
    assert t.get("/diagnostics").json()["runtime"]["settings"]["adminAuth"] == "UNSET"


def test_hardened_fake_refuses_anonymous_and_limits_the_service_account(fake: NodeRedFake) -> None:
    t = httpx.Client(transport=httpx.MockTransport(fake.handle), base_url=BASE)
    assert t.get("/auth/login").json()["type"] == "credentials"
    assert [t.get(p).status_code for p in ("/flows", "/nodes", "/settings", "/diagnostics")] == [401] * 4
    assert t.post("/flows", json=[]).status_code == 401
    form = {"client_id": "node-red-admin", "grant_type": "password", "username": policy.SERVICE_USER}
    assert t.post("/auth/token", data={**form, "password": "fout", "scope": ""}).status_code == 403
    assert t.post("/auth/token", data={**form, "password": SERVICE_PW, "scope": "*"}).status_code == 403
    token = t.post("/auth/token", data={**form, "password": SERVICE_PW, "scope": ""}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    assert t.get("/settings", headers=h).json()["user"] == {
        "username": policy.SERVICE_USER,
        "permissions": list(policy.SERVICE_PERMISSIONS),
    }
    # het dienstaccount mag geen modules installeren (geen nodes.write); de beheerder krijgt 404 (palette uit)
    assert t.post("/nodes", json={"module": "x"}, headers=h).status_code == 401
    admin = fake.login(policy.ADMIN_USER, ADMIN_PW, "*")
    assert admin is not None
    assert t.post("/nodes", json={"module": "x"}, headers={"Authorization": f"Bearer {admin}"}).status_code == 404
    assert "exec" not in policy.type_modules(t.get("/nodes", headers=h).json())


# ------------------------------------------------------------------------------------------------------- de client
def test_client_reads_flows_nodes_settings_and_revokes_its_token(fake: NodeRedFake) -> None:
    fake.deploy(simple_flow())
    with client_for(fake) as c:
        doc = c.get_flows()
        assert doc.rev == fake.rev and len(doc.flows) == 4
        assert all("credentials" not in n for n in doc.flows)
        assert c.get_settings()["version"] == NODE_RED_TAG
        assert {"inject", "function", "debug"} <= set(policy.type_modules(c.get_nodes()))
        assert c.get_diagnostics()["runtime"]["settings"]["adminAuth"] == "SET"
        assert len(fake.tokens) == 1
    assert fake.tokens == {} and len(fake.revoked) == 1  # token ingetrokken bij het sluiten
    assert fake.seen_passwords == [SERVICE_PW]  # één aanmelding voor alle aanroepen


def test_client_refuses_an_unsecured_node_red() -> None:
    open_fake = NodeRedFake()
    open_fake.deploy(simple_flow())
    with pytest.raises(NodeRedError) as err:
        client_for(open_fake).get_flows()
    assert err.value.reason == "niet_beveiligd"
    assert ("GET", "/flows") not in open_fake.requests  # er is niets gelezen
    assert api_error(err.value).status_code == 502


def test_client_wrong_password_and_missing_permission(fake: NodeRedFake) -> None:
    with pytest.raises(NodeRedError) as err:
        client_for(fake, password="verkeerd").get_flows()
    assert err.value.reason == "aanmelding_geweigerd"
    # een account zonder flows.write krijgt van Node-RED 401 op POST /flows → nooit een stille 'gelukt'
    limited = json.loads(json.dumps(fake.admin_auth))
    limited["users"][0]["permissions"] = ["flows.read"]
    fake.admin_auth = limited
    c = client_for(fake)
    rev = c.get_flows().rev
    with pytest.raises(NodeRedError) as err:
        c.post_flows(rev, simple_flow())
    assert err.value.reason == "aanmelding_geweigerd" and fake.writes == []


def test_client_relogs_in_once_when_the_token_is_revoked(fake: NodeRedFake) -> None:
    c = client_for(fake)
    c.get_flows()
    fake.tokens.clear()  # Node-RED herstart: sessies weg
    assert c.get_flows().rev == fake.rev
    assert fake.seen_passwords == [SERVICE_PW, SERVICE_PW]


def test_post_flows_needs_the_current_rev_and_is_never_repeated(fake: NodeRedFake) -> None:
    fake.deploy(simple_flow())
    c = client_for(fake)
    stale = c.get_flows().rev
    fake.deploy(simple_flow(label="Intussen gewijzigd"))
    with pytest.raises(NodeRedError) as err:
        c.post_flows(stale, [])
    assert err.value.reason == "versie_conflict" and fake.writes == []
    # een serverfout bij schrijven wordt niet herhaald (de uitkomst is dan onbekend; de aanroeper leest terug)
    fake.fail_next_post = 503
    posts_before = fake.requests.count(("POST", "/flows"))
    with pytest.raises(NodeRedError) as err:
        c.post_flows(fake.rev, [])
    assert err.value.reason == "http_5xx"
    assert fake.requests.count(("POST", "/flows")) == posts_before + 1
    # een verloren antwoord: Node-RED heeft de flows wél gezet, de client meldt eerlijk 'timeout'
    fake.drop_next_post_response = True
    with pytest.raises(NodeRedError) as err:
        c.post_flows(fake.rev, [])
    assert err.value.reason == "timeout" and fake.flows == []
    new_rev = c.post_flows(fake.rev, simple_flow())
    assert new_rev == fake.rev and fake.writes[-1]["deployment_type"] == "full"
    assert fake.writes[-1]["door"] == policy.SERVICE_USER


def test_credentials_blob_round_trip_and_other_secret(fake: NodeRedFake, hashes: tuple[str, str]) -> None:
    flows = simple_flow()
    secret_value = "s3cr3t-van-de-mqtt-broker"
    fake.deploy(flows, {flows[1]["id"]: {"user": "mqtt", "password": secret_value}})
    blob = json.loads((fake.data_dir / "flows_cred.json").read_text())  # type: ignore[operator]
    assert set(blob) == {"$"} and secret_value not in json.dumps(blob)
    c = client_for(fake)
    rev = c.post_flows(c.get_flows().rev, [])
    assert fake.credentials == {}
    c.post_flows(rev, flows, credentials=blob)
    assert fake.credentials == {flows[1]["id"]: {"user": "mqtt", "password": secret_value}}
    assert fake.writes[-1]["met_credentials"] is True
    # een Node-RED met een andere credentialSecret weigert het blok en verandert niets
    other = NodeRedFake()
    other.apply_arguments(policy.define_arguments(hashes[0], hashes[1], "een-andere-sleutel"))
    c2 = client_for(other)
    with pytest.raises(NodeRedError) as err:
        c2.post_flows(c2.get_flows().rev, flows, credentials=blob)
    assert err.value.reason == "credentials_niet_te_ontsleutelen" and other.flows == [] and other.writes == []


def test_client_never_follows_redirects_and_limits_the_answer(fake: NodeRedFake) -> None:
    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://elders.test/"})

    c = NodeRedClient(BASE, "u", "p", SETTINGS, transport=httpx.MockTransport(redirect), sleep=lambda _s: None)
    with pytest.raises(NodeRedError) as err:
        c.login_scheme()
    assert err.value.reason == "redirect"

    fake.deploy(simple_flow())
    small = client_for(fake, max_bytes=64)
    with pytest.raises(NodeRedError) as err:
        small.get_flows()
    assert err.value.reason == "antwoord_te_groot"


def test_client_retries_reads_but_reports_unreachable(fake: NodeRedFake) -> None:
    calls = {"n": 0}

    def flaky(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(503, text="bezig")
        return fake.handle(request)

    c = NodeRedClient(BASE, policy.SERVICE_USER, SERVICE_PW, SETTINGS, httpx.MockTransport(flaky), lambda _s: None)
    assert c.login_scheme()["type"] == "credentials" and calls["n"] == 3
    fake.up = False
    with pytest.raises(NodeRedError) as err:
        client_for(fake).get_flows()
    assert err.value.reason == "onbereikbaar"
    e = api_error(err.value)
    assert (e.status_code, e.code, e.headers) == (503, "node_red_unavailable", {"Retry-After": "30"})


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (b"geen json", "antwoord_ongeldig"),
        (b'{"flows": [], "rev": "KORT"}', "antwoord_ongeldig"),
        (b'{"flows": [{"id": 1, "type": "tab"}], "rev": "0123456789abcdef"}', "antwoord_ongeldig"),
        (b"[]", "antwoord_ongeldig"),
    ],
)
def test_client_rejects_unexpected_flow_answers(fake: NodeRedFake, body: bytes, reason: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/flows":
            return httpx.Response(200, content=body, headers={"content-type": "application/json"})
        return fake.handle(request)

    c = NodeRedClient(BASE, policy.SERVICE_USER, SERVICE_PW, SETTINGS, httpx.MockTransport(handler), lambda _s: None)
    with pytest.raises(NodeRedError) as err:
        c.get_flows()
    assert err.value.reason == reason  # nooit een lege lijst als 'geen flows'


def test_client_turns_a_broken_compressed_answer_into_its_own_error(fake: NodeRedFake) -> None:
    """R-TECH-7: elke fout wordt NodeRedError met een vaste reason, ook een antwoord dat niet te decoderen is."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/flows":
            calls.append(request.url.path)
            return httpx.Response(
                200,
                content=b"dit is geen gzip",
                headers={"content-type": "application/json", "content-encoding": "gzip"},
            )
        return fake.handle(request)

    c = NodeRedClient(BASE, policy.SERVICE_USER, SERVICE_PW, SETTINGS, httpx.MockTransport(handler), lambda _s: None)
    with pytest.raises(NodeRedError) as err:
        c.get_flows()
    assert (err.value.reason, err.value.path) == ("antwoord_ongeldig", "/flows")
    assert calls == ["/flows"], "een kapot antwoord is geen netwerkfout: niet herhalen"
    e = api_error(err.value)
    assert (e.status_code, e.code) == (502, "node_red_fout")


def test_api_error_mapping_covers_every_reason_class() -> None:
    for reason in CONFIG_REASONS:
        e = api_error(NodeRedError(reason))
        assert (e.status_code, e.code) == (409, "node_red_niet_ingesteld")
    for reason in UNREACHABLE_REASONS:
        e = api_error(NodeRedError(reason))
        assert (e.status_code, e.code) == (503, "node_red_unavailable")
    for reason in ("niet_beveiligd", "aanmelding_geweigerd", "antwoord_ongeldig", "versie_conflict"):
        e = api_error(NodeRedError(reason))
        assert (e.status_code, e.code) == (502, "node_red_fout") and e.details["reason"] == reason


# ------------------------------------------------------------------------------------------- isolatie (B11-001)
def test_isolation_of_the_hardening_profile_is_measured_in_order(fake: NodeRedFake) -> None:
    report = policy.check_isolation(client_for(fake), ("node-red",))
    assert report["status"] == "gemeten_in_orde" and report["afwijkingen"] == [] and report["fout"] is None
    by_id = {r["id"]: r["status"] for r in report["checks"]}
    assert all(by_id[c] == "ok" for c in policy.MEASURED)
    # wat alleen op de NAS te zien is, wordt nooit als 'ok' gemeld
    assert all(by_id[c] == "niet_meetbaar" for c in policy.NOT_MEASURABLE)
    assert report["node_red_version"] == NODE_RED_TAG and "NIET GEVALIDEERD" in report["validatie"]


def test_isolation_of_an_open_node_red_is_a_deviation() -> None:
    report = policy.check_isolation(client_for(NodeRedFake()), ("node-red",))
    assert report["status"] == "afwijking"
    assert {"editor_aanmelding", "anoniem_geweigerd"} <= set(report["afwijkingen"])
    by_id = {r["id"]: r for r in report["checks"]}
    # zonder aanmelding leest de dienst bewust niets: de rest is 'onbekend', nooit 'ok'
    assert by_id["exec_node_afwezig"]["status"] == "onbekend"
    assert by_id["exec_node_afwezig"]["detail"] == {"reden": "niet_beveiligd"}


def _args(hashes: tuple[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for arg in policy.define_arguments(hashes[0], hashes[1], SECRET):
        if arg.startswith("--define="):
            key, _, raw = arg.removeprefix("--define=").partition("=")
            out[key] = raw
    return out


@pytest.mark.parametrize(
    ("drop", "expected"),
    [
        ("nodesExcludes", "exec_node_afwezig"),
        ("functionExternalModules", "function_modules_uit"),
        ("externalModules", "palette_installatie_uit"),
        ("credentialSecret", "credentials_versleuteld"),
    ],
)
def test_each_missing_argument_is_its_own_deviation(hashes: tuple[str, str], drop: str, expected: str) -> None:
    """B11-001: laat één argument uit het formulier weg en precies die controle wordt een afwijking."""
    args = [f"--define={k}={v}" for k, v in _args(hashes).items() if k != drop]
    fake = NodeRedFake()
    fake.apply_arguments(args)
    report = policy.check_isolation(client_for(fake), ("node-red",))
    assert report["status"] == "afwijking" and report["afwijkingen"] == [expected]


def test_foreign_module_and_wide_service_account_are_deviations(fake: NodeRedFake) -> None:
    fake.extra_sets.append(
        {
            "id": "node-red-contrib-x/x",
            "name": "x",
            "types": ["x-node"],
            "enabled": True,
            "module": "node-red-contrib-x",
        }
    )
    report = policy.check_isolation(client_for(fake), ("node-red",))
    assert report["afwijkingen"] == ["modules_toegestaan"]
    assert policy.check_isolation(client_for(fake), ("node-red", "node-red-contrib-x"))["status"] == "gemeten_in_orde"
    # een uitgeschakelde node-set telt niet mee
    fake.extra_sets[0]["enabled"] = False
    assert policy.check_isolation(client_for(fake), ("node-red",))["status"] == "gemeten_in_orde"
    # het dienstaccount met alle rechten is een afwijking (de dienst zou de editor kunnen beheren)
    report = policy.check_isolation(client_for(fake, password=ADMIN_PW, user=policy.ADMIN_USER), ("node-red",))
    assert report["afwijkingen"] == ["dienstaccount_minimaal"]


def test_isolation_is_unknown_when_node_red_is_unreachable(fake: NodeRedFake) -> None:
    fake.up = False
    report = policy.check_isolation(client_for(fake), ("node-red",))
    assert report["status"] == "onbekend" and report["fout"]["reason"] == "onbereikbaar"
    assert {r["status"] for r in report["checks"] if r["id"] in policy.MEASURED} == {"onbekend"}


def test_define_arguments_never_need_a_shell(hashes: tuple[str, str]) -> None:
    args = policy.define_arguments(hashes[0], hashes[1], SECRET)
    assert args[-1] == "--no-telemetry" and all(a.startswith("--") for a in args)
    parsed = _args(hashes)
    admin_auth = json.loads(parsed["adminAuth"])
    assert [u["username"] for u in admin_auth["users"]] == [policy.SERVICE_USER, policy.ADMIN_USER]
    assert admin_auth["users"][0]["permissions"] == list(policy.SERVICE_PERMISSIONS)
    assert all(u["password"].startswith("$2b$10$") for u in admin_auth["users"])
    assert SERVICE_PW not in " ".join(args) and ADMIN_PW not in " ".join(args)  # alleen hashes
    assert json.loads(parsed["nodesExcludes"]) == ["90-exec.js"]


# ---------------------------------------------------------------------------------------------- flowscan (B11-001)
def _modules(fake: NodeRedFake) -> dict[str, str]:
    return policy.type_modules(fake.node_sets())


def test_scan_blocks_an_exec_node_even_when_node_red_accepts_the_flow(fake: NodeRedFake) -> None:
    c = client_for(fake)
    c.post_flows(c.get_flows().rev, [*simple_flow(), *exec_flow()])  # Node-RED weigert dit niet (gemeten)
    result = policy.scan(c.get_flows().flows, _modules(fake), ("node-red",))
    by_label = {t.label: t for t in result.tabs}
    assert by_label["Melding bij storing"].blocked is False
    blocked = by_label["Shell (verboden)"]
    assert blocked.blocked and blocked.blocked_reason == "verboden_node"
    assert result.summary()["geblokkeerd"] == 1


def test_scan_blocks_exec_also_when_the_node_is_still_loaded() -> None:
    """Ook bij een onbeveiligde Node-RED (exec geladen) blijft een exec-node verboden."""
    result = policy.scan(exec_flow(), policy.type_modules(NodeRedFake().node_sets()), ("node-red",))
    assert [t.blocked_reason for t in result.tabs] == ["verboden_node"]


def test_scan_follows_subflows_and_config_nodes(fake: NodeRedFake) -> None:
    flows = [
        {"id": "tab1", "type": "tab", "label": "Gebruikt subflow"},
        {"id": "tab2", "type": "tab", "label": "Schoon"},
        {"id": "sub1", "type": "subflow", "name": "buiten"},
        {"id": "sub2", "type": "subflow", "name": "binnen"},
        {"id": "n1", "type": "subflow:sub1", "z": "tab1", "wires": []},
        {"id": "n2", "type": "subflow:sub2", "z": "sub1", "wires": []},  # subflow in een subflow
        {"id": "n3", "type": "exec", "z": "sub2", "wires": []},
        {"id": "n4", "type": "debug", "z": "tab2", "wires": []},
        {"id": "cfg1", "type": "vreemde-config"},  # configuratienode van een onbekend type
        {"id": "n5", "type": "mqtt out", "z": "tab2", "broker": "cfg1", "wires": []},
    ]
    result = policy.scan(flows, _modules(fake), ("node-red",))
    by_id = {t.tab_id: t for t in result.tabs}
    assert by_id["tab1"].findings == [
        {"code": "verboden_node", "node_id": "n3", "node_type": "exec", "via_subflow": "sub2"}
    ]
    assert by_id["tab2"].findings == [
        {"code": "onbekend_type", "node_id": "cfg1", "node_type": "vreemde-config", "via_config": True}
    ]
    assert [w["node_type"] for w in by_id["tab2"].warnings] == ["mqtt out"]


def test_scan_checksum_changes_only_for_the_changed_tab(fake: NodeRedFake) -> None:
    a = simple_flow("tabaaaaaaaaaaaa1", "A")
    b = simple_flow("tabbbbbbbbbbbbb1", "B")
    before = {t.tab_id: t.checksum for t in policy.scan([*a, *b], _modules(fake), ("node-red",)).tabs}
    b[2]["func"] = "msg.payload = 1; return msg;"
    after = {t.tab_id: t.checksum for t in policy.scan([*b, *a], _modules(fake), ("node-red",)).tabs}
    assert before["tabaaaaaaaaaaaa1"] == after["tabaaaaaaaaaaaa1"]  # volgorde van nodes maakt niet uit
    assert before["tabbbbbbbbbbbbb1"] != after["tabbbbbbbbbbbbb1"]


def test_scan_unknown_type_and_module_outside_allowlist(fake: NodeRedFake) -> None:
    fake.extra_sets.append(
        {
            "id": "node-red-contrib-x/x",
            "name": "x",
            "types": ["x-node"],
            "enabled": True,
            "module": "node-red-contrib-x",
        }
    )
    flows = [
        {"id": "tab1", "type": "tab", "label": "T"},
        {"id": "n1", "type": "x-node", "z": "tab1"},
        {"id": "n2", "type": "bestaat-niet", "z": "tab1"},
        {"id": "n3", "type": "subflow:weg", "z": "tab1"},
    ]
    codes = [f["code"] for f in policy.scan(flows, _modules(fake), ("node-red",)).tabs[0].findings]
    assert codes == ["module_niet_toegestaan", "onbekend_type", "onbekend_type"]
    allowed = policy.scan(flows[:2], _modules(fake), ("node-red", "node-red-contrib-x")).tabs[0]
    assert allowed.blocked is False
