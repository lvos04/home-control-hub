"""B11 — de vaste regels van de automatisering, zonder database of netwerk.

Eventcatalogus (B11-002), voorbeeld-events (B11-004), de harde weigerlijst en scope van flow-tokens (B11-003, EX18,
EX27, EX45), de flowscan (B11-001) en de kleine rekenregels van de wachtrij.
"""

from __future__ import annotations

import copy
import uuid
from datetime import timedelta
from typing import Any

import pytest

from integrations.domains.automation import actions, eventcatalog, inbox, policy, samples
from tests.fakes.node_red_fake import exec_flow, node, simple_flow, tab


def env(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "source_app": "home-control-hub",
        "source_event_id": "test:1",
        "event_type": "energy.reading.recorded",
        "entity": {"type": "meter", "id": "meter-1"},
        "timestamp_utc": "2026-01-01T12:00:00Z",
        "trace_id": str(uuid.uuid4()),
        "correlation_id": None,
        "actor": {"type": "system", "id": "test"},
        "classification": "internal",
        "payload": {"vermogen_w": 100},
        "payload_ref": None,
    }
    base.update(overrides)
    return base


# ------------------------------------------------------------------------------------------- eventcatalogus (B11-002)
def test_valid_envelope_in_own_domain_is_deliverable() -> None:
    verdict = eventcatalog.classify(env())
    assert verdict.status == "geldig" and verdict.deliverable


def test_unknown_schema_version_is_kept_and_named_not_dropped() -> None:
    # de vorm van een onbekende versie kennen we niet: zelfs met vreemde velden wordt hij bewaard en gemeld
    verdict = eventcatalog.classify(env(schema_version="9.9", nieuw_veld={"x": 1}, payload="geen object"))
    assert verdict.status == "onbekende_schema_versie" and not verdict.deliverable
    assert verdict.detail == {"schema_version": "9.9", "ondersteund": ["1.0"]}


@pytest.mark.parametrize(
    ("overrides", "status", "reden"),
    [
        ({"event_type": "weer.meting.recorded"}, "onbekend_type", "domein_onbekend"),
        ({"event_type": "app.iets.changed"}, "onbekend_type", "geen_vast_type_in_gedeeld_domein"),
        ({"source_app": "mediaguard"}, "buiten_domein", "bron_is_geen_eigenaar"),
        ({"source_app": "media-source-optimizer", "event_type": "media.item.added"}, "buiten_domein", None),
        ({"source_app": "my-house", "event_type": "energy.reading.recorded"}, "buiten_domein", None),
        (
            {
                "source_app": "onbekende-app",
                "event_type": "app.health.changed",
                "entity": {"type": "app", "id": "onbekende-app"},
                "payload": {"status": "down"},
            },
            "buiten_domein",
            "bron_onbekend",
        ),
    ],
)
def test_events_outside_the_catalog_are_classified(overrides: dict[str, Any], status: str, reden: str | None) -> None:
    verdict = eventcatalog.classify(env(**overrides))
    assert verdict.status == status and not verdict.deliverable
    if reden is not None:
        assert verdict.detail["reden"] == reden


def test_typed_event_payload_is_checked() -> None:
    good = env(
        source_app="mediaguard",
        event_type="app.health.changed",
        entity={"type": "app", "id": "mediaguard"},
        payload={"status": "down"},
    )
    assert eventcatalog.classify(good).status == "geldig"
    bad_status = copy.deepcopy(good)
    bad_status["payload"]["status"] = "kapot"
    verdict = eventcatalog.classify(bad_status)
    assert verdict.status == "ongeldige_payload" and verdict.detail["getypeerd"] is True
    other_app = copy.deepcopy(good)
    other_app["entity"]["id"] = "jelly-leon"  # een app meldt alleen zijn eigen gezondheid
    verdict = eventcatalog.classify(other_app)
    assert verdict.status == "buiten_domein" and verdict.detail["reden"] == "niet_over_de_eigen_app"
    service = env(event_type="service.token.rotated", entity={"type": "service", "id": "mediaguard"}, payload={})
    assert eventcatalog.classify(service).status == "buiten_domein"
    service["entity"] = {"type": "service", "id": "home-control-hub"}
    assert eventcatalog.classify(service).status == "geldig"
    service["entity"] = {"type": "app", "id": "home-control-hub"}
    assert eventcatalog.classify(service).status == "ongeldige_payload"
    assert eventcatalog.classify(env(payload={"ernst": "paniek"})).status == "ongeldige_payload"
    assert eventcatalog.classify(env(payload={"ernst": "hoog"})).status == "geldig"


@pytest.mark.parametrize(
    ("overrides", "veld"),
    [
        ({"event_id": "geen-uuid"}, "event_id"),
        ({"source_app": "Hoofdletters"}, "source_app"),
        ({"source_event_id": ""}, "source_event_id"),
        ({"event_type": "GEEN.geldig"}, "event_type"),
        ({"entity": {"type": "meter"}}, "entity"),
        ({"entity": {"type": "Met Spatie", "id": "x"}}, "entity.type"),
        ({"timestamp_utc": "2026-01-01 12:00"}, "timestamp_utc"),
        ({"trace_id": "x"}, "trace_id"),
        ({"correlation_id": "x"}, "correlation_id"),
        ({"actor": {"type": "robot", "id": "x"}}, "actor.type"),
        ({"classification": "geheim"}, "classification"),
        ({"payload": [1, 2]}, "payload"),
        ({"payload": {"x": "y" * (16 * 1024)}}, "payload"),
        ({"payload_ref": 5}, "payload_ref"),
        ({"extra": 1}, "extra"),
    ],
)
def test_malformed_envelopes_are_rejected_with_the_field(overrides: dict[str, Any], veld: str) -> None:
    with pytest.raises(eventcatalog.EnvelopeError) as caught:
        eventcatalog.classify(env(**overrides))
    assert veld in [f["veld"] for f in caught.value.fouten]


def test_missing_required_field_and_non_object() -> None:
    broken = env()
    del broken["actor"]
    with pytest.raises(eventcatalog.EnvelopeError) as caught:
        eventcatalog.classify(broken)
    assert {"veld": "actor", "probleem": "verplicht veld ontbreekt"} in caught.value.fouten
    with pytest.raises(eventcatalog.EnvelopeError):
        eventcatalog.classify("geen object")  # type: ignore[arg-type]


def test_trigger_rules() -> None:
    assert eventcatalog.trigger_problem("energy.reading.recorded", "1.0") is None
    assert eventcatalog.trigger_problem("app.health.changed", "1.0") is None
    assert "schema-versie" in str(eventcatalog.trigger_problem("energy.reading.recorded", "2.0"))
    assert "catalogus" in str(eventcatalog.trigger_problem("weer.meting.recorded", "1.0"))
    assert "vaste typen" in str(eventcatalog.trigger_problem("app.iets.changed", "1.0"))
    assert "geldig eventtype" in str(eventcatalog.trigger_problem("Energy", "1.0"))
    assert "geldig eventtype" in str(eventcatalog.trigger_problem("a." * 70 + "b", "1.0"))


def test_catalog_view_is_complete_and_honest() -> None:
    view = eventcatalog.catalog_view()
    assert view["envelope"]["schema_versions"] == ["1.0"] and view["envelope"]["max_payload_bytes"] == 16384
    assert set(view["envelope"]["required"]) | set(view["envelope"]["optional"]) == set(eventcatalog.ENVELOPE_FIELDS)
    assert view["owners"]["home-control-hub"] == ["sso", "energy", "network", "automation", "flow"]
    assert "media-source-optimizer" not in view["owners"] and "my-house" not in view["owners"]
    types = [item["event_type"] for item in view["items"]]
    assert len(types) == len(set(types)) and "app.health.changed" in types
    for item in view["items"]:
        assert item["soort"] in ("probleem", "herstel", "informatie") and item["sources"]
        assert item["schema_versions"] == ["1.0"] and item["contract_ref"]
    assert any("MSO en my_house" in note for note in view["notes_nl"])
    assert eventcatalog.owners_of("media") == ["jelly-leon", "mediaguard"]
    assert eventcatalog.owners_of("app") == sorted(eventcatalog.OWNER_DOMAINS)
    assert eventcatalog.verb_kind("failed") == "probleem" and eventcatalog.verb_kind("recorded") == "informatie"


# ----------------------------------------------------------------------------------------- voorbeeld-events (B11-004)
def test_samples_are_fixed_valid_and_marked_as_examples() -> None:
    assert samples.checksum() == samples.SAMPLES_SHA256
    verified = samples.verified()
    assert list(verified) == [
        "energie-meting",
        "netwerk-nieuw-apparaat",
        "backup-mislukt",
        "app-gezondheid",
        "download-mislukt",
        "toegang-ingetrokken",
    ]
    for sample in verified.values():
        envelope = sample["envelope"]
        assert envelope["payload"]["voorbeeld"] is True and envelope["actor"] == {"type": "system", "id": "voorbeeld"}
        assert envelope["classification"] != "sensitive"
        assert eventcatalog.classify(envelope).status == "geldig", sample["id"]
    # geen echte waarden: geen IP-adres, geen poolnaam, alleen .invalid-adressen
    text = str(samples.SAMPLES)
    assert "192.168." not in text and "tank" not in text


def test_samples_cannot_be_changed_by_a_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    copy_ = samples.verified()
    copy_["energie-meting"]["envelope"]["payload"]["vermogen_w"] = 999_999
    assert samples.verified()["energie-meting"]["envelope"]["payload"]["vermogen_w"] == 420
    changed = copy.deepcopy(samples.SAMPLES)
    changed[0]["envelope"]["payload"]["vermogen_w"] = 1
    monkeypatch.setattr(samples, "SAMPLES", changed)
    with pytest.raises(samples.SamplesChanged):
        samples.verified()


# ------------------------------------------------------------------------- harde weigerlijst (B11-003, EX27, EX45)
@pytest.mark.parametrize(
    ("action_id", "target", "parameters", "reden"),
    [
        ("zfs.dataset.delete", {"type": "dataset", "id": "x"}, {}, "destructief_verboden"),
        ("zfs.dataset.destroy", {}, {}, "destructief_verboden"),
        ("zfs.pool.wipe", {}, {}, "destructief_verboden"),
        ("media.library.purge", {}, {}, "destructief_verboden"),
        ("app.uninstall_data", {}, {}, "destructief_verboden"),
        ("disk.format", {}, {}, "destructief_verboden"),
        ("energy.boiler.switch", {}, {}, "boiler_nooit"),
        ("device.switch.set", {"type": "device", "id": "Boiler-zolder"}, {}, "boiler_nooit"),
        ("device.switch.set", {"type": "device", "id": "stekker-3"}, {"entity": "switch.warmwater"}, "boiler_nooit"),
        ("device.switch.set", {"type": "device", "id": "x"}, {"naam": {"diep": ["water_heater"]}}, "boiler_nooit"),
        ("system.shell.run", {}, {}, "shell_verboden"),
        ("system.sudo.run", {}, {}, "shell_verboden"),
        ("app.exec", {}, {}, "shell_verboden"),
        ("docker.container.start", {}, {}, "shell_verboden"),
        ("host.ssh_command", {}, {}, "shell_verboden"),
        ("policy.rule.update", {}, {}, "beleid_verboden"),
        ("sso.user.create", {}, {}, "beleid_verboden"),
        ("app.rbac.update", {}, {}, "beleid_verboden"),
        ("claude.overage.enable", {}, {}, "betaald_verboden"),
        ("store.purchase.create", {}, {}, "betaald_verboden"),
    ],
)
def test_hard_refusals(action_id: str, target: dict[str, Any], parameters: dict[str, Any], reden: str) -> None:
    assert actions.local_refusal(action_id, target, parameters) == reden
    assert reden in actions.REFUSALS_NL


@pytest.mark.parametrize(
    ("action_id", "target", "parameters"),
    [
        ("notification.send", {"type": "user", "id": "user-1"}, {"tekst": "De boiler verbruikt veel stroom"}),
        ("app.restart", {"type": "app", "id": "jellyfin"}, {}),
        ("zfs.snapshot.create", {"type": "dataset", "id": "x"}, {"naam": "voor-update"}),
        ("app.update", {"type": "app", "id": "shelly-dashboard"}, {}),  # 'sh' alleen als los segment verboden
        ("notification.send", {"type": "user", "id": "user-1"}, {"tekst": "Storing \u2014 zie de Hub \u00e9n de app"}),
    ],
)
def test_ordinary_actions_are_not_refused_locally(
    action_id: str, target: dict[str, Any], parameters: dict[str, Any]
) -> None:
    assert actions.local_refusal(action_id, target, parameters) is None


@pytest.mark.parametrize(
    "action_id",
    [
        # onder een andere naam iets verwijderen, terugdraaien of schakelen: niet op de vaste lijst, dus nooit
        "zfs.dataset.rm",
        "zfs.dataset.destroyrecursive",
        "zfs.snapshot.rollback",
        "media.file.trash",
        "energy.device.switch",
        "device.switch.set",
        "app.uninstall_everything",
    ],
)
def test_actions_outside_the_fixed_list_are_refused(action_id: str) -> None:
    """Fail-closed (R-VEILIG-1): wat niet op de vaste lijst van contract §8 staat, gaat nooit naar de Hub."""
    assert actions.local_refusal(action_id, {"type": "device", "id": "shelly-plug-3"}, {"aan": True}) == (
        "onbekende_actie"
    )
    assert actions.REFUSALS_NL["onbekende_actie"]
    assert "onbekende_actie" in actions.HIGH_SEVERITY


def test_fixed_list_is_the_executor_allowlist_of_the_contract() -> None:
    """De vaste lijst is precies de executor-allowlist v1 uit contract §8, zonder app.uninstall_data (nooit
    aangeboden). Wijzigt het contract, dan wordt deze test rood en moet de lijst bewust worden bijgewerkt."""
    from pathlib import Path

    contract = Path(__file__).resolve().parents[4] / "docs" / "platform-v2" / "PLATFORM_CONTRACTEN.md"
    text = contract.read_text(encoding="utf-8")
    table = text.split("Executor-allowlist v1:", 1)[1].split("**Acties via de eigenaar-connector**", 1)[0]
    listed: set[str] = set()
    for line in table.splitlines():
        if line.startswith("| `"):
            first = line.split("|")[1]
            listed |= {part.strip().strip("`") for part in first.split("/")}
    assert len(listed) == 11, listed
    assert listed - {"app.uninstall_data"} == actions.FLOW_ACTIONS
    assert set(actions.RISK_TABLE) == actions.FLOW_ACTIONS


@pytest.mark.parametrize(
    ("action_id", "target", "parameters", "reden"),
    [
        # onzichtbare en niet-ASCII-tekens in een id (doel of parameternaam): geweigerd
        ("app.restart", {"type": "app", "id": "boi\u200bler"}, {}, "ongeldige_tekens"),
        ("app.restart", {"type": "app", "id": "b\u043eiler"}, {}, "ongeldige_tekens"),  # Cyrillische o
        ("app.restart", {"type": "app", "id": "jellyfin\u2060"}, {}, "ongeldige_tekens"),
        ("app.restart", {"type": "app", "id": "jellyfin\n"}, {}, "ongeldige_tekens"),
        ("app.restart", {"type": "app", "id": "jellyfin"}, {"na\u200bam": 1}, "ongeldige_tekens"),
        ("notification.send", {"type": "u\u0441er", "id": "user-1"}, {"tekst": "x"}, "ongeldige_tekens"),
        # in parameterwaarden wordt eerst genormaliseerd (NFKC, zonder onzichtbare tekens en scheidingstekens)
        ("app.restart", {"type": "app", "id": "jellyfin"}, {"apparaat": "boi\u200bler"}, "boiler_nooit"),
        (
            "app.restart",
            {"type": "app", "id": "jellyfin"},
            {"apparaat": "\uff42\uff4f\uff49\uff4c\uff45\uff52"},
            "boiler_nooit",
        ),
        ("app.restart", {"type": "app", "id": "jellyfin"}, {"apparaat": "Hot Water"}, "boiler_nooit"),
        ("app.restart", {"type": "app", "id": "jellyfin"}, {"apparaat": "warm-water"}, "boiler_nooit"),
        ("app.restart", {"type": "app", "id": "jellyfin"}, {"apparaat": "bo\u00efler"}, "boiler_nooit"),
        ("app.restart", {"type": "app", "id": "boi ler"}, {}, "boiler_nooit"),
    ],
)
def test_ids_are_plain_text_and_content_is_normalized_before_the_scan(
    action_id: str, target: dict[str, Any], parameters: dict[str, Any], reden: str
) -> None:
    assert actions.local_refusal(action_id, target, parameters) == reden


def test_too_deeply_nested_parameters_are_refused() -> None:
    deep: Any = "x"
    for _ in range(20):
        deep = {"n": deep}
    assert actions.local_refusal("app.restart", {"type": "app", "id": "jellyfin"}, {"p": deep}) == "ongeldige_tekens"


@pytest.mark.parametrize(
    ("action_id", "target"),
    [
        ("app.stop", {"type": "app", "id": "emby"}),
        ("app.restart", {"type": "app", "id": "Emby"}),
        ("app.update", {"host_id": "nas-primary", "app_id": "embyserver"}),
        ("app.uninstall", {"type": "app", "id": "emby-server"}),
        ("app.rollback", {"type": "app", "id": "emby_2"}),
    ],
)
def test_emby_is_never_a_target_of_a_flow(action_id: str, target: dict[str, Any]) -> None:
    """HARDE EIS (R-HARDE-EIS-3): het platform stopt, updatet of verwijdert Emby nooit (contract §2.3 regel 3)."""
    assert actions.local_refusal(action_id, target, {}) == "emby_nooit_door_platform"
    assert "emby_nooit_door_platform" in actions.HIGH_SEVERITY
    assert actions.local_refusal(action_id, {"type": "app", "id": "jellyfin"}, {}) is None


def test_boiler_in_a_notification_target_is_still_refused() -> None:
    # alleen de vrije tekst van een melding is uitgezonderd; het doel wordt altijd bekeken
    assert actions.local_refusal("notification.send", {"type": "device", "id": "boiler"}, {}) == "boiler_nooit"


def test_token_scope_rules() -> None:
    assert actions.scope_problem("notification.send") is None
    assert actions.scope_problem("app.*") is None
    assert actions.scope_problem("zfs.snapshot.create") is None
    assert actions.scope_problem("zfs.*") is None, "dekt zfs.snapshot.* van de vaste lijst"
    assert actions.scope_problem("zfs.snapshot.*") is None
    for bad in ("*", "App.Restart", "app..x", "app.*.x", "a" * 90, "zfs.dataset.delete", "energy.boiler.*", "shell.*"):
        assert actions.scope_problem(bad) is not None, bad
    # fail-closed: een actie of patroon buiten de vaste lijst hoort niet in een scope (R-VEILIG-1)
    for bad in ("energy.*", "media.*", "device.*", "energy.device.switch", "zfs.dataset.rm", "zfs.dataset.*"):
        assert actions.scope_problem(bad) is not None, bad
    assert actions.in_scope("app.restart", ["app.*"])
    assert actions.in_scope("zfs.snapshot.create", ["zfs.*"])
    assert not actions.in_scope("zfs.dataset.rm", ["zfs.*"]), "een patroon dekt alleen acties van de vaste lijst"
    assert not actions.in_scope("energy.device.switch", ["energy.*", "energy.device.switch"])
    assert actions.in_scope("notification.send", ["notification.send"])
    assert not actions.in_scope("application.restart", ["app.*"]), "een patroon geldt per segment, niet per voorvoegsel"
    assert not actions.in_scope("app.restart", ["notification.send"])
    assert not actions.in_scope("app.restart", [])


def test_risk_preview_ignores_the_claim_of_the_flow() -> None:
    preview = actions.risk_preview("app.update", "R0")
    assert preview["klasse_min"] == "R2" and preview["goedkeuring_vereist"] is True
    assert preview["risk_claim"] == "R0" and preview["risk_claim_genegeerd"] is True
    assert actions.risk_preview("notification.send", None)["goedkeuring_vereist"] is False
    unknown = actions.risk_preview("device.switch.set", "R0")
    assert unknown["bekend"] is False and unknown["klasse_min"] is None and unknown["goedkeuring_vereist"] is None


def test_dedupe_key_binds_flow_event_action_and_exact_parameters() -> None:
    flow, event = uuid.uuid4(), uuid.uuid4()
    key = actions.dedupe_key(flow, event, "app.restart", {"type": "app", "id": "a"}, {"x": 1, "y": 2})
    assert key == actions.dedupe_key(flow, event, "app.restart", {"id": "a", "type": "app"}, {"y": 2, "x": 1})
    assert key != actions.dedupe_key(flow, uuid.uuid4(), "app.restart", {"type": "app", "id": "a"}, {"x": 1, "y": 2})
    assert key != actions.dedupe_key(uuid.uuid4(), event, "app.restart", {"type": "app", "id": "a"}, {"x": 1, "y": 2})
    assert key != actions.dedupe_key(flow, event, "app.stop", {"type": "app", "id": "a"}, {"x": 1, "y": 2})
    assert key != actions.dedupe_key(flow, event, "app.restart", {"type": "app", "id": "b"}, {"x": 1, "y": 2})
    assert key != actions.dedupe_key(flow, event, "app.restart", {"type": "app", "id": "a"}, {"x": 1, "y": 3})


# ------------------------------------------------------------------------------------------------- wachtrij (EX46)
def test_backoff_grows_and_is_capped() -> None:
    assert [inbox.backoff(n).total_seconds() for n in (0, 1, 2, 3, 4)] == [30, 30, 60, 120, 240]
    assert inbox.backoff(50) == timedelta(hours=1)
    assert inbox.MAX_ATTEMPTS == 10


def test_origin_chain_only_keeps_wellformed_unique_flow_entries() -> None:
    a, b = inbox.chain_entry(uuid.uuid4()), inbox.chain_entry(uuid.uuid4())
    assert inbox.clean_chain([a, b, a, "flow:nee", 7, None, "user:x"]) == [a, b]
    assert inbox.clean_chain("flow:x") == [] and inbox.clean_chain(None) == []
    many = [inbox.chain_entry(uuid.uuid4()) for _ in range(40)]
    assert len(inbox.clean_chain(many)) == inbox.MAX_CHAIN * 2


# ----------------------------------------------------------------------------------------------- flowscan (B11-001)
MODULES = {"inject": "node-red", "function": "node-red", "debug": "node-red", "exec": "node-red", "x": "contrib-x"}
ALLOWED = ("node-red",)


def test_scan_blocks_exec_and_unknown_and_foreign_modules() -> None:
    flows = [
        *simple_flow(),
        *exec_flow(),
        tab("tabvreemd0000001", "Vreemd"),
        node("vreemd0000000001", "x", "tabvreemd0000001"),
        node("vreemd0000000002", "bestaat-niet", "tabvreemd0000001"),
    ]
    result = policy.scan(flows, MODULES, ALLOWED)
    by_tab = {t.tab_id: t for t in result.tabs}
    assert by_tab["tab0000000000001"].blocked is False and by_tab["tab0000000000001"].blocked_reason is None
    assert by_tab["tabexec000000001"].blocked_reason == "verboden_node"
    codes = sorted(f["code"] for f in by_tab["tabvreemd0000001"].findings)
    assert codes == ["module_niet_toegestaan", "onbekend_type"]
    assert result.summary()["geblokkeerd"] == 2 and result.node_count == len(flows)
    # dezelfde module wél toegestaan: alleen het onbekende type blijft over
    again = policy.scan(flows, MODULES, ("node-red", "contrib-x"))
    assert [f["code"] for f in {t.tab_id: t for t in again.tabs}["tabvreemd0000001"].findings] == ["onbekend_type"]


def test_scan_follows_subflows_and_config_nodes() -> None:
    flows = [
        tab("tabschoon0000001", "Lijkt schoon"),
        node("schoon0000000001", "subflow:sub0000000000001", "tabschoon0000001"),
        {"id": "sub0000000000001", "type": "subflow", "name": "Verstopt"},
        node("sub00000exec0001", "exec", "sub0000000000001", command="true"),
        tab("tabconfig0000001", "Met configuratie"),
        node("config0000000001", "inject", "tabconfig0000001", broker="cfg0000000000001"),
        {"id": "cfg0000000000001", "type": "x", "name": "vreemde configuratie"},
        {"id": "cfg0000000000002", "type": "x", "name": "ongebruikt"},
        tab("tabweg0000000001", "Verwijst naar niets"),
        node("weg0000000000001", "subflow:bestaat-niet", "tabweg0000000001"),
    ]
    result = policy.scan(flows, MODULES, ALLOWED)
    by_tab = {t.tab_id: t for t in result.tabs}
    hidden = by_tab["tabschoon0000001"].findings
    assert [f["code"] for f in hidden] == ["verboden_node"] and hidden[0]["via_subflow"] == "sub0000000000001"
    via_config = by_tab["tabconfig0000001"].findings
    assert [f["code"] for f in via_config] == ["module_niet_toegestaan"] and via_config[0]["via_config"] is True
    assert [f["code"] for f in by_tab["tabweg0000000001"].findings] == ["onbekend_type"]
    assert [f["node_id"] for f in result.global_findings] == ["cfg0000000000002"]


LINK_MODULES = {**MODULES, "link in": "node-red", "link out": "node-red", "link call": "node-red"}


def _linked_to_exec(link_type: str = "link out", **extra: Any) -> list[dict[str, Any]]:
    """Tabblad "Schoon" stuurt via een link-node berichten naar een tabblad met een exec-node (R-VEILIG-3)."""
    return [
        tab("tabschoon0000001", "Schoon"),
        node("schoon00inject01", "inject", "tabschoon0000001", [["schoon00link0001"]]),
        node("schoon00link0001", link_type, "tabschoon0000001", links=["exec0000linkin01"], **extra),
        *exec_flow(),
        node("exec0000linkin01", "link in", "tabexec000000001", [["tabexec0exec0001"]], links=["schoon00link0001"]),
    ]


@pytest.mark.parametrize("link_type", ["link out", "link call"])
def test_scan_follows_link_nodes_to_other_tabs(link_type: str) -> None:
    result = policy.scan(_linked_to_exec(link_type), LINK_MODULES, ALLOWED)
    by_tab = {t.tab_id: t for t in result.tabs}
    clean = by_tab["tabschoon0000001"]
    assert clean.blocked and clean.blocked_reason == "verboden_node"
    assert [(f["code"], f["node_type"], f.get("via_link")) for f in clean.findings] == [
        ("verboden_node", "exec", "tabexec000000001")
    ]
    assert by_tab["tabexec000000001"].blocked


def test_scan_follows_link_nodes_in_both_directions_through_subflows_and_dynamic_calls() -> None:
    # het exec-tabblad stuurt berichten naar een schoon tabblad: ook dan delen ze hun bevindingen
    back = [
        tab("tabschoon0000001", "Schoon"),
        node("schoon00linkin01", "link in", "tabschoon0000001", [["schoon00debug001"]], links=["exec0000link0001"]),
        node("schoon00debug001", "debug", "tabschoon0000001"),
        *exec_flow(),
        node("exec0000link0001", "link out", "tabexec000000001", links=["schoon00linkin01"]),
    ]
    assert {t.tab_id: t.blocked for t in policy.scan(back, LINK_MODULES, ALLOWED).tabs} == {
        "tabschoon0000001": True,
        "tabexec000000001": True,
    }
    # een link in een subflow geldt voor elk tabblad dat de subflow gebruikt; en transitief (A → B → exec)
    via_sub = [
        tab("tabsub0000000001", "Met subflow"),
        node("tabsub00subflow1", "subflow:sub0000000000001", "tabsub0000000001"),
        {"id": "sub0000000000001", "type": "subflow", "name": "Doorgeefluik"},
        node("sub00000link0001", "link out", "sub0000000000001", links=["midden00linkin01"]),
        tab("tabmidden000001", "Midden"),
        node("midden00linkin01", "link in", "tabmidden000001", [["midden00link0001"]]),
        node("midden00link0001", "link out", "tabmidden000001", links=["exec0000linkin01"]),
        *exec_flow(),
        node("exec0000linkin01", "link in", "tabexec000000001", [["tabexec0exec0001"]]),
        tab("tabvrij000000001", "Niet verbonden"),
        node("vrij0000debug001", "debug", "tabvrij000000001"),
    ]
    by_tab = {t.tab_id: t for t in policy.scan(via_sub, LINK_MODULES, ALLOWED).tabs}
    assert by_tab["tabsub0000000001"].blocked and by_tab["tabmidden000001"].blocked
    assert not by_tab["tabvrij000000001"].blocked
    # een dynamische link call kiest pas tijdens het draaien: verbonden met elk tabblad met een link in
    dynamic = [
        tab("tabdyn0000000001", "Dynamisch"),
        node("dyn00000call0001", "link call", "tabdyn0000000001", links=[], linkType="dynamic"),
        *exec_flow(),
        node("exec0000linkin01", "link in", "tabexec000000001", [["tabexec0exec0001"]], name="ergens"),
    ]
    assert {t.tab_id: t.blocked for t in policy.scan(dynamic, LINK_MODULES, ALLOWED).tabs}["tabdyn0000000001"]


def test_scan_checksum_of_a_linked_tab_follows_the_tabs_it_is_linked_to() -> None:
    flows = _linked_to_exec()
    for n in flows:
        if n["type"] == "exec":
            n["type"] = "debug"  # eerst onschuldig verbonden
    before = {t.tab_id: t for t in policy.scan(flows, LINK_MODULES, ALLOWED).tabs}
    assert not before["tabschoon0000001"].blocked
    after = {t.tab_id: t for t in policy.scan(_linked_to_exec(), LINK_MODULES, ALLOWED).tabs}
    assert after["tabschoon0000001"].checksum != before["tabschoon0000001"].checksum, "nieuwe versie met de bevinding"
    # een tabblad zonder link-nodes houdt precies de checksum van vóór deze regel
    alone = policy.scan(simple_flow(), LINK_MODULES, ALLOWED).tabs[0].checksum
    assert alone == policy.scan(simple_flow(), MODULES, ALLOWED).tabs[0].checksum


def test_scan_checksum_changes_only_with_the_flow_itself() -> None:
    base = policy.scan(simple_flow(), MODULES, ALLOWED).tabs[0].checksum
    other_tab = [
        *simple_flow(),
        tab("tabander00000001", "Ander"),
        node("ander00000000001", "debug", "tabander00000001"),
    ]
    assert policy.scan(other_tab, MODULES, ALLOWED).tabs[0].checksum == base
    changed = simple_flow()
    for n in changed:
        if n["type"] == "function":
            n["func"] = "return null;"
    assert policy.scan(changed, MODULES, ALLOWED).tabs[0].checksum != base
    # de checksum van het geheel hangt niet af van de volgorde van de velden binnen een node
    shuffled = [dict(reversed(list(n.items()))) for n in simple_flow()]
    assert policy.flows_checksum(simple_flow()) == policy.flows_checksum(shuffled)
    assert policy.flows_checksum(simple_flow()) != policy.flows_checksum(changed)
