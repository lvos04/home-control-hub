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

from integrations.domains.automation import actions, eventcatalog, inbox, policy, samples, snapshots
from tests.fakes.node_red_fake import bypass_scenarios, clean_tab_id, exec_flow, node, simple_flow, tab


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


def test_adr_0016_says_what_a_refused_request_of_a_blocked_flow_sends_to_the_hub() -> None:
    """R-VEILIG-7: een geweigerd actieverzoek van een geblokkeerde flow gaat niet als actieverzoek naar de Hub, maar
    wel als event ``flow.action.rejected``, zoals elke weigering (gemeten in
    test_blocked_flow_keeps_its_token_but_gets_nothing_and_may_request_nothing). ADR-0016 kop 2 zegt dat zo."""
    from pathlib import Path

    adr = Path(__file__).resolve().parents[4] / "docs" / "adr" / "ADR-0016-b11-node-red-automatisering.md"
    kop2 = adr.read_text(encoding="utf-8").split("### 2. ", 1)[1].split("\n### 3. ", 1)[0]
    assert "niets naar de Hub" not in kop2 and "niets van de flow naar de Hub" not in kop2
    assert "geen actieverzoek naar de Hub" in kop2 and "`flow.action.rejected`" in kop2


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
    # grof blokkeren (besluit gebruiker, R-VEILIG-3 herreview 3): het schone tabblad is meegeblokkeerd, met de oorzaken
    clean = by_tab["tab0000000000001"]
    assert clean.blocked and clean.blocked_reason == policy.SOURCE_BLOCKED
    assert [(f["oorzaak"], f["plaats"]) for f in clean.findings] == [
        ("verboden_node", "tabexec000000001"),
        ("module_niet_toegestaan", "tabvreemd0000001"),
        ("onbekend_type", "tabvreemd0000001"),
    ]
    assert by_tab["tabexec000000001"].blocked_reason == "verboden_node"
    codes = sorted(f["code"] for f in by_tab["tabvreemd0000001"].findings)
    assert codes == ["module_niet_toegestaan", "onbekend_type"]
    assert result.summary()["geblokkeerd"] == 3 and result.node_count == len(flows)
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
    assert by_tab["tabsub0000000001"].blocked_reason == by_tab["tabmidden000001"].blocked_reason == "verboden_node"
    # niet verbonden: toch geblokkeerd (grof blokkeren), maar als meegeblokkeerd, niet via een link
    assert by_tab["tabvrij000000001"].blocked_reason == policy.SOURCE_BLOCKED
    assert not any("via_link" in f for f in by_tab["tabvrij000000001"].findings)
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


WIRE_MODULES = {**LINK_MODULES, "http request": "node-red"}
CLEAN, BAD, GHOST = "tabschoon0000001", "tabexec000000001", "spook00000000001"


def _wire_to_exec() -> list[dict[str, Any]]:
    """Gewone draad (``wires``) van een inject in "Schoon" naar de exec-node in een ander tabblad, zonder link-node."""
    return [
        tab(CLEAN, "Schoon"),
        node("schoon00inject01", "inject", CLEAN, [["tabexec0exec0001"]]),
        *exec_flow(tab_id=BAD),
    ]


def _wire_from_contrib() -> list[dict[str, Any]]:
    """Gewone draad van een node uit een niet-toegestane module (ander tabblad) naar een node in "Schoon"."""
    return [
        tab(CLEAN, "Schoon"),
        node("schoon00http0001", "http request", CLEAN),
        tab("tabcontrib000001", "Contrib"),
        node("contrib0node0001", "x", "tabcontrib000001", [["schoon00http0001"]]),
    ]


def _ghost_tab_links_in() -> list[dict[str, Any]]:
    """Een node met een ``z`` die geen tabblad of subflow is: Node-RED maakt daar zelf een tabblad van (parseConfig,
    ``addedTabs``) en laat hem draaien. Van daaruit gaat een link out naar een link in in "Schoon"."""
    return [
        tab(CLEAN, "Schoon"),
        node("schoon00http0001", "http request", CLEAN),
        node("schoon00linkin01", "link in", CLEAN, [["schoon00http0001"]]),
        node("spook000contrib1", "x", GHOST, [["spook000linkout1"]], x=10, y=10),
        node("spook000linkout1", "link out", GHOST, links=["schoon00linkin01"], mode="link", x=20, y=10),
    ]


def _config_in_other_tab() -> list[dict[str, Any]]:
    """Een node in "Schoon" verwijst (eigenschap) naar een configuratienode die in een ander tabblad staat en uit een
    niet-toegestane module komt; Node-RED zoekt zo'n node over alle flows heen (``RED.nodes.getNode``)."""
    return [
        tab(CLEAN, "Schoon"),
        node("schoon00inject01", "inject", CLEAN, broker="ander000broker01"),
        tab("tabander00000001", "Ander"),
        node("ander000broker01", "x", "tabander00000001"),
    ]


@pytest.mark.parametrize(
    ("flows", "code", "other"),
    [
        pytest.param(_wire_to_exec(), "verboden_node", BAD, id="draad naar"),
        pytest.param(_wire_from_contrib(), "module_niet_toegestaan", "tabcontrib000001", id="draad van"),
        pytest.param(_ghost_tab_links_in(), "module_niet_toegestaan", GHOST, id="spook-z"),
        pytest.param(_config_in_other_tab(), "module_niet_toegestaan", "tabander00000001", id="configuratie elders"),
    ],
)
def test_scan_follows_every_reference_to_another_tab(flows: list[dict[str, Any]], code: str, other: str) -> None:
    """R-VEILIG-3 (herreview): Node-RED levert ook af via een gewone draad naar een node in een ander tabblad
    (Flow.getNode vraagt een onbekende id aan de bovenliggende flow) en vanuit een node met een onbekende ``z``."""
    by_tab = {t.tab_id: t for t in policy.scan(flows, WIRE_MODULES, ALLOWED).tabs}
    clean = by_tab[CLEAN]
    assert clean.blocked and clean.blocked_reason == code, clean.findings
    # een node in een spooktabblad heeft daarnaast zelf de bevinding tabblad_onbekend (grof blokkeren)
    ghost_nodes = [n for n in flows if n.get("z") == GHOST] if other == GHOST else []
    expected = [(code, other)] + [("tabblad_onbekend", other)] * len(ghost_nodes)
    assert sorted((f["code"], f.get("via_link")) for f in clean.findings) == sorted(expected)
    assert by_tab[other].blocked and by_tab[other].blocked_reason == code


def test_scan_treats_a_node_with_an_unknown_tab_as_its_own_tab() -> None:
    result = policy.scan(_ghost_tab_links_in(), WIRE_MODULES, ALLOWED)
    by_tab = {t.tab_id: t for t in result.tabs}
    ghost = by_tab[GHOST]
    assert ghost.label == GHOST and ghost.node_count == 2 and ghost.node_types == ["link out", "x"]
    assert [(f["code"], f["node_id"]) for f in ghost.findings] == [
        ("module_niet_toegestaan", "spook000contrib1"),
        ("tabblad_onbekend", "spook000contrib1"),
        ("tabblad_onbekend", "spook000linkout1"),
    ]
    assert result.global_findings == [], "de bevinding staat op het spooktabblad zelf, niet in de ongebruikte lijst"
    assert result.summary()["geblokkeerd"] == 2
    # een losse node zonder tabblad en zonder draad: zelf geblokkeerd, en het schone tabblad nu ook (grof blokkeren)
    alone = [*simple_flow(), node("spook000contrib1", "x", GHOST, x=10, y=10)]
    by_tab = {t.tab_id: t for t in policy.scan(alone, WIRE_MODULES, ALLOWED).tabs}
    assert by_tab[GHOST].blocked_reason == "module_niet_toegestaan"
    assert by_tab["tab0000000000001"].blocked_reason == policy.SOURCE_BLOCKED
    assert {f["plaats"] for f in by_tab["tab0000000000001"].findings} == {GHOST}


@pytest.mark.parametrize(
    "flows",
    [
        pytest.param(
            [*simple_flow(), node("los00000inject01", "inject", "tab0000000000001", [["bestaatniet00001"]])],
            id="draad naar niets",
        ),
        pytest.param(
            [*simple_flow(), node("los00000linkout1", "link out", "tab0000000000001", links=["bestaatniet00001"])],
            id="link naar niets",
        ),
        pytest.param(
            [
                tab("tabsub0000000001", "Met subflow"),
                node("tabsub00subflow1", "subflow:sub0000000000001", "tabsub0000000001"),
                {"id": "sub0000000000001", "type": "subflow", "name": "Doorgeefluik"},
                node("sub00000debug001", "debug", "sub0000000000001"),
                *simple_flow(),
                # een draad naar de id die Node-RED een node in een subflow-instantie geeft (``<instantie>-<node>``)
                node("los00000inject01", "inject", "tab0000000000001", [["tabsub00subflow1-sub00000debug001"]]),
            ],
            id="draad naar een node in een subflow-instantie",
        ),
    ],
)
def test_scan_blocks_a_wire_or_link_to_a_node_that_is_not_in_the_configuration(flows: list[dict[str, Any]]) -> None:
    """Fail-closed: een draad of link naar een id die nergens te plaatsen is, is een bevinding voor het eigen tabblad."""
    by_tab = {t.tab_id: t for t in policy.scan(flows, WIRE_MODULES, ALLOWED).tabs}
    own = by_tab["tab0000000000001"]
    assert own.blocked and own.blocked_reason == "verwijzing_onbekend", own.findings
    assert own.findings[0]["node_id"] == "los00000inject01" or own.findings[0]["node_id"] == "los00000linkout1"
    assert own.findings[0]["ref"] == "bestaatniet00001" or own.findings[0]["ref"].startswith("tabsub00subflow1-")
    assert "verwijzing_onbekend" in snapshots.POLICY_REASONS, "anders wordt zo'n flow nooit meer hervat"


def test_scan_checksum_of_a_wired_tab_follows_the_tab_it_is_wired_to() -> None:
    flows = _wire_to_exec()
    for n in flows:
        if n["type"] == "exec":
            n["type"] = "debug"
    before = {t.tab_id: t for t in policy.scan(flows, WIRE_MODULES, ALLOWED).tabs}
    assert not before[CLEAN].blocked
    after = {t.tab_id: t for t in policy.scan(_wire_to_exec(), WIRE_MODULES, ALLOWED).tabs}
    assert after[CLEAN].checksum != before[CLEAN].checksum, "nieuwe versie met de bevinding"


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


# ------------------------------------------------------- grof blokkeren (R-VEILIG-3 herreview 3, besluit gebruiker)
BYPASS_MODULES = {
    **WIRE_MODULES,
    "catch": "node-red",
    "json": "node-red",
    "tls-config": "node-red",
    "mqtt-broker": "node-red",
}
SCENARIOS = ("sc1", "sc2", "sc3", "sc4", "sc5", "sc6")
TAB2 = "tabander00000002"  # eigen voorvoegsel: simple_flow maakt de node-id's uit de eerste 8 tekens


def _clean_of(name: str) -> str:
    return clean_tab_id(int(name[2]))


def _causes(result: policy.ScanResult) -> set[str]:
    """Alle oorzaken die de scan ergens noemt (eigen bevindingen, die van elders en die buiten elk tabblad)."""
    found = {f.get("oorzaak", f["code"]) for t in result.tabs for f in t.findings}
    return found | {f["code"] for f in result.global_findings}


def _assert_source_blocked(result: policy.ScanResult) -> None:
    """Besluit 'grof blokkeren': elk tabblad van de bron is geblokkeerd, met een reden die na herstel weer pauzeert."""
    assert result.tabs, "zonder tabbladen bewijst deze controle niets"
    assert all(t.blocked for t in result.tabs), [(t.tab_id, t.findings) for t in result.tabs]
    assert {t.blocked_reason for t in result.tabs} <= set(snapshots.POLICY_REASONS)
    for t in result.tabs:
        if t.blocked_reason == policy.SOURCE_BLOCKED:
            # meegeblokkeerd: elke bevinding noemt de oorzaak elders en waar die staat, nooit het tabblad zelf
            assert all(f["code"] == policy.SOURCE_BLOCKED and f["plaats"] != t.tab_id for f in t.findings), t.findings
            assert all(f["oorzaak"] != policy.SOURCE_BLOCKED for f in t.findings), t.findings


@pytest.mark.parametrize("bad_type", ["x", "exec", None], ids=["module", "exec", "zonder-verboden-node"])
@pytest.mark.parametrize("name", SCENARIOS)
def test_scan_blocks_every_tab_of_the_source_for_each_route_of_the_review(name: str, bad_type: str | None) -> None:
    """R-VEILIG-3 (herreview 3): langs deze zes routes levert de echte Node-RED 5.0.9 een bericht af in het schone
    tabblad. Besluit van de gebruiker: staat ergens in de configuratie iets verbodens of iets wat de dienst niet kan
    plaatsen, dan zijn alle tabbladen geblokkeerd. Ook zonder verboden node is elke route zelf zo'n plek."""
    result = policy.scan(bypass_scenarios(bad_type)[name], BYPASS_MODULES, ALLOWED)
    _assert_source_blocked(result)
    clean = {t.tab_id: t for t in result.tabs}[_clean_of(name)]
    # sc5: de tweede node met dezelfde id staat in het schone tabblad zelf; die bevinding krijgt dat tabblad zelf
    assert clean.blocked_reason == ("dubbele_id" if name == "sc5" else policy.SOURCE_BLOCKED), clean.findings
    expected = {
        "sc1": "niet_plaatsbaar",
        "sc2": "niet_plaatsbaar",
        "sc3": "vorm_ongeldig",
        "sc4": "verwijzing_onbekend",
        "sc5": "dubbele_id",
        "sc6": "vorm_ongeldig",
    }[name]
    assert expected in {f.get("oorzaak", f["code"]) for f in clean.findings}, clean.findings
    if bad_type is not None:
        verboden = "module_niet_toegestaan" if bad_type == "x" else "verboden_node"
        assert verboden in _causes(result), [(t.tab_id, t.findings) for t in result.tabs]


def test_scan_blocks_every_tab_of_the_combined_configuration_of_the_review() -> None:
    """Alle routes samen (zoals de proef op de echte image), met en zonder verboden node; ook Schoon7 en Vies7."""
    for bad_type in ("x", None):
        flows = [n for name in (*SCENARIOS, "sc7") for n in bypass_scenarios(bad_type)[name]]
        result = policy.scan(flows, BYPASS_MODULES, ALLOWED)
        _assert_source_blocked(result)
        tab_ids = {t.tab_id for t in result.tabs}
        assert {clean_tab_id(n) for n in range(1, 8)} <= tab_ids


def test_scan_control_wire_between_tabs_stays_blocked_and_is_clean_without_a_forbidden_node() -> None:
    """Controle sc7: de gewone draad blijft gevolgd (de bevinding van de bron, met ``via_link``); zonder verboden node
    is een draad tussen twee schone tabbladen gewoon toegestaan."""
    by_tab = {t.tab_id: t for t in policy.scan(bypass_scenarios("x")["sc7"], BYPASS_MODULES, ALLOWED).tabs}
    clean = by_tab[clean_tab_id(7)]
    assert clean.blocked and clean.blocked_reason == "module_niet_toegestaan"
    assert [f.get("via_link") for f in clean.findings] == ["tabvies000000007"]
    clean_only = policy.scan(bypass_scenarios(None)["sc7"], BYPASS_MODULES, ALLOWED)
    assert [t.blocked for t in clean_only.tabs] == [False, False] and clean_only.global_findings == []


def _with(*extra: Any) -> list[Any]:
    """Twee schone tabbladen plus iets wat de dienst niet kan plaatsen of wat niet mag."""
    return [*simple_flow(), *simple_flow(tab_id=TAB2, label="Ook schoon"), *extra]


LONG_ID = "t" * 121  # één teken langer dan automation_flow.source_flow_id (String(120))
#: R-VEILIG-8: id of z langer dan 120 tekens, een NUL of een losse surrogaat in een tekst (ook een label of een
#: sleutel, ook diep in een eigenschap). De echte Node-RED neemt ze aan; vóór het herstel stopte elke synchronisatie.
ODD_TEXT_FORMS: dict[str, tuple[Any, ...]] = {
    "tabblad-id 121 tekens": (tab(LONG_ID, "Lang"), node("lang0000inject01", "inject", LONG_ID)),
    "id 121 tekens": (node("i" * 121, "inject", TAB2),),
    "z 121 tekens": (node("los", "debug", "z" * 121),),
    "NUL in id": (tab("tabexec000000001", "Shell"), node("exec\x00x", "exec", "tabexec000000001")),
    "NUL in label": (tab("tablabel00000001", "a\x00b"),),
    "NUL diep in een eigenschap": (node("los", "comment", TAB2, info={"a": ["b", {"c": "d\x00"}]}),),
    "losse surrogaat in naam": (node("naam0000inject01", "inject", TAB2, name="\ud800"),),
    "losse surrogaat in sleutel": (node("los", "inject", TAB2) | {"\udfff": 1},),
}


@pytest.mark.parametrize(
    ("flows", "cause"),
    [
        pytest.param(_with(node("los", "inject", "tab0000000000001") | {"id": 5}), "vorm_ongeldig", id="id als getal"),
        pytest.param(_with(node("los", "inject", "tab0000000000001") | {"id": ["Q"]}), "vorm_ongeldig", id="id lijst"),
        pytest.param(_with(node("", "inject", "tab0000000000001")), "vorm_ongeldig", id="lege id"),
        pytest.param(
            _with(node("los00000exec0001", "exec", TAB2) | {"type": ["exec"]}), "vorm_ongeldig", id="type lijst"
        ),
        pytest.param(_with(node("los", "debug", "x") | {"z": {"id": TAB2}}), "vorm_ongeldig", id="z als object"),
        pytest.param(_with(node("los", "debug", "x") | {"z": 7}), "vorm_ongeldig", id="z als getal"),
        pytest.param(
            _with(node("los", "inject", TAB2) | {"wires": [[["tab00000debug001"]]]}), "vorm_ongeldig", id="wires genest"
        ),
        pytest.param(_with(node("los", "inject", TAB2) | {"wires": {"0": [TAB2]}}), "vorm_ongeldig", id="wires object"),
        pytest.param(_with(node("los", "inject", TAB2) | {"wires": None}), "vorm_ongeldig", id="wires null"),
        pytest.param(_with(node("los", "link out", TAB2, links="tab00000debug001")), "vorm_ongeldig", id="links tekst"),
        pytest.param(_with(node("los", "link out", TAB2, links=[5])), "vorm_ongeldig", id="links met getal"),
        pytest.param(_with(5), "vorm_ongeldig", id="geen object: getal"),
        pytest.param(_with(None), "vorm_ongeldig", id="geen object: null"),
        pytest.param(_with(["tab0000000000001"]), "vorm_ongeldig", id="geen object: lijst"),
        pytest.param(_with(node("tab00000debug001", "debug", TAB2)), "dubbele_id", id="dubbele id in twee tabbladen"),
        pytest.param(_with(tab(TAB2, "Nog eens")), "dubbele_id", id="dubbele tabblad-id"),
        pytest.param(_with(node("spook0000debug01", "debug", "spook00000000001")), "tabblad_onbekend", id="spook-z"),
        pytest.param(
            _with({"id": "cfgjunction00001", "type": "junction", "wires": [["tab00000debug001"]]}),
            "niet_plaatsbaar",
            id="configuratienode met draad",
        ),
        pytest.param(
            _with(
                node("los", "inject", TAB2, [["cfgtls0000000001"]]), {"id": "cfgtls0000000001", "type": "tls-config"}
            ),
            "niet_plaatsbaar",
            id="draad naar een configuratienode",
        ),
        pytest.param(_with(node("los", "inject", TAB2, [[TAB2]])), "niet_plaatsbaar", id="draad naar een tabblad"),
        pytest.param(_with(node("los", "inject", TAB2, [["bestaatniet00001"]])), "verwijzing_onbekend", id="niets"),
        pytest.param(_with({"id": "los", "type": "subflow:bestaat-niet"}), "onbekend_type", id="subflow buiten tab"),
        pytest.param(
            _with(
                {"id": "sub0000000000001", "type": "subflow", "name": "Ongebruikt"},
                node("s", "exec", "sub0000000000001"),
            ),
            "verboden_node",
            id="ongebruikte subflow met exec",
        ),
        pytest.param(_with({"id": "cfg0000000000002", "type": "x"}), "module_niet_toegestaan", id="ongebruikte config"),
        # R-VEILIG-8 (herreview 4): vormen die de echte Node-RED 5.0.9 aanneemt, bewaart en teruggeeft
        *(pytest.param(_with(*form), "vorm_ongeldig", id=name) for name, form in ODD_TEXT_FORMS.items()),
    ],
)
def test_scan_blocks_every_tab_when_something_cannot_be_placed_or_is_forbidden(flows: list[Any], cause: str) -> None:
    """Vormfout in id/type/z/wires/links, geen object, dubbele id, een node zonder plaatsbaar tabblad, een draad naar
    iets wat geen node in een tabblad is, of iets verbodens buiten elk tabblad: alle tabbladen geblokkeerd."""
    result = policy.scan(flows, BYPASS_MODULES, ALLOWED)
    _assert_source_blocked(result)
    assert cause in _causes(result), [(t.tab_id, t.findings) for t in result.tabs]


def test_scan_of_a_source_blocked_tab_names_the_cause_and_its_place_and_versions_with_it() -> None:
    """De melding zegt welk tabblad de oorzaak is; de checksum (en dus de versie) van het meegeblokkeerde tabblad
    volgt de oorzaken en is na het weghalen precies die van ervoor."""
    before = {t.tab_id: t for t in policy.scan(_with(), MODULES, ALLOWED).tabs}
    assert not before[TAB2].blocked
    bad = {t.tab_id: t for t in policy.scan(_with(*exec_flow()), MODULES, ALLOWED).tabs}
    assert bad["tabexec000000001"].blocked_reason == "verboden_node"
    assert [(f["code"], f["oorzaak"], f["plaats"], f["node_id"], f["node_type"]) for f in bad[TAB2].findings] == [
        (policy.SOURCE_BLOCKED, "verboden_node", "tabexec000000001", "tabexec0exec0001", "exec")
    ]
    assert bad[TAB2].checksum != before[TAB2].checksum, "nieuwe versie met de bevinding"
    after = {t.tab_id: t for t in policy.scan(_with(), MODULES, ALLOWED).tabs}
    assert after[TAB2].checksum == before[TAB2].checksum and not after[TAB2].blocked


def test_scan_leaves_a_clean_configuration_active() -> None:
    """Een gewone, schone configuratie blijft actief: link-nodes, een junction, een subflow met in/uit, een groep,
    configuratienodes (gebruikt en ongebruikt), een uitgeschakeld tabblad en een draad tussen schone tabbladen."""
    flows = [
        *simple_flow(),
        node("tab00000junct001", "junction", "tab0000000000001", [["tab00000linkout1"]]),
        node("tab00000linkout1", "link out", "tab0000000000001", mode="link", links=["tabanderlinkin01"]),
        node("tab00000http0001", "http request", "tab0000000000001", tls="cfgtls0000000001"),
        {"id": "tab00000groep001", "type": "group", "z": "tab0000000000001", "nodes": ["tab00000http0001"]},
        node("tab00000catch001", "catch", "tab0000000000001", scope=["tab00000functi01"]),
        {"id": "cfgtls0000000001", "type": "tls-config", "name": "tls"},
        {"id": "cfgbroker0000001", "type": "mqtt-broker", "name": "ongebruikt"},
        {"id": "cfgglobal0000001", "type": "global-config", "env": [], "modules": {}},
        *simple_flow(tab_id=TAB2, label="Ook schoon"),
        node("tabanderlinkin01", "link in", TAB2, [["tabandersubflow1"]], links=["tab00000linkout1"]),
        node("tabandersubflow1", "subflow:sub0000000000001", TAB2, [["tabandercall0001"]]),
        node("tabandercall0001", "link call", TAB2, [["tabanderdebug001"]], links=["tabanderlinkin01"]),
        node("tabanderdyn00001", "link call", TAB2, linkType="dynamic", links=[]),
        {
            "id": "sub0000000000001",
            "type": "subflow",
            "name": "Doorgeef",
            "in": [{"x": 50, "y": 30, "wires": [{"id": "sub00000junct001"}]}],
            "out": [{"x": 250, "y": 30, "wires": [{"id": "sub00000junct001", "port": 0}]}],
        },
        node("sub00000junct001", "junction", "sub0000000000001", [[]]),
        tab("tabuit0000000001", "Uitgeschakeld", disabled=True),
        node("tabuit00debug001", "debug", "tabuit0000000001"),
        {"id": "tab00000comment1", "type": "comment", "z": "tab0000000000001", "name": "uitleg", "wires": []},
        *bypass_scenarios(None)["sc7"],
    ]
    result = policy.scan(flows, BYPASS_MODULES, ALLOWED)
    assert len(result.tabs) == 5
    assert [(t.tab_id, t.findings) for t in result.tabs if t.blocked] == []
    assert result.global_findings == [] and result.summary()["geblokkeerd"] == 0


@pytest.mark.parametrize("name", list(ODD_TEXT_FORMS))
def test_scan_of_an_odd_text_form_gives_findings_and_checksums_that_can_be_stored(name: str) -> None:
    """R-VEILIG-8: zo'n vorm is een gewone bevinding ``vorm_ongeldig``, geen crash. Wat de dienst daarna opslaat
    (tabblad-id hooguit 120 tekens, label, typen, bevindingen, samenvatting) bevat geen NUL en geen losse surrogaat
    (PostgreSQL en UTF-8 weigeren die), de checksum is te berekenen en de momentopname bewaart de configuratie zelf
    ongewijzigd (versleuteld) en leest haar terug."""
    import json
    import re

    flows = _with(*ODD_TEXT_FORMS[name])
    result = policy.scan(flows, BYPASS_MODULES, ALLOWED)
    _assert_source_blocked(result)
    assert "vorm_ongeldig" in _causes(result)
    stored = json.dumps(
        [[t.tab_id, t.label, t.node_types, t.findings, t.checksum] for t in result.tabs] + [result.summary()],
        ensure_ascii=False,
    )
    assert "\x00" not in stored and "\\u0000" not in stored, stored
    stored.encode("utf-8")  # een losse surrogaat zou hier falen
    assert all(len(t.tab_id) <= 120 for t in result.tabs)
    assert re.fullmatch("[0-9a-f]{64}", policy.flows_checksum(flows))
    assert json.loads(policy.canonical({"flows": flows})) == {"flows": flows}


def test_scan_leaves_ids_of_120_characters_and_any_valid_text_active() -> None:
    """Geen vals blokkeren (R-VEILIG-8): een id en een ``z`` van precies 120 tekens, letters met accenten, een emoji
    (een geldig surrogaatpaar in JSON), andere schriften en stuurtekens als tab, regeleinde of bel zijn gewoon tekst."""
    import json

    long_tab = "t" * 120
    flows = json.loads(
        json.dumps(
            [
                tab(long_tab, "Wóónkamer ☕ 😀 中文 ελληνικά\tmet tab\nen regel"),
                node("i" * 120, "inject", long_tab, [["f" * 120]], name="ïnject"),
                node("f" * 120, "function", long_tab, [["d" * 120]], func="// é \x07\r\n\treturn msg; // 😀"),
                node("d" * 120, "debug", long_tab, name="\U0001f600 klaar", info={"ß": ["ü", {"ø": "ç"}]}),
            ],
            ensure_ascii=True,  # zoals over de lijn: de emoji als 😀, een geldig paar
        )
    )
    result = policy.scan(flows, MODULES, ALLOWED)
    assert [(t.tab_id, t.blocked) for t in result.tabs] == [(long_tab, False)], result.tabs[0].findings
    assert result.global_findings == []


def test_checksums_of_valid_text_are_unchanged_by_the_surrogate_rule() -> None:
    """Een losse surrogaat maakt de checksum niet meer onmogelijk (R-VEILIG-8), maar voor geldige tekst blijven de bytes
    precies zoals voorheen: anders zou elke bestaande momentopname als onleesbaar gelden (``open_snapshot``)."""
    import hashlib
    import json

    flows = [
        *simple_flow(label="Wóónkamer ☕ 😀 中文"),
        node("tab00000comment1", "comment", "tab0000000000001", info="é"),
    ]
    before = json.dumps(flows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert policy.canonical(flows) == before
    assert policy.flows_checksum(flows) == hashlib.sha256(before).hexdigest()


_SEED_SCRIPT = """
import json, sys
from integrations.domains.automation import policy
flows, modules = json.load(sys.stdin)
res = policy.scan(flows, modules, ("node-red",))
print(json.dumps([[t.tab_id, t.blocked, t.findings, t.checksum] for t in res.tabs] + [res.global_findings]))
"""


def test_scan_outcome_does_not_depend_on_the_hash_seed() -> None:
    """R-VEILIG-3 (herreview 3): met een dubbele id in twee echte tabbladen hing de uitkomst af van de volgorde van
    een set (PYTHONHASHSEED). Nu: voor elke seed dezelfde uitkomst, en het schone tabblad is altijd geblokkeerd."""
    import json
    import os
    import subprocess
    import sys

    dubbel = [
        tab("tabvies000000005", "Vies5"),
        tab(clean_tab_id(5), "Schoon5"),
        node("vies5inject00001", "inject", "tabvies000000005", [["dubbel0000000005"]]),
        node("vies5contrib0001", "x", "tabvies000000005", [["dubbel0000000005"]]),
        node("dubbel0000000005", "link out", "tabvies000000005", mode="link", links=[]),
        node("dubbel0000000005", "link in", clean_tab_id(5), [["schoon5debug001"]], links=[]),
        node("schoon5debug001", "debug", clean_tab_id(5)),
    ]
    combined = [n for name in (*SCENARIOS, "sc7") for n in bypass_scenarios("x")[name]]
    for flows in (dubbel, combined):
        outputs = set()
        for seed in range(10):
            done = subprocess.run(  # noqa: S603 - vaste interpreter, vast script
                [sys.executable, "-c", _SEED_SCRIPT],
                input=json.dumps([flows, BYPASS_MODULES]),
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONHASHSEED": str(seed)},
                check=True,
                timeout=120,
            )
            outputs.add(done.stdout)
        assert len(outputs) == 1, f"{len(outputs)} verschillende uitkomsten over 10 seeds"
        tabs = json.loads(outputs.pop())[:-1]
        assert tabs and all(blocked for _tab, blocked, _f, _c in tabs), tabs


# ------------------------------------------------------------------------------ credentials-bestand (B11-005, R-VEILIG-4)
BLOB = {"$": "0123456789abcdef0123456789abcdefZ2VoZWlt"}


def test_credentials_file_is_read_when_it_is_a_plain_file(tmp_path: Any) -> None:
    import json

    assert snapshots.read_credentials(None).status == "niet_gekoppeld"
    assert snapshots.read_credentials(tmp_path).status == "afwezig"
    assert snapshots.read_credentials(tmp_path / "bestaat-niet").status == "afwezig"
    (tmp_path / snapshots.CRED_FILE).write_text(json.dumps(BLOB), encoding="utf-8")
    got = snapshots.read_credentials(tmp_path)
    assert got.status == "meegenomen" and got.blob == BLOB


def test_credentials_file_never_follows_a_symlink(tmp_path: Any) -> None:
    """Node-RED schrijft zelf in de datamap: een koppeling naar een bestand erbuiten wordt nooit gelezen."""
    import json
    import os

    outside = tmp_path / "buiten"
    outside.mkdir()
    (outside / "geheim.json").write_text(json.dumps({"$": "inhoud-van-buiten-de-datamap"}), encoding="utf-8")
    data_dir = tmp_path / "node-red"
    data_dir.mkdir()
    target = data_dir / snapshots.CRED_FILE
    for points_to in (outside / "geheim.json", "/proc/self/environ", "/proc/self/pagemap", "bestaat-niet"):
        if target.is_symlink():
            target.unlink()
        os.symlink(points_to, target)
        got = snapshots.read_credentials(data_dir)
        assert (got.status, got.blob) == ("onleesbaar", None), points_to


def test_credentials_file_that_is_no_plain_file_is_unreadable_and_never_blocks(tmp_path: Any) -> None:
    import os
    import threading

    os.mkfifo(tmp_path / snapshots.CRED_FILE)  # zonder O_NONBLOCK zou open() hier blijven wachten
    out: list[Any] = []
    worker = threading.Thread(target=lambda: out.append(snapshots.read_credentials(tmp_path)), daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive(), "het lezen van een FIFO bleef hangen"
    assert out[0].status == "onleesbaar"
    os.unlink(tmp_path / snapshots.CRED_FILE)
    (tmp_path / snapshots.CRED_FILE).mkdir()
    assert snapshots.read_credentials(tmp_path).status == "onleesbaar"


def test_credentials_file_is_read_with_a_hard_limit(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    import json
    import os

    path = tmp_path / snapshots.CRED_FILE
    path.write_text(json.dumps({"$": "x" * 100}), encoding="utf-8")
    monkeypatch.setattr(snapshots, "MAX_CRED_BYTES", 50)
    assert snapshots.read_credentials(tmp_path).status == "onleesbaar"
    # ook als de grootte niet klopt (zoals bij /proc, dat st_size 0 meldt): hooguit MAX_CRED_BYTES + 1 byte lezen
    real_fstat = os.fstat

    def zero_size(fd: int) -> Any:
        st = real_fstat(fd)
        return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, st.st_uid, st.st_gid, 0, 0, 0, 0))

    reads: list[int] = []
    real_read = os.read

    def counted(fd: int, n: int) -> bytes:
        reads.append(n)
        return real_read(fd, n)

    monkeypatch.setattr(snapshots.os, "fstat", zero_size)
    monkeypatch.setattr(snapshots.os, "read", counted)
    assert snapshots.read_credentials(tmp_path).status == "onleesbaar"
    assert sum(reads) <= 51


# -------------------------------------------------------------------------------- installatiegebruiker (S-P2-310)
def test_installation_user_is_568_and_the_image_default_is_only_a_measurement() -> None:
    """S-P2-310 bouwpunt 6. Het formulier van het profiel noemt de installatiegebruiker van het manifest van
    jelly-leon-platform (568:568). De standaardgebruiker van de image (1000, gemeten zonder ``--user``) is een aparte
    waarde: alleen de verwachte uitkomst van de meting ``gebruiker_niet_root`` in het verificatierapport, geen
    installatievoorschrift. Zou iemand de twee gelijkzetten (de installatiegebruiker 1000, of de meting 568), dan
    faalt deze test."""
    import json
    from pathlib import Path

    from integrations.domains.automation import catalog

    form = policy.Profile(
        created=True, admin_password_rotated=False, arguments=[], admin_password=None, stored={}
    ).form()
    assert form["gebruiker"] == {"uid": 568, "gid": 568, "root": False}
    assert catalog.NODE_RED_INSTALL_UID == 568 and catalog.NODE_RED_IMAGE_UID == 1000
    report = json.loads(
        (Path(__file__).resolve().parents[4] / "docs/b11/node-red-verificatie.json").read_text(encoding="utf-8")
    )
    measured = next(c for c in report["checks"] if c["id"] == "gebruiker_niet_root")
    assert measured["ok"] is True
    assert measured["detail"] == {"uid": str(catalog.NODE_RED_IMAGE_UID), "verwacht": catalog.NODE_RED_IMAGE_UID}
    assert measured["detail"]["uid"] != "0"
