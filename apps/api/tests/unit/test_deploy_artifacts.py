"""Unit: installatie-artefacten volgen contract 1.3 (alleen standaard Custom App, gepinde images, manifest §9, geen
root-PID 1 en zelf gezette no-new-privileges, healthcheck met controlevlag, Custom App-instructies met digest) +
OpenAPI-drift."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from integrations.cli import export_openapi
from tests.conftest import REPO_ROOT

#: de manifestvalidator van appstore-en-fork (C1.3-ASF-08): in CI een eigen venv op een vaste commit (``HCH_JL_MANIFEST``,
#: zie .github/workflows/ci.yml); lokaal de venv van de checkout naast deze repo. Met
#: ``HCH_MANIFEST_VALIDATOR_VERPLICHT=1`` faalt de test als de validator ontbreekt (CI mag hem niet stil overslaan).
APPSTORE_CLI = Path(
    os.environ.get("HCH_JL_MANIFEST") or REPO_ROOT.parent / "appstore-en-fork" / ".venv" / "bin" / "jl-manifest"
)
VALIDATOR_VERPLICHT = os.environ.get("HCH_MANIFEST_VALIDATOR_VERPLICHT") == "1"
DEPLOY = REPO_ROOT / "deploy"
FORBIDDEN_HOST_PATHS = ("/", "/mnt", "/etc", "/var/run", "/root")


def test_openapi_export_has_no_drift() -> None:
    committed = (REPO_ROOT / "docs/openapi/home-control-hub.openapi.json").read_text(encoding="utf-8")
    assert export_openapi() == committed, "OpenAPI wijkt af: draai 'make openapi' en commit het resultaat"


def test_openapi_documents_error_and_idempotency_contract() -> None:
    spec = json.loads(export_openapi())
    post = spec["paths"]["/integrations/v1/sso/recovery/accounts"]["post"]
    assert any(p["name"] == "Idempotency-Key" and p["in"] == "header" for p in post["parameters"])
    for path in (
        "/connector/v1/discover",
        "/connector/v1/health",
        "/connector/v1/items",
        "/connector/v1/propose",
        "/connector/v1/apply",
        "/connector/v1/rollback",
        "/connector/v1/evidence/{evidence_id}",
        "/connector/v1/events",
        "/connector/v1/hub-link",
        "/connector/v1/hub-link/unlink",
        "/healthz",
        "/readyz",
    ):
        assert path in spec["paths"], path
    # contract 1.2 §6/§3.8: de oude koppelroutes bestaan niet meer
    assert "/integrations/v1/enrollment" not in spec["paths"]
    assert "/integrations/v1/enrollment/unpair" not in spec["paths"]
    unlink = spec["paths"]["/connector/v1/hub-link/unlink"]["post"]
    assert any(p["name"] == "Idempotency-Key" and p["in"] == "header" for p in unlink["parameters"])


def test_manifest_is_custom_app_and_safe() -> None:
    m = yaml.safe_load((DEPLOY / "manifest/home-control-hub.manifest.yaml").read_text(encoding="utf-8"))
    assert m["manifest_version"] == "1" and m["app_id"] == "home-control-hub"
    assert m["install"]["method"] == "custom_app"
    assert "compose" not in m and "custom_compose_config" not in json.dumps(m)
    assert m["image"]["repository"] == "ghcr.io/lvos04/home-control-hub" and m["image"]["tag"] != "latest"
    # contract 1.2 §9: poorten alleen in network.ports; custom_app.ports en joins_platform_network vervallen
    assert "ports" not in m["custom_app"] and "joins_platform_network" not in m["network"]
    ports = {p["name"]: p for p in m["network"]["ports"]}
    assert ports["web"]["container_port"] == 30420 and ports["web"]["protocol"] == "tcp"
    assert m["healthcheck"]["port"] in ports and m["custom_app"]["portal"]["port"] in ports
    assert m["custom_app"]["env"] == []  # HUB_* zet de Hub zelf bij installatie (§3.2)
    assert m["privileges"] == {"privileged": False, "cap_add": [], "devices": [], "gpu": "none"}
    assert m["network"]["host_network"] is False
    for s in m["storage"]:
        assert s["mount"] not in FORBIDDEN_HOST_PATHS
    assert m["validation_status"] == "unvalidated"
    version = (REPO_ROOT / "VERSION").read_text().strip()
    assert m["version"] == m["image"]["tag"] == version


def test_manifest_follows_contract_1_3() -> None:
    """Contract 1.3 §9 (C1.3-HCH-13): HUB_* is gereserveerd, monitorplan in healthcheck.monitor, kop 1.3 en alleen
    geaccepteerde waarschuwingen uit de vaste lijst."""
    text = (DEPLOY / "manifest/home-control-hub.manifest.yaml").read_text(encoding="utf-8")
    m = yaml.safe_load(text)
    assert "platformcontract 1.3 §9" in text.splitlines()[0]
    names = [p["name"] for p in m.get("parameters", [])] + [e["name"] for e in m["custom_app"]["env"]]
    assert not [n for n in names if n.upper().startswith("HUB_")]
    assert m["healthcheck"]["monitor"] == {"pad": "/readyz", "verwachte_status": 200, "timeout_s": 8, "interval_s": 60}
    assert m["healthcheck"]["monitor"]["pad"] == m["healthcheck"]["path"]
    assert [a["code"] for a in m["accepted_findings"]] == ["digest_pending_release"]
    assert all(a["reden_nl"] for a in m["accepted_findings"])


@pytest.mark.skipif(
    not VALIDATOR_VERPLICHT and not APPSTORE_CLI.is_file(),
    reason="geen manifestvalidator (HCH_JL_MANIFEST of een lokale appstore-en-fork met venv)",
)
def test_manifest_is_valid_for_the_1_3_validator_in_strict_mode() -> None:
    """Dezelfde controle als de release-CI van appstore-en-fork: jl-manifest validate --strict (C1.3-ASF-08)."""
    assert APPSTORE_CLI.is_file(), f"manifestvalidator verplicht maar niet gevonden: {APPSTORE_CLI}"
    out = subprocess.run(  # noqa: S603 - vaste opdracht, geen shell
        [str(APPSTORE_CLI), "validate", "--strict", str(DEPLOY / "manifest/home-control-hub.manifest.yaml")],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert "GELDIG — 0 fout(en)" in out.stdout


def _socket_via_storage(m: dict[str, Any]) -> str:
    # bewust zonder declaratie in storage[]: een onvolledige declaratie stopt de validator al bij het schema
    m["custom_app"]["storage"].append({"name": "docker", "type": "host_path", "host_path": "/var/run/docker.sock"})
    return "custom_app.storage[1].host_path"


def _socket_via_env(m: dict[str, Any]) -> str:
    m["custom_app"]["env"].append({"name": "DOCKER_HOST", "value": "unix:///var/run/docker.sock"})
    return "custom_app.env[0]"


@pytest.mark.skipif(
    not VALIDATOR_VERPLICHT and not APPSTORE_CLI.is_file(),
    reason="geen manifestvalidator (HCH_JL_MANIFEST of een lokale appstore-en-fork met venv)",
)
@pytest.mark.parametrize("variant", [_socket_via_storage, _socket_via_env], ids=["opslag", "omgeving"])
def test_validator_rejects_a_manifest_variant_with_a_docker_socket(
    tmp_path: Path, variant: Callable[[dict[str, Any]], str]
) -> None:
    """S-P2-290 (negatief): een variant van het eigen manifest met een Docker-socket wordt door dezelfde validator
    geweigerd (``docker_socket_forbidden``), zodat 'geen Docker-socket' niet alleen een belofte in de docs is."""
    assert APPSTORE_CLI.is_file(), f"manifestvalidator verplicht maar niet gevonden: {APPSTORE_CLI}"
    m = yaml.safe_load((DEPLOY / "manifest/home-control-hub.manifest.yaml").read_text(encoding="utf-8"))
    pad = variant(m)
    bestand = tmp_path / "variant.manifest.yaml"
    bestand.write_text(yaml.safe_dump(m, allow_unicode=True, sort_keys=False), encoding="utf-8")
    out = subprocess.run(  # noqa: S603 - vaste opdracht, geen shell
        [str(APPSTORE_CLI), "validate", "--strict", str(bestand)],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
    )
    assert out.returncode != 0, out.stdout + out.stderr
    regels = [r for r in out.stdout.splitlines() if "docker_socket_forbidden" in r]
    assert regels and all(r.split()[0] == "FOUT" for r in regels), out.stdout
    assert any(pad in r for r in regels), out.stdout


def test_dockerfile_pins_base_images_by_digest_and_no_latest() -> None:
    text = (DEPLOY / "allinone/Dockerfile").read_text(encoding="utf-8")
    images = re.findall(r"^ARG \w+_IMAGE=(\S+)$", text, flags=re.MULTILINE)
    assert len(images) == 2
    for img in images:
        assert re.search(r":\d+\.\d+(\.\d+)?[\w.-]*@sha256:[0-9a-f]{64}$", img), img
    assert ":latest" not in text and "docker.sock" not in text
    assert "/run/secrets/ca_bundle" in text and "required=false" in text  # CA alleen als optionele BuildKit-secret
    assert "ca-bundle.crt" not in text
    # A6/HC7: geen init die als root blijft draaien; de bewaker is PID 1 en zet zelf no-new-privileges
    assert "dumb-init==" not in text and "bin/dumb-init" not in text and "bin/tini" not in text
    assert 'ENTRYPOINT ["python", "/usr/local/lib/hch/supervisor.py"]' in text
    sup = (DEPLOY / "allinone/supervisor.py").read_text(encoding="utf-8")
    assert "PR_SET_NO_NEW_PRIVS = 38" in sup and "PR_CAPBSET_DROP" in sup and "def reap_orphans" in sup
    assert "os.setgroups([])" in sup
    hc = (DEPLOY / "allinone/healthcheck.py").read_text(encoding="utf-8")
    assert "os.setuid(UID)" in hc and "PR_SET_NO_NEW_PRIVS = 38" in hc and "PR_CAPBSET_DROP = 24" in hc
    # contract 1.3 §2.2 (C1.3-HCH-12): exec-vorm en een controlevlag voor de rooktest
    assert 'CMD ["python", "/usr/local/lib/hch/healthcheck.py"]' in text and "--controle" in hc
    # de wissel is de eerste handeling: vóór /readyz en vóór de controle
    main = hc[hc.index("def main()") :]
    assert main.index("wissel()") < main.index("--controle") < main.index("/readyz")


def test_smoke_test_runs_like_the_custom_app_form() -> None:
    """A6: de rooktest draait zonder --security-opt no-new-privileges en zonder --cap-drop (zoals het formulier) en
    controleert per proces Uid 568, CapEff 0 en NoNewPrivs 1."""
    text = (DEPLOY / "allinone/smoke-test.sh").read_text(encoding="utf-8")
    run = text[text.index("run() {") : text.index("}", text.index("run() {"))]
    code = "\n".join(line for line in run.splitlines()[1:] if not line.lstrip().startswith("#"))
    assert "docker run" in code
    assert "--security-opt" not in code and "--cap-drop" not in code and "--cap-add" not in code
    for needle in ('["568"] * 4', '"0" * 16', '"NoNewPrivs"', "pid1_is_supervisor_568", "zombies_reaped"):
        assert needle in text, needle
    # contract 1.3 §2.2: ook CapPrm/CapAmb 0, CapBnd 0 bij een start als root, en de healthcheck apart
    for needle in ('"CapPrm"', '"CapAmb"', '"CapBnd"', "healthcheck.py --controle", "procs_ok $NAME 1"):
        assert needle in text, needle


def test_no_yaml_or_compose_install_instructions() -> None:
    guide = (DEPLOY / "truenas/CUSTOM_APP.md").read_text(encoding="utf-8")
    assert "Custom App" in guide and "30420" in guide and "/appdata" in guide
    # contract 1.2: tag met digest (§2.2), publieke image met registry-login alleen als terugval (§2.1),
    # HUB_KEY_FINGERPRINT (§3.2) en geen lokale ontkoppelcode meer (§3.7)
    assert "@sha256:" in guide and "release/digests.json" in guide and "HUB_KEY_FINGERPRINT" in guide
    assert "terugval" in guide.lower() and "ontkoppelcode" not in guide.lower()
    lowered = guide.lower()
    assert "install via yaml" in lowered  # alleen genoemd als wat je NIET doet
    assert "geen yaml" in lowered and "custom_compose_config" not in lowered
    compose = (DEPLOY / "dev/compose.yaml").read_text(encoding="utf-8")
    assert "GEEN installatiemethode" in compose


#: alle installatiedocumenten onder deploy/truenas (V-096): ook NODE_RED_CUSTOM_APP.md (S-P2-290)
INSTALL_DOCS = sorted((DEPLOY / "truenas").glob("*.md"))
#: een verbod staat direct vóór de genoemde weg ("geen *Install via YAML*", "niet `curl … | sh`"); een los "geen",
#: "nooit" of "niet" ergens anders in de regel telt niet als verbod (A-09, S-P2-290 R-MANIFEST-5)
_VERBOD = r"\b(?:geen|nooit|niet)\s+(?:(?:via|met|een)\s+)?[*_`(\"']*"
#: installatiewegen die alleen als verbod genoemd mogen worden: YAML en een terminal (curl/wget naar een shell, ssh,
#: sudo, een shellscript of sh -c)
VERBODEN_WEGEN: dict[str, str] = {
    "Install via YAML": r"install via yaml",
    "curl/wget naar een shell": r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b",
    "ssh": r"\bssh\s+[\w.@-]",
    "sudo": r"\bsudo\s+[\w.-]",
    "shellscript": r"(?:\b(?:ba|z|da)?sh\s+|\./)[\w./-]*\.sh\b",
    "sh -c": r"\b(?:ba|z|da)?sh\s+-c\b",
}


def _installatieweg_fouten(naam: str, tekst: str) -> list[str]:
    """Alle plekken in een installatiedocument met een installatieweg via YAML, compose of een terminal."""
    fouten: list[str] = []
    lowered = tekst.lower()
    for verboden in ("custom_compose_config", "docker compose up", "docker-compose up", "docker exec"):
        if verboden in lowered:
            fouten.append(f"{naam}: {verboden}")
    for regel in lowered.splitlines():
        for weg, patroon in VERBODEN_WEGEN.items():
            for treffer in re.finditer(patroon, regel):
                if not re.search(_VERBOD + r"$", regel[: treffer.start()]):
                    fouten.append(f"{naam}: '{weg}' niet als verbod genoemd: {regel}")
    return fouten


def test_install_docs_give_no_yaml_compose_or_terminal_route() -> None:
    """V-096 / contract kop 1: geen installatieweg via YAML, compose of een terminal (curl/wget naar een shell, ssh,
    sudo, een shellscript) in welk installatiedocument dan ook; zulke wegen alleen genoemd als wat je niet doet."""
    namen = [p.name for p in INSTALL_DOCS]
    assert "CUSTOM_APP.md" in namen and "NODE_RED_CUSTOM_APP.md" in namen, namen
    for p in INSTALL_DOCS:
        assert _installatieweg_fouten(p.name, p.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    "regel",
    [
        "Installeer met `curl … | sh`.",
        "Installeer met `curl -fsSL https://voorbeeld.invalid/install | sudo bash`.",
        "Of: `wget -qO- https://voorbeeld.invalid/i | sh`.",
        "Log in met `ssh beheerder@nas` en start de app.",
        "Voer `sudo docker run home-control-hub` uit.",
        "Draai `bash install.sh` of `./install.sh`.",
        "Start met `sh -c 'installeer'`.",
        "Geen zorgen: kies *Install via YAML*.",
        "Dit is niet moeilijk: Install via YAML.",
    ],
)
def test_install_route_check_rejects_a_terminal_or_yaml_route_in_a_copy(regel: str) -> None:
    """A-09: de controle ziet een terminal- of YAML-weg in een kopie van een installatiedocument; een los
    "geen/niet/nooit" elders in de regel maakt er geen verbod van."""
    tekst = (DEPLOY / "truenas/CUSTOM_APP.md").read_text(encoding="utf-8") + "\n" + regel + "\n"
    assert _installatieweg_fouten("CUSTOM_APP.md (kopie)", tekst) != []


@pytest.mark.parametrize(
    "regel",
    [
        "Geen YAML, geen *Install via YAML*, geen terminal.",
        "Knop **Custom App** (niet *Install via YAML*).",
        "Nooit `curl … | sh`, geen `sudo docker run` en geen `ssh beheerder@nas`.",
    ],
)
def test_install_route_check_accepts_a_route_named_as_prohibition(regel: str) -> None:
    tekst = (DEPLOY / "truenas/CUSTOM_APP.md").read_text(encoding="utf-8") + "\n" + regel + "\n"
    assert _installatieweg_fouten("CUSTOM_APP.md (kopie)", tekst) == []


def test_node_red_doc_refers_to_the_manifest_without_own_form_fields() -> None:
    """S-P2-290 bouwpunt 3: NODE_RED_CUSTOM_APP.md verwijst naar het manifest van jelly-leon-platform (568:568) en
    beschrijft geen eigen formuliervelden (geen 1000:1000, geen argumenten van het profiel)."""
    text = (DEPLOY / "truenas/NODE_RED_CUSTOM_APP.md").read_text(encoding="utf-8")
    assert "install/manifests/node-red.manifest.yaml" in text and "568:568" in text
    assert "1000:1000" not in text and "--define" not in text and "credentialSecret=" not in text


def test_node_red_docs_describe_what_the_code_does_without_a_service_account() -> None:
    """R-TECH-1 / R-MANIFEST-2 (S-P2-290): met een Node-RED volgens het manifest is er tot besluit C-12 geen
    dienstaccount; de code geeft dan `onbekend` met `geen_aanmelding` (snapshots.run_isolation_check,
    nodered.client_from_source). Beide documenten noemen dat, en de Hub-handelingen heten nog niet beschikbaar."""
    for naam in ("NODE_RED_CUSTOM_APP.md", "CUSTOM_APP.md"):
        text = (DEPLOY / "truenas" / naam).read_text(encoding="utf-8")
        assert "`geen_aanmelding`" in text, naam
        assert "nog niet beschikbaar" in text, naam
    text = (DEPLOY / "truenas/NODE_RED_CUSTOM_APP.md").read_text(encoding="utf-8")
    probleemrijen = [r for r in text.splitlines() if r.startswith("|") and "`geen_aanmelding`" in r]
    assert probleemrijen, "de tabel Problemen mist geen_aanmelding"
    assert "*Isolatie meten*" not in text  # geen knop in de Hub die nog niet bestaat


def test_node_red_docs_do_not_promise_that_the_key_is_out_of_reach() -> None:
    """R-TECH-2 / R-MANIFEST-1 (S-P2-290): de dataset van een Node-RED volgens het manifest bevat ook de sleutel van de
    credentials (.config.runtime.json). Geen belofte "kan niet ontsleutelen" en geen koppel-instructie voor die
    dataset; het risico staat er met naam."""
    for naam in ("NODE_RED_CUSTOM_APP.md", "CUSTOM_APP.md"):
        text = (DEPLOY / "truenas" / naam).read_text(encoding="utf-8")
        assert "niet ontsleutelen" not in text, naam
        assert ".config.runtime.json" in text, naam
        assert "Mount Path = `/node-red-data`" not in text and "Mount Path `/node-red-data`" not in text, naam


def test_install_docs_name_settings_that_the_manifest_does_not_set() -> None:
    """R-MANIFEST-3 (P-INSTALLATIE punt 9): een HCH_*-variabele uit een installatiedocument die het manifest niet
    zet, staat er met de uitdrukkelijke melding dat ze niet in het manifest staat."""
    m = yaml.safe_load((DEPLOY / "manifest/home-control-hub.manifest.yaml").read_text(encoding="utf-8"))
    in_manifest = {e["name"] for e in m["custom_app"]["env"]}
    for p in INSTALL_DOCS:
        text = p.read_text(encoding="utf-8")
        extra = set(re.findall(r"\bHCH_[A-Z0-9_]+\b", text)) - in_manifest
        if extra:
            assert "niet in het manifest" in text, f"{p.name}: {sorted(extra)} zonder melding"


#: de vaste zin uit S-P2-290 (kop "Bewijs"), op één regel zodat een letterlijke controle hem vindt (R-TECH-4)
VASTE_ZIN = "NIET GEVALIDEERD (echte NAS): niet als Custom App op TrueNAS geïnstalleerd; zie STAPPEN_P6.md."


@pytest.mark.parametrize(
    "pad",
    [
        "README.md",
        "CHANGELOG.md",
        "deploy/truenas/CUSTOM_APP.md",
        "deploy/truenas/NODE_RED_CUSTOM_APP.md",
        "docs/adr/ADR-0016-b11-node-red-automatisering.md",
        "docs/platform-v2/DELTA_MATRIX.md",
    ],
)
def test_fixed_not_validated_sentence_is_on_one_line(pad: str) -> None:
    text = (REPO_ROOT / pad).read_text(encoding="utf-8")
    assert any(VASTE_ZIN in regel for regel in text.splitlines()), pad


def test_workflows_pin_actions_by_sha() -> None:
    for wf in (REPO_ROOT / ".github/workflows").glob("*.yml"):
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = re.search(r"uses:\s*(\S+)", line)
            if m:
                assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{wf.name}: {m.group(1)} niet op SHA gepind"


def test_ci_runs_the_validator_and_the_peil_reference_as_mandatory() -> None:
    """C1.3-HCH-13 en Peil 1.1.1 (E07): in CI draaien de manifestvalidator en de referentie-renderer op vaste commits en
    verplicht; zonder die stappen zouden de twee tests hierboven en in test_statuspagina_peil.py stil overgeslagen
    worden."""
    ci = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert re.search(r"VALIDATOR_COMMIT: [0-9a-f]{40}\n", ci)
    assert '/bin/jl-manifest" validate --strict deploy/manifest/home-control-hub.manifest.yaml' in ci
    assert 'echo "HCH_MANIFEST_VALIDATOR_VERPLICHT=1"' in ci and 'echo "HCH_PEIL_REFERENTIE_VERPLICHT=1"' in ci
    assert '["bron_commit"]' in ci and "/design/ontwerptaal/bouw/sjabloon.py" in ci
