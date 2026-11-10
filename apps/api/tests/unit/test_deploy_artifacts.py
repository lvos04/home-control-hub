"""Unit: installatie-artefacten volgen contract 1.3 (alleen standaard Custom App, gepinde images, manifest §9, geen
root-PID 1 en zelf gezette no-new-privileges, healthcheck met controlevlag, Custom App-instructies met digest) +
OpenAPI-drift."""

from __future__ import annotations

import json
import os
import re
import subprocess

import pytest
import yaml

from integrations.cli import export_openapi
from tests.conftest import REPO_ROOT

APPSTORE_CLI = REPO_ROOT.parent / "appstore-en-fork" / ".venv" / "bin" / "jl-manifest"
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


@pytest.mark.skipif(not APPSTORE_CLI.is_file(), reason="geen lokale appstore-en-fork met venv (validator)")
def test_manifest_is_valid_for_the_1_3_validator_in_strict_mode() -> None:
    """Dezelfde controle als de release-CI van appstore-en-fork: jl-manifest validate --strict (C1.3-ASF-08)."""
    out = subprocess.run(  # noqa: S603 - vaste opdracht, geen shell
        [str(APPSTORE_CLI), "validate", "--strict", str(DEPLOY / "manifest/home-control-hub.manifest.yaml")],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert "GELDIG — 0 fout(en)" in out.stdout


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


def test_workflows_pin_actions_by_sha() -> None:
    for wf in (REPO_ROOT / ".github/workflows").glob("*.yml"):
        for line in wf.read_text(encoding="utf-8").splitlines():
            m = re.search(r"uses:\s*(\S+)", line)
            if m:
                assert re.search(r"@[0-9a-f]{40}$", m.group(1)), f"{wf.name}: {m.group(1)} niet op SHA gepind"
