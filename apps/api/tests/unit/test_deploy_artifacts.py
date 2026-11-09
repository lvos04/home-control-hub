"""Unit: installatie-artefacten volgen contract 1.1 (alleen standaard Custom App, gepinde images) + OpenAPI-drift."""

from __future__ import annotations

import json
import re

import yaml

from integrations.cli import export_openapi
from tests.conftest import REPO_ROOT

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
        "/healthz",
        "/readyz",
    ):
        assert path in spec["paths"], path


def test_manifest_is_custom_app_and_safe() -> None:
    m = yaml.safe_load((DEPLOY / "manifest/home-control-hub.manifest.yaml").read_text(encoding="utf-8"))
    assert m["manifest_version"] == "1" and m["app_id"] == "home-control-hub"
    assert m["install"]["method"] == "custom_app"
    assert "compose" not in m and "custom_compose_config" not in json.dumps(m)
    assert m["image"]["repository"] == "ghcr.io/lvos04/home-control-hub" and m["image"]["tag"] != "latest"
    assert m["custom_app"]["ports"][0]["container_port"] == 30420
    assert m["privileges"] == {"privileged": False, "cap_add": [], "devices": [], "gpu": "none"}
    assert m["network"]["host_network"] is False
    for s in m["storage"]:
        assert s["mount"] not in FORBIDDEN_HOST_PATHS
    assert m["validation_status"].startswith("NIET GEVALIDEERD")
    version = (REPO_ROOT / "VERSION").read_text().strip()
    assert m["version"] == m["image"]["tag"] == version


def test_dockerfile_pins_base_images_by_digest_and_no_latest() -> None:
    text = (DEPLOY / "allinone/Dockerfile").read_text(encoding="utf-8")
    images = re.findall(r"^ARG \w+_IMAGE=(\S+)$", text, flags=re.MULTILINE)
    assert len(images) == 2
    for img in images:
        assert re.search(r":\d+\.\d+(\.\d+)?[\w.-]*@sha256:[0-9a-f]{64}$", img), img
    assert ":latest" not in text and "docker.sock" not in text
    assert "/run/secrets/ca_bundle" in text and "required=false" in text  # CA alleen als optionele BuildKit-secret
    assert "ca-bundle.crt" not in text


def test_no_yaml_or_compose_install_instructions() -> None:
    guide = (DEPLOY / "truenas/CUSTOM_APP.md").read_text(encoding="utf-8")
    assert "Custom App" in guide and "30420" in guide and "/appdata" in guide
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
