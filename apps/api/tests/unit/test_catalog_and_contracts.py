"""Unit: inventaris zonder claims, Excel-koppeling, Hub-adres-validatie, retries en HTTP-tijdlimieten."""

from __future__ import annotations

import json

import httpx
import pytest

from integrations.config import Settings
from integrations.domains.automation.catalog import FORBIDDEN_NODE_TYPES
from integrations.domains.energy.catalog import EXPECTED_METER_ROLES
from integrations.domains.sso.catalog import APP_COVERAGE
from integrations.hubclient import HubClient, HubUrlError, validate_hub_url
from integrations.sources import ALL_SOURCES
from tests.conftest import REPO_ROOT


def _excel_ids() -> set[str]:
    data = json.loads((REPO_ROOT / "docs/platform-v2/EXCEL_TAKEN.json").read_text(encoding="utf-8"))
    return {row["ID"] for row in data}


def test_every_capability_links_to_an_excel_task() -> None:
    ids = _excel_ids()
    for spec in ALL_SOURCES.values():
        for cap in spec.capabilities:
            assert cap.task_ids and set(cap.task_ids) <= ids, (spec.source_id, cap.capability_id)


def test_no_unverified_claims_about_external_apps() -> None:
    for spec in ALL_SOURCES.values():
        assert spec.api_verification == "te_verifieren", spec.source_id
    for app in APP_COVERAGE:
        assert app.oidc_support in ("te_verifieren", "gepland"), app.app_id
        assert app.oidc_support != "ondersteund"
    assert {s.domain for s in ALL_SOURCES.values()} == {"network", "automation", "sso", "energy"}


def test_only_b13_001_capabilities_are_marked_built() -> None:
    built = {c.capability_id for s in ALL_SOURCES.values() for c in s.capabilities if c.build_status == "gebouwd"}
    assert built == {"sso.recovery.register", "sso.break_glass.drill", "sso.authentik.health.read"}


def test_safety_rules_in_catalog() -> None:
    assert "exec" in FORBIDDEN_NODE_TYPES
    assert all(r.read_only for r in EXPECTED_METER_ROLES)
    boiler = next(r for r in EXPECTED_METER_ROLES if r.role == "boiler_socket")
    assert "verboden" in boiler.notes_nl and boiler.read_only


@pytest.mark.parametrize(
    "url",
    [
        "ftp://nas:30400",
        "http://",
        "http://user:pw@nas:30400",
        "http://nas:30400/?x=1",
        "http://localhost:30400",
        "http://127.0.0.1:30400",
        "http://[::1]:30400",
        "nas:30400",
    ],
)
def test_hub_url_rejected(url: str) -> None:
    with pytest.raises(HubUrlError):
        validate_hub_url(url)


def test_hub_url_ok_and_loopback_only_in_dev() -> None:
    assert validate_hub_url(" http://nas.lan:30400/ ") == "http://nas.lan:30400"
    assert validate_hub_url("http://127.0.0.1:30400", allow_loopback=True) == "http://127.0.0.1:30400"


def test_hub_client_retries_then_succeeds() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ConnectError("weg", request=request)
        if len(calls) == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"ok": True})

    client = HubClient(Settings(), transport=httpx.MockTransport(handler), sleep=lambda _s: None)
    assert client.get_json("http://hub.test", "/x") == {"ok": True}
    assert len(calls) == 3


def test_hub_client_max_three_attempts_and_no_retry_on_4xx() -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(503 if "retry" in request.url.path else 400)

    client = HubClient(Settings(), transport=httpx.MockTransport(handler), sleep=lambda _s: None)
    assert client.request("GET", "http://hub.test", "/retry").status_code == 503 and len(calls) == 3
    calls.clear()
    assert client.request("GET", "http://hub.test", "/fout").status_code == 400 and len(calls) == 1


def test_default_timeouts_match_contract() -> None:
    s = Settings()
    assert (s.http_connect_timeout_s, s.http_read_timeout_s, s.http_max_attempts) == (5.0, 15.0, 3)
    assert s.port == 30420 and s.jwt_max_lifetime_s == 120 and s.jwt_issuer == "hub"
