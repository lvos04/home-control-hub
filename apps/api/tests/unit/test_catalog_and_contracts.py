"""Unit: inventaris zonder claims, Excel-koppeling, Hub-adres-validatie, retries en HTTP-tijdlimieten."""

from __future__ import annotations

import json

import httpx
import pytest

from integrations.config import Settings
from integrations.domains.automation.catalog import FORBIDDEN_NODE_TYPES
from integrations.domains.energy.catalog import EXPECTED_METER_ROLES
from integrations.domains.sso.authentik import compat
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
    """Alleen wat in een officiële bron of de broncode staat; nooit 'ondersteund' zonder URL en verificatie."""
    for spec in ALL_SOURCES.values():
        if spec.source_id == "authentik":
            assert spec.api_verification == "geverifieerd_docs" and spec.api_verification_ref
        else:
            assert spec.api_verification == "te_verifieren", spec.source_id
    report = json.loads((REPO_ROOT / "docs/b13/authentik-api-verificatie.json").read_text(encoding="utf-8"))
    assert report["all_ok"] and {r["version"] for r in report["results"]} == {
        f"{y}.{m}.{p}" for y, m, p in compat.RELEASE_LINES
    }
    assert all(r["schema_sha256"] == compat.SCHEMA_SHA256[r["version"]] for r in report["results"])
    for app in APP_COVERAGE:
        assert app.trusted_header_sso == "niet_toegestaan"
        assert app.source.url and app.source.ref and app.source.checked_on
        if app.oidc_support in ("ondersteund", "ondersteund_met_voorwaarden", "niet_ondersteund"):
            assert app.source.verification in ("geverifieerd_docs", "geverifieerd_broncode"), app.app_id
        if app.oidc_support == "gepland":
            assert app.source.kind == "eigen_plan"
        assert app.mapping_allowed == (app.oidc_support != "niet_ondersteund" and bool(app.roles))
    by_id = {a.app_id: a for a in APP_COVERAGE}
    for own in ("mediaguard", "media-source-optimizer", "my_house"):
        assert by_id[own].oidc_support == "niet_ondersteund" and by_id[own].source.kind == "broncode"
    assert {s.domain for s in ALL_SOURCES.values()} == {"network", "automation", "sso", "energy"}


def test_built_capabilities_are_exactly_b13() -> None:
    built = {c.capability_id for s in ALL_SOURCES.values() for c in s.capabilities if c.build_status == "gebouwd"}
    assert built == {
        "sso.recovery.register",
        "sso.break_glass.drill",
        "sso.authentik.health.read",
        "sso.authentik.detect",
        "sso.oidc.hub.propose",
        "sso.oidc.hub.check",
        "sso.app_mapping",
        "sso.rights.read",
        "sso.audit.events",
        "sso.config.export",
        "sso.upgrade.gate",
        "sso.restore.check",
        "sso.sessions.revoke.propose",
    }
    # uitvoeren in Authentik is nergens gebouwd (vereist een ondertekend ExecutionRequest, P2)
    applies = [c for s in ALL_SOURCES.values() for c in s.capabilities if c.kind == "apply"]
    assert applies and all(c.build_status == "niet_gebouwd" for c in applies)


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
        # contract 1.2 §3.2: geen pad, geen link-local, geen 0.0.0.0/::, geen fragment, geldige poort
        "http://nas:30400/api",
        "http://nas:30400/#x",
        "http://169.254.10.20:30400",
        "http://[fe80::1]:30400",
        "http://0.0.0.0:30400",
        "http://[::]:30400",
        "http://nas:0",
        "http://nas:99999",
        "http://nas .lan:30400",
        "",
        # review contract 1.2: afwijkende IPv4-vormen en een punt achteraan omzeilen de regels hierboven niet
        "http://127.1:30400",
        "http://2130706433:30400",
        "http://0x7f000001:30400",
        "http://0:30400",
        "http://010.0.0.1:30400",
        "http://169.254.1:30400",
        "http://localhost.:30400",
        "http://127.0.0.1.:30400",
        "http://[::ffff:127.0.0.1]:30400",
    ],
)
def test_hub_url_rejected(url: str) -> None:
    with pytest.raises(HubUrlError):
        validate_hub_url(url)


def test_hub_url_ok_and_loopback_only_in_dev() -> None:
    assert validate_hub_url(" http://nas.lan:30400/ ") == "http://nas.lan:30400"
    assert validate_hub_url("http://127.0.0.1:30400", allow_loopback=True) == "http://127.0.0.1:30400"
    # gewone namen die met cijfers of 0x beginnen en IPv6-ULA blijven geldig
    for ok in ("http://1nas.lan:30400", "http://0xnas:30400", "http://[fd00::1]:30400", "http://nas.lan.:30400"):
        assert validate_hub_url(ok) == ok


def test_hub_client_never_follows_redirects_and_ignores_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """§3.2/§5: 3xx is een storing (nooit volgen) en proxy-omgevingsvariabelen worden genegeerd; één poging per
    aanroep (herhalen met backoff regelt de koppellogica zelf)."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.host == "hub.test":
            return httpx.Response(302, headers={"Location": "http://evil.test/api/v1/services/enroll"})
        return httpx.Response(200)

    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
    client = HubClient(Settings(), transport=httpx.MockTransport(handler))
    r = client.request("POST", "http://hub.test:30400", "/api/v1/services/enroll", json={})
    assert r.status_code == 302 and calls == ["http://hub.test:30400/api/v1/services/enroll"]
    with client.client() as c:
        assert c.follow_redirects is False and c._trust_env is False
    calls.clear()

    def down(request: httpx.Request) -> httpx.Response:
        calls.append("x")
        raise httpx.ConnectError("weg", request=request)

    with pytest.raises(httpx.ConnectError):
        HubClient(Settings(), transport=httpx.MockTransport(down)).request("GET", "http://hub.test", "/x")
    assert calls == ["x"]


def test_default_timeouts_match_contract() -> None:
    s = Settings()
    assert (s.http_connect_timeout_s, s.http_read_timeout_s, s.http_max_attempts) == (5.0, 15.0, 3)
    assert s.port == 30420 and s.jwt_max_lifetime_s == 120 and s.jwt_issuer == "hub"


def test_every_event_type_follows_contract_7() -> None:
    """Contract §7: precies <domein>.<object>.<gebeurtenis> (zoals de inbox van de Hub controleert). Gecontroleerd
    in de broncode én in ``events.emit`` zelf, zodat een nieuw eventtype met vier segmenten meteen faalt."""
    import re
    import uuid as _uuid

    from integrations import events

    src = REPO_ROOT / "apps/api/src/integrations"
    names = set()
    for f in src.rglob("*.py"):
        names |= set(re.findall(r'event_type="([^"]+)"', f.read_text(encoding="utf-8")))
    assert len(names) >= 20
    bad = sorted(n for n in names if not events.EVENT_TYPE_RE.match(n))
    assert bad == []
    for wrong in ("sso.authentik.sync.failed", "sso.failed", "SSO.access.revoked", "sso.access-x.revoked"):
        with pytest.raises(ValueError):
            events.emit(
                None,  # type: ignore[arg-type]
                event_type=wrong,
                entity_type="x",
                entity_id="1",
                actor_type="system",
                actor_id="t",
                trace_id=str(_uuid.uuid4()),
            )


def test_event_payload_and_ids_fit_the_hub_limits() -> None:
    from integrations import events

    big = {"status": "x", "lijst": ["a" * 100] * 400}
    fitted = events._fit_payload(big)
    assert fitted["_ingekort"] is True and fitted["status"] == "x" and "lijst" not in fitted
    assert events._fit_payload({"a": 1}) == {"a": 1}
