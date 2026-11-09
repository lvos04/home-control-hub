"""Integratie (PostgreSQL): migraties, auth/rollen, foutformaat, Idempotency-Key, ETag, connector, statuspagina."""

from __future__ import annotations

import time
import uuid
from typing import Any

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

from integrations.config import Settings
from integrations.migrations import downgrade, head_revision, upgrade
from integrations.models import all_models
from tests.conftest import AUTHENTIK_URL, HUB_URL, FakeHub, idem, recreate_database

pytestmark = pytest.mark.integration


# ------------------------------------------------------------------ migraties
def test_migrations_up_down_up_and_no_drift() -> None:
    url = recreate_database("hch_test_migrations")
    settings = Settings(database_url=url)
    upgrade(settings)
    eng = create_engine(url)
    tables = set(inspect(eng).get_table_names())
    assert {"sso_admin_account", "network_device", "automation_flow", "energy_meter", "outbox_event"} <= tables
    with eng.connect() as c:
        labels = {r[0] for r in c.execute(text("SELECT code FROM energy_sample_quality"))}
        assert labels == {"gemeten", "geschat", "onbekend"}
        ctx = MigrationContext.configure(c, opts={"compare_type": True})
        diff = compare_metadata(ctx, all_models().metadata)
    assert diff == [], f"schema-drift tussen modellen en migraties: {diff}"
    downgrade(settings, "base")
    assert set(inspect(eng).get_table_names()) <= {"alembic_version"}
    upgrade(settings)
    with eng.connect() as c:
        assert c.execute(text("SELECT version_num FROM alembic_version")).scalar() == head_revision(settings)
    eng.dispose()


def test_schema_invariants_enforced_by_database(clean_db: str) -> None:
    """Invarianten uit B10/B13/B14 worden door PostgreSQL zelf afgedwongen."""
    eng = create_engine(clean_db)
    bad_statements = [
        # B10-001: geen malware zonder bewijs
        "INSERT INTO network_security_finding (id, category, severity, confidence, evidence, status, detected_by, "
        "created_at, updated_at) VALUES (gen_random_uuid(), 'malware', 'hoog', 0.9, '[]', 'open', 'regel', now(), now())",
        # B13-001: noodaccount niet SSO-only
        "INSERT INTO sso_admin_account (id, system, username, display_name, is_break_glass, login_kind, mfa_status, "
        "mfa_methods, status, notes, version, created_by, updated_by, created_at, updated_at) VALUES "
        "(gen_random_uuid(), 'hub_local', 'x', '', true, 'sso', 'onbekend', '[]', 'actief', '', 1, 't', 't', now(), now())",
        # B14: meter altijd read-only (boiler nooit schakelen)
        "INSERT INTO energy_meter (id, source_id, source_meter_id, display_name, unit, read_only, version, created_at, "
        "updated_at) VALUES (gen_random_uuid(), 'my_house', 'boiler', 'Boiler', 'kWh', false, 1, now(), now())",
        # B14-001: geen CPU-model zonder kalibratie
        "INSERT INTO energy_estimate_provenance (id, method, assumptions, confidence, created_at) VALUES "
        "(gen_random_uuid(), 'cpu_model', '{}', 0.5, now())",
        # netwerkwijzigingen nooit R0/R1
        "INSERT INTO network_policy_change (id, action_kind, risk_class, status, requires_independent_test, "
        "created_at, created_by) VALUES (gen_random_uuid(), 'firewall', 'R1', 'voorstel', true, now(), 't')",
    ]
    for stmt in bad_statements:
        with eng.connect() as c, pytest.raises(Exception, match="check constraint"):
            c.execute(text(stmt))
    eng.dispose()


# ------------------------------------------------------------------ auth, rollen, foutformaat
def test_error_format_and_trace_id(client: Any) -> None:
    tid = str(uuid.uuid4())
    r = client.get("/connector/v1/discover", headers={"X-Trace-Id": tid})
    assert r.status_code == 401
    body = r.json()
    assert set(body) == {"code", "message", "details", "trace_id"}
    assert body["code"] == "unauthorized" and body["trace_id"] == tid and r.headers["X-Trace-Id"] == tid
    assert client.get("/bestaat-niet").json()["code"] == "not_found"


def test_not_paired_is_fail_closed(client: Any, auth: Any) -> None:
    r = client.get("/connector/v1/discover", headers=auth("admin"))
    assert r.status_code == 401 and r.json()["details"]["reason"] in ("jwks_niet_beschikbaar", "niet_gekoppeld")


def test_roles_least_privilege(paired_client: Any, auth: Any) -> None:
    c = paired_client
    assert c.get("/integrations/v1/sso/recovery/overview", headers=auth("admin")).status_code == 200
    r = c.get("/integrations/v1/sso/recovery/overview", headers=auth("operator"))
    assert r.status_code == 403 and r.json()["code"] == "forbidden"
    assert c.get("/integrations/v1/sso/recovery/status", headers=auth("operator")).status_code == 200
    assert c.get("/integrations/v1/sso/recovery/status", headers=auth("viewer")).status_code == 403
    assert c.get("/integrations/v1/sso/app-coverage", headers=auth("viewer")).status_code == 200
    assert c.get("/integrations/v1/sso/app-coverage", headers=auth("kind")).status_code == 403
    r = c.put("/integrations/v1/sources/authentik", json={"base_url": AUTHENTIK_URL}, headers=idem(auth("viewer")))
    assert r.status_code == 403


def test_service_token_access(paired_client: Any, fake_hub: FakeHub) -> None:
    svc = {"Authorization": f"Bearer {fake_hub.issued_token}"}
    assert paired_client.get("/connector/v1/discover", headers=svc).status_code == 200
    assert paired_client.get("/connector/v1/events", headers=svc).status_code == 200
    # het service-token geeft geen beheerrechten op het herstelregister
    assert paired_client.get("/integrations/v1/sso/recovery/overview", headers=svc).status_code == 403
    bad = {"Authorization": "Bearer svc-" + "0" * 64}
    assert paired_client.get("/connector/v1/discover", headers=bad).status_code == 401


def test_jwks_fail_closed_when_hub_down(app_factory: Any, fake_hub: FakeHub, hub_keys: Any) -> None:
    fake_hub.include_jwks_in_enroll = False
    c = app_factory(jwks_ttl_s=1, jwks_max_stale_s=0)
    state = c.app.state
    with state.db.sessions() as s:
        assert state.enrollment.enroll_with_code(s, HUB_URL, "KOPP-ELCO-DE42").ok
        s.commit()
    token = {"Authorization": f"Bearer {hub_keys.token(['admin'])}"}
    assert c.get("/connector/v1/discover", headers=token).status_code == 200
    assert fake_hub.jwks_calls >= 1
    fake_hub.up = False
    time.sleep(1.2)  # cache verlopen, Hub weg → fail-closed
    r = c.get("/connector/v1/discover", headers=token)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "jwks_niet_beschikbaar"
    health = c.get("/connector/v1/health", headers={"Authorization": f"Bearer {fake_hub.issued_token}"}).json()
    jwks_check = next(x for x in health["checks"] if x["name"] == "hub_jwks")
    assert jwks_check["status"] == "down" and health["status"] == "degraded"


# ------------------------------------------------------------------ idempotency en ETag
def test_idempotency_required_replay_and_conflict(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    body = {"system": "hub_local", "username": "nood", "is_break_glass": True, "login_kind": "lokaal"}
    r = c.post("/integrations/v1/sso/recovery/accounts", json=body, headers=h)
    assert r.status_code == 400 and r.json()["code"] == "idempotency_key_required"
    r = c.post("/integrations/v1/sso/recovery/accounts", json=body, headers={**h, "Idempotency-Key": "geen-uuid"})
    assert r.json()["code"] == "idempotency_key_invalid"
    key = str(uuid.uuid4())
    first = c.post("/integrations/v1/sso/recovery/accounts", json=body, headers=idem(h, key))
    second = c.post("/integrations/v1/sso/recovery/accounts", json=body, headers=idem(h, key))
    assert first.status_code == second.status_code == 201
    assert first.json()["id"] == second.json()["id"] and second.headers["Idempotent-Replay"] == "true"
    listing = c.get("/integrations/v1/sso/recovery/accounts", headers=h).json()
    assert len(listing["items"]) == 1  # géén tweede uitvoering
    other = c.post("/integrations/v1/sso/recovery/accounts", json={**body, "username": "ander"}, headers=idem(h, key))
    assert other.status_code == 409 and other.json()["code"] == "idempotency_key_conflict"
    dup = c.post("/integrations/v1/sso/recovery/accounts", json=body, headers=idem(h))
    assert dup.status_code == 409 and dup.json()["code"] == "conflict"


def test_etag_if_match(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    created = c.post("/integrations/v1/sso/recovery/accounts",
                     json={"system": "authentik", "username": "akadmin", "login_kind": "beide"}, headers=idem(h))
    acc_id, etag = created.json()["id"], created.headers["ETag"]
    url = f"/integrations/v1/sso/recovery/accounts/{acc_id}"
    r = c.patch(url, json={"display_name": "Authentik-beheer"}, headers=idem(h))
    assert r.status_code == 428 and r.json()["code"] == "precondition_required"
    ok = c.patch(url, json={"display_name": "Authentik-beheer"}, headers=idem(h, **{"If-Match": etag}))
    assert ok.status_code == 200 and ok.headers["ETag"] != etag
    stale = c.patch(url, json={"display_name": "x"}, headers=idem(h, **{"If-Match": etag}))
    assert stale.status_code == 412 and stale.json()["code"] == "precondition_failed"
    assert c.get(url, headers=h).headers["ETag"] == ok.headers["ETag"]


# ------------------------------------------------------------------ connectorcontract
def test_connector_discover_health_items(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    d = c.get("/connector/v1/discover", headers=h).json()
    assert d["app_id"] == "home-control-hub" and d["schema_version"] == "1.0"
    assert set(d["capabilities"]) == {"read", "stream"}
    assert {"propose", "apply", "rollback"} == set(d["unavailable_capabilities"])
    assert set(d["domains"]) == {"network", "automation", "sso", "energy"} and d["timestamp_utc"].endswith("Z")
    health = c.get("/connector/v1/health", headers=h).json()
    assert health["status"] in ("healthy", "degraded", "down", "unknown")
    names = {x["name"]: x for x in health["checks"]}
    assert names["hub_koppeling"]["status"] == "healthy"
    assert names["bronnen"]["status"] == "unknown"  # niet geconfigureerd ≠ gezond
    assert names["herstelregister"]["status"] == "unknown"
    items = c.get("/connector/v1/items", params={"type": "source", "limit": 3}, headers=h).json()
    assert len(items["items"]) == 3 and items["next_cursor"]
    rest = c.get("/connector/v1/items", params={"type": "source", "cursor": items["next_cursor"], "limit": 200},
                 headers=h).json()
    assert len(items["items"]) + len(rest["items"]) == 10 and rest["next_cursor"] is None
    assert all(i["runtime"]["health"]["status"] == "unknown" for i in items["items"] + rest["items"])
    assert c.get("/connector/v1/items", params={"type": "bestaat-niet"}, headers=h).json()["code"] == "invalid_type"
    r = c.get("/connector/v1/items", params={"type": "network.device"}, headers=h)
    assert r.status_code == 501 and r.json()["code"] == "capability_unavailable"
    r = c.get("/connector/v1/items", params={"type": "sso.admin_account"}, headers=auth("viewer"))
    assert r.status_code == 403


@pytest.mark.parametrize("path", ["/connector/v1/propose", "/connector/v1/apply", "/connector/v1/rollback"])
def test_connector_mutations_honestly_unavailable(paired_client: Any, auth: Any, path: str) -> None:
    r = paired_client.post(path, json={}, headers=auth("admin"))
    assert r.status_code == 501 and r.json()["code"] == "capability_unavailable"
    assert paired_client.post(path, json={}, headers=auth("viewer")).status_code == 403


@pytest.mark.parametrize(
    "path",
    ["/integrations/v1/network/devices", "/integrations/v1/network/dns/summary", "/integrations/v1/network/tunnels",
     "/integrations/v1/automation/flows", "/integrations/v1/automation/event-types", "/integrations/v1/energy/meters",
     "/integrations/v1/energy/usage", "/integrations/v1/energy/advice"],
)
def test_unbuilt_domain_data_is_501_not_empty(paired_client: Any, auth: Any, path: str) -> None:
    r = paired_client.get(path, headers=auth("viewer"))
    assert r.status_code == 501
    body = r.json()
    assert body["code"] == "capability_unavailable" and body["details"]["status"] == "niet_gebouwd"


def test_domain_structures(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("viewer")
    cov = c.get("/integrations/v1/energy/coverage", headers=h).json()
    roles = {i["role"]: i for i in cov["items"]}
    assert set(roles) == {"p1_net", "boiler_socket", "airco_outdoor", "nas_host"}
    assert all(i["measurement_status"] == "onbekend" and i["quality"] == "onbekend" and i["read_only"]
               for i in cov["items"])
    pol = c.get("/integrations/v1/automation/policy", headers=h).json()
    assert "exec" in pol["forbidden_node_types"] and pol["forbidden_node_types_verification"] == "te_verifieren"
    caps = c.get("/integrations/v1/network/capabilities", headers=h).json()
    assert {s["source_id"] for s in caps["sources"]} == {"netalertx", "adguard_home", "tailscale", "cloudflared",
                                                         "router"}
    apps = c.get("/integrations/v1/sso/app-coverage", headers=h).json()["items"]
    assert all(a["oidc_support"] in ("te_verifieren", "gepland") for a in apps)


def test_source_config_vault_and_probe(paired_client: Any, auth: Any, fake_hub: FakeHub) -> None:
    c, h = paired_client, auth("admin")
    r = c.put("/integrations/v1/sources/authentik",
              json={"base_url": "http://127.0.0.1:9000", "enabled": True}, headers=idem(h))
    assert r.status_code == 422  # loopback wijst naar de container zelf
    r = c.put("/integrations/v1/sources/authentik",
              json={"base_url": AUTHENTIK_URL, "enabled": True, "credential": "ak-api-token-abcdefgh1234"},
              headers=idem(h))
    assert r.status_code == 201
    view = r.json()["runtime"]
    assert view["credential_present"] and view["credential_last4"] == "1234" and "ak-api-token" not in r.text
    assert view["health"]["status"] == "unknown"
    p = c.post("/integrations/v1/sources/authentik/probe", headers=idem(h)).json()
    assert p["status"] == "healthy" and p["reason_code"] == "liveness_ok"
    fake_hub.authentik_up = False
    p = c.post("/integrations/v1/sources/authentik/probe", headers=idem(h)).json()
    assert p["status"] == "down" and p["reason_code"] == "onbereikbaar"
    r = c.post("/integrations/v1/sources/netalertx/probe", headers=idem(h))
    assert r.status_code == 501 and r.json()["code"] == "capability_unavailable"
    # update zonder If-Match → 428
    r = c.put("/integrations/v1/sources/authentik", json={"base_url": AUTHENTIK_URL}, headers=idem(h))
    assert r.status_code == 428
    with c.app.state.db.sessions() as s:
        raw = s.execute(text("SELECT ciphertext FROM vault_secret WHERE ref='vault://source/authentik'")).scalar()
        assert raw is not None and b"ak-api-token" not in raw
        idem_rows = s.execute(text("SELECT response_body::text, request_hash FROM idempotency_record")).all()
        assert all("ak-api-token" not in (row[0] or "") for row in idem_rows)


# ------------------------------------------------------------------ gezondheid en statuspagina
def test_healthz_readyz_without_auth(client: Any) -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    r = client.get("/readyz")
    assert r.status_code == 200 and {c["name"] for c in r.json()["checks"]} == {"database", "migraties", "geheimen"}


def test_status_page_not_paired(client: Any) -> None:
    r = client.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    html = r.text
    assert 'lang="nl"' in html and "niet gekoppeld" in html and "Koppelcode" in html
    assert "default-src 'none'" in r.headers["Content-Security-Policy"] and "<script" not in html
    assert r.cookies.get("hch_csrf")
