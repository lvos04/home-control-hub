"""Integratie B13-002…005 (PostgreSQL + nep-Hub + nep-Authentik via MockTransport). Sim-getest, geen echte Authentik.

Acceptatie (Excel):
- B13-002 "Wrong issuer/aud/replay rejected": JWT-replay (jti) hier; issuer/aud in test_security; OIDC-client als
  R2-voorstel met preview/diff/preview_hash, toepassen eerlijk 'nog niet toepasbaar'.
- B13-003 "Geen automatische toegang via onbeveiligde X-Forwarded-User header": zie test_review_p0; hier de dekking
  per app met bron en de groep→rol-regels.
- B13-004 "Viewer kan geen apps stoppen of credentials ophalen".
- B13-005 "Na herstel draaien correct mapped privileges en 2FA": herstelcheck tegen een export.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import jwt
import pytest
from sqlalchemy import text

from tests.conftest import AUTHENTIK_URL, REPO_ROOT, FakeHub, HubKeys, idem
from tests.fakes.authentik_fake import CLIENT_SECRET, DEFAULT_TOKEN, FLOW_PASSWORD, AuthentikFake

pytestmark = pytest.mark.integration

BASE = "/integrations/v1/sso"
REDIRECT = "https://hub.lan.invalid/api/v1/auth/oidc/callback"  # testwaarde (.invalid), geen echte waarde
HUB_ACTION = "sso.oidc.hub.register"


def _source(c: Any, h: Any, token: str = DEFAULT_TOKEN) -> None:
    r = c.put(
        "/integrations/v1/sources/authentik",
        json={"base_url": AUTHENTIK_URL, "enabled": True, "credential": token},
        headers=idem(h),
    )
    assert r.status_code in (200, 201), r.text


def _put_source_again(c: Any, h: Any, token: str) -> None:
    etag = c.get("/integrations/v1/sources/authentik", headers=h).json()["runtime"]["etag"]
    r = c.put(
        "/integrations/v1/sources/authentik",
        json={"base_url": AUTHENTIK_URL, "enabled": True, "credential": token},
        headers=idem(h, **{"If-Match": etag}),
    )
    assert r.status_code == 200, r.text


def _map(c: Any, h: Any, app_id: str, group: str, role: str) -> Any:
    return c.post(
        f"{BASE}/role-mappings", json={"app_id": app_id, "authentik_group": group, "role": role}, headers=idem(h)
    )


def _hub_mappings(c: Any, h: Any) -> None:
    for group, role in (("hub-beheerders", "admin"), ("hub-operators", "operator"), ("hub-lezers", "viewer")):
        assert _map(c, h, "ai-server-manager", group, role).status_code == 201


def _propose(c: Any, h: Any, action_id: str = HUB_ACTION, key: str | None = None, **extra: Any) -> Any:
    params = extra.pop("parameters", {"redirect_uris": [REDIRECT]})
    return c.post(
        "/connector/v1/propose", json={"action_id": action_id, "parameters": params, **extra}, headers=idem(h, key=key)
    )


def _outbox(c: Any) -> list[tuple[str, dict[str, Any], str]]:
    with c.app.state.db.sessions() as s:
        return [
            (r[0], r[1], r[2])
            for r in s.execute(text("SELECT event_type, payload, classification FROM outbox_event ORDER BY seq"))
        ]


def _service(fake_hub: FakeHub) -> dict[str, str]:
    return {"Authorization": f"Bearer {fake_hub.issued_token}"}


# ------------------------------------------------------------------ detectie
def test_detect_needs_configuration_and_reports_least_privilege(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake
) -> None:
    c, h = paired_client, auth("admin")
    r = c.post(f"{BASE}/authentik/detect", headers=idem(h))
    assert r.status_code == 409 and r.json()["code"] == "authentik_niet_ingesteld"
    _source(c, h)
    r = c.post(f"{BASE}/authentik/detect", headers=idem(h))
    d = r.json()
    assert r.status_code == 200 and d["version"] == "2026.8.5" and d["status"] == "healthy"
    assert d["compat"]["support"] == "geverifieerd" and d["evidence_id"]
    assert d["token"]["least_privilege"] == "deels_gecontroleerd"  # rolrechten niet via de API te controleren
    status = c.get(f"{BASE}/authentik", headers=h).json()
    assert status["detection"]["version"] == "2026.8.5" and status["source"]["runtime"]["credential_last4"]
    authentik_fake.token_user = {"pk": 1, "username": "akadmin", "is_superuser": True}
    d = c.post(f"{BASE}/authentik/detect", headers=idem(h)).json()
    assert d["status"] == "degraded" and d["reason_code"] == "token_te_ruim"
    for url in (f"{BASE}/authentik", "/integrations/v1/sources/authentik", "/connector/v1/items?type=source"):
        assert DEFAULT_TOKEN not in c.get(url, headers=h).text  # token nooit terug


# ------------------------------------------------------------------ B13-002
def test_hub_oidc_proposal_is_preview_only(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, fake_hub: FakeHub
) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    r = _propose(c, h)
    assert r.status_code == 422 and r.json()["code"] == "voorstel_geblokkeerd"
    assert [b["code"] for b in r.json()["details"]["blockers"]] == ["geen_groepen_gekoppeld"]
    _hub_mappings(c, h)
    key = str(uuid.uuid4())
    r = _propose(c, h, key=key, risk_claim="R0", reason="Hub-login via Authentik")
    assert r.status_code == 201, r.text
    p = r.json()
    for field in (
        "proposal_id",
        "preview_hash",
        "resource_etag",
        "diff",
        "blast_radius",
        "risk_claim",
        "rollback_recipe",
        "requires_backup",
    ):
        assert field in p, field
    assert p["risk_claim"] == "R2" and p["requires_backup"] is True  # R0-claim genegeerd (EX18)
    assert p["apply_status"] == "nog_niet_toepasbaar" and r.headers["ETag"] == f'"{p["preview_hash"]}"'
    assert [d["operation"] for d in p["diff"]] == ["aanmaken"] * 5
    assert CLIENT_SECRET not in r.text and all("client_secret" not in q.get("body", {}) for q in p["requests"])
    assert authentik_fake.writes == []  # er is niets naar Authentik geschreven
    again = _propose(c, h, key=key, risk_claim="R0", reason="Hub-login via Authentik")
    assert again.json()["proposal_id"] == p["proposal_id"] and again.headers.get("Idempotent-Replay") == "true"
    # toepassen kan (nog) niet: eerlijk 501, ook met een voorstel-id
    a = c.post("/connector/v1/apply", json={"proposal_id": p["proposal_id"]}, headers=h)
    assert a.status_code == 501 and a.json()["details"]["reden"] == "nog_niet_toepasbaar"
    assert authentik_fake.writes == []
    listed = c.get(f"{BASE}/proposals", headers=h).json()["items"]
    assert [x["proposal_id"] for x in listed] == [p["proposal_id"]]
    assert c.get(f"{BASE}/proposals/{p['proposal_id']}", headers=h).json()["preview_hash"] == p["preview_hash"]
    ev = c.get(f"/connector/v1/evidence/{p['proposal_id']}", headers=_service(fake_hub)).json()
    assert ev["kind"] == "sso_proposal" and ev["record"]["apply_status"] == "nog_niet_toepasbaar"
    assert "sso.proposal.created" in [e[0] for e in _outbox(c)]
    # de database zelf weigert een ander apply_status (eerlijkheid afgedwongen)
    with c.app.state.db.sessions() as s, pytest.raises(Exception, match="check constraint"):
        s.execute(text("UPDATE sso_proposal SET apply_status = 'toegepast'"))
    with c.app.state.db.sessions() as s, pytest.raises(Exception, match="check constraint"):
        s.execute(text("UPDATE sso_proposal SET risk_claim = 'R1'"))


def test_proposal_drift_version_and_outage(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    _hub_mappings(c, h)
    first = _propose(c, h).json()
    same = _propose(c, h, expected_version=first["resource_etag"])
    assert same.status_code == 201 and same.json()["resource_etag"] == first["resource_etag"]
    authentik_fake.add_hub_app("hub")  # iemand maakte intussen een client aan (approval drift, EX19)
    authentik_fake.providers[-1]["name"] = "Hub (OIDC)"
    drift = _propose(c, h, expected_version=first["resource_etag"])
    assert drift.status_code == 409 and drift.json()["code"] == "resource_gewijzigd"
    authentik_fake.version = "2027.2.0"
    r = _propose(c, h)
    assert r.status_code == 409 and r.json()["code"] == "authentik_versie_niet_geverifieerd"
    authentik_fake.version = "2026.8.5"
    authentik_fake.up = False
    r = _propose(c, h)
    assert r.status_code == 503 and r.json()["code"] == "authentik_onbereikbaar"
    authentik_fake.up = True
    _put_source_again(c, h, "ingetrokken-token-0123456789")
    r = _propose(c, h)
    assert r.status_code == 502 and r.json()["code"] == "authentik_token_geweigerd"
    r = _propose(c, h, action_id="shell.exec", parameters={})
    assert r.status_code == 422 and r.json()["code"] == "onbekende_actie"
    r = _propose(c, h, parameters={"redirect_uris": ["http://hub.lan.invalid/cb"]})
    assert r.status_code == 422 and r.json()["code"] == "validation_error"
    with c.app.state.db.sessions() as s:
        assert (
            s.execute(text("SELECT count(*) FROM sso_proposal")).scalar() == 2
        )  # mislukte voorstellen niet opgeslagen


def test_proposal_roles(paired_client: Any, auth: Any, fake_hub: FakeHub) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    _hub_mappings(c, h)
    for role in ("viewer", "operator", "kind"):
        assert _propose(c, auth(role)).status_code == 403, role
    r = _propose(c, _service(fake_hub))  # de Hub (service-token) mag voorstellen
    assert r.status_code == 201 and r.json()["created_by"] == "service:hub"


def test_hub_client_check_is_read_only(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    _hub_mappings(c, h)
    authentik_fake.add_hub_app("hub", redirect=REDIRECT)
    r = c.get(f"{BASE}/oidc/hub/check", params={"slug": "hub", "redirect_uri": [REDIRECT]}, headers=auth("operator"))
    res = r.json()
    checks = {x["name"]: x["status"] for x in res["checks"]}
    assert r.status_code == 200 and checks["redirect_uris_verwacht"] == "ok" and checks["pkce_s256"] == "ok"
    assert checks["toegang"] == "afwijking" and res["outcome"] == "afwijking"  # geen bindingen = open voor iedereen
    assert authentik_fake.writes == [] and CLIENT_SECRET not in r.text
    assert c.get(f"{BASE}/oidc/hub/check", headers=auth("viewer")).status_code == 403


def test_sessions_revoke_proposal(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    r = _propose(c, h, action_id="sso.sessions.revoke", parameters={"usernames": ["anna"]})
    p = r.json()
    assert r.status_code == 201 and p["blast_radius"]["sessions"] == 1
    assert [q["method"] for q in p["requests"]] == ["DELETE"] and authentik_fake.writes == []
    r = _propose(c, h, action_id="sso.sessions.revoke", parameters={"usernames": ["anna"], "all_users": True})
    assert r.status_code == 422


# ------------------------------------------------------------------ B13-003
def test_b13_003_mapping_rules(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    cov = {a["app_id"]: a for a in c.get(f"{BASE}/app-coverage", headers=auth("viewer")).json()["items"]}
    assert (
        cov["immich"]["oidc_support"] == "ondersteund"
        and cov["immich"]["source"]["verification"] == "geverifieerd_docs"
    )
    assert cov["mediaguard"]["source"]["kind"] == "broncode" and cov["mediaguard"]["effective_status"] == "eigen_login"
    r = c.put(f"{BASE}/apps/mediaguard/setting", json={"login_mode": "oidc"}, headers=idem(h))
    assert r.status_code == 409 and r.json()["code"] == "oidc_niet_ondersteund"
    r = c.put(f"{BASE}/apps/immich/setting", json={"login_mode": "oidc"}, headers=idem(h))
    assert r.status_code == 201 and r.json()["installation_check"] == "niet_getest"
    cov = {a["app_id"]: a for a in c.get(f"{BASE}/app-coverage", headers=h).json()["items"]}
    assert cov["immich"]["effective_status"] == "oidc_gekozen_niet_getest"  # nooit 'actief' zonder echte test
    r = c.put(f"{BASE}/apps/immich/setting", json={"login_mode": "native"}, headers=idem(h))
    assert r.status_code == 428  # bestaande instelling: If-Match verplicht
    assert _map(c, h, "mediaguard", "hub-beheerders", "admin").json()["code"] == "koppeling_niet_mogelijk"
    assert _map(c, h, "immich", "immich-gebruikers", "superadmin").status_code == 422
    m = _map(c, h, "immich", "immich-gebruikers", "user")
    assert m.status_code == 201
    assert _map(c, h, "immich", "immich-gebruikers", "admin").status_code == 409  # één rol per groep per app
    assert _map(c, auth("operator"), "immich", "x", "user").status_code == 403  # rollen wijzigen alleen admin
    r = c.post(
        f"{BASE}/apps/immich/installation-check", json={"outcome": "mislukt", "notes": "login faalde"}, headers=idem(h)
    )
    assert r.status_code == 200 and r.json()["login_mode"] == "native"  # mislukt → terug naar eigen login
    with c.app.state.db.sessions() as s, pytest.raises(Exception, match="check constraint"):
        s.execute(text("UPDATE sso_app_setting SET login_mode='oidc' WHERE app_id='immich'"))
    etag = m.json()["etag"]
    assert c.delete(f"{BASE}/role-mappings/{m.json()['id']}", headers=idem(h)).status_code == 428
    assert c.delete(f"{BASE}/role-mappings/{m.json()['id']}", headers=idem(h, **{"If-Match": etag})).status_code == 200
    events = [e[0] for e in _outbox(c)]
    assert events.count("sso.role_mapping.changed") == 2 and "sso.app_setting.checked" in events


# ------------------------------------------------------------------ B13-004
def test_b13_004_events_rights_and_anomalies(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, fake_hub: FakeHub
) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    _hub_mappings(c, h)
    c.post(
        f"{BASE}/recovery/accounts",
        json={"system": "authentik", "username": "nood-ak", "is_break_glass": True, "login_kind": "lokaal"},
        headers=idem(h),
    )
    authentik_fake.add_event("login", "anna", minutes_ago=30)
    first = c.post(f"{BASE}/authentik/sync", headers=idem(_service(fake_hub))).json()
    assert first["status"] == "ok" and first["events"]["new"] == 1 and first["rights"]["status"] == "basislijn"
    # mislukte logins, impersonatie, noodaccount-login en een gekoppelde groep die wijzigt
    for i in range(5):
        authentik_fake.add_event("login_failed", "bram", minutes_ago=5 - i)
    authentik_fake.add_event("impersonation_started", "akadmin")
    authentik_fake.add_event("login", "nood-ak")
    authentik_fake.add_event(
        "model_updated",
        "akadmin",
        context={"model": {"app": "authentik_core", "model_name": "group", "pk": "x", "name": "hub-beheerders"}},
    )
    authentik_fake.add_event("email_sent", "anna")  # niet relevant → niet bewaard
    authentik_fake.set_members("hub-beheerders", ["anna", "kim"])  # kim wordt Hub-admin
    authentik_fake.set_members("hub-lezers", ["kim"])  # carla verliest viewer
    second = c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()
    assert second["status"] == "ok" and second["events"]["new"] == 8 and second["rights"]["changes"] == 2
    rules = {a["rule_id"] for a in c.get(f"{BASE}/anomalies", headers=auth("operator")).json()["items"]}
    assert rules == {
        "mislukte_logins_reeks",
        "impersonatie",
        "noodaccount_login",
        "gekoppelde_groep_gewijzigd",
        "beheerrecht_toegekend",
    }
    third = c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()
    assert third["events"]["new"] == 0 and third["anomalies_new"] == 0  # ontdubbeld, geen herhaalde meldingen
    out = _outbox(c)
    revoked = [p for t, p, _c in out if t == "sso.access.revoked"]
    assert revoked == [
        {
            "change": "gewijzigd",
            "roles_lost": {"ai-server-manager": ["viewer"]},
            "active_before": True,
            "active_after": True,
            "groups_removed": ["hub-lezers"],
        }
    ]
    assert all(
        cl == "sensitive"
        for t, _p, cl in out
        if t in ("sso.anomaly.detected", "sso.access.revoked", "sso.access.changed")
    )
    assert len([t for t, _p, _c in out if t == "sso.anomaly.detected"]) == 5
    rights = c.get(f"{BASE}/rights", headers=h).json()
    assert rights["rights"]["kim"]["roles"] == {"ai-server-manager": ["admin", "viewer"]}
    assert {d["username"] for d in rights["differences"]} == {"kim", "carla"}
    actions = {e["action"] for e in c.get(f"{BASE}/authentik/events", headers=h).json()["items"]}
    assert "email_sent" not in actions and {"login", "login_failed", "impersonation_started"} <= actions


def test_b13_004_partial_read_never_revokes(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    _hub_mappings(c, h)
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["rights"]["status"] == "basislijn"
    authentik_fake.forbidden.add("/api/v3/core/users/")  # half leesbaar: geen 'iedereen kwijt'
    r = c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()
    assert r["status"] == "onvolledig" and r["rights"]["status"] == "onvolledig"
    assert not [t for t, _p, _c in _outbox(c) if t in ("sso.access.revoked", "sso.access.changed")]
    authentik_fake.up = False
    r = c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()
    assert r["status"] == "fout" and r["reason"] == "onbereikbaar"
    assert [t for t, _p, _c in _outbox(c)].count("sso.authentik.sync.failed") == 1
    r = c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()
    assert [t for t, _p, _c in _outbox(c)].count("sso.authentik.sync.failed") == 1  # alleen bij overgang


def test_b13_004_viewer_cannot_change_anything_or_get_credentials(paired_client: Any, auth: Any) -> None:
    """Acceptatie B13-004: viewer kan geen apps stoppen of credentials ophalen. Afgeleid uit de OpenAPI-export."""
    c, admin = paired_client, auth("admin")
    _source(c, admin)
    doc = json.loads((REPO_ROOT / "docs/openapi/home-control-hub.openapi.json").read_text(encoding="utf-8"))
    viewer = auth("viewer")
    mutating = 0
    for path, methods in doc["paths"].items():
        url = path.replace("{source_id}", "authentik").replace("{app_id}", "immich")
        url = url.replace("{", "").replace("}", "")  # overige padparameters: ongeldig maar autorisatie gaat voor
        for method in methods:
            if method in ("post", "put", "patch", "delete") and path not in (
                "/integrations/v1/sso/break-glass/evaluate",
                "/integrations/v1/sso/recovery/kit/verify",
            ):
                mutating += 1
                r = c.request(method.upper(), url, headers=idem(viewer), json={})
                assert r.status_code == 403, (method, path, r.status_code)
    assert mutating >= 25
    for url in (
        f"{BASE}/rights",
        f"{BASE}/authentik/events",
        f"{BASE}/authentik/config-exports",
        f"{BASE}/recovery/overview",
    ):
        assert c.get(url, headers=viewer).status_code == 403, url
    src = c.get("/integrations/v1/sources/authentik", headers=viewer)
    assert src.status_code == 200 and DEFAULT_TOKEN not in src.text and src.json()["runtime"]["credential_present"]


# ------------------------------------------------------------------ B13-005
def _ready_break_glass(c: Any, h: Any) -> None:
    from tests.integration.test_b13_001_recovery import _prepare_break_glass

    acc = _prepare_break_glass(c, h)
    detail = c.get(f"{BASE}/recovery/accounts/{acc['id']}", headers=h).json()
    r = c.post(
        f"{BASE}/recovery/drills",
        json={
            "account_id": acc["id"],
            "method_id": detail["recovery_methods"][0]["id"],
            "mode": "handmatig",
            "outcome": "ok",
            "client_scope": "lan",
            "authenticator_state": "offline",
        },
        headers=idem(h),
    )
    assert r.status_code == 201


def test_b13_005_export_gate_and_restore_check(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, fake_hub: FakeHub
) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    _hub_mappings(c, h)
    authentik_fake.version = "2026.5.8"
    gate = c.post(f"{BASE}/authentik/upgrade-gate", json={"target_version": "2026.8.5"}, headers=idem(h)).json()
    status = {x["name"]: x["status"] for x in gate["checks"]}
    assert gate["outcome"] == "rood" and status["upgradepad"] == "ok" and status["configuratie_export"] == "fout"
    assert (
        status["noodtoegang"] == "fout"
        and status["database_backup"] == "onbekend"
        and status["catalogusversie"] == "onbekend"
    )
    exp = c.post(f"{BASE}/authentik/config-exports", headers=idem(h))
    meta = exp.json()
    assert exp.status_code == 201 and meta["complete"] and meta["mfa_users"] == 2 and meta["evidence_id"]
    assert set(meta["flow_exports"]) >= {
        "default-provider-authorization-implicit-consent",
        "default-authentication-flow",
    }
    full = c.get(f"{BASE}/authentik/config-exports/{meta['id']}", headers=h)
    for secret in (CLIENT_SECRET, FLOW_PASSWORD, "nooit-bewaren", "@voorbeeld.invalid"):
        assert secret not in full.text
    _ready_break_glass(c, h)
    gate = c.post(
        f"{BASE}/authentik/upgrade-gate",
        json={"target_version": "2026.8.5", "backup_checkpoint": {"id": "snap-1"}},
        headers=idem(h),
    ).json()
    status = {x["name"]: x["status"] for x in gate["checks"]}
    assert status["database_backup"] == "onbekend" and gate["outcome"] == "onbekend"  # admin-opgave is geen bewijs
    hub = c.post(
        f"{BASE}/authentik/upgrade-gate",
        json={"target_version": "2026.8.5", "backup_checkpoint": {"id": "snap-1"}},
        headers=idem(_service(fake_hub)),
    ).json()
    status = {x["name"]: x["status"] for x in hub["checks"]}
    assert status["database_backup"] == "ok" and status["noodtoegang"] == "ok" and status["configuratie_export"] == "ok"
    assert hub["outcome"] == "onbekend"  # catalogusversie blijft onbekend: nooit 'groen' op aannames
    skip = c.post(f"{BASE}/authentik/upgrade-gate", json={"target_version": "2027.1.0"}, headers=idem(h)).json()
    assert {x["name"]: x["status"] for x in skip["checks"]}["upgradepad"] == "onbekend"
    down = c.post(f"{BASE}/authentik/upgrade-gate", json={"target_version": "2026.2.7"}, headers=idem(h)).json()
    assert (
        down["outcome"] == "rood"
        and {x["name"]: x["detail"].get("code") for x in down["checks"]}["upgradepad"] == "downgrade"
    )

    # herstel zonder verschil → ok
    ok = c.post(f"{BASE}/authentik/restore-check", json={"export_id": meta["id"]}, headers=idem(h)).json()
    assert ok["outcome"] == "ok", ok
    # herstel met verlies van 2FA, gewijzigde groep en ontbrekende provider → afwijking + anomaly + event
    authentik_fake.devices["anna"] = []
    authentik_fake.set_members("hub-operators", [])
    authentik_fake.providers = [p for p in authentik_fake.providers if p["name"] != "Immich"]
    bad = c.post(f"{BASE}/authentik/restore-check", json={"export_id": meta["id"]}, headers=idem(h)).json()
    checks = {x["name"]: x for x in bad["checks"]}
    assert bad["outcome"] == "afwijking"
    assert checks["mfa_beheerders"]["detail"]["lost"] == [
        {"user": "anna", "missing_types": {"authentik_stages_authenticator_totp.totpdevice": 1}}
    ]
    assert checks["groepen"]["status"] == "afwijking" and checks["providers"]["detail"]["missing"] == ["Immich"]
    assert "herstel_afwijking" in {a["rule_id"] for a in c.get(f"{BASE}/anomalies", headers=h).json()["items"]}
    assert "sso.authentik.restore_check.completed" in [e[0] for e in _outbox(c)]
    assert authentik_fake.writes == []


def test_b13_005_incomplete_export_is_not_a_baseline(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake
) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h)
    authentik_fake.forbidden.add("/api/v3/authenticators/admin/all/")
    meta = c.post(f"{BASE}/authentik/config-exports", headers=idem(h)).json()
    assert meta["complete"] is False and any(m["part"] == "mfa" for m in meta["missing"])
    r = c.post(f"{BASE}/authentik/restore-check", json={"export_id": meta["id"]}, headers=idem(h))
    assert r.status_code == 409 and r.json()["code"] == "export_onvolledig"


# ------------------------------------------------------------------ B13-002: JWT-replay
def test_jwt_replay_rejected_for_mutations(paired_client: Any, hub_keys: HubKeys) -> None:
    c = paired_client
    token = {"Authorization": f"Bearer {hub_keys.token(['admin'])}"}
    body = {"system": "hub_local", "username": "eenmalig", "login_kind": "lokaal"}
    key = str(uuid.uuid4())
    first = c.post(f"{BASE}/recovery/accounts", json=body, headers={**token, "Idempotency-Key": key})
    assert first.status_code == 201
    retry = c.post(f"{BASE}/recovery/accounts", json=body, headers={**token, "Idempotency-Key": key})
    assert retry.status_code == 201 and retry.headers.get("Idempotent-Replay") == "true"  # netwerk-retry mag
    other = c.post(
        f"{BASE}/recovery/accounts",
        json={**body, "username": "tweede"},
        headers={**token, "Idempotency-Key": str(uuid.uuid4())},
    )
    assert other.status_code == 401 and other.json()["details"]["reason"] == "token_hergebruikt"
    assert c.get(f"{BASE}/recovery/accounts", headers=token).status_code == 200  # lezen mag binnen de levensduur
    now = int(time.time())
    claims = {"iss": "hub", "aud": "home-control-hub", "sub": "user-1", "roles": ["admin"], "iat": now, "exp": now + 60}
    raw = jwt.encode(claims, hub_keys.private, algorithm="EdDSA", headers={"kid": hub_keys.kid})
    no_jti = {"Authorization": f"Bearer {raw}"}
    r = c.post(
        f"{BASE}/recovery/accounts",
        json={**body, "username": "derde"},
        headers={**no_jti, "Idempotency-Key": str(uuid.uuid4())},
    )
    assert r.status_code == 401 and r.json()["details"]["reason"] == "jti_ontbreekt"


def test_worker_syncs_authentik_and_pushes_events(
    paired_client: Any, auth: Any, make_settings: Any, fake_hub: FakeHub, authentik_fake: AuthentikFake
) -> None:
    from integrations.worker import Worker

    c, h = paired_client, auth("admin")
    _source(c, h)
    for i in range(5):
        authentik_fake.add_event("login_failed", "bram", minutes_ago=i)
    worker = Worker(make_settings(authentik_sync_interval_s=60), transport=fake_hub.transport)
    worker.run_once()
    assert worker.state.stats["authentik_syncs"] == 1
    worker.run_once()  # interval nog niet verstreken
    assert worker.state.stats["authentik_syncs"] == 1
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not any(e["event_type"] == "sso.anomaly.detected" for e in fake_hub.inbox):
        worker.push_step()
    assert any(e["event_type"] == "sso.anomaly.detected" and e["classification"] == "sensitive" for e in fake_hub.inbox)
    off = Worker(make_settings(authentik_sync_interval_s=0), transport=fake_hub.transport)
    off.run_once()
    assert off.state.stats["authentik_syncs"] == 0


def test_retention_of_events_and_snapshots(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    """Geen ongebreidelde groei: events 30 dagen, rechtenkaart alleen bij verandering, oude momentopnames opgeruimd."""
    from integrations.domains.sso import authaudit

    c, h = paired_client, auth("admin")
    _source(c, h)
    _hub_mappings(c, h)
    for _ in range(3):
        c.post(f"{BASE}/authentik/sync", headers=idem(h))
    with c.app.state.db.sessions() as s:
        assert s.execute(text("SELECT count(*) FROM sso_authentik_snapshot WHERE kind='rechten'")).scalar() == 1
        s.execute(
            text(
                "INSERT INTO sso_auth_event (authentik_pk, action, created, ingested_at) "
                "VALUES ('oud', 'login', now() - interval '31 days', now())"
            )
        )
        s.commit()
    with c.app.state.db.sessions() as s:
        authaudit.purge_old_events(s)
        s.commit()
        assert s.execute(text("SELECT count(*) FROM sso_auth_event WHERE authentik_pk='oud'")).scalar() == 0
        assert s.execute(text("SELECT count(*) FROM sso_authentik_snapshot WHERE kind='rechten'")).scalar() == 1
