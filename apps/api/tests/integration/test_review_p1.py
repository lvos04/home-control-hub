"""Review P1 (B13-002…005): aanvullende negatieve tests van de onafhankelijke QA. Sim-getest, geen echte Authentik.

- Het Authentik-API-token komt nooit in logs (ook DEBUG en tracebacks), API-antwoorden, de database (buiten de
  versleutelde vault), de outbox of de idempotency-opslag — ook niet als Authentik het token in een foutantwoord
  terugkaatst, en ook niet via de worker.
- Geen wijziging zonder door de Hub ondertekend verzoek: een vervalste of anders ondertekende JWT verandert niets;
  ``/connector/v1/apply`` voert ook met een "ondertekend ExecutionRequest"-achtige body niets uit.
- Geen oude gegevens als gezond: de rechtenkaart wordt ``verouderd`` als Authentik niet meer volledig gelezen kan
  worden; een gat in de events wordt een blijvende afwijking.
- B13-003: ook op de nieuwe P1-routes geen toegang via X-Forwarded-User e.d.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from integrations.domains.sso import authaudit
from integrations.timeutil import iso, utcnow
from tests.conftest import AUTHENTIK_URL, FakeHub, HubKeys, idem, pair
from tests.fakes.authentik_fake import AuthentikFake
from tests.integration.test_review_p0 import TRUSTED_HEADER_ATTEMPT

pytestmark = pytest.mark.integration

BASE = "/integrations/v1/sso"
REDIRECT = "https://hub.lan.invalid/api/v1/auth/oidc/callback"  # testwaarde (.invalid), geen echte waarde
LEAK_TOKEN = "ak-lektest-" + uuid.uuid4().hex + uuid.uuid4().hex  # uniek, zodat elke vondst echt een lek is


def _source(c: Any, h: Any, token: str) -> None:
    r = c.put(
        "/integrations/v1/sources/authentik",
        json={"base_url": AUTHENTIK_URL, "enabled": True, "credential": token},
        headers=idem(h),
    )
    assert r.status_code in (200, 201), r.text


def _hub_mappings(c: Any, h: Any) -> None:
    for group, role in (("hub-beheerders", "admin"), ("hub-operators", "operator"), ("hub-lezers", "viewer")):
        r = c.post(
            f"{BASE}/role-mappings",
            json={"app_id": "ai-server-manager", "authentik_group": group, "role": role},
            headers=idem(h),
        )
        assert r.status_code == 201, r.text


def _all_rows_text(c: Any) -> dict[str, str]:
    """Elke rij van elke tabel als tekst (behalve de versleutelde vault zelf)."""
    out: dict[str, str] = {}
    with c.app.state.db.sessions() as s:
        tables = [
            r[0]
            for r in s.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename"))
        ]
        for t in tables:
            rows = s.execute(text(f'SELECT row_to_json(x)::text FROM "{t}" x')).scalars()  # noqa: S608 - pg_tables
            out[t] = "\n".join(rows)
    return out


# ------------------------------------------------------------------ token nooit in logs/antwoorden/database
def test_authentik_token_never_in_logs_responses_or_database(
    app_factory: Any,
    auth: Any,
    authentik_fake: AuthentikFake,
    fake_hub: FakeHub,
    make_settings: Any,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from integrations.worker import Worker

    caplog.set_level(logging.DEBUG)  # ook httpx/httpcore op DEBUG
    c = app_factory(http_max_attempts=1)  # geen herhaalpogingen met wachttijd: de test blijft snel
    assert pair(c, fake_hub).ok
    h = auth("admin")
    authentik_fake.token = LEAK_TOKEN
    authentik_fake.add_event("login", "anna", minutes_ago=3)
    _source(c, h, LEAK_TOKEN)
    _hub_mappings(c, h)
    authentik_fake.add_hub_app("hub", redirect=REDIRECT)
    texts: list[str] = []

    def call(method: str, url: str, **kw: Any) -> Any:
        r = c.request(method, url, **kw)
        texts.append(r.text)
        texts.append(json.dumps(dict(r.headers)))
        return r

    def happy_and_error_paths() -> None:
        call("POST", f"{BASE}/authentik/detect", headers=idem(h))
        call("POST", f"{BASE}/authentik/sync", headers=idem(h))
        call(
            "POST",
            "/connector/v1/propose",
            json={"action_id": "sso.oidc.hub.register", "parameters": {"redirect_uris": [REDIRECT]}},
            headers=idem(h),
        )
        call(
            "POST",
            "/connector/v1/propose",
            json={"action_id": "sso.sessions.revoke", "parameters": {"all_users": True}},
            headers=idem(h),
        )
        call("GET", f"{BASE}/oidc/hub/check", params={"slug": "hub", "redirect_uri": [REDIRECT]}, headers=h)
        exp = call("POST", f"{BASE}/authentik/config-exports", headers=idem(h))
        call("POST", f"{BASE}/authentik/upgrade-gate", json={"target_version": "2026.8.5"}, headers=idem(h))
        if exp.status_code == 201:
            call("POST", f"{BASE}/authentik/restore-check", json={"export_id": exp.json()["id"]}, headers=idem(h))
        for url in (
            f"{BASE}/authentik",
            f"{BASE}/rights",
            f"{BASE}/authentik/events",
            f"{BASE}/anomalies",
            f"{BASE}/proposals",
            "/integrations/v1/sources/authentik",
            "/integrations/v1/sources",
            "/connector/v1/items?type=source",
            "/connector/v1/health",
        ):
            call("GET", url, headers=h)
        worker = Worker(make_settings(authentik_sync_interval_s=1, http_max_attempts=1), transport=fake_hub.transport)
        worker.run_once()

    happy_and_error_paths()
    # Misdragende Authentik: kaatst het Authorization-header terug in foutantwoorden (500 en 403)
    authentik_fake.echo_auth_in_errors = True
    authentik_fake.fail["/api/v3/core/users/"] = 500
    authentik_fake.fail["/api/v3/events/events/"] = 500
    happy_and_error_paths()
    authentik_fake.fail["/api/v3/admin/version/"] = 500
    happy_and_error_paths()
    authentik_fake.fail.clear()
    authentik_fake.token = "ander-token-" + uuid.uuid4().hex  # ons token wordt geweigerd (403 met echo)
    happy_and_error_paths()
    authentik_fake.timeouts.add("/api/v3/admin/version/")
    happy_and_error_paths()
    authentik_fake.timeouts.clear()
    authentik_fake.up = False
    happy_and_error_paths()

    assert len(texts) > 100
    leaked_in = [i for i, t in enumerate(texts) if LEAK_TOKEN in t]
    assert leaked_in == [], "token in een API-antwoord of -header"
    assert LEAK_TOKEN not in caplog.text  # inclusief tracebacks
    assert all(LEAK_TOKEN not in str(r.args) for r in caplog.records)
    rows = _all_rows_text(c)
    assert "vault_secret" in rows and "outbox_event" in rows and "idempotency_record" in rows
    leaked_tables = [t for t, body in rows.items() if LEAK_TOKEN in body]
    assert leaked_tables == [], f"token leesbaar in tabel(len): {leaked_tables}"
    # het token is wel bruikbaar opgeslagen (versleuteld) — anders bewijst deze test niets
    assert c.app.state.vault is not None
    with c.app.state.db.sessions() as s:
        ref = s.execute(text("SELECT credential_ref FROM integration_source WHERE source_id='authentik'")).scalar()
        assert ref and c.app.state.vault.get(s, ref) == LEAK_TOKEN
    assert any(call[2] for call in authentik_fake.calls)  # er is echt met het token gebeld


# ------------------------------------------------------------------ geen wijziging zonder ondertekend verzoek
def _forged_tokens(hub_keys: HubKeys) -> dict[str, str]:
    now = int(time.time())
    claims = {
        "iss": "hub",
        "aud": "home-control-hub",
        "sub": "aanvaller",
        "token_use": "user",
        "roles": ["admin"],
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    other = Ed25519PrivateKey.generate()
    return {
        "andere_sleutel": jwt.encode(claims, other, algorithm="EdDSA", headers={"kid": hub_keys.kid}),
        "hs256_met_kid": jwt.encode(claims, "geheim-" + "x" * 32, algorithm="HS256", headers={"kid": hub_keys.kid}),
        "geen_handtekening": jwt.encode(claims, None, algorithm="none"),
        "verkeerde_aud": jwt.encode(
            {**claims, "aud": "ai-server-manager"}, hub_keys.private, algorithm="EdDSA", headers={"kid": hub_keys.kid}
        ),
        "verkeerde_iss": jwt.encode(
            {**claims, "iss": "authentik"}, hub_keys.private, algorithm="EdDSA", headers={"kid": hub_keys.kid}
        ),
    }


def test_no_change_without_a_hub_signed_request(
    paired_client: Any, auth: Any, hub_keys: HubKeys, authentik_fake: AuthentikFake
) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h, authentik_fake.token)
    _hub_mappings(c, h)
    before = _all_rows_text(c)
    mutations: list[tuple[str, str, dict[str, Any] | None]] = [
        ("PUT", f"{BASE}/apps/immich/setting", {"login_mode": "oidc"}),
        ("POST", f"{BASE}/role-mappings", {"app_id": "immich", "authentik_group": "x", "role": "admin"}),
        ("POST", f"{BASE}/authentik/sync", None),
        (
            "POST",
            "/connector/v1/propose",
            {"action_id": "sso.oidc.hub.register", "parameters": {"redirect_uris": [REDIRECT]}},
        ),
        (
            "PUT",
            "/integrations/v1/sources/authentik",
            {"base_url": "http://elders.invalid:9000", "enabled": True, "credential": "x" * 20},
        ),
    ]
    for name, token in _forged_tokens(hub_keys).items():
        for method, url, body in mutations:
            r = c.request(
                method,
                url,
                json=body,
                headers={"Authorization": f"Bearer {token}", "Idempotency-Key": str(uuid.uuid4())},
            )
            assert r.status_code == 401 and r.json()["code"] == "unauthorized", (name, url, r.status_code)
    after = _all_rows_text(c)
    assert after == before  # niets gewijzigd, ook geen jti verbruikt of audit geschreven
    assert authentik_fake.writes == []


def test_apply_never_executes_even_with_a_signed_looking_request(
    paired_client: Any, auth: Any, fake_hub: FakeHub, authentik_fake: AuthentikFake
) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h, authentik_fake.token)
    _hub_mappings(c, h)
    p = c.post(
        "/connector/v1/propose",
        json={"action_id": "sso.oidc.hub.register", "parameters": {"redirect_uris": [REDIRECT]}},
        headers=idem(h),
    ).json()
    request_like = {
        "proposal": {"proposal_id": p["proposal_id"], "preview_hash": p["preview_hash"]},
        "approval": {"approval_id": str(uuid.uuid4()), "preview_hash": p["preview_hash"], "one_time_nonce": "n"},
        "policy_decision": {"risk_class": "R2", "rule_ids": ["x"], "policy_hash": "0" * 64},
        "issued_at": iso(utcnow()),
        "expires_at": iso(utcnow() + timedelta(minutes=5)),
        "nonce": str(uuid.uuid4()),
        "signature": "A" * 86,
    }
    before = _all_rows_text(c)
    service = fake_hub.service_auth()
    for who in (h, service):
        for url in ("/connector/v1/apply", "/connector/v1/rollback"):
            r = c.post(url, json=request_like, headers=idem(who))  # per wijziging een nieuwe JWT (zoals de Hub)
            assert r.status_code == 501 and r.json()["code"] == "capability_unavailable", (url, r.text)
    for role in ("viewer", "operator", "kind"):
        assert c.post("/connector/v1/apply", json=request_like, headers=idem(auth(role))).status_code == 403
    after = _all_rows_text(c)
    for table in ("sso_proposal", "audit_event", "outbox_event", "sso_app_setting", "sso_group_role_mapping"):
        assert after[table] == before[table], table
    assert authentik_fake.writes == []
    assert c.get(f"{BASE}/proposals/{p['proposal_id']}", headers=h).json()["apply_status"] == "nog_niet_toepasbaar"


# ------------------------------------------------------------------ geen oude gegevens als gezond
def _age_rights(c: Any, minutes: int) -> None:
    """Zet de laatste bevestiging en momentopname van de rechtenkaart terug in de tijd (testhulp)."""
    with c.app.state.db.sessions() as s:
        old = utcnow() - timedelta(minutes=minutes)
        s.execute(text("UPDATE sso_authentik_snapshot SET taken_at = :t WHERE kind = 'rechten'"), {"t": old})
        row = s.execute(text("SELECT value FROM service_state WHERE key = 'authentik_sync'")).scalar()
        assert row is not None and row.get("rights_verified")
        row["rights_verified"]["at"] = old.isoformat()
        s.execute(
            text("UPDATE service_state SET value = CAST(:v AS jsonb) WHERE key = 'authentik_sync'"),
            {"v": json.dumps(row)},
        )
        s.commit()


def test_rights_map_is_never_shown_as_ok_when_stale(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake
) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h, authentik_fake.token)
    _hub_mappings(c, h)
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["rights"]["status"] == "basislijn"
    fresh = c.get(f"{BASE}/rights", headers=h).json()
    assert fresh["status"] == "ok" and fresh["freshness"]["status"] == "ok"
    # 'ongewijzigd' maakt geen nieuwe momentopname, maar bevestigt de kaart wel opnieuw
    _age_rights(c, 60)
    assert c.get(f"{BASE}/rights", headers=h).json()["status"] == "verouderd"
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["rights"]["status"] == "ongewijzigd"
    again = c.get(f"{BASE}/rights", headers=h).json()
    assert again["status"] == "ok" and again["observed_at"] > again["snapshot_taken_at"]
    # Authentik weg: de kaart blijft zichtbaar, maar nooit als 'ok' zodra ze te oud is
    authentik_fake.up = False
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["status"] == "fout"
    _age_rights(c, 60)
    stale = c.get(f"{BASE}/rights", headers=h).json()
    assert stale["status"] == "verouderd" and stale["rights"]  # gegevens nog te zien, als verouderd
    assert stale["freshness"]["last_sync_status"] == "fout" and stale["freshness"]["last_sync_reason"] == "onbereikbaar"
    assert "onbekend" in stale["freshness"]["message_nl"]
    # half leesbaar (geen rechten op gebruikers): ook geen nieuwe bevestiging
    authentik_fake.up = True
    authentik_fake.forbidden.add("/api/v3/core/users/")
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["rights"]["status"] == "onvolledig"
    assert c.get(f"{BASE}/rights", headers=h).json()["status"] == "verouderd"
    authentik_fake.forbidden.clear()
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["rights"]["status"] == "ongewijzigd"
    assert c.get(f"{BASE}/rights", headers=h).json()["status"] == "ok"
    # de grens volgt het synchronisatie-interval (≥ 15 min, ≥ 3 intervallen)
    assert authaudit.rights_max_age(300) == timedelta(minutes=15)
    assert authaudit.rights_max_age(3600) == timedelta(hours=3)
    assert authaudit.rights_max_age(0) == timedelta(minutes=15)


def test_event_gap_becomes_a_lasting_anomaly(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    c, h = paired_client, auth("admin")
    _source(c, h, authentik_fake.token)
    for i in range(authaudit.MAX_PAGES * 100 + 20):  # meer dan één synchronisatie kan lezen
        authentik_fake.add_event("login", "anna", minutes_ago=600 - i)
    first = c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()
    assert first["status"] == "onvolledig" and first["reason"] == "events_niet_volledig_gelezen"
    anomalies = c.get(f"{BASE}/anomalies", headers=h).json()["items"]
    gap = [a for a in anomalies if a["rule_id"] == "events_onvolledig"]
    assert len(gap) == 1 and gap[0]["severity"] == "middel" and "ontbreken" in gap[0]["message_nl"]
    second = c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()
    assert second["status"] == "ok" and second["events"]["complete"] is True
    gap = [a for a in c.get(f"{BASE}/anomalies", headers=h).json()["items"] if a["rule_id"] == "events_onvolledig"]
    assert len(gap) == 1  # blijft staan (zichtbaar in de Hub), geen dubbele melding
    with c.app.state.db.sessions() as s:
        types = list(s.execute(text("SELECT event_type, payload FROM outbox_event ORDER BY seq")))
    assert any(t == "sso.anomaly.detected" and p["rule_id"] == "events_onvolledig" for t, p in types)


# ------------------------------------------------------------------ B13-003 op de P1-routes
def test_b13_003_no_header_sso_on_p1_routes(paired_client: Any, auth: Any) -> None:
    c = paired_client
    for url in (f"{BASE}/rights", f"{BASE}/app-coverage", f"{BASE}/role-mappings", f"{BASE}/authentik"):
        r = c.get(url, headers=TRUSTED_HEADER_ATTEMPT)
        assert r.status_code == 401 and r.json()["code"] == "unauthorized", url
    viewer = auth("viewer")
    assert c.get(f"{BASE}/rights", headers={**viewer, **TRUSTED_HEADER_ATTEMPT}).status_code == 403
    r = c.put(
        f"{BASE}/apps/immich/setting", json={"login_mode": "oidc"}, headers=idem(viewer, **TRUSTED_HEADER_ATTEMPT)
    )
    assert r.status_code == 403
    r = c.post(
        f"{BASE}/role-mappings",
        json={"app_id": "ai-server-manager", "authentik_group": "hub-beheerders", "role": "admin"},
        headers=idem(viewer, **TRUSTED_HEADER_ATTEMPT),
    )
    assert r.status_code == 403
    cov = c.get(f"{BASE}/app-coverage", headers=auth("viewer")).json()["items"]
    assert cov and all(a["trusted_header_sso"] == "niet_toegestaan" for a in cov)
    # elke bewering 'ondersteund' heeft een bron met URL, ref en datum (B13-003: alleen met bronvermelding)
    for a in cov:
        src = a["source"]
        assert src["url"] and src["ref"] and src["checked_on"] and src["verification"], a["app_id"]
        if a["oidc_support"] in ("ondersteund", "ondersteund_met_voorwaarden"):
            assert src["kind"] in ("officiele_docs", "broncode") and src["verification"].startswith("geverifieerd")


# ------------------------------------------------------------------ contract §7: elk event komt door de Hub-inbox
def test_every_p1_event_is_accepted_by_the_hub_inbox(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, fake_hub: FakeHub, make_settings: Any
) -> None:
    """Review P1: drie eventtypen hadden vier segmenten (sso.authentik.sync.failed e.d.); de echte Hub-inbox weigert
    die (patroon <domein>.<object>.<gebeurtenis>) en ze zouden na 10 pogingen als dead-letter eindigen. De nep-Hub
    valideert nu net als de Hub; hier ontstaan alle soorten P1-events en ze moeten allemaal aankomen."""
    from integrations.worker import Worker

    c, h = paired_client, auth("admin")
    _source(c, h, authentik_fake.token)
    _hub_mappings(c, h)
    for i in range(5):
        authentik_fake.add_event("login_failed", "bram", minutes_ago=5 - i)
    assert c.post(f"{BASE}/authentik/detect", headers=idem(h)).status_code == 200
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).status_code == 200
    r = c.post(
        "/connector/v1/propose",
        json={"action_id": "sso.oidc.hub.register", "parameters": {"redirect_uris": [REDIRECT]}},
        headers=idem(h),
    )
    assert r.status_code == 201
    exp = c.post(f"{BASE}/authentik/config-exports", headers=idem(h)).json()
    c.post(f"{BASE}/authentik/upgrade-gate", json={"target_version": "2026.8.5"}, headers=idem(h))
    authentik_fake.set_members("hub-operators", [])
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["rights"]["status"] == "vergeleken"
    c.post(f"{BASE}/authentik/restore-check", json={"export_id": exp["id"]}, headers=idem(h))
    r = c.put(f"{BASE}/apps/immich/setting", json={"login_mode": "oidc"}, headers=idem(h))
    assert r.status_code == 201
    c.post(f"{BASE}/apps/immich/installation-check", json={"outcome": "mislukt"}, headers=idem(h))
    authentik_fake.up = False
    assert c.post(f"{BASE}/authentik/sync", headers=idem(h)).json()["status"] == "fout"
    worker = Worker(make_settings(authentik_sync_interval_s=0), transport=fake_hub.transport)
    for _ in range(20):
        worker.push_step()
        with c.app.state.db.sessions() as s:
            pending = s.execute(text("SELECT count(*) FROM outbox_event WHERE delivery_status <> 'delivered'"))
            if pending.scalar() == 0:
                break
    assert fake_hub.rejected == []
    with c.app.state.db.sessions() as s:
        statuses = dict(
            s.execute(text("SELECT delivery_status, count(*) FROM outbox_event GROUP BY delivery_status")).all()
        )
    assert set(statuses) == {"delivered"}, statuses
    delivered = {e["event_type"] for e in fake_hub.inbox}
    assert {
        "sso.authentik.detected",
        "sso.authentik_sync.failed",
        "sso.authentik_upgrade_gate.evaluated",
        "sso.authentik_restore_check.completed",
        "sso.authentik.config_exported",
        "sso.anomaly.detected",
        "sso.access.revoked",
        "sso.proposal.created",
        "sso.role_mapping.changed",
        "sso.app_setting.changed",
        "sso.app_setting.checked",
    } <= delivered
