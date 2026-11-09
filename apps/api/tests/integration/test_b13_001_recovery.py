"""Integratie B13-001 — accountrecovery en admin-toegang (sim: nep-Hub + nep-Authentik via MockTransport).

Acceptatie (Excel): "Authenticator offline → break glass in Hub blijft testbaar."
Gewenst gedrag (B13): twee beheerherstelmethodes, versleuteld herstelmateriaal exporteren, geen SSO-only lock-out;
lokaal noodaccount alleen LAN/VPN, verloop en audit, MFA.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import text

from tests.conftest import AUTHENTIK_URL, FakeHub, idem

pytestmark = pytest.mark.integration

BASE = "/integrations/v1/sso"
PASSPHRASE = "correct paard batterij nietje 2026!"
LAN = {"cidr": "192.168.50.0/24", "kind": "lan"}  # testbereik (geen echte NAS-waarde)
VPN = {"cidr": "100.64.0.0/10", "kind": "vpn"}


def _create_account(c: Any, h: dict[str, str], **body: Any) -> dict[str, Any]:
    r = c.post(f"{BASE}/recovery/accounts", json=body, headers=idem(h))
    assert r.status_code == 201, r.text
    return r.json()


def _prepare_break_glass(c: Any, h: dict[str, str]) -> dict[str, Any]:
    acc = _create_account(
        c,
        h,
        system="hub_local",
        username="noodbeheer",
        display_name="Noodaccount",
        is_break_glass=True,
        login_kind="lokaal",
    )
    for method, hint in (("lokaal_wachtwoord_lan", "wachtwoordmanager"), ("verzegelde_envelop", "kluis")):
        r = c.post(
            f"{BASE}/recovery/accounts/{acc['id']}/methods",
            json={"method_type": method, "storage_hint": hint},
            headers=idem(h),
        )
        assert r.status_code == 201 and r.json()["sso_independent"] is True
    r = c.put(
        f"{BASE}/recovery/accounts/{acc['id']}/emergency-access",
        json={"network_scopes": [LAN, VPN], "session_max_minutes": 30, "reason": "Noodtoegang beheer"},
        headers=idem(h),
    )
    assert r.status_code == 201, r.text
    etag = c.get(f"{BASE}/recovery/accounts/{acc['id']}", headers=h).headers["ETag"]
    r = c.post(
        f"{BASE}/recovery/accounts/{acc['id']}/mfa-attestation",
        json={"mfa_status": "bevestigd", "mfa_methods": ["webauthn"]},
        headers=idem(h, **{"If-Match": etag}),
    )
    assert r.status_code == 200
    return acc


def test_break_glass_testable_while_authenticator_offline(paired_client: Any, auth: Any, fake_hub: FakeHub) -> None:
    """Kernacceptatie B13-001: Authentik onbereikbaar → zelftest van de noodtoegang slaagt en is vastgelegd."""
    c, h = paired_client, auth("admin")
    r = c.put("/integrations/v1/sources/authentik", json={"base_url": AUTHENTIK_URL, "enabled": True}, headers=idem(h))
    assert r.status_code == 201
    acc = _prepare_break_glass(c, h)
    fake_hub.authentik_up = False  # authenticator offline

    drill = c.post(f"{BASE}/recovery/drills", json={"account_id": acc["id"], "mode": "zelftest"}, headers=idem(h))
    assert drill.status_code == 201, drill.text
    d = drill.json()
    assert d["outcome"] == "ok" and d["authenticator_state"] == "offline"
    checks = {x["name"]: x["status"] for x in d["checks"]}
    assert checks == {
        "account_actief": "ok",
        "lokale_login": "ok",
        "herstelmethodes": "ok",
        "noodtoegang_geregistreerd": "ok",
        "beleid_binnen_bereik": "ok",
        "beleid_buiten_bereik_geweigerd": "ok",
        "authenticator": "info",
    }
    # beoordeling werkt zonder Authentik: LAN/VPN toegestaan, internet geweigerd
    ok = c.post(f"{BASE}/break-glass/evaluate", json={"account_id": acc["id"], "client_ip": "192.168.50.7"}, headers=h)
    assert ok.json()["allowed"] is True and ok.json()["authenticator_required"] is False
    assert ok.json()["session_max_minutes"] == 30
    vpn = c.post(f"{BASE}/break-glass/evaluate", json={"account_id": acc["id"], "client_ip": "100.70.1.2"}, headers=h)
    assert vpn.json()["allowed"] is True
    wan = c.post(f"{BASE}/break-glass/evaluate", json={"account_id": acc["id"], "client_ip": "198.51.100.4"}, headers=h)
    assert wan.json()["allowed"] is False and wan.json()["reasons"][0]["code"] == "buiten_bereik"

    # ook met Authentik helemaal niet geconfigureerd blijft het testbaar
    with c.app.state.db.sessions() as s:
        s.execute(text("DELETE FROM integration_source WHERE source_id='authentik'"))
        s.commit()
    d2 = c.post(f"{BASE}/recovery/drills", json={"account_id": acc["id"], "mode": "zelftest"}, headers=idem(h)).json()
    assert d2["outcome"] == "ok" and d2["authenticator_state"] == "niet_geconfigureerd"


def test_full_recovery_journey_and_readiness(paired_client: Any, auth: Any, fake_hub: FakeHub) -> None:
    c, h = paired_client, auth("admin")
    status = c.get(f"{BASE}/recovery/status", headers=h).json()
    assert status["level"] == "onbekend" and status["health"] == "unknown"  # leeg register is nooit groen

    # alleen een SSO-account → risico op SSO-only lock-out
    ak = _create_account(c, h, system="authentik", username="akadmin", login_kind="sso")
    status = c.get(f"{BASE}/recovery/status", headers=h).json()
    assert status["level"] == "risico"
    assert {"geen_noodaccount", "geen_lokale_hub_admin"} <= {r["code"] for r in status["reasons"]}
    assert "accounts" not in status  # totaalstatus zonder accountdetails

    acc = _prepare_break_glass(c, h)
    detail = c.get(f"{BASE}/recovery/accounts/{acc['id']}", headers=h).json()
    assert detail["readiness"]["level"] == "risico"
    assert [r["code"] for r in detail["readiness"]["reasons"]] == ["nooit_handmatig_geoefend"]

    # handmatige oefening (attestatie) na echte login via LAN met Authentik uit
    methods = detail["recovery_methods"]
    r = c.post(
        f"{BASE}/recovery/drills",
        json={
            "account_id": acc["id"],
            "method_id": methods[0]["id"],
            "mode": "handmatig",
            "outcome": "ok",
            "client_scope": "lan",
            "authenticator_state": "offline",
            "notes": "Geoefend met Authentik uit",
        },
        headers=idem(h),
    )
    assert r.status_code == 201 and r.json()["validation_nl"].startswith("Handmatig bevestigd")
    detail = c.get(f"{BASE}/recovery/accounts/{acc['id']}", headers=h).json()
    assert detail["readiness"] == {"level": "ok", "reasons": []}
    assert detail["recovery_methods"][0]["last_verified_at"] is not None

    # echte activatie → rotatie vereist → risico tot rotatie bevestigd
    act = c.post(
        f"{BASE}/break-glass/activations",
        json={"account_id": acc["id"], "client_ip": "192.168.50.9", "mode": "echt"},
        headers=idem(h),
    )
    assert act.status_code == 201 and act.json()["rotation_required"] is True
    assert act.json()["matched_scope"] == "192.168.50.0/24"
    detail = c.get(f"{BASE}/recovery/accounts/{acc['id']}", headers=h).json()
    assert "rotatie_na_gebruik_vereist" in [r["code"] for r in detail["readiness"]["reasons"]]
    rot = c.post(f"{BASE}/break-glass/activations/{act.json()['id']}/rotated", headers=idem(h))
    assert rot.status_code == 200 and rot.json()["rotated_at"]
    assert c.get(f"{BASE}/recovery/accounts/{acc['id']}", headers=h).json()["readiness"]["level"] == "ok"

    # activatie vanaf internet wordt geweigerd én geaudit
    denied = c.post(
        f"{BASE}/break-glass/activations",
        json={"account_id": acc["id"], "client_ip": "203.0.113.50", "mode": "echt"},
        headers=idem(h),
    )
    assert denied.status_code == 403 and denied.json()["code"] == "noodtoegang_geweigerd"

    # totaal: Authentik-admin zonder herstelmethodes blijft een risico
    overview = c.get(f"{BASE}/recovery/overview", headers=h).json()
    assert overview["accounts"][acc["id"]]["level"] == "ok"
    assert overview["accounts"][ak["id"]]["level"] == "risico" and overview["level"] == "risico"

    # audit + events (Hub-outbox) aanwezig, geredigeerd
    with c.app.state.db.sessions() as s:
        actions = {r[0] for r in s.execute(text("SELECT action FROM audit_event WHERE domain='sso'"))}
        events = [r[0] for r in s.execute(text("SELECT event_type FROM outbox_event ORDER BY seq"))]
    assert {
        "admin_account.registered",
        "recovery_method.added",
        "emergency_access.changed",
        "recovery_drill.recorded",
        "break_glass.activated",
        "break_glass.denied",
        "break_glass.rotated",
    } <= actions
    assert "sso.recovery.readiness_changed" in events and "sso.break_glass.denied" in events
    ev = c.get("/connector/v1/events", headers=h).json()
    env = ev["items"][0]
    assert env["schema_version"] == "1.0" and env["source_app"] == "home-control-hub" and env["event_id"]
    assert env["timestamp_utc"].endswith("Z") and env["actor"]["type"] == "user"


def test_recovery_kit_export_verify_without_secrets(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    acc = _prepare_break_glass(c, h)
    weak = c.post(f"{BASE}/recovery/kit/export", json={"passphrase": "te kort"}, headers=idem(h))
    assert weak.status_code == 422
    r = c.post(f"{BASE}/recovery/kit/export", json={"passphrase": PASSPHRASE}, headers=idem(h))
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["contains_secrets"] is False and body["accounts_count"] == 1
    assert "noodbeheer" not in json.dumps(body["kit"])  # inhoud is versleuteld
    v = c.post(f"{BASE}/recovery/kit/verify", json={"passphrase": PASSPHRASE, "kit": body["kit"]}, headers=h).json()
    assert v["readable"] and v["accounts_count"] == 1 and v["register_sha256"] == body["register_sha256"]
    assert v["contains_secrets"] is False and v["procedure_steps"] >= 5
    bad = c.post(f"{BASE}/recovery/kit/verify", json={"passphrase": PASSPHRASE + "x", "kit": body["kit"]}, headers=h)
    assert bad.status_code == 422 and bad.json()["code"] == "herstelkit_onleesbaar"
    # de wachtwoordzin staat nergens in de database
    with c.app.state.db.sessions() as s:
        dump = " ".join(
            str(row)
            for table in (
                "idempotency_record",
                "audit_event",
                "outbox_event",
                "sso_recovery_kit_export",
                "service_state",
            )
            for row in s.execute(text(f"SELECT * FROM {table}"))  # noqa: S608 - vaste tabelnamen
        )
    assert PASSPHRASE not in dump and "paard batterij" not in dump
    exports = c.get(f"{BASE}/recovery/kit/exports", headers=h).json()["items"]
    assert len(exports) == 1 and exports[0]["ciphertext_sha256"] == body["kit"]["ciphertext_sha256"]
    assert acc["id"]


@pytest.mark.parametrize(
    ("body", "fragment"),
    [
        ({"system": "hub_local", "username": "x", "login_kind": "lokaal", "password": "geheim"}, "password"),
        ({"system": "hub_local", "username": "x", "login_kind": "sso", "is_break_glass": True}, "SSO"),
        (
            {
                "system": "hub_local",
                "username": "x",
                "login_kind": "lokaal",
                "notes": "wachtwoord is Zx81-qPw7-Lm22-Vb90-Kd33",
            },
            "geheimen",
        ),
        ({"system": "hub_local", "username": "x y", "login_kind": "lokaal"}, "username"),
        ({"system": "onbekend", "username": "x", "login_kind": "lokaal"}, "system"),
    ],
)
def test_register_refuses_secrets_and_sso_only_break_glass(
    paired_client: Any, auth: Any, body: dict, fragment: str
) -> None:
    r = paired_client.post(f"{BASE}/recovery/accounts", json=body, headers=idem(auth("admin")))
    assert r.status_code == 422 and r.json()["code"] == "validation_error"
    assert fragment.lower() in r.text.lower()


def test_emergency_access_rules(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    normal = _create_account(c, h, system="truenas", username="truenas_admin", login_kind="lokaal")
    r = c.put(
        f"{BASE}/recovery/accounts/{normal['id']}/emergency-access", json={"network_scopes": [LAN]}, headers=idem(h)
    )
    assert r.status_code == 409 and r.json()["code"] == "geen_noodaccount"
    bg = _create_account(c, h, system="hub_local", username="nood2", login_kind="beide", is_break_glass=True)
    for scopes in ([{"cidr": "0.0.0.0/0", "kind": "lan"}], [{"cidr": "8.8.8.0/24", "kind": "vpn"}]):
        r = c.put(
            f"{BASE}/recovery/accounts/{bg['id']}/emergency-access", json={"network_scopes": scopes}, headers=idem(h)
        )
        assert r.status_code == 422 and "internet" in r.json()["message"]
    r = c.put(
        f"{BASE}/recovery/accounts/{bg['id']}/emergency-access",
        json={"network_scopes": [LAN], "session_max_minutes": 600},
        headers=idem(h),
    )
    assert r.status_code == 422  # sessieduur max. 240 minuten
    r = c.put(f"{BASE}/recovery/accounts/{bg['id']}/emergency-access", json={"network_scopes": [LAN]}, headers=idem(h))
    assert r.status_code == 201
    etag = r.headers["ETag"]
    rv = c.post(f"{BASE}/recovery/accounts/{bg['id']}/emergency-access/review", headers=idem(h, **{"If-Match": etag}))
    assert rv.status_code == 200
    rk = c.post(
        f"{BASE}/recovery/accounts/{bg['id']}/emergency-access/revoke",
        headers=idem(h, **{"If-Match": rv.headers["ETag"]}),
    )
    assert rk.status_code == 200 and rk.json()["status"] == "ingetrokken"
    ev = c.post(f"{BASE}/break-glass/evaluate", json={"account_id": bg["id"], "client_ip": "192.168.50.2"}, headers=h)
    assert ev.json()["allowed"] is False
    # een noodaccount kan niet naar SSO-only worden gezet
    etag = c.get(f"{BASE}/recovery/accounts/{bg['id']}", headers=h).headers["ETag"]
    r = c.patch(
        f"{BASE}/recovery/accounts/{bg['id']}", json={"login_kind": "sso"}, headers=idem(h, **{"If-Match": etag})
    )
    assert r.status_code == 422


def test_hub_service_can_evaluate_and_report_but_not_manage(paired_client: Any, auth: Any, fake_hub: FakeHub) -> None:
    c, h = paired_client, auth("admin")
    acc = _prepare_break_glass(c, h)
    svc = {"Authorization": f"Bearer {fake_hub.issued_token}"}
    ev = c.post(
        f"{BASE}/break-glass/evaluate", json={"account_id": acc["id"], "client_ip": "192.168.50.3"}, headers=svc
    )
    assert ev.status_code == 200 and ev.json()["allowed"]
    act = c.post(
        f"{BASE}/break-glass/activations",
        json={"account_id": acc["id"], "client_ip": "192.168.50.3", "mode": "oefening"},
        headers=idem(svc),
    )
    assert act.status_code == 201 and act.json()["rotation_required"] is False
    assert act.json()["reported_by"] == "service:hub"
    assert c.post(f"{BASE}/recovery/kit/export", json={"passphrase": PASSPHRASE}, headers=idem(svc)).status_code == 403
    assert c.get(f"{BASE}/recovery/accounts", headers=svc).status_code == 403
    viewer = auth("viewer")
    assert (
        c.post(
            f"{BASE}/break-glass/evaluate", json={"account_id": acc["id"], "client_ip": "192.168.50.3"}, headers=viewer
        ).status_code
        == 403
    )


def test_pagination_of_accounts(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    for i in range(5):
        _create_account(c, h, system="overig", username=f"acc{i}", login_kind="lokaal")
    first = c.get(f"{BASE}/recovery/accounts", params={"limit": 2}, headers=h).json()
    seen = [a["username"] for a in first["items"]]
    cursor = first["next_cursor"]
    while cursor:
        page = c.get(f"{BASE}/recovery/accounts", params={"limit": 2, "cursor": cursor}, headers=h).json()
        seen += [a["username"] for a in page["items"]]
        cursor = page["next_cursor"]
    assert seen == [f"acc{i}" for i in range(5)]
    assert c.get(f"{BASE}/recovery/accounts", params={"cursor": "kapot"}, headers=h).json()["code"] == "invalid_cursor"
    assert c.get(f"{BASE}/recovery/accounts", params={"limit": 500}, headers=h).status_code == 422
