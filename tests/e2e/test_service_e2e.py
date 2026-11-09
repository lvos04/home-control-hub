"""Dienst-E2E (Sim-getest): koppelen met eenmalig token, B13-001 met Authentik offline, events naar de Hub-inbox,
eerlijke 501's, en fail-closed als de Hub wegvalt. Volgorde van de tests is bewust (module-scope stack)."""

from __future__ import annotations

import time
import uuid

import httpx

from tests.e2e.conftest import Stack

PASS = "e2e wachtwoordzin voor de herstelkit!"


def _idem(h: dict[str, str]) -> dict[str, str]:
    return {**h, "Idempotency-Key": str(uuid.uuid4())}


def _wait(cond, timeout: float = 30, step: float = 0.5) -> bool:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if cond():
            return True
        time.sleep(step)
    return False


def test_01_ready_and_enrolled_with_one_time_token(stack: Stack) -> None:
    assert httpx.get(f"{stack.hch}/readyz").json()["status"] == "ready"
    assert _wait(lambda: "Gekoppeld met de Hub" in httpx.get(f"{stack.hch}/").text), "worker koppelde niet"
    reqs = httpx.get(f"{stack.hub}/sim/enroll-requests").json()
    assert len(reqs) == 1 and reqs[0]["app_id"] == "home-control-hub" and reqs[0]["kind"] == "token"
    page = httpx.get(f"{stack.hch}/").text
    assert "e2e-eenmalig-token" not in page


def test_02_auth_and_roles_over_http(stack: Stack) -> None:
    assert httpx.get(f"{stack.hch}/connector/v1/discover").status_code == 401
    d = httpx.get(f"{stack.hch}/connector/v1/discover", headers=stack.token("viewer"))
    assert d.status_code == 200 and d.json()["app_id"] == "home-control-hub"
    r = httpx.get(f"{stack.hch}/integrations/v1/sso/recovery/overview", headers=stack.token("viewer"))
    assert r.status_code == 403 and r.json()["code"] == "forbidden"
    r = httpx.get(f"{stack.hch}/integrations/v1/network/devices", headers=stack.token("viewer"))
    assert r.status_code == 501 and r.json()["code"] == "capability_unavailable"


def test_03_b13_001_break_glass_with_authentik_offline(stack: Stack) -> None:
    h = stack.token("admin")
    base = f"{stack.hch}/integrations/v1/sso"
    r = httpx.put(
        f"{stack.hch}/integrations/v1/sources/authentik",
        json={"base_url": f"{stack.hub}/sim/authentik", "enabled": True},
        headers=_idem(h),
    )
    assert r.status_code == 201, r.text
    acc = httpx.post(
        f"{base}/recovery/accounts",
        headers=_idem(h),
        json={"system": "hub_local", "username": "e2e-nood", "is_break_glass": True, "login_kind": "lokaal"},
    ).json()
    for m in ("lokaal_wachtwoord_vpn", "hardwaresleutel"):
        assert (
            httpx.post(
                f"{base}/recovery/accounts/{acc['id']}/methods", json={"method_type": m}, headers=_idem(h)
            ).status_code
            == 201
        )
    r = httpx.put(
        f"{base}/recovery/accounts/{acc['id']}/emergency-access",
        headers=_idem(h),
        json={"network_scopes": [{"cidr": "10.99.0.0/16", "kind": "lan"}]},
    )
    assert r.status_code == 201
    httpx.post(f"{stack.hub}/sim/authentik", json={"up": False})
    drill = httpx.post(
        f"{base}/recovery/drills", json={"account_id": acc["id"], "mode": "zelftest"}, headers=_idem(h)
    ).json()
    assert drill["outcome"] == "ok" and drill["authenticator_state"] == "offline"
    ev = httpx.post(
        f"{base}/break-glass/evaluate", json={"account_id": acc["id"], "client_ip": "10.99.3.4"}, headers=h
    ).json()
    assert ev["allowed"] and ev["authenticator_required"] is False
    kit = httpx.post(f"{base}/recovery/kit/export", json={"passphrase": PASS}, headers=_idem(h)).json()
    v = httpx.post(f"{base}/recovery/kit/verify", json={"passphrase": PASS, "kit": kit["kit"]}, headers=h).json()
    assert v["readable"] and v["accounts_count"] == 1 and v["contains_secrets"] is False


def test_04_idempotent_replay_over_http(stack: Stack) -> None:
    h = {**stack.token("admin"), "Idempotency-Key": str(uuid.uuid4())}
    body = {"system": "overig", "username": "e2e-replay", "login_kind": "lokaal"}
    url = f"{stack.hch}/integrations/v1/sso/recovery/accounts"
    a, b = httpx.post(url, json=body, headers=h), httpx.post(url, json=body, headers=h)
    assert a.status_code == b.status_code == 201 and a.json()["id"] == b.json()["id"]
    assert b.headers.get("Idempotent-Replay") == "true"


def test_05_events_pushed_to_hub_inbox(stack: Stack) -> None:
    def has_drill() -> bool:
        return any(e["event_type"] == "sso.recovery_drill.recorded" for e in httpx.get(f"{stack.hub}/sim/inbox").json())

    assert _wait(has_drill), "worker pushte de events niet naar de Hub-inbox"
    inbox = httpx.get(f"{stack.hub}/sim/inbox").json()
    e = inbox[0]
    assert e["schema_version"] == "1.0" and e["source_app"] == "home-control-hub"
    assert len({x["event_id"] for x in inbox}) == len(inbox)
    assert e["timestamp_utc"].endswith("Z")


def test_06_fail_closed_when_hub_disappears(stack: Stack) -> None:
    token = stack.token("admin")
    assert httpx.get(f"{stack.hch}/connector/v1/discover", headers=token).status_code == 200
    stack.hub_proc.terminate()
    stack.hub_proc.wait(10)
    time.sleep(4)  # JWKS-ttl (2 s) + max. oud (1 s) voorbij
    r = httpx.get(f"{stack.hch}/connector/v1/discover", headers=token)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "jwks_niet_beschikbaar"
    assert httpx.get(f"{stack.hch}/readyz").status_code == 200  # de dienst zelf blijft gezond en bereikbaar
    assert "Home Control Hub" in httpx.get(f"{stack.hch}/").text
