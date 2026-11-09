"""Dienst-E2E (Sim-getest): koppelen met eenmalig token, B13-001 met Authentik offline, events naar de Hub-inbox,
B13-002…005 tegen een nep-Authentik over HTTP (voorstel zonder schrijven, sync met afwijking naar de Hub, export,
gate, herstelcheck), eerlijke 501's, fail-closed als de Hub wegvalt, geen header-SSO en een grens op de
verzoekgrootte. Volgorde van de tests is bewust (module-scope stack)."""

from __future__ import annotations

import time
import uuid

import httpx

from tests.e2e.conftest import Stack, TokenHeaders

PASS = "e2e wachtwoordzin voor de herstelkit!"


def _idem(h: dict[str, str]) -> dict[str, str]:
    base = h.fresh() if isinstance(h, TokenHeaders) else h  # één JWT per wijziging (replaybescherming)
    return {**base, "Idempotency-Key": str(uuid.uuid4())}


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


def test_05b_b13_authentik_over_http(stack: Stack) -> None:
    h = stack.token("admin")
    base = f"{stack.hch}/integrations/v1/sso"
    ak_token = httpx.get(f"{stack.authentik}/sim/token").json()["token"]
    src = httpx.get(f"{stack.hch}/integrations/v1/sources/authentik", headers=h).json()  # bestaat al (test_03)
    r = httpx.put(
        f"{stack.hch}/integrations/v1/sources/authentik",
        json={"base_url": stack.authentik, "enabled": True, "credential": ak_token},
        headers={**_idem(h), "If-Match": src["runtime"]["etag"]},
    )
    assert r.status_code == 200, r.text
    det = httpx.post(f"{base}/authentik/detect", headers=_idem(h)).json()
    assert det["version"] == "2026.8.5" and det["status"] == "healthy"
    for group, role in (("hub-beheerders", "admin"), ("hub-lezers", "viewer")):
        m = httpx.post(
            f"{base}/role-mappings",
            json={"app_id": "ai-server-manager", "authentik_group": group, "role": role},
            headers=_idem(h),
        )
        assert m.status_code == 201
    p = httpx.post(
        f"{stack.hch}/connector/v1/propose",
        json={"action_id": "sso.oidc.hub.register", "parameters": {"redirect_uris": ["https://hub.lan.invalid/cb"]}},
        headers=_idem(h),
    )
    assert p.status_code == 201 and p.json()["apply_status"] == "nog_niet_toepasbaar", p.text
    a = httpx.post(f"{stack.hch}/connector/v1/apply", json={"proposal_id": p.json()["proposal_id"]}, headers=h)
    assert a.status_code == 501
    assert httpx.get(f"{stack.authentik}/sim/writes").json() == []  # nooit naar Authentik geschreven
    exp = httpx.post(f"{base}/authentik/config-exports", headers=_idem(h)).json()
    assert exp["complete"] is True
    gate = httpx.post(f"{base}/authentik/upgrade-gate", json={"target_version": "2026.8.5"}, headers=_idem(h)).json()
    assert gate["outcome"] == "rood"  # zelfde versie / geen bevestigde back-up: nooit groen
    rc = httpx.post(f"{base}/authentik/restore-check", json={"export_id": exp["id"]}, headers=_idem(h)).json()
    assert rc["outcome"] == "ok"
    for _ in range(5):
        httpx.post(f"{stack.authentik}/sim/events", json={"action": "login_failed", "username": "bram"})

    def anomaly_in_hub() -> bool:
        inbox = httpx.get(f"{stack.hub}/sim/inbox").json()
        return any(
            e["event_type"] == "sso.anomaly.detected" and e["payload"]["rule_id"] == "mislukte_logins_reeks"
            for e in inbox
        )

    assert _wait(anomaly_in_hub, timeout=40), "worker las Authentik niet of pushte de afwijking niet naar de Hub"
    reused = {**h, "Idempotency-Key": str(uuid.uuid4())}
    first = httpx.post(f"{base}/authentik/sync", headers=reused)
    second = httpx.post(f"{base}/authentik/sync", headers={**h, "Idempotency-Key": str(uuid.uuid4())})
    assert first.status_code == 200, first.text
    assert second.status_code == 401 and second.json()["details"]["reason"] == "token_hergebruikt", second.text


def test_06_fail_closed_when_hub_disappears(stack: Stack) -> None:
    token = stack.token("admin")
    ok = httpx.get(f"{stack.hch}/connector/v1/discover", headers=token)
    assert ok.status_code == 200, ok.text
    stack.hub_proc.terminate()
    stack.hub_proc.wait(10)
    time.sleep(4)  # JWKS-ttl (2 s) + max. oud (1 s) voorbij
    r = httpx.get(f"{stack.hch}/connector/v1/discover", headers=token)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "jwks_niet_beschikbaar"
    assert httpx.get(f"{stack.hch}/readyz").status_code == 200  # de dienst zelf blijft gezond en bereikbaar
    assert "Home Control Hub" in httpx.get(f"{stack.hch}/").text


def test_07_no_header_sso_and_body_limit_over_http(stack: Stack) -> None:
    """B13-003 en de grens op de verzoekgrootte via een echte uvicorn-server (geen auth nodig om te weigeren)."""
    headers = {"X-Forwarded-User": "admin", "X-Authentik-Username": "akadmin", "Remote-User": "admin"}
    r = httpx.get(f"{stack.hch}/integrations/v1/sso/recovery/overview", headers=headers)
    assert r.status_code == 401 and r.json()["code"] == "unauthorized"
    r = httpx.post(
        f"{stack.hch}/integrations/v1/sso/recovery/accounts",
        content=b"x" * (1024 * 1024 + 1),
        headers={**headers, "Content-Type": "application/json"},
    )
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"
    assert httpx.get(f"{stack.hch}/healthz").status_code == 200


def test_08_no_tokens_in_process_logs(stack: Stack) -> None:
    """Review P1: het Authentik-API-token en het eenmalige koppeltoken staan nooit in de logs van API of worker
    (de worker heeft dan al vele keren met het token gesynchroniseerd, ook terwijl de Hub weg was)."""
    from tests.e2e.conftest import ENROLL_TOKEN

    assert stack.logs is not None
    ak_token = httpx.get(f"{stack.authentik}/sim/token").json()["token"]
    assert len(ak_token) >= 20
    for name in ("api.log", "worker.log"):
        for p in stack.procs:  # logs volledig wegschrijven
            assert p.poll() is None, f"{name}: proces is onverwacht gestopt"
        text = (stack.logs / name).read_text(encoding="utf-8", errors="replace")
        assert text.strip(), f"{name} is leeg; de controle zou niets bewijzen"
        assert ak_token not in text, f"Authentik-token in {name}"
        assert ENROLL_TOKEN not in text, f"koppeltoken in {name}"
