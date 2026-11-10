"""Dienst-E2E (Sim-getest): echte processen (API + worker) tegen de Hub-simulator volgens contract 1.2.

Koppelen met het eenmalige env-token + ``HUB_KEY_FINGERPRINT`` (exact verzoek §3.3, bevestigen met services/self),
inkomend alleen Hub-JWT's (gebruikers- en dienst-JWT, nooit het service-token), B13-001 met Authentik offline,
events naar de Hub-inbox, B13-002…005 tegen een nep-Authentik, ondertekende sleutelrotatie, tokenrotatie op verzoek
van de Hub, een Hub-storing (gepinde sleutels blijven werken, geen intrekking), geen header-SSO en de 1 MiB-grens
(ook chunked), geen tokens in de logs, intrekken → opnieuw koppelen met een nieuw env-token → ontkoppelen door de Hub.
Volgorde van de tests is bewust (module-scope stack)."""

from __future__ import annotations

import time
import uuid
from typing import Any

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

    def linked() -> bool:
        link = httpx.get(f"{stack.hch}/readyz").json()["hub_link"]
        return bool(link["state"] == "gekoppeld" and stack.link_file().get("confirmed_at"))

    assert _wait(linked), "worker koppelde niet of bevestigde niet met services/self"
    state = httpx.get(f"{stack.hub}/sim/state").json()
    reqs = state["enroll_requests"]
    assert len(reqs) == 1 and set(reqs[0]) == {"app_id", "version", "base_url", "public_key_jwk"}  # + token
    assert reqs[0]["app_id"] == "home-control-hub" and set(reqs[0]["public_key_jwk"]) == {"kty", "crv", "x", "kid"}
    assert ["GET", "/api/v1/services/self"] in state["calls"]
    link = stack.link_file()
    assert link["schema_version"] == "1.3" and link["via"] == "token" and link["pending"] is None  # §3.5 (1.3)
    assert link["pins"]["keyset_fingerprint"] == state["fingerprint"] and link["service_id"] == state["service_id"]
    page = httpx.get(f"{stack.hch}/").text
    assert stack.enroll_tokens[0] not in page and link["service_token"] not in page
    assert state["fingerprint"] in page and 'action="/koppelen"' not in page  # na koppelen geen formulier meer
    assert "Ontkoppelen of opnieuw koppelen gaat via de Hub" in page


def test_02_auth_and_roles_over_http(stack: Stack) -> None:
    r = httpx.get(f"{stack.hch}/connector/v1/discover")
    assert r.status_code == 401 and r.json()["details"]["reason"] == "invalid_token"
    svc_token = stack.link_file()["service_token"]
    r = httpx.get(f"{stack.hch}/connector/v1/discover", headers={"Authorization": f"Bearer {svc_token}"})
    assert r.status_code == 401 and r.json()["details"]["reason"] == "service_token_not_accepted"
    hub_link = httpx.get(f"{stack.hch}/connector/v1/hub-link", headers=stack.service())
    assert hub_link.status_code == 200 and hub_link.json()["state"] == "gekoppeld"
    assert svc_token not in hub_link.text
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
    assert second.status_code == 401 and second.json()["details"]["reason"] == "token_replayed", second.text


def test_05c_hub_accepted_every_event(stack: Stack) -> None:
    """Contract §7: de Hub-simulator valideert de envelope net als de echte Hub; niets mag geweigerd zijn."""
    rejected = httpx.get(f"{stack.hub}/sim/rejected").json()
    assert rejected == [], rejected
    assert len(httpx.get(f"{stack.hub}/sim/inbox").json()) >= 5


def test_05d_signed_key_rotation_over_http(stack: Stack) -> None:
    """§4.5: de Hub publiceert een met de gepinde sleutel ondertekende rotatie; een JWT met de nieuwe sleutel krijgt
    eerst direct 401 ``unknown_key`` (poll op de achtergrond) en wordt daarna geaccepteerd."""
    rot = httpx.post(f"{stack.hub}/sim/key-rotation").json()  # de Hub ondertekent vanaf nu met de nieuwe sleutel
    first = httpx.get(f"{stack.hch}/connector/v1/discover", headers=stack.token("viewer"))
    assert first.status_code in (200, 401)
    if first.status_code == 401:
        assert first.json()["details"]["reason"] == "unknown_key"
    assert _wait(
        lambda: httpx.get(f"{stack.hch}/connector/v1/discover", headers=stack.token("viewer")).status_code == 200
    )
    view = httpx.get(f"{stack.hch}/connector/v1/hub-link", headers=stack.token("viewer")).json()
    assert view["rotation_sequence"] == 1 and rot["kid"] in view["pinned_kids"]["jwt"]
    assert view["keyset_fingerprint"] == rot["fingerprint"]


def test_05e_token_rotation_on_hub_request(stack: Stack) -> None:
    """§3.8: rotatie aanvragen in de Hub → ``Hub-Token-Rotation: required`` → de dienst roteert zelf (≤ 5 min; hier
    met een korte bevestigingscyclus) en bevestigt het nieuwe token."""
    before = stack.link_file()["service_token_last4"]
    httpx.post(f"{stack.hub}/sim/request-rotation")

    def rotated() -> bool:
        link = stack.link_file()
        return bool(link["service_token_last4"] != before and link["confirmed_at"])

    assert _wait(rotated), "de dienst roteerde zijn service-token niet"
    assert ["POST", "/api/v1/services/self/rotate"] in httpx.get(f"{stack.hub}/sim/state").json()["calls"]


def test_06_pinned_keys_keep_working_during_hub_outage(stack: Stack) -> None:
    """De vertrouwensset zijn de gepinde sleutels; een storing bij de Hub (5xx) is nooit een intrekking."""
    httpx.post(f"{stack.hub}/sim/outage", json={"on": True})
    try:
        time.sleep(3)  # enkele bevestigingsrondes van de worker tegen een Hub die 503 geeft
        r = httpx.get(f"{stack.hch}/connector/v1/discover", headers=stack.token("admin"))
        assert r.status_code == 200, r.text
        assert stack.link_file()["state"] == "gekoppeld"
        assert httpx.get(f"{stack.hch}/readyz").status_code == 200  # de dienst zelf blijft gezond
    finally:
        httpx.post(f"{stack.hub}/sim/outage", json={"on": False})
    calls = httpx.get(f"{stack.hub}/sim/state").json()["calls"]
    assert ["GET", "/api/v1/auth/jwks"] not in calls  # de JWKS via HTTP wordt nooit opgehaald (voegt niets toe)


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

    def chunks() -> Any:
        for _ in range(40):
            yield b"a" * 32768  # 1,25 MiB zonder Content-Length (chunked), vóór de authenticatie

    r = httpx.post(f"{stack.hch}/connector/v1/hub-link/unlink", content=chunks(), headers=_idem(stack.service()))
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"
    assert stack.link_file()["state"] == "gekoppeld"
    assert httpx.get(f"{stack.hch}/healthz").status_code == 200


def test_08_no_tokens_in_process_logs(stack: Stack) -> None:
    """Review P1: het Authentik-API-token en het eenmalige koppeltoken staan nooit in de logs van API of worker
    (de worker heeft dan al vele keren met het token gesynchroniseerd, ook terwijl de Hub weg was)."""
    assert stack.logs is not None
    service_token = stack.link_file()["service_token"]
    ak_token = httpx.get(f"{stack.authentik}/sim/token").json()["token"]
    assert len(ak_token) >= 20
    for name in ("api.log", "worker.log"):
        for p in stack.procs:  # logs volledig wegschrijven
            assert p.poll() is None, f"{name}: proces is onverwacht gestopt"
        text = (stack.logs / name).read_text(encoding="utf-8", errors="replace")
        assert text.strip(), f"{name} is leeg; de controle zou niets bewijzen"
        assert ak_token not in text, f"Authentik-token in {name}"
        for token in stack.enroll_tokens:
            assert token not in text, f"koppeltoken in {name}"
        assert service_token not in text, f"service-token in {name}"
        assert "ontkoppelcode" not in text.lower(), f"lokale ontkoppelcode in {name} (bestaat niet meer)"


def test_09_revoke_relink_with_new_env_token_then_unlink_by_hub(stack: Stack) -> None:
    """§3.8: intrekken in de Hub (services/self 401) → ``ingetrokken``; opnieuw koppelen alleen via de Hub (nieuw
    env-token, zoals ``app.update``); daarna ontkoppelt de Hub met een dienst-JWT; een herhaalde unlink geeft 401
    ``not_linked`` (telt voor de Hub als gelukt)."""
    httpx.post(f"{stack.hub}/sim/revoke")
    assert _wait(lambda: stack.link_file()["state"] == "ingetrokken"), "intrekking niet gezien"
    r = httpx.get(f"{stack.hch}/connector/v1/discover", headers=stack.token("admin"))
    assert r.status_code == 401 and r.json()["details"]["reason"] == "revoked"
    assert 'action="/koppelen"' not in httpx.get(f"{stack.hch}/").text
    grant = stack.grant()
    stack.restart_worker(HUB_ENROLLMENT_TOKEN=grant["secret"], HUB_KEY_FINGERPRINT=grant["fingerprint"])
    assert _wait(lambda: stack.link_file()["state"] == "gekoppeld" and bool(stack.link_file()["confirmed_at"]))
    assert len(stack.link_file()["used_enrollment_token_sha256"]) == 2
    assert httpx.get(f"{stack.hch}/connector/v1/discover", headers=stack.token("admin")).status_code == 200
    key = str(uuid.uuid4())
    r = httpx.post(
        f"{stack.hch}/connector/v1/hub-link/unlink", headers={**stack.service().fresh(), "Idempotency-Key": key}
    )
    assert r.status_code == 200 and r.json()["state"] == "ontkoppeld", r.text
    again = httpx.post(
        f"{stack.hch}/connector/v1/hub-link/unlink", headers={**stack.service().fresh(), "Idempotency-Key": key}
    )
    assert again.status_code == 401 and again.json()["details"]["reason"] == "not_linked"
    link = stack.link_file()
    assert link["service_token"] is None and link["pins"] is None and link["previous_pins"] is not None
    page = httpx.get(f"{stack.hch}/").text
    assert "ontkoppeld" in page and 'action="/koppelen"' not in page


def test_10_hub_gone_service_stays_up(stack: Stack) -> None:
    stack.hub_proc.terminate()
    stack.hub_proc.wait(10)
    time.sleep(2)
    assert httpx.get(f"{stack.hch}/readyz").status_code == 200
    assert "Home Control Hub" in httpx.get(f"{stack.hch}/").text
    for p in stack.procs:
        assert p.poll() is None
