"""Integratie: koppelen (omgevingstoken én koppelcode via de statuspagina), ontkoppelen, outbox-push, worker."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text

from integrations.events import MAX_ATTEMPTS
from integrations.timeutil import utcnow
from integrations.worker import Worker
from tests.conftest import ENV_TOKEN, HUB_URL, PAIR_CODE, FakeHub, idem

pytestmark = pytest.mark.integration


def _form_token(client: Any) -> str:
    page = client.get("/")
    m = re.search(r'name="csrf" value="([^"]+)"', page.text)
    assert m
    return m.group(1)


def test_env_token_enrollment_via_worker(make_settings: Any, fake_hub: FakeHub, app_factory: Any) -> None:
    settings = make_settings(hub_url=HUB_URL, enrollment_token=ENV_TOKEN)
    worker = Worker(settings, transport=fake_hub.transport)
    worker.run_once()
    req = fake_hub.enroll_requests[0]
    assert req["app_id"] == "home-control-hub" and req["kind"] == "token" and req["secret"] == ENV_TOKEN
    assert req["public_key_jwk"]["kty"] == "OKP" and "d" not in req["public_key_jwk"]
    c = app_factory(hub_url=HUB_URL, enrollment_token=ENV_TOKEN)
    page = c.get("/").text
    assert "gekoppeld" in page and fake_hub.issued_token not in page and ENV_TOKEN not in page
    assert fake_hub.issued_token[-4:] in page  # alleen de laatste 4 tekens
    # een tweede run doet niets (token is waardeloos na gebruik)
    worker.run_once()
    assert len(fake_hub.enroll_requests) == 1
    with c.app.state.db.sessions() as s:
        stored = s.execute(text("SELECT value::text FROM service_state WHERE key='hub_link'")).scalar()
        raw = s.execute(text("SELECT ciphertext FROM vault_secret WHERE ref='vault://hub/service-token'")).scalar()
    assert fake_hub.issued_token not in stored and ENV_TOKEN not in stored
    assert raw is not None and fake_hub.issued_token.encode() not in raw


def test_env_token_rejected_is_final_and_hub_down_is_retryable(make_settings: Any, fake_hub: FakeHub) -> None:
    worker = Worker(
        make_settings(hub_url=HUB_URL, enrollment_token="verlopen-token-123456"), transport=fake_hub.transport
    )
    worker.run_once()
    st = worker.enrollment.public_state
    with worker.db.sessions() as s:
        state = st(s)
    assert state["status"] == "koppelen_mislukt" and state["reason"] == "hub_weigerde_token"
    worker.state.next_enroll_at = 0
    worker.run_once()
    assert len(fake_hub.enroll_requests) == 1  # definitief afgewezen token wordt niet opnieuw geprobeerd

    fake_hub.up = False
    w2 = Worker(make_settings(hub_url=HUB_URL, enrollment_token=ENV_TOKEN), transport=fake_hub.transport)
    w2.hub.sleep = lambda _s: None
    w2.run_once()
    with w2.db.sessions() as s:
        state = w2.enrollment.public_state(s)
    assert state["reason"] == "hub_onbereikbaar" and w2.state.next_enroll_at > 0
    fake_hub.up = True
    w2.state.next_enroll_at = 0
    w2.run_once()
    with w2.db.sessions() as s:
        assert w2.enrollment.public_state(s)["status"] == "gekoppeld"


def test_no_hub_shows_honest_not_paired(client: Any) -> None:
    html = client.get("/").text
    assert "niet gekoppeld" in html and "geen Hub-adres" in html


def test_pairing_code_via_status_page(client: Any, fake_hub: FakeHub) -> None:
    c = client
    r = c.post("/koppelen", data={"csrf": "fout", "hub_url": HUB_URL, "code": PAIR_CODE}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].endswith("ongeldig_formulier")
    token = _form_token(c)
    r = c.post(
        "/koppelen",
        data={"csrf": token, "hub_url": "http://localhost:30400", "code": PAIR_CODE},
        follow_redirects=False,
    )
    assert r.headers["location"].endswith("ongeldig_hub_adres")
    r = c.post("/koppelen", data={"csrf": token, "hub_url": HUB_URL, "code": "FOUT-CODE"}, follow_redirects=False)
    assert r.headers["location"].endswith("hub_weigerde_code")
    r = c.post(
        "/koppelen",
        data={"csrf": token, "hub_url": HUB_URL, "code": PAIR_CODE},
        headers={"Origin": "http://kwaadaardig.example"},
        follow_redirects=False,
    )
    assert r.headers["location"].endswith("ongeldig_formulier")  # cross-site formulier geweigerd
    r = c.post("/koppelen", data={"csrf": token, "hub_url": HUB_URL, "code": PAIR_CODE}, follow_redirects=False)
    assert r.headers["location"].endswith("melding=gekoppeld")
    assert fake_hub.enroll_requests[-1]["kind"] == "koppelcode"
    page = c.get("/?melding=gekoppeld").text
    assert "Gekoppeld met de Hub" in page and "Ontkoppelen" in page and "Koppelcode" not in page
    # opnieuw koppelen kan niet zolang gekoppeld
    r = c.post("/koppelen", data={"csrf": token, "hub_url": HUB_URL, "code": PAIR_CODE}, follow_redirects=False)
    assert r.headers["location"].endswith("al_gekoppeld")
    # gereflecteerde invoer bestaat niet: onbekende melding wordt genegeerd
    assert "<script>" not in c.get("/?melding=<script>alert(1)</script>").text


def test_unpair_requires_local_code(paired_client: Any, auth: Any) -> None:
    c = paired_client
    token = _form_token(c)
    r = c.post("/ontkoppelen", data={"csrf": token, "unpair_code": "AAAA-BBBB-CCCC"}, follow_redirects=False)
    assert r.headers["location"].endswith("ontkoppelcode_onjuist")
    # de echte code staat alleen in de app-log; in de test zetten we een bekende code
    import hashlib

    c.app.state.unpair_code_sha256 = hashlib.sha256(b"TEST-CODE-0001").hexdigest()
    r = c.post("/ontkoppelen", data={"csrf": token, "unpair_code": "test-code-0001"}, follow_redirects=False)
    assert r.headers["location"].endswith("melding=ontkoppeld")
    assert c.get("/connector/v1/discover", headers=auth("admin")).status_code == 401  # fail-closed na ontkoppelen


def test_pair_throttle(client: Any) -> None:
    token = _form_token(client)
    locs = [
        client.post(
            "/koppelen", data={"csrf": token, "hub_url": HUB_URL, "code": "FOUT"}, follow_redirects=False
        ).headers["location"]
        for _ in range(12)
    ]
    assert locs[-1].endswith("te_veel_pogingen")


def test_admin_unpair_api(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("admin")
    st = c.get("/integrations/v1/enrollment", headers=h).json()
    assert st["status"] == "gekoppeld" and st["jwks"]["available"] and "service_token" not in st
    r = c.post("/integrations/v1/enrollment/unpair", headers=idem(h))
    assert r.status_code == 200 and r.json()["status"] == "niet_gekoppeld"


def test_outbox_push_delivery_dead_letter_and_not_paired(
    paired_client: Any, make_settings: Any, fake_hub: FakeHub, auth: Any
) -> None:
    c, h = paired_client, auth("admin")
    c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "hub_local", "username": "a", "login_kind": "lokaal"},
        headers=idem(h),
    )
    worker = Worker(make_settings(), transport=fake_hub.transport)
    worker.run_once()
    assert fake_hub.inbox and fake_hub.inbox[0]["source_app"] == "home-control-hub"
    with worker.db.sessions() as s:
        pending = s.execute(text("SELECT count(*) FROM outbox_event WHERE delivery_status <> 'delivered'")).scalar()
    assert pending == 0
    # Hub weigert → backoff, na MAX_ATTEMPTS dead letter (zichtbaar in health)
    fake_hub.inbox_status = 500
    c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "hub_local", "username": "b", "login_kind": "lokaal"},
        headers=idem(h),
    )
    for _ in range(MAX_ATTEMPTS):
        with worker.db.sessions() as s:
            s.execute(text("UPDATE outbox_event SET next_attempt_at = now() WHERE delivery_status='pending'"))
            s.commit()
        worker.run_once()
    health = c.get("/connector/v1/health", headers=h).json()
    outbox = next(x for x in health["checks"] if x["name"] == "outbox")
    assert outbox["status"] == "degraded" and outbox["detail"]["dead_letter"] >= 1
    assert c.get("/connector/v1/events", headers=h).json()["dead_letter_count"] >= 1


def test_worker_closes_expired_activations(
    paired_client: Any, make_settings: Any, fake_hub: FakeHub, auth: Any
) -> None:
    c, h = paired_client, auth("admin")
    acc = c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "hub_local", "username": "nood", "login_kind": "lokaal", "is_break_glass": True},
        headers=idem(h),
    ).json()
    c.put(
        f"/integrations/v1/sso/recovery/accounts/{acc['id']}/emergency-access",
        json={"network_scopes": [{"cidr": "10.20.0.0/16", "kind": "lan"}]},
        headers=idem(h),
    )
    act = c.post(
        "/integrations/v1/sso/break-glass/activations",
        json={"account_id": acc["id"], "client_ip": "10.20.1.1", "mode": "oefening"},
        headers=idem(h),
    ).json()
    worker = Worker(make_settings(), transport=fake_hub.transport)
    with worker.db.sessions() as s:
        s.execute(
            text("UPDATE sso_break_glass_activation SET activated_at=:a, expires_at=:e WHERE id=:i"),
            {"a": utcnow() - timedelta(hours=2), "e": utcnow() - timedelta(hours=1), "i": act["id"]},
        )
        s.commit()
    worker.run_once()
    assert worker.state.stats["closed_activations"] == 1
    with worker.db.sessions() as s:
        assert s.execute(text("SELECT closed_at IS NOT NULL FROM sso_break_glass_activation")).scalar()
        assert (
            s.execute(text("SELECT count(*) FROM outbox_event WHERE event_type='sso.break_glass.expired'")).scalar()
            == 1
        )
