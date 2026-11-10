"""Integratie (PostgreSQL, Hub-simulator): de ``reason``-tabel van contract 1.3 §4.7 over HTTP en de controlevolgorde
(C1.3-HCH-03, RV9): 1 MiB-laag → aanmelding (``state`` → tokensoort → handtekening/``kid`` → claims → ``token_use`` →
``jti``) → body, rol en ``Idempotency-Key``. Zonder geldige aanmelding is het antwoord altijd 401, ook bij een
onleesbare of ongeldige body of een ontbrekende ``Idempotency-Key``. Sim-getest."""

from __future__ import annotations

import time
import uuid
from typing import Any

import jwt
import pytest

from tests.conftest import FakeHub, HubKeys, SimKey, idem

pytestmark = pytest.mark.integration

PAD = "/integrations/v1/sso/recovery/accounts"  # POST met JSON-body, alleen admin, Idempotency-Key verplicht
GELDIG = {"system": "overig", "username": "volgorde", "login_kind": "lokaal"}


def _reason(r: Any) -> str:
    assert r.status_code == 401, (r.status_code, r.text[:200])
    body = r.json()
    assert body["code"] == "unauthorized" and set(body) == {"code", "message", "details", "trace_id"}
    return str(body["details"]["reason"])


def _claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    c = {
        "iss": "hub",
        "aud": "home-control-hub",
        "sub": "user-1",
        "token_use": "user",
        "roles": ["admin"],
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    c.update(over)
    return c


@pytest.mark.parametrize(
    ("header", "reason"),
    [
        (None, "invalid_token"),  # geen Authorization-header
        ("Basic YWRtaW46YWRtaW4=", "invalid_token"),  # ander schema
        ("Bearer ", "invalid_token"),  # lege waarde
        ("Bearer   ", "invalid_token"),
        ("Bearer geen.geldige.jws", "invalid_token"),
        ("Bearer svc_" + "a" * 43, "service_token_not_accepted"),
    ],
)
def test_reason_table_for_the_header(paired_client: Any, header: str | None, reason: str) -> None:
    headers = {"Authorization": header} if header is not None else {}
    assert _reason(paired_client.get("/connector/v1/discover", headers=headers)) == reason


def test_reason_table_for_keys_and_claims(paired_client: Any, hub_keys: HubKeys) -> None:
    c = paired_client
    zonder_kid = jwt.encode(_claims(), hub_keys.private, algorithm="EdDSA")
    assert _reason(c.get("/connector/v1/discover", headers={"Authorization": f"Bearer {zonder_kid}"})) == "unknown_key"
    andere = SimKey()  # gepinde kid, maar de handtekening is van een andere sleutel
    vals = jwt.encode(_claims(), andere.private, algorithm="EdDSA", headers={"kid": hub_keys.kid})
    assert _reason(c.get("/connector/v1/discover", headers={"Authorization": f"Bearer {vals}"})) == "invalid_token"
    lijst = jwt.encode(
        _claims(aud=["home-control-hub"]), hub_keys.private, algorithm="EdDSA", headers={"kid": hub_keys.kid}
    )
    assert _reason(c.get("/connector/v1/discover", headers={"Authorization": f"Bearer {lijst}"})) == "invalid_token"


def test_authentication_comes_before_the_body(paired_client: Any, hub_keys: HubKeys) -> None:
    """FastAPI leest een JSON-body vóór de afhankelijkheden; zonder AuthFirstRoute gaf een onleesbare body zonder
    aanmelding 422. Nu altijd 401 (en een geweigerde aanmelding verbruikt niets)."""
    c = paired_client
    for body in (b"{kapot", b"[1,", b"\xff\xfe"):
        r = c.post(
            PAD, content=body, headers={"Content-Type": "application/json", "Idempotency-Key": str(uuid.uuid4())}
        )
        assert _reason(r) == "invalid_token"
    andere = SimKey()
    token = jwt.encode(_claims(), andere.private, algorithm="EdDSA", headers={"kid": andere.kid})
    r = c.post(PAD, content=b"{kapot", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    assert _reason(r) == "unknown_key"
    # schemafout zonder aanmelding: ook 401
    assert _reason(c.post(PAD, json={"onbekend": 1}, headers={"Idempotency-Key": str(uuid.uuid4())})) == "invalid_token"


def test_authentication_comes_before_idempotency_key_and_role(paired_client: Any, auth: Any) -> None:
    c = paired_client
    # geen aanmelding en geen Idempotency-Key: 401, niet 400
    assert _reason(c.post(PAD, json=GELDIG)) == "invalid_token"
    # wel aangemeld: daarna pas Idempotency-Key (400) en rol (403); nooit 401
    r = c.post(PAD, json=GELDIG, headers=auth("admin"))
    assert (r.status_code, r.json()["code"]) == (400, "idempotency_key_required")
    r = c.post(PAD, json=GELDIG, headers=idem(auth("viewer")))
    assert (r.status_code, r.json()["code"], r.json()["details"]["reason"]) == (403, "forbidden", "rol_ontbreekt")


def test_body_errors_after_authentication_still_consume_the_jti(paired_client: Any, hub_keys: HubKeys) -> None:
    """§4.6: elke POST verbruikt de ``jti`` (ook als de body daarna ongeldig blijkt)."""
    c = paired_client
    token = hub_keys.token(["admin"])
    kop = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = c.post(PAD, content=b"{kapot", headers={**kop, "Idempotency-Key": str(uuid.uuid4())})
    assert (r.status_code, r.json()["code"]) == (422, "validation_error")
    r = c.post(PAD, json=GELDIG, headers={**kop, "Idempotency-Key": str(uuid.uuid4())})
    assert _reason(r) == "token_replayed"


def test_body_limit_comes_first_even_without_authentication(paired_client: Any) -> None:
    def brokken() -> Any:
        for _ in range(40):
            yield b"a" * 32768  # 1,25 MiB zonder Content-Length

    r = paired_client.post(PAD, content=brokken(), headers={"Content-Type": "application/json"})
    assert (r.status_code, r.json()["code"], r.json()["details"]) == (
        413,
        "payload_too_large",
        {"max_bytes": 1024 * 1024},
    )


def test_not_linked_gives_not_linked_before_anything(client: Any, fake_hub: FakeHub) -> None:
    r = client.post(PAD, content=b"{kapot", headers={"Content-Type": "application/json"})
    assert _reason(r) == "not_linked"
    assert fake_hub.enroll_requests == []
