"""Unit: inkomende authenticatie volgens contract 1.2 §4.3–§4.7 (gepinde sleutels, vaste ``reason``-waarden en hun
controlevolgorde, ``token_use``, ``jti`` + replay), geheimen-init en redactie."""

from __future__ import annotations

import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import pytest

from integrations.enrollment import _pins_from
from integrations.errors import ApiError
from integrations.hublink_store import HubLinkStore, LinkState
from integrations.redact import looks_like_secret, redact
from integrations.security.auth import REASONS, Authenticator, JwtPolicy
from integrations.security.hubkeys import validate_hub_jwk
from integrations.security.secrets import enroll_public_jwk, ensure_secrets, load_identity, load_vault_key
from tests.conftest import HubKeys, SimKey

SID = str(uuid.uuid4())


class MemoryReplay:
    """Zelfde regels als ``ReplayGuard`` (§4.6), in het geheugen."""

    def __init__(self, broken: bool = False) -> None:
        self.seen: dict[tuple[str, str], tuple[str, str, str, str | None]] = {}
        self.broken = broken

    def check(
        self, *, iss: str, jti: str, exp: float, subject: str, method: str, path: str, idempotency_key: Any
    ) -> None:
        from integrations.security.auth import auth_error

        if self.broken:
            raise ApiError(503, "replay_check_unavailable", "weg")
        key = (iss, jti)
        now = (subject, method, path, idempotency_key)
        if key not in self.seen:
            self.seen[key] = now
            return
        if idempotency_key is None or self.seen[key] != now:
            raise auth_error("token_replayed")


def _store(tmp_path: Path, keys: HubKeys, state: str = "gekoppeld") -> HubLinkStore:
    store = HubLinkStore(tmp_path)
    jwks = [validate_hub_jwk(k) for k in keys.jwks()["keys"]]
    pins = _pins_from(jwks, [validate_hub_jwk(keys.sim.policy_jwk())], "enroll", "2026-11-09T12:00:00Z")
    linked = state == "gekoppeld"
    store.write_initial(
        LinkState(
            state=state,  # type: ignore[arg-type]
            hub_url="http://hub.test:30400",
            service_id=SID,
            first_linked_at="2026-11-09T12:00:00Z",
            service_token=("svc_" + "a" * 43) if linked else None,
            pins=pins if linked else None,
            previous_pins=None if linked else pins,
        )
    )
    return store


@pytest.fixture
def replay() -> MemoryReplay:
    return MemoryReplay()


@pytest.fixture
def unknown_polls() -> list[int]:
    return []


@pytest.fixture
def authn(tmp_path: Path, hub_keys: HubKeys, replay: MemoryReplay, unknown_polls: list[int]) -> Authenticator:
    return Authenticator(_store(tmp_path, hub_keys), JwtPolicy(), replay, lambda: unknown_polls.append(1))


def _reason(exc: pytest.ExceptionInfo[ApiError]) -> str:
    assert exc.value.status_code == 401 and exc.value.code == "unauthorized"
    return str(exc.value.details["reason"])


def _fail(a: Authenticator, token: str | None, method: str = "GET", idem: str | None = None) -> str:
    header = None if token is None else f"Bearer {token}"
    with pytest.raises(ApiError) as exc:
        a.authenticate(header, method=method, path="/connector/v1/propose", idempotency_key=idem)
    return _reason(exc)


def _claims(**over: Any) -> dict[str, Any]:
    now = int(time.time())
    base = {
        "iss": "hub",
        "aud": "home-control-hub",
        "sub": "u1",
        "token_use": "user",
        "roles": ["admin"],
        "iat": now,
        "nbf": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def _sign(keys: HubKeys, claims: dict[str, Any], kid: str | None = None, key: Any = None) -> str:
    return jwt.encode(claims, key or keys.private, algorithm="EdDSA", headers={"kid": kid or keys.kid})


# ------------------------------------------------------------------ geldige tokens
def test_user_jwt_accepted_and_roles_filtered(authn: Authenticator, hub_keys: HubKeys) -> None:
    p = authn.authenticate(f"Bearer {hub_keys.token(['admin', 'onbekende_rol'], sub='u1')}")
    assert p.kind == "user" and p.subject == "u1" and p.roles == frozenset({"admin"})


def test_role_kind_always_wins(authn: Authenticator, hub_keys: HubKeys) -> None:
    """§4.2: rol ``kind`` wint altijd van andere rollen in dezelfde JWT."""
    assert authn.authenticate(f"Bearer {hub_keys.token(['admin', 'kind'])}").roles == frozenset({"kind"})


def test_hub_service_jwt_gives_service_principal(authn: Authenticator, hub_keys: HubKeys) -> None:
    p = authn.authenticate(f"Bearer {hub_keys.sim.service_jwt(SID.upper())}")  # UUID-vergelijking, niet als tekst
    assert p.kind == "service" and p.audit_id == "service:hub" and p.roles == frozenset({"service"})
    assert "admin" not in p.roles


# ------------------------------------------------------------------ vaste reasons (§4.7)
@pytest.mark.parametrize("state", ["nooit_gekoppeld", "ontkoppeld"])
def test_not_linked(tmp_path: Path, hub_keys: HubKeys, state: str) -> None:
    store = HubLinkStore(tmp_path) if state == "nooit_gekoppeld" else _store(tmp_path, hub_keys, state)
    a = Authenticator(store, JwtPolicy(), MemoryReplay())
    assert _fail(a, hub_keys.token(["admin"])) == "not_linked"
    assert _fail(a, None) == "not_linked"  # eerst de toestand, dan pas het token


def test_revoked(tmp_path: Path, hub_keys: HubKeys) -> None:
    a = Authenticator(_store(tmp_path, hub_keys, "ingetrokken"), JwtPolicy(), MemoryReplay())
    assert _fail(a, hub_keys.token(["admin"])) == "revoked"
    assert _fail(a, "svc_" + "a" * 43) == "revoked"


def test_corrupt_link_file_trusts_nothing(tmp_path: Path, hub_keys: HubKeys) -> None:
    store = _store(tmp_path, hub_keys)
    (tmp_path / "hub-link.json").write_text("{kapot", encoding="utf-8")
    a = Authenticator(store, JwtPolicy(), MemoryReplay())
    assert _fail(a, hub_keys.token(["admin"])) == "not_linked"


def test_service_token_not_accepted_inbound(authn: Authenticator) -> None:
    """§4.3: een inkomend ``Bearer svc_…`` (ook het eigen, geldige service-token) wordt nooit geaccepteerd."""
    assert _fail(authn, "svc_" + "a" * 43) == "service_token_not_accepted"
    assert _fail(authn, "svc_iets") == "service_token_not_accepted"


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer ", "Bearer geen.jwt", "Bearer a.b.c.d"])
def test_missing_or_malformed_token(authn: Authenticator, header: str | None) -> None:
    with pytest.raises(ApiError) as exc:
        authn.authenticate(header)
    assert _reason(exc) == "invalid_token"


def test_unknown_kid_is_rejected_and_triggers_background_poll(
    authn: Authenticator, hub_keys: HubKeys, unknown_polls: list[int]
) -> None:
    other = SimKey()
    assert _fail(authn, _sign(hub_keys, _claims(), kid=other.kid, key=other.private)) == "unknown_key"
    assert unknown_polls == [1]
    no_kid = jwt.encode(_claims(), hub_keys.private, algorithm="EdDSA")
    assert _fail(authn, no_kid) == "unknown_key"


def test_swapped_key_with_pinned_kid_is_rejected(authn: Authenticator, hub_keys: HubKeys) -> None:
    """Vergelijking op de sleutel zelf (x), niet alleen op ``kid``: een andere sleutel met de gepinde kid faalt."""
    other = SimKey()
    assert _fail(authn, _sign(hub_keys, _claims(), kid=hub_keys.kid, key=other.private)) == "invalid_token"


def test_http_jwks_adds_no_trust(tmp_path: Path, hub_keys: HubKeys) -> None:
    """Een sleutel die de Hub (of een aanvaller) via HTTP in de JWKS zet, wordt niet vertrouwd zolang hij niet gepind
    is: de Authenticator kijkt alleen naar ``hub-link.json``."""
    a = Authenticator(_store(tmp_path, hub_keys), JwtPolicy(), MemoryReplay())
    rogue = SimKey()
    hub_keys.sim.jwt_keys.append(rogue)  # staat nu in de HTTP-JWKS van de nep-Hub
    assert _fail(a, _sign(hub_keys, _claims(), kid=rogue.kid, key=rogue.private)) == "unknown_key"


def test_algorithm_confusion_is_invalid_token(authn: Authenticator, hub_keys: HubKeys) -> None:
    hs = jwt.encode(_claims(), "geheim-" + "x" * 32, algorithm="HS256", headers={"kid": hub_keys.kid})
    unsigned = jwt.encode(_claims(), None, algorithm="none", headers={"kid": hub_keys.kid})  # type: ignore[arg-type]
    assert _fail(authn, hs) == "invalid_token"
    assert _fail(authn, unsigned) == "invalid_token"


def test_expired(authn: Authenticator, hub_keys: HubKeys) -> None:
    now = int(time.time())
    assert _fail(authn, _sign(hub_keys, _claims(iat=now - 200, nbf=now - 200, exp=now - 100))) == "token_expired"


@pytest.mark.parametrize(
    "over",
    [
        {"iss": "nep-hub"},
        {"aud": "andere-dienst"},
        {"aud": "ai-server-manager"},
        # §4.2/§4.3: aud is precies de string <app_id>; een lijst (ook met deze dienst erin) is ongeldig, anders is
        # dezelfde JWT ook bij een andere dienst bruikbaar (review contract 1.2)
        {"aud": ["home-control-hub", "zoeken-en-persoonlijke-ai"]},
        {"aud": ["home-control-hub"]},
        {"exp": int(time.time()) + 3600},  # exp - iat > 120 s
        {"nbf": int(time.time()) + 600},
        {"iat": int(time.time()) + 600, "nbf": int(time.time()) + 600, "exp": int(time.time()) + 660},
        {"exp": None},
        {"iat": None},
        {"nbf": None},
        {"sub": None},
        {"sub": ""},
        {"iss": None},
        {"aud": None},
        {"iat": "nu"},
    ],
)
def test_invalid_claims(authn: Authenticator, hub_keys: HubKeys, over: dict[str, Any]) -> None:
    assert _fail(authn, _sign(hub_keys, _claims(**over))) == "invalid_token"


@pytest.mark.parametrize(
    "over",
    [
        {"token_use": None},
        {"token_use": "admin"},
        {"token_use": "user", "roles": ["service"]},
        {"token_use": "user", "roles": ["admin", "service"]},
        {"token_use": "user", "roles": "admin"},
        {"token_use": "hub_service", "sub": "hub", "roles": ["service"]},  # geen service_id
        {"token_use": "hub_service", "sub": "hub", "roles": ["service"], "service_id": str(uuid.uuid4())},
        {"token_use": "hub_service", "sub": "nep", "roles": ["service"], "service_id": SID},
        {"token_use": "hub_service", "sub": "hub", "roles": ["service", "admin"], "service_id": SID},
        {"token_use": "hub_service", "sub": "hub", "roles": ["admin"], "service_id": SID},
        {"token_use": "hub_service", "sub": "hub", "roles": ["service"], "service_id": "geen-uuid"},
    ],
)
def test_token_use_invalid(authn: Authenticator, hub_keys: HubKeys, over: dict[str, Any]) -> None:
    assert _fail(authn, _sign(hub_keys, _claims(**over))) == "token_use_invalid"


def test_jti_missing_on_any_jwt(authn: Authenticator, hub_keys: HubKeys) -> None:
    """§4.6: ``jti`` is op **elke** JWT verplicht, ook bij lezen."""
    assert _fail(authn, _sign(hub_keys, _claims(jti=None))) == "jti_missing"
    assert _fail(authn, hub_keys.sim.service_jwt(SID, jti=None)) == "jti_missing"
    assert _fail(authn, _sign(hub_keys, _claims(jti=""))) == "jti_missing"


def test_jti_replay_on_mutations(authn: Authenticator, hub_keys: HubKeys) -> None:
    token = hub_keys.token(["admin"])
    key = str(uuid.uuid4())
    authn.authenticate(f"Bearer {token}", method="POST", path="/x", idempotency_key=key)
    # exacte herhaling (netwerk-retry): toegestaan, de idempotency-laag geeft het opgeslagen resultaat
    authn.authenticate(f"Bearer {token}", method="POST", path="/x", idempotency_key=key)
    with pytest.raises(ApiError) as exc:  # andere wijziging met dezelfde jti
        authn.authenticate(f"Bearer {token}", method="POST", path="/x", idempotency_key=str(uuid.uuid4()))
    assert _reason(exc) == "token_replayed"
    with pytest.raises(ApiError) as exc:
        authn.authenticate(f"Bearer {token}", method="DELETE", path="/x", idempotency_key=key)
    assert _reason(exc) == "token_replayed"
    # lezen mag binnen de levensduur vaker
    for _ in range(3):
        authn.authenticate(f"Bearer {token}", method="GET", path="/x")
    # zonder Idempotency-Key is er geen exacte herhaling
    other = hub_keys.token(["admin"])
    authn.authenticate(f"Bearer {other}", method="POST", path="/y")
    with pytest.raises(ApiError) as exc:
        authn.authenticate(f"Bearer {other}", method="POST", path="/y")
    assert _reason(exc) == "token_replayed"


def test_service_jwt_replay_also_rejected(authn: Authenticator, hub_keys: HubKeys) -> None:
    token = hub_keys.sim.service_jwt(SID)
    authn.authenticate(f"Bearer {token}", method="POST", path="/connector/v1/hub-link/unlink", idempotency_key="k1")
    with pytest.raises(ApiError) as exc:
        authn.authenticate(f"Bearer {token}", method="POST", path="/connector/v1/propose", idempotency_key="k2")
    assert _reason(exc) == "token_replayed"


def test_replay_check_unavailable_is_fail_closed(tmp_path: Path, hub_keys: HubKeys) -> None:
    a = Authenticator(_store(tmp_path, hub_keys), JwtPolicy(), MemoryReplay(broken=True))
    with pytest.raises(ApiError) as exc:
        a.authenticate(f"Bearer {hub_keys.token(['admin'])}", method="POST", path="/x", idempotency_key="k")
    assert exc.value.status_code == 503 and exc.value.code == "replay_check_unavailable"
    assert a.authenticate(f"Bearer {hub_keys.token(['admin'])}", method="GET", path="/x").kind == "user"


def test_check_order_follows_section_4_7(authn: Authenticator, hub_keys: HubKeys) -> None:
    """``state`` → tokensoort → handtekening/``kid`` → claims → ``token_use`` → ``jti``: bij meerdere fouten wint de
    eerste in die volgorde."""
    other = SimKey()
    now = int(time.time())
    # onbekende kid + verlopen + geen token_use + geen jti → unknown_key
    t = _sign(
        hub_keys, _claims(exp=now - 100, iat=now - 150, token_use=None, jti=None), kid=other.kid, key=other.private
    )
    assert _fail(authn, t) == "unknown_key"
    # verlopen + geen token_use + geen jti → token_expired
    assert _fail(authn, _sign(hub_keys, _claims(exp=now - 100, iat=now - 150, token_use=None, jti=None))) == (
        "token_expired"
    )
    # verkeerde aud + geen token_use → invalid_token
    assert _fail(authn, _sign(hub_keys, _claims(aud="x", token_use=None))) == "invalid_token"
    # geen token_use + geen jti → token_use_invalid
    assert _fail(authn, _sign(hub_keys, _claims(token_use=None, jti=None))) == "token_use_invalid"


def test_every_reason_is_from_the_fixed_list() -> None:
    assert set(REASONS) == {
        "not_linked",
        "revoked",
        "service_token_not_accepted",
        "unknown_key",
        "token_expired",
        "invalid_token",
        "token_use_invalid",
        "jti_missing",
        "token_replayed",
    }


# ------------------------------------------------------------------ geheimen
def test_ensure_secrets_creates_0600_and_never_overwrites(tmp_path: Path) -> None:
    d = tmp_path / "secrets"
    assert sorted(ensure_secrets(d)) == ["identity.ed25519", "vault.key"]
    key1 = load_vault_key(d)
    ident1 = enroll_public_jwk(load_identity(d))
    for name in ("vault.key", "identity.ed25519"):
        assert stat.S_IMODE((d / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    os.chmod(d / "vault.key", 0o644)
    assert ensure_secrets(d) == []
    assert load_vault_key(d) == key1 and enroll_public_jwk(load_identity(d)) == ident1
    assert stat.S_IMODE((d / "vault.key").stat().st_mode) == 0o600  # te ruime rechten worden strakker gezet
    assert not (d / "hub-link.json").exists()  # koppelstatus is geen gegenereerd geheim


# ------------------------------------------------------------------ redactie
def test_redact_masks_secret_keys_and_tokens() -> None:
    data = {
        "service_token": "abc",
        "password": "geheim",
        "nested": [{"api_key": "x", "credential_last4": "1234"}],
        "msg": "Authorization: Bearer eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
    }
    out = redact(data)
    assert out["service_token"] == "***" and out["password"] == "***"
    assert out["nested"][0]["api_key"] == "***" and out["nested"][0]["credential_last4"] == "1234"
    assert "eyJ" not in out["msg"]


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("wachtwoordmanager, map Noodtoegang", False),
        ("Opgeslagen in de kluis op zolder", False),
        ("token ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4", True),
        ("Bearer abc.def", True),
        ("7f3a9c2e1b4d6f8a0c2e4b6d8f0a1c3e", True),
    ],
)
def test_looks_like_secret(text: str, secret: bool) -> None:
    assert looks_like_secret(text) is secret
