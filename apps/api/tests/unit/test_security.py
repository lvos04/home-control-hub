"""Unit: JWKS-cache (fail-closed), JWT-validatie (§4), service-token, geheimen-init, redactie."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import jwt
import pytest

from integrations.errors import ApiError
from integrations.redact import looks_like_secret, redact
from integrations.security.auth import Authenticator, JwtPolicy, sha256_hex, validate_jwt
from integrations.security.jwks import JwksCache, JwksUnavailable, UnknownKey, parse_jwks
from integrations.security.secrets import ensure_secrets, load_identity, load_vault_key, public_jwk
from tests.conftest import HubKeys


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def _reason(exc: pytest.ExceptionInfo[ApiError]) -> str:
    return str(exc.value.details["reason"])


# ------------------------------------------------------------------ JWKS
def test_parse_jwks_only_ed25519(hub_keys: HubKeys) -> None:
    doc = {
        "keys": [
            hub_keys.jwk,
            {"kty": "RSA", "kid": "rsa", "n": "x", "e": "AQAB"},
            {"kty": "OKP", "crv": "X25519", "x": hub_keys.jwk["x"], "kid": "x"},
            {"kty": "OKP", "crv": "Ed25519", "x": "kort", "kid": "kapot"},
        ]
    }
    keys = parse_jwks(doc)
    assert list(keys) == [hub_keys.kid]
    with pytest.raises(ValueError):
        parse_jwks({"geen": "keys"})


def test_jwks_cache_fresh_stale_then_fail_closed(hub_keys: HubKeys) -> None:
    clock = Clock()
    calls = {"n": 0, "fail": False}

    def fetch() -> dict:
        calls["n"] += 1
        if calls["fail"]:
            raise ConnectionError("hub offline")
        return hub_keys.jwks()

    cache = JwksCache(fetch, ttl_s=300, max_stale_s=900, min_refresh_interval_s=30, clock=clock)
    assert cache.get_key(hub_keys.kid) is not None and calls["n"] == 1
    clock.t += 100
    cache.get_key(hub_keys.kid)
    assert calls["n"] == 1  # vers uit cache
    calls["fail"] = True
    clock.t += 400  # verouderd, verversen faalt → oude set nog bruikbaar
    cache.get_key(hub_keys.kid)
    assert cache.status().stale and cache.status().available
    clock.t += 1000  # voorbij max_stale → fail-closed
    with pytest.raises(JwksUnavailable):
        cache.get_key(hub_keys.kid)
    assert not cache.status().available


def test_jwks_unknown_kid_refresh_is_rate_limited(hub_keys: HubKeys) -> None:
    clock = Clock()
    calls = {"n": 0}

    def fetch() -> dict:
        calls["n"] += 1
        return hub_keys.jwks()

    cache = JwksCache(fetch, min_refresh_interval_s=30, clock=clock)
    cache.get_key(hub_keys.kid)
    for _ in range(20):
        with pytest.raises(UnknownKey):
            cache.get_key("onbekend")
    assert calls["n"] == 1  # geen ophaalvloed bij onbekende kid's
    clock.t += 31
    with pytest.raises(UnknownKey):
        cache.get_key("onbekend")
    assert calls["n"] == 2


def test_jwks_without_hub_is_unavailable() -> None:
    with pytest.raises(JwksUnavailable):
        JwksCache(None).get_key("x")


# ------------------------------------------------------------------ JWT
@pytest.fixture
def cache(hub_keys: HubKeys) -> JwksCache:
    c = JwksCache(lambda: hub_keys.jwks())
    c.seed(hub_keys.jwks())
    return c


def test_valid_jwt(hub_keys: HubKeys, cache: JwksCache) -> None:
    p = validate_jwt(hub_keys.token(["admin", "onbekende_rol"], sub="u1"), cache, JwtPolicy())
    assert p.kind == "user" and p.subject == "u1" and p.roles == frozenset({"admin"})


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"iss": "nep-hub"}, "verkeerde_issuer"),
        ({"aud": "andere-dienst"}, "verkeerde_audience"),
        ({"iat_offset": -400, "lifetime": 60}, "token_verlopen"),
        ({"lifetime": 3600}, "levensduur_te_lang"),
        ({"kid": "onbekend"}, "onbekende_sleutel"),
    ],
)
def test_jwt_rejections(hub_keys: HubKeys, cache: JwksCache, kwargs: dict, reason: str) -> None:
    with pytest.raises(ApiError) as exc:
        validate_jwt(hub_keys.token(["admin"], **kwargs), cache, JwtPolicy(leeway_s=0))
    assert exc.value.status_code == 401 and _reason(exc) == reason


def test_jwt_algorithm_confusion_rejected(hub_keys: HubKeys, cache: JwksCache) -> None:
    now = int(time.time())
    claims = {"iss": "hub", "aud": "home-control-hub", "sub": "x", "roles": ["admin"], "iat": now, "exp": now + 60}
    hs = jwt.encode(claims, hub_keys.jwk["x"], algorithm="HS256", headers={"kid": hub_keys.kid})
    unsigned = jwt.encode(claims, None, algorithm="none")  # type: ignore[arg-type]
    for token in (hs, unsigned):
        with pytest.raises(ApiError) as exc:
            validate_jwt(token, cache, JwtPolicy())
        assert _reason(exc) == "algoritme_niet_toegestaan"


def test_jwt_signed_by_other_key_rejected(cache: JwksCache) -> None:
    other = HubKeys()
    forged = other.token(["admin"], kid=HubKeys().kid)
    with pytest.raises(ApiError):
        validate_jwt(forged, cache, JwtPolicy())
    # zelfde kid, andere sleutel → handtekening ongeldig
    real_kid = next(iter(parse_jwks(cache._fetch())))  # type: ignore[misc]
    with pytest.raises(ApiError) as exc:
        validate_jwt(other.token(["admin"], kid=real_kid), cache, JwtPolicy())
    assert _reason(exc) == "token_ongeldig"


def test_authenticator_service_token_and_not_paired(hub_keys: HubKeys, cache: JwksCache) -> None:
    token = "svc-" + "a" * 40
    state = {"hash": None}
    auth = Authenticator(cache, JwtPolicy(), lambda: state["hash"])
    with pytest.raises(ApiError) as exc:
        auth.authenticate(f"Bearer {token}")
    assert _reason(exc) == "niet_gekoppeld"
    state["hash"] = sha256_hex(token)
    p = auth.authenticate(f"Bearer {token}")
    assert p.kind == "service" and p.roles == frozenset({"service"})
    with pytest.raises(ApiError) as exc:
        auth.authenticate("Bearer svc-verkeerd-token-00000000000000")
    assert _reason(exc) == "service_token_ongeldig"
    for header in (None, "", "Basic abc", "Bearer "):
        with pytest.raises(ApiError):
            auth.authenticate(header)


# ------------------------------------------------------------------ geheimen
def test_ensure_secrets_creates_0600_and_never_overwrites(tmp_path: Path) -> None:
    d = tmp_path / "secrets"
    assert sorted(ensure_secrets(d)) == ["identity.ed25519", "vault.key"]
    key1 = load_vault_key(d)
    ident1 = public_jwk(load_identity(d))
    for name in ("vault.key", "identity.ed25519"):
        assert stat.S_IMODE((d / name).stat().st_mode) == 0o600
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    os.chmod(d / "vault.key", 0o644)
    assert ensure_secrets(d) == []
    assert load_vault_key(d) == key1 and public_jwk(load_identity(d)) == ident1
    assert stat.S_IMODE((d / "vault.key").stat().st_mode) == 0o600  # te ruime rechten worden strakker gezet


def test_public_jwk_shape(tmp_path: Path) -> None:
    ensure_secrets(tmp_path)
    jwk = public_jwk(load_identity(tmp_path))
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["alg"] == "EdDSA"
    assert "d" not in jwk  # nooit de privésleutel


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
