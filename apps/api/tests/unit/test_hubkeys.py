"""Unit (A5): testvectoren van contract 1.2 §4.5 (thumbprint + sleutelset-vingerafdruk), normalisatie van
vingerafdruk en koppelcode (§3.3), tokenformaten (§3.4) en de publieke sleutel van het enroll-verzoek (§3.3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from integrations.security.hubkeys import (
    ENROLLMENT_TOKEN_RE,
    SERVICE_TOKEN_RE,
    InvalidKeyError,
    enroll_jwk,
    fingerprints_equal,
    format_fingerprint,
    jwk_thumbprint,
    keyset_fingerprint,
    normalize_fingerprint,
    normalize_pairing_code,
    validate_hub_jwk,
)
from integrations.security.secrets import enroll_public_jwk, ensure_secrets, load_identity

# Contract 1.2 §4.5 (publieke sleutels; alleen voor tests)
JWT_X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"  # RFC 8037 A.1
JWT_TP = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
POLICY_X = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
POLICY_TP = "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y"
JWT2_X = "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc"
JWT2_TP = "AkXIZFzonb59ZmGwyKgi3H3BwMi6amevqdKQiLZhdtc"


def _jwk(x: str) -> dict[str, str]:
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def test_thumbprint_vectors() -> None:
    assert jwk_thumbprint(_jwk(JWT_X)) == JWT_TP
    assert jwk_thumbprint(_jwk(POLICY_X)) == POLICY_TP
    assert jwk_thumbprint(_jwk(JWT2_X)) == JWT2_TP
    # extra velden (kid/use/alg) tellen niet mee in de thumbprint
    assert jwk_thumbprint({**_jwk(JWT_X), "kid": "x", "use": "sig", "alg": "EdDSA"}) == JWT_TP


def test_keyset_fingerprint_vectors() -> None:
    assert keyset_fingerprint([_jwk(JWT_X)], [_jwk(POLICY_X)]) == "MEGG-8GFG-2E4Y-K2RQ"
    two = keyset_fingerprint([_jwk(JWT_X), _jwk(JWT2_X)], [_jwk(POLICY_X)])
    assert two == "CYRC-JS8C-14AN-JR17"
    # volgorde van jwks.keys maakt niet uit (gesorteerd op bytewaarde van de thumbprint)
    assert keyset_fingerprint([_jwk(JWT2_X), _jwk(JWT_X)], [_jwk(POLICY_X)]) == two


@pytest.mark.parametrize(
    "given",
    ["MEGG-8GFG-2E4Y-K2RQ", "megg8gfg2e4yk2rq", "MEGG 8GFG 2E4Y K2RQ", "MEGG-8GFG-2E4Y-K2RQ ", "megg-8gfg-2e4y-k2rq"],
)
def test_fingerprint_normalisation(given: str) -> None:
    assert fingerprints_equal(given, "MEGG-8GFG-2E4Y-K2RQ")
    assert format_fingerprint(given) == "MEGG-8GFG-2E4Y-K2RQ"


def test_fingerprint_o_i_l_mapping_and_rejects() -> None:
    # O→0, I/L→1 (de vingerafdruk kent geen O/I/L)
    assert normalize_fingerprint("0000-1111-0000-1111") == "0000111100001111"
    assert normalize_fingerprint("OOOO-IIII-oooo-llll") == "0000111100001111"
    for bad in (None, "", "MEGG-8GFG-2E4Y", "MEGG-8GFG-2E4Y-K2RQ-XXXX", "U" * 16, "x" * 100):
        assert normalize_fingerprint(bad) is None
    assert not fingerprints_equal(None, "MEGG-8GFG-2E4Y-K2RQ")
    assert not fingerprints_equal("CYRC-JS8C-14AN-JR17", "MEGG-8GFG-2E4Y-K2RQ")


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("ABCD-EFGH-JKMN", "ABCD-EFGH-JKMN"),
        ("abcd efgh jkmn", "ABCD-EFGH-JKMN"),
        ("KOPP-ELCO-DE42", "K0PP-E1C0-DE42"),
        ("abcdefghjkmn", "ABCD-EFGH-JKMN"),
        ("ABCD-EFGH-JKM", None),  # 11 tekens
        ("ABCD-EFGH-JKMNP", None),  # 13 tekens
        ("ABCD-EFGH-JKMU", None),  # U zit niet in Crockford
        ("A" * 33, None),  # > 32 tekens invoer
        ("", None),
    ],
)
def test_pairing_code_normalisation(given: str, expected: str | None) -> None:
    assert normalize_pairing_code(given) == expected


def test_token_formats() -> None:
    assert ENROLLMENT_TOKEN_RE.match("enr_" + "A" * 43)
    assert not ENROLLMENT_TOKEN_RE.match("enr_" + "A" * 42)
    assert not ENROLLMENT_TOKEN_RE.match("enr_" + "A" * 42 + "=")
    assert SERVICE_TOKEN_RE.match("svc_" + "-_aZ09" * 7 + "x")
    assert not SERVICE_TOKEN_RE.match("svc-" + "a" * 43)


def test_enroll_jwk_has_exactly_kty_crv_x_kid(tmp_path: Path) -> None:
    """§3.3 / A7: ``public_key_jwk`` alleen ``{kty, crv, x, kid}`` met ``kid`` = RFC 7638-thumbprint; geen
    ``use``/``alg``/``d`` (de Hub weigert die in 1.2 met 422)."""
    ensure_secrets(tmp_path)
    jwk = enroll_public_jwk(load_identity(tmp_path))
    assert set(jwk) == {"kty", "crv", "x", "kid"}
    assert jwk["kid"] == jwk_thumbprint(jwk) and len(jwk["x"]) == 43
    assert enroll_jwk(load_identity(tmp_path).public_key()) == jwk


def test_validate_hub_jwk() -> None:
    good = {**_jwk(JWT_X), "kid": "k1", "use": "sig", "alg": "EdDSA"}
    assert validate_hub_jwk(good) == {**_jwk(JWT_X), "kid": "k1"}
    for bad in (
        {**good, "use": "enc"},
        {**good, "alg": "RS256"},
        {k: v for k, v in good.items() if k != "kid"},
        {**good, "kid": ""},
        {**good, "d": "geheim"},  # privé-deel
        {**good, "crv": "X25519"},
        {**good, "x": JWT_X + "A"},
        {**good, "x": JWT_X[:-1] + "p"},  # niet-canonieke base64url
        "geen object",
    ):
        with pytest.raises(InvalidKeyError):
            validate_hub_jwk(bad)
