"""Unit: B13-001-regels — LAN/VPN-bereiken, noodtoegang beoordelen (zonder Authentik), herstelstatus, herstelkit."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from integrations.domains.sso import recovery
from integrations.domains.sso.kit import KitError, decrypt_kit, encrypt_kit
from integrations.domains.sso.models import SSO_INDEPENDENT_METHODS

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
PASS = "lange wachtwoordzin voor de kluis 2026"


# ------------------------------------------------------------------ bereiken
@pytest.mark.parametrize(
    "cidr",
    ["192.168.1.0/24", "10.0.0.0/8", "172.16.5.0/24", "100.64.0.0/10", "100.100.1.5/32", "fd7a:115c:a1e0::/48"],
)
def test_private_scopes_accepted(cidr: str) -> None:
    assert recovery.validate_scopes([{"cidr": cidr, "kind": "lan"}])[0]["cidr"]


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "8.8.8.0/24", "203.0.113.0/24", "::/0", "2001:db8::/32", "127.0.0.1/32",
                                  "169.254.0.0/16", "192.168.0.0/15", "geen-cidr"])
def test_public_or_invalid_scopes_rejected(cidr: str) -> None:
    with pytest.raises(recovery.ScopeError):
        recovery.validate_scopes([{"cidr": cidr, "kind": "vpn"}])


def test_scope_kind_and_limits() -> None:
    with pytest.raises(recovery.ScopeError):
        recovery.validate_scopes([])
    with pytest.raises(recovery.ScopeError):
        recovery.validate_scopes([{"cidr": "10.0.0.0/24", "kind": "internet"}])
    dedup = recovery.validate_scopes([{"cidr": "10.0.0.1/24", "kind": "lan"}, {"cidr": "10.0.0.0/24", "kind": "lan"}])
    assert dedup == [{"cidr": "10.0.0.0/24", "kind": "lan"}]


# ------------------------------------------------------------------ beoordelen
def _eval(ip: str, **kw: object) -> recovery.Evaluation:
    base: dict = {"account_status": "actief", "is_break_glass": True, "login_kind": "lokaal", "policy_status": "actief",
                  "scopes": [{"cidr": "192.168.10.0/24", "kind": "lan"}, {"cidr": "100.64.0.0/10", "kind": "vpn"}],
                  "session_max_minutes": 60}
    base.update(kw)
    return recovery.evaluate_access(**base, client_ip=ip)


def test_evaluate_inside_lan_and_vpn() -> None:
    lan = _eval("192.168.10.20")
    assert lan.allowed and lan.matched_scope == "192.168.10.0/24" and lan.session_max_minutes == 60
    assert _eval("100.101.102.103").allowed
    assert lan.to_dict()["authenticator_required"] is False


@pytest.mark.parametrize(
    ("ip", "kw", "code"),
    [
        ("203.0.113.10", {}, "buiten_bereik"),
        ("192.168.11.5", {}, "buiten_bereik"),
        ("192.168.10.5", {"account_status": "uitgeschakeld"}, "account_uitgeschakeld"),
        ("192.168.10.5", {"is_break_glass": False}, "geen_noodaccount"),
        ("192.168.10.5", {"login_kind": "sso"}, "alleen_sso"),
        ("192.168.10.5", {"policy_status": "ingetrokken"}, "geen_noodtoegang"),
        ("192.168.10.5", {"policy_status": None, "scopes": None}, "geen_noodtoegang"),
        ("niet-een-ip", {}, "ongeldig_ip"),
    ],
)
def test_evaluate_denials(ip: str, kw: dict, code: str) -> None:
    ev = _eval(ip, **kw)
    assert not ev.allowed and code in [r["code"] for r in ev.reasons] and ev.session_max_minutes is None


def test_probe_addresses() -> None:
    assert recovery.probe_addresses([{"cidr": "192.168.10.0/24", "kind": "lan"}]) == ("192.168.10.1", "203.0.113.10")
    assert recovery.probe_addresses([{"cidr": "100.100.1.5/32", "kind": "vpn"}]) == ("100.100.1.5", "203.0.113.10")
    assert recovery.probe_addresses([{"cidr": "fd00::/64", "kind": "vpn"}])[1] == "2001:db8::10"


# ------------------------------------------------------------------ herstelstatus
def _account(**kw: object) -> recovery.AccountView:
    base: dict = {
        "id": "a1", "system": "hub_local", "username": "nood", "status": "actief", "is_break_glass": True,
        "login_kind": "lokaal", "mfa_status": "bevestigd",
        "methods": [{"method_type": "lokaal_wachtwoord_lan", "status": "actief"},
                    {"method_type": "verzegelde_envelop", "status": "actief"}],
        "emergency": {"status": "actief", "scopes": [{"cidr": "192.168.10.0/24", "kind": "lan"}],
                      "last_reviewed_at": NOW - timedelta(days=10), "review_interval_days": 90},
        "drills": [{"mode": "handmatig", "outcome": "ok", "performed_at": NOW - timedelta(days=5)}],
    }
    base.update(kw)
    return recovery.AccountView(**base)


def _codes(acc: recovery.AccountView) -> list[str]:
    return [r["code"] for r in recovery.evaluate_account(acc, NOW, 90).reasons]


def test_fully_prepared_account_is_ok() -> None:
    assert recovery.evaluate_account(_account(), NOW, 90).level == "ok"


@pytest.mark.parametrize(
    ("kw", "code"),
    [
        ({"methods": [{"method_type": "lokaal_wachtwoord_lan", "status": "actief"}]}, "minder_dan_twee_herstelmethodes"),
        ({"methods": [{"method_type": "authentik_herstelsleutel", "status": "actief"},
                      {"method_type": "lokaal_wachtwoord_lan", "status": "ingetrokken"}]}, "alleen_sso_afhankelijk"),
        ({"mfa_status": "niet_ingesteld"}, "mfa_niet_ingesteld"),
        ({"emergency": None}, "geen_noodtoegang"),
        ({"emergency": {"status": "actief", "scopes": [], "last_reviewed_at": NOW - timedelta(days=200),
                        "review_interval_days": 90}}, "herbevestiging_verlopen"),
        ({"drills": []}, "nooit_handmatig_geoefend"),
        ({"drills": [{"mode": "zelftest", "outcome": "ok", "performed_at": NOW}]}, "nooit_handmatig_geoefend"),
        ({"drills": [{"mode": "handmatig", "outcome": "ok", "performed_at": NOW - timedelta(days=120)}]},
         "oefening_verouderd"),
        ({"drills": [{"mode": "handmatig", "outcome": "ok", "performed_at": NOW - timedelta(days=9)},
                     {"mode": "handmatig", "outcome": "mislukt", "performed_at": NOW - timedelta(days=1)}]},
         "laatste_oefening_mislukt"),
        ({"open_rotations": 1}, "rotatie_na_gebruik_vereist"),
    ],
)
def test_risk_reasons(kw: dict, code: str) -> None:
    acc = _account(**kw)
    assert code in _codes(acc)
    assert recovery.evaluate_account(acc, NOW, 90).level == "risico"


def test_unknown_mfa_is_unknown_not_green() -> None:
    res = recovery.evaluate_account(_account(mfa_status="onbekend"), NOW, 90)
    assert res.level == "onbekend"


def test_review_soon_is_warning_only() -> None:
    acc = _account(emergency={"status": "actief", "scopes": [], "last_reviewed_at": NOW - timedelta(days=85),
                              "review_interval_days": 90})
    res = recovery.evaluate_account(acc, NOW, 90)
    assert res.level == "ok" and "herbevestiging_binnenkort" in [r["code"] for r in res.reasons]


def test_overall_levels() -> None:
    empty = recovery.evaluate_overall([], NOW, 90)
    assert empty["level"] == "onbekend" and empty["reasons"][0]["code"] == "geen_beheeraccounts"
    only_sso = recovery.evaluate_overall([_account(is_break_glass=False, login_kind="sso", system="authentik")], NOW, 90)
    codes = [r["code"] for r in only_sso["reasons"]]
    assert only_sso["level"] == "risico" and "geen_noodaccount" in codes and "geen_lokale_hub_admin" in codes
    good = recovery.evaluate_overall([_account()], NOW, 90)
    assert good["level"] == "ok" and good["counts"] == {"accounts": 1, "ok": 1, "risico": 0, "onbekend": 0}
    assert recovery.LEVEL_TO_HEALTH[good["level"]] == "healthy"


def test_sso_independence_is_derived() -> None:
    assert "authentik_herstelsleutel" not in SSO_INDEPENDENT_METHODS
    assert {"lokaal_wachtwoord_lan", "truenas_console", "verzegelde_envelop"} <= SSO_INDEPENDENT_METHODS


# ------------------------------------------------------------------ herstelkit
def test_kit_roundtrip_and_failures() -> None:
    kit = encrypt_kit({"register": {"accounts": [{"username": "nood"}]}}, PASS)
    assert kit["format"] == "hch-herstelkit/1" and "nood" not in str(kit)
    assert decrypt_kit(kit, PASS)["register"]["accounts"][0]["username"] == "nood"
    with pytest.raises(KitError):
        decrypt_kit(kit, PASS + "x")
    tampered = {**kit, "ciphertext": kit["ciphertext"][:-4] + "AAAA"}
    with pytest.raises(KitError):
        decrypt_kit(tampered, PASS)
    with pytest.raises(KitError):
        decrypt_kit({**kit, "kdf": {**kit["kdf"], "n": 2}}, PASS)


@pytest.mark.parametrize("weak", ["kort", "aaaaaaaaaaaaaaaaaaaa", "x" * 2000])
def test_kit_weak_passphrase(weak: str) -> None:
    with pytest.raises(KitError):
        encrypt_kit({}, weak)
