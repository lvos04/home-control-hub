"""B13-001 — deterministische regels voor beheerherstel en noodtoegang (geen I/O, geen Authentik).

Alles hier werkt zonder SSO/Authentik: zo blijft noodtoegang testbaar als de authenticator offline is.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from ...timeutil import ensure_aware
from .models import SSO_INDEPENDENT_METHODS

IpNet = ipaddress.IPv4Network | ipaddress.IPv6Network

# Alleen privé-bereiken: LAN (RFC 1918), CGNAT 100.64/10 (o.a. Tailscale) en IPv6 ULA fc00::/7.
ALLOWED_PRIVATE_NETS: tuple[IpNet, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
)
MAX_SCOPES = 16
# Tegentest in de zelftest: documentatie-adressen (RFC 5737 / RFC 3849), nooit een echt adres.
PUBLIC_PROBE_V4 = ipaddress.ip_address("203.0.113.10")
PUBLIC_PROBE_V6 = ipaddress.ip_address("2001:db8::10")

CRITICAL_SYSTEMS = frozenset({"hub_local", "authentik", "truenas"})
Level = Literal["ok", "risico", "onbekend"]


class ScopeError(ValueError):
    """Ongeldig netwerkbereik; boodschap is Nederlands."""


def validate_scopes(raw: list[dict[str, Any]]) -> list[dict[str, str]]:
    if not raw:
        raise ScopeError("Geef minstens één LAN- of VPN-bereik op (CIDR).")
    if len(raw) > MAX_SCOPES:
        raise ScopeError(f"Maximaal {MAX_SCOPES} bereiken.")
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw:
        kind = str(item.get("kind", "")).strip()
        if kind not in ("lan", "vpn"):
            raise ScopeError("Soort bereik moet 'lan' of 'vpn' zijn.")
        cidr = str(item.get("cidr", "")).strip()
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ScopeError(f"'{cidr}' is geen geldig netwerkbereik (CIDR).") from exc
        if not any(net.version == allowed.version and net.subnet_of(allowed) for allowed in ALLOWED_PRIVATE_NETS):  # type: ignore[arg-type]
            raise ScopeError(
                f"'{net}' is geen privé-LAN/VPN-bereik. Noodtoegang mag nooit vanaf internet: gebruik een bereik binnen "
                "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 of fc00::/7."
            )
        key = str(net)
        if key in seen:
            continue
        seen.add(key)
        out.append({"cidr": key, "kind": kind})
    return out


@dataclass
class Evaluation:
    allowed: bool
    reasons: list[dict[str, str]]
    matched_scope: str | None = None
    session_max_minutes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reasons": self.reasons,
            "matched_scope": self.matched_scope,
            "session_max_minutes": self.session_max_minutes,
            "authenticator_required": False,
        }


def _reason(code: str, message_nl: str, severity: str = "risico") -> dict[str, str]:
    return {"code": code, "message_nl": message_nl, "severity": severity}


def evaluate_access(
    *,
    account_status: str,
    is_break_glass: bool,
    login_kind: str,
    policy_status: str | None,
    scopes: list[dict[str, str]] | None,
    session_max_minutes: int | None,
    client_ip: str,
) -> Evaluation:
    """Mag dit noodaccount vanaf ``client_ip`` de noodtoegang gebruiken? Raadpleegt nooit Authentik."""
    reasons: list[dict[str, str]] = []
    try:
        ip = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return Evaluation(False, [_reason("ongeldig_ip", "Het client-IP-adres is ongeldig.")])
    if account_status != "actief":
        reasons.append(_reason("account_uitgeschakeld", "Het account is uitgeschakeld."))
    if not is_break_glass:
        reasons.append(_reason("geen_noodaccount", "Dit account is niet als noodaccount geregistreerd."))
    if login_kind == "sso":
        reasons.append(_reason("alleen_sso", "Dit account kan alleen via SSO inloggen; dat is geen noodtoegang."))
    if policy_status != "actief" or not scopes:
        reasons.append(_reason("geen_noodtoegang", "Er is geen actieve noodtoegang (LAN/VPN-bereik) geregistreerd."))
    matched: str | None = None
    for scope in scopes or []:
        net = ipaddress.ip_network(scope["cidr"], strict=False)
        if ip.version == net.version and ip in net:
            matched = scope["cidr"]
            break
    if scopes and matched is None:
        reasons.append(_reason("buiten_bereik", "Het adres valt buiten de geregistreerde LAN/VPN-bereiken."))
    allowed = not reasons
    return Evaluation(allowed, reasons, matched, session_max_minutes if allowed else None)


def probe_addresses(scopes: list[dict[str, str]]) -> tuple[str, str]:
    """Een adres binnen het eerste bereik en een publiek documentatie-adres van dezelfde IP-versie (zelftest)."""
    net = ipaddress.ip_network(scopes[0]["cidr"], strict=False)
    inside = net.network_address + 1 if net.num_addresses > 2 else net.network_address
    outside = PUBLIC_PROBE_V4 if net.version == 4 else PUBLIC_PROBE_V6
    return str(inside), str(outside)


# ------------------------------------------------------------------ gereedheid (herstelstatus)
@dataclass
class AccountView:
    id: str
    system: str
    username: str
    status: str
    is_break_glass: bool
    login_kind: str
    mfa_status: str
    methods: list[dict[str, Any]] = field(default_factory=list)  # {method_type, status}
    emergency: dict[str, Any] | None = None  # {status, scopes, last_reviewed_at, review_interval_days}
    drills: list[dict[str, Any]] = field(default_factory=list)  # {mode, outcome, performed_at}
    open_rotations: int = 0


@dataclass
class Readiness:
    level: Level
    reasons: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {"level": self.level, "reasons": self.reasons}


def evaluate_account(acc: AccountView, now: datetime, drill_max_age_days: int) -> Readiness:
    reasons: list[dict[str, str]] = []
    active_methods = [m for m in acc.methods if m.get("status") == "actief"]
    if len(active_methods) < 2:
        reasons.append(_reason("minder_dan_twee_herstelmethodes", "Minder dan twee actieve herstelmethodes."))
    if not any(m["method_type"] in SSO_INDEPENDENT_METHODS for m in active_methods):
        reasons.append(_reason("alleen_sso_afhankelijk", "Geen herstelmethode die zonder SSO/Authentik werkt."))
    if acc.system in CRITICAL_SYSTEMS:
        if acc.mfa_status == "niet_ingesteld":
            reasons.append(_reason("mfa_niet_ingesteld", "MFA is niet ingesteld."))
        elif acc.mfa_status == "onbekend":
            reasons.append(_reason("mfa_onbekend", "MFA-status is niet bevestigd.", "onbekend"))
    if acc.is_break_glass:
        em = acc.emergency
        if not em or em.get("status") != "actief":
            reasons.append(_reason("geen_noodtoegang", "Noodaccount zonder actieve LAN/VPN-noodtoegang."))
        else:
            due = ensure_aware(em["last_reviewed_at"]) + timedelta(days=int(em["review_interval_days"]))
            if due < now:
                reasons.append(_reason("herbevestiging_verlopen", "De noodtoegang is niet tijdig herbevestigd."))
            elif due - now < timedelta(days=7):
                reasons.append(
                    _reason("herbevestiging_binnenkort", "Herbevestig de noodtoegang binnen 7 dagen.", "let_op")
                )
    if acc.open_rotations:
        reasons.append(
            _reason(
                "rotatie_na_gebruik_vereist", "Noodtoegang is echt gebruikt; roteer het wachtwoord en bevestig dat."
            )
        )
    manual = sorted(
        (d for d in acc.drills if d.get("mode") == "handmatig"),
        key=lambda d: ensure_aware(d["performed_at"]),
        reverse=True,
    )
    if not manual:
        reasons.append(_reason("nooit_handmatig_geoefend", "Herstel is nog nooit handmatig geoefend."))
    else:
        last = manual[0]
        if last.get("outcome") != "ok":
            reasons.append(_reason("laatste_oefening_mislukt", "De laatste handmatige oefening is mislukt."))
        elif now - ensure_aware(last["performed_at"]) > timedelta(days=drill_max_age_days):
            reasons.append(
                _reason("oefening_verouderd", f"De laatste geslaagde oefening is ouder dan {drill_max_age_days} dagen.")
            )
    return Readiness(_level(reasons), reasons)


def _level(reasons: list[dict[str, str]]) -> Level:
    severities = {r["severity"] for r in reasons}
    if "risico" in severities:
        return "risico"
    if "onbekend" in severities:
        return "onbekend"
    return "ok"


def evaluate_overall(accounts: list[AccountView], now: datetime, drill_max_age_days: int) -> dict[str, Any]:
    active = [a for a in accounts if a.status == "actief"]
    per_account = {a.id: evaluate_account(a, now, drill_max_age_days) for a in active}
    reasons: list[dict[str, str]] = []
    if not active:
        reasons.append(
            _reason("geen_beheeraccounts", "Er zijn nog geen beheeraccounts in het herstelregister.", "onbekend")
        )
    elif not any(a.is_break_glass and a.login_kind != "sso" for a in active):
        reasons.append(
            _reason("geen_noodaccount", "Geen noodaccount dat zonder SSO kan inloggen: risico op SSO-only lock-out.")
        )
    if active and not any(a.system == "hub_local" and a.login_kind != "sso" for a in active):
        reasons.append(_reason("geen_lokale_hub_admin", "Geen lokaal Hub-beheeraccount (onafhankelijk van SSO)."))
    levels = [r.level for r in per_account.values()]
    level: Level = _level(reasons)
    if level != "risico":
        if "risico" in levels:
            level = "risico"
        elif "onbekend" in levels and level == "ok":
            level = "onbekend"
    return {
        "level": level,
        "reasons": reasons,
        "accounts": {k: v.to_dict() for k, v in per_account.items()},
        "counts": {
            "accounts": len(active),
            "ok": levels.count("ok"),
            "risico": levels.count("risico"),
            "onbekend": levels.count("onbekend"),
        },
    }


LEVEL_TO_HEALTH = {"ok": "healthy", "risico": "degraded", "onbekend": "unknown"}
