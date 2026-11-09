"""Inventaris B13 en de SSO-dekkingsmatrix (structuur voor B13-003).

Geen enkele app staat als "ondersteunt OIDC" tot de officiële documentatie van de gepinde versie is bekeken én het op
een echte installatie is getest (B13-003: "MediaGuard/MSO/my_house niet aannemen dat OIDC bestaat").
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from .. import SourceSpec, cap

SOURCES: tuple[SourceSpec, ...] = (
    SourceSpec(
        source_id="authentik",
        domain="sso",
        display_name="Authentik",
        role_nl="Centrale OIDC-authenticatie waar apps dat echt ondersteunen; nooit single point of failure.",
        owner_nl="Authentik is eigenaar van zijn gebruikers, providers en sessies; deze dienst leest en registreert.",
        install_doc="I09",
        install_method="catalog_app",
        upstream="https://github.com/goauthentik/authentik",
        required_decisions=("D03", "D17"),
        api_verification="te_verifieren",
        capabilities=(
            cap(
                "sso.recovery.register",
                "Herstelregister beheeraccounts (zonder geheimen)",
                "read",
                ("B13-001",),
                build_status="gebouwd",
            ),
            cap(
                "sso.break_glass.drill",
                "Noodtoegang oefenen, ook met Authentik offline",
                "read",
                ("B13-001",),
                build_status="gebouwd",
            ),
            cap(
                "sso.authentik.health.read",
                "Bereikbaarheid van Authentik (liveness-probe)",
                "read",
                ("B13-001",),
                build_status="gebouwd",
                notes_nl="Probe-pad te verifiëren tegen de Authentik-docs van de gepinde versie.",
            ),
            cap("sso.users.read", "Gebruikers, groepen en sessies uit Authentik", "read", ("B13-004",)),
            cap("sso.oidc.hub", "OIDC Authorization Code + PKCE voor de Hub", "read", ("B13-002",)),
            cap("sso.access.revoke", "Toegang intrekken en sessies beëindigen", "apply", ("B13-004", "B13-005"), "R2"),
        ),
        probe_path="/-/health/live/",
        notes_nl="Installatie via de officiële TrueNAS-catalogusapp waar die bestaat (versie vastgezet); D17 vereist.",
        forbidden_nl=(
            "Authentik-admin nooit publiek; alleen LAN/VPN (I21 stap 2).",
            "Geen automatische toegang via een onbeveiligde X-Forwarded-User-header (B13-003).",
        ),
    ),
)

OidcSupport = Literal["te_verifieren", "ondersteund", "niet_ondersteund", "gepland"]


@dataclass(frozen=True)
class AppSsoCoverage:
    app_id: str
    display_name: str
    oidc_support: OidcSupport
    trusted_header_support: Literal["te_verifieren", "n.v.t."]
    current_login: str
    where_to_verify: str
    notes_nl: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Alles 'te_verifieren' of 'gepland' (eigen platformcode die nog gebouwd moet worden). Nooit 'ondersteund' zonder bewijs.
APP_COVERAGE: tuple[AppSsoCoverage, ...] = (
    AppSsoCoverage(
        "ai-server-manager",
        "Hub",
        "gepland",
        "n.v.t.",
        "lokaal account (argon2id)",
        "eigen code: B13-002",
        "OIDC voor de Hub is werkpakket B13-002; lokaal account blijft altijd.",
    ),
    AppSsoCoverage(
        "mediaguard",
        "MediaGuard",
        "te_verifieren",
        "te_verifieren",
        "eigen login",
        "repo lvos04/media-guard-ultimate (delta-matrix)",
    ),
    AppSsoCoverage(
        "media-source-optimizer",
        "Media Source Optimizer",
        "te_verifieren",
        "te_verifieren",
        "eigen login",
        "repo lvos04/media-source-optimizer (delta-matrix)",
    ),
    AppSsoCoverage(
        "my_house", "my_house", "te_verifieren", "te_verifieren", "eigen login", "repo lvos04/my_house (delta-matrix)"
    ),
    AppSsoCoverage(
        "jelly-leon",
        "Jelly Leon (Jellyfin-fork)",
        "te_verifieren",
        "te_verifieren",
        "eigen login",
        "officiële Jellyfin-docs + fork lvos04/jelly-leon",
    ),
    AppSsoCoverage(
        "immich",
        "Immich",
        "te_verifieren",
        "te_verifieren",
        "eigen login",
        "officiële Immich-docs (https://github.com/immich-app/immich)",
    ),
    AppSsoCoverage(
        "node-red",
        "Node-RED",
        "te_verifieren",
        "te_verifieren",
        "adminAuth (eigen)",
        "officiële Node-RED-docs (https://github.com/node-red/node-red)",
    ),
    AppSsoCoverage(
        "adguard-home",
        "AdGuard Home",
        "te_verifieren",
        "te_verifieren",
        "eigen login",
        "officiële AdGuard Home-docs (https://github.com/AdguardTeam/AdGuardHome)",
    ),
    AppSsoCoverage(
        "netalertx",
        "NetAlertX",
        "te_verifieren",
        "te_verifieren",
        "eigen login",
        "officiële NetAlertX-docs (https://github.com/netalertx/NetAlertX)",
    ),
    AppSsoCoverage(
        "truenas",
        "TrueNAS-web-UI",
        "te_verifieren",
        "n.v.t.",
        "lokaal TrueNAS-account",
        "officiële TrueNAS-docs voor de versie uit D01",
        "TrueNAS-beheer blijft alleen LAN/VPN, ook met SSO.",
    ),
)
