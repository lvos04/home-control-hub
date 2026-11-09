"""Inventaris B13 en de SSO-dekkingsmatrix (B13-003).

Een app staat alleen op "ondersteund" als een officiële bron (docs) of de broncode dat zegt — met URL, versie/commit en
datum. Dat is géén test op een echte installatie: die bevestigt een beheerder per app na een testlogin
(``sso_app_setting.installation_check``). MediaGuard/MSO/my_house: niet aangenomen, in de broncode gecontroleerd.
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
        owner_nl="Authentik is eigenaar van zijn gebruikers, providers en sessies; deze dienst leest, stelt voor en "
        "registreert (schrijven pas met een door de Hub ondertekend ExecutionRequest, P2).",
        install_doc="I09",
        install_method="catalog_app",
        upstream="https://github.com/goauthentik/authentik",
        required_decisions=("D03", "D17"),
        api_verification="geverifieerd_docs",
        api_verification_ref="officiële schema.yml per release-lijn 2024.10–2026.8 (docs/b13/authentik-api-verificatie.json)",
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
                notes_nl="Pad /-/health/live/ staat in authentik/root/urls.py (tag version/2026.8.5).",
            ),
            cap(
                "sso.authentik.detect",
                "Versiedetectie, API-capabilities en least-privilege-controle van het token",
                "read",
                ("B13-002", "B13-004"),
                build_status="gebouwd",
            ),
            cap(
                "sso.oidc.hub.propose",
                "Voorstel OIDC-provider + applicatie voor de Hub (preview/diff/preview_hash)",
                "propose",
                ("B13-002",),
                "R2",
                build_status="gebouwd",
            ),
            cap(
                "sso.oidc.hub.check",
                "Controle van een bestaande Hub-client (alleen lezen)",
                "read",
                ("B13-002",),
                build_status="gebouwd",
            ),
            cap(
                "sso.oidc.hub.apply",
                "Voorstel toepassen in Authentik",
                "apply",
                ("B13-002",),
                "R2",
                notes_nl="Vereist een door de Hub ondertekend ExecutionRequest (contract §8); komt in P2.",
            ),
            cap("sso.app_mapping", "SSO-dekking per app en groep → rol", "read", ("B13-003",), build_status="gebouwd"),
            cap(
                "sso.rights.read",
                "Rechtenkaart (gebruikers, groepen, rollen) met verschillen",
                "read",
                ("B13-004",),
                build_status="gebouwd",
            ),
            cap(
                "sso.audit.events",
                "Logins en wijzigingen lezen, afwijkingen als events",
                "stream",
                ("B13-004",),
                build_status="gebouwd",
            ),
            cap(
                "sso.config.export",
                "Geschoonde configuratie-export (API + flow-blueprints)",
                "read",
                ("B13-005",),
                build_status="gebouwd",
            ),
            cap(
                "sso.upgrade.gate",
                "Pre-upgrade-gate (versiepad, export, back-up, noodtoegang)",
                "read",
                ("B13-005",),
                build_status="gebouwd",
            ),
            cap(
                "sso.restore.check",
                "Herstelcheck: rechten, MFA, providers na herstel",
                "read",
                ("B13-005",),
                build_status="gebouwd",
            ),
            cap(
                "sso.sessions.revoke.propose",
                "Voorstel sessies intrekken",
                "propose",
                ("B13-005",),
                "R2",
                build_status="gebouwd",
            ),
            cap(
                "sso.access.revoke",
                "Toegang intrekken en sessies beëindigen (uitvoeren)",
                "apply",
                ("B13-004", "B13-005"),
                "R2",
                notes_nl="Uitvoeren vereist een door de Hub ondertekend ExecutionRequest (P2).",
            ),
        ),
        probe_path="/-/health/live/",
        probe_path_verified=True,
        notes_nl="Installatie via de officiële TrueNAS-catalogusapp 'authentik' (trein community; op 2026-11-09 "
        "catalogusversie 1.3.63 met app_version 2026.8.5, te verifiëren bij installatie). 'Mount Docker Socket' moet "
        "UIT blijven (geen Docker-socket in containers). D17 (domein/HTTPS) vereist.",
        forbidden_nl=(
            "Authentik-admin nooit publiek; alleen LAN/VPN (I21 stap 2).",
            "Geen automatische toegang via een onbeveiligde X-Forwarded-User-header (B13-003).",
            "Catalogusoptie 'Mount Docker Socket' nooit aanzetten (geen Docker-socket in containers).",
            "Geen downgrade van Authentik; herstel alleen via back-up (officiële upgradedocs).",
        ),
    ),
)

OidcSupport = Literal["ondersteund", "ondersteund_met_voorwaarden", "niet_ondersteund", "gepland", "te_verifieren"]
SourceKind = Literal["officiele_docs", "broncode", "eigen_plan"]
SourceVerification = Literal["geverifieerd_docs", "geverifieerd_broncode", "te_verifieren", "n.v.t."]
CHECKED_ON = "2026-11-09"


@dataclass(frozen=True)
class SupportSource:
    kind: SourceKind
    url: str
    ref: str  # versie, commit of datum van de gelezen bron
    verification: SourceVerification
    checked_on: str = CHECKED_ON
    quote_nl: str = ""  # korte samenvatting van wat de bron zegt


@dataclass(frozen=True)
class AppSsoCoverage:
    """B13-003: per app of OIDC **echt** ondersteund wordt (met bron), anders blijft de eigen login.

    Vertrouwde-header-SSO (X-Forwarded-User e.d.) is voor elke app ``niet_toegestaan``: zonder gecontroleerde
    proxy-inrichting kan iedereen op het LAN die headers zetten (B13-003-acceptatie).
    """

    app_id: str
    display_name: str
    oidc_support: OidcSupport
    native_login: str
    source: SupportSource
    roles: tuple[str, ...] = ()
    role_claim_nl: str = ""
    conditions_nl: str = ""
    trusted_header_sso: Literal["niet_toegestaan"] = "niet_toegestaan"

    @property
    def mapping_allowed(self) -> bool:
        """Groep→rol-koppelingen alleen voor apps die OIDC (gaan) ondersteunen."""
        return self.oidc_support in ("ondersteund", "ondersteund_met_voorwaarden", "gepland") and bool(self.roles)

    @property
    def oidc_allowed(self) -> bool:
        """Loginroute 'oidc' kiezen mag alleen als de bron het (met voorwaarden) bevestigt."""
        return self.oidc_support in ("ondersteund", "ondersteund_met_voorwaarden")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["roles"] = list(self.roles)
        d["mapping_allowed"] = self.mapping_allowed
        d["oidc_allowed"] = self.oidc_allowed
        return d


HUB_ROLES = ("admin", "operator", "viewer", "kind")

# Bronnen gelezen op 2026-11-09. 'geverifieerd_*' betekent: in de genoemde bron gelezen — NIET op een echte installatie
# getest (dat is per app een handmatige bevestiging na een testlogin, zie sso_app_setting).
APP_COVERAGE: tuple[AppSsoCoverage, ...] = (
    AppSsoCoverage(
        "ai-server-manager",
        "Hub",
        "gepland",
        "lokaal account (argon2id) + noodlogin",
        SupportSource(
            "eigen_plan",
            "docs/platform-v2/02_BOUWPLANNEN/B13_AUTHENTIK_SSO.md (B13-002); lvos04/ai-server-manager "
            "apps/api/src/hub/routers/auth.py",
            "ai-server-manager@40850dc",
            "n.v.t.",
            quote_nl="De Hub heeft nu alleen een lokaal account; OIDC-login is werk in ai-server-manager (B13-002).",
        ),
        roles=HUB_ROLES,
        role_claim_nl="claim 'groups' (scope profile) → Hub-rol via de groep→rol-koppeling van deze dienst",
        conditions_nl="Lokaal account en noodlogin blijven altijd (B13-001); OIDC is een extra route.",
    ),
    AppSsoCoverage(
        "mediaguard",
        "MediaGuard",
        "niet_ondersteund",
        "eigen login (scrypt, sessie + CSRF, 2FA/TOTP)",
        SupportSource(
            "broncode",
            "lvos04/media-guard-ultimate apps/core/mediaguard/api/auth.py",
            "media-guard-ultimate@8cd3175",
            "geverifieerd_broncode",
            quote_nl="Alleen eigen login en API-sleutels; geen OIDC/OAuth in de code.",
        ),
    ),
    AppSsoCoverage(
        "media-source-optimizer",
        "Media Source Optimizer",
        "niet_ondersteund",
        "eigen login (sessie + CSRF)",
        SupportSource(
            "broncode",
            "lvos04/media-source-optimizer apps/core/mso/api/foundation.py (POST /auth/login)",
            "media-source-optimizer@4558ee4",
            "geverifieerd_broncode",
            quote_nl="Alleen eigen sessielogin; geen OIDC/OAuth in de code.",
        ),
    ),
    AppSsoCoverage(
        "my_house",
        "my_house",
        "niet_ondersteund",
        "eigen login",
        SupportSource(
            "broncode",
            "lvos04/my_house apps/api/src/shc_api/routers/auth.py (POST /login)",
            "my_house@210614b",
            "geverifieerd_broncode",
            quote_nl="Alleen eigen login en tokens; geen OIDC/OAuth in de code.",
        ),
    ),
    AppSsoCoverage(
        "jelly-leon",
        "Jelly Leon (Jellyfin-fork)",
        "niet_ondersteund",
        "eigen Jellyfin-gebruikers (+ Quick Connect)",
        SupportSource(
            "officiele_docs",
            "https://jellyfin.org/docs/general/server/users/",
            "docs gelezen 2026-11-09; fork lvos04/jelly-leon (Jellyfin 10.11.11)",
            "geverifieerd_docs",
            quote_nl="'Jellyfin users are entirely local'. SSO-plugins van derden zijn niet officieel en worden niet gebruikt.",
        ),
    ),
    AppSsoCoverage(
        "immich",
        "Immich",
        "ondersteund",
        "eigen login (blijft als terugval)",
        SupportSource(
            "officiele_docs",
            "https://docs.immich.app/administration/oauth",
            "docs gelezen 2026-11-09 (nieuwste release v3.3.6)",
            "geverifieerd_docs",
            quote_nl="Ondersteunt OpenID Connect (Authentik als voorbeeld); Role Claim 'immich_role' met 'user' of 'admin'.",
        ),
        roles=("admin", "user"),
        role_claim_nl="claim 'immich_role' (waarde 'user' of 'admin') via een scope-koppeling in Authentik",
        conditions_nl="Mobiele app vereist een extra redirect-URI (app.immich:///oauth-callback); bij installatie de "
        "docs van de gepinde versie opnieuw lezen.",
    ),
    AppSsoCoverage(
        "node-red",
        "Node-RED",
        "ondersteund_met_voorwaarden",
        "adminAuth met eigen gebruikers (bcrypt)",
        SupportSource(
            "officiele_docs",
            "https://nodered.org/docs/user-guide/runtime/securing-node-red",
            "docs gelezen 2026-11-09 (nieuwste release 5.0.9)",
            "geverifieerd_docs",
            quote_nl="'OAuth/OpenID based authentication' via een Passport-strategie in adminAuth (type 'strategy').",
        ),
        roles=("*", "read"),
        role_claim_nl="permissions in adminAuth ('*' = volledig, 'read' = alleen lezen)",
        conditions_nl="Vereist een Passport-OIDC-module en aanpassing van settings.js; of dat met de TrueNAS-"
        "catalogusapp kan is te verifiëren. Tot dan: adminAuth met eigen wachtwoord.",
    ),
    AppSsoCoverage(
        "adguard-home",
        "AdGuard Home",
        "niet_ondersteund",
        "eigen gebruikers (BCrypt) in AdGuardHome.yaml",
        SupportSource(
            "officiele_docs",
            "https://github.com/AdguardTeam/AdGuardHome/wiki/Configuration",
            "wiki gelezen 2026-11-09 (nieuwste release v0.107.80)",
            "geverifieerd_docs",
            quote_nl="Webtoegang via 'users' met BCrypt-wachtwoord; geen OIDC-instelling beschreven.",
        ),
    ),
    AppSsoCoverage(
        "netalertx",
        "NetAlertX",
        "niet_ondersteund",
        "eigen wachtwoordbeveiliging",
        SupportSource(
            "officiele_docs",
            "https://github.com/netalertx/NetAlertX/blob/main/docs/README.md",
            "docs gelezen 2026-11-09 (nieuwste release v26.10.28)",
            "geverifieerd_docs",
            quote_nl="Geen OIDC; alleen een community-concept voor Authelia via forward-auth (header-SSO, hier verboden).",
        ),
    ),
    AppSsoCoverage(
        "truenas",
        "TrueNAS-web-UI",
        "niet_ondersteund",
        "lokaal TrueNAS-account (+ OTP) of API-sleutel",
        SupportSource(
            "broncode",
            "https://github.com/truenas/middleware src/middlewared/middlewared/utils/auth.py (AuthMech)",
            "middleware master@ece9d19 (2026-11-09); versie uit D01 te verifiëren",
            "geverifieerd_broncode",
            quote_nl="Aanmeldmechanismen: API_KEY_PLAIN, PASSWORD_PLAIN, TOKEN_PLAIN, OTP_TOKEN, SCRAM — geen OIDC.",
        ),
        conditions_nl="TrueNAS-beheer blijft alleen LAN/VPN, ook met SSO elders.",
    ),
)
APP_BY_ID = {a.app_id: a for a in APP_COVERAGE}
