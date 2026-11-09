"""Authentik-versies en het API-oppervlak dat deze dienst gebruikt (B13-002…005).

Bron van waarheid: de officiële OpenAPI-schema's (``schema.yml``) per release-tag in
https://github.com/goauthentik/authentik. ``tools/authentik_schema_check.py`` controleert per release-lijn of élk pad,
elke queryparameter en elk veld uit ``USED_API`` in dat schema staat; het resultaat (met sha256 van elk schema) staat in
``docs/b13/authentik-api-verificatie.json``. Gecontroleerd op ``VERIFIED_ON``.

Regels:
- Alleen release-lijnen in ``RELEASE_LINES`` gelden als *geverifieerd*. Een nieuwere lijn is ``nieuwer_dan_geverifieerd``:
  lezen mag (met waarschuwing), voorstellen niet. Ouder dan ``MIN_LINE`` → ``te_oud``.
- Een patchversie binnen een lijn wordt als API-gelijk aan de gecontroleerde nieuwste patch beschouwd (aanname; niet per
  patch geverifieerd). Dat staat zo in de detectie-uitkomst.
- Upgradepad (officiële docs, https://docs.goauthentik.io/install-config/upgrade/, gelezen 2026-11-09): geen downgrade;
  per release-lijn upgraden, eerst naar de nieuwste patch van de huidige lijn.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

VERIFIED_ON = "2026-11-09"
SCHEMA_SOURCE = "https://raw.githubusercontent.com/goauthentik/authentik/version/{version}/schema.yml"
UPGRADE_DOCS = "https://docs.goauthentik.io/install-config/upgrade/"
BACKUP_DOCS = "https://docs.goauthentik.io/sys-mgmt/ops/backup-restore/"
OAUTH2_DOCS = "https://docs.goauthentik.io/add-secure-apps/providers/oauth2/"

# Nieuwste patch per release-lijn (git ls-remote --tags, 2026-11-09). Volgorde = upgradevolgorde.
RELEASE_LINES: tuple[tuple[int, int, int], ...] = (
    (2024, 10, 5),
    (2024, 12, 5),
    (2025, 2, 4),
    (2025, 4, 4),
    (2025, 6, 4),
    (2025, 8, 6),
    (2025, 10, 4),
    (2025, 12, 6),
    (2026, 2, 7),
    (2026, 5, 8),
    (2026, 8, 5),
)
MIN_LINE = (2024, 10)
# sha256 van het gecontroleerde schema.yml per tag (zie docs/b13/authentik-api-verificatie.json)
SCHEMA_SHA256: dict[str, str] = {
    "2024.10.5": "8cd04822fb4b70f1d7886bf2bbdd9a1fac94aada3f7edec7be55e23625a397a2",
    "2024.12.5": "d645bd2a93fa37ff654472ad64f5e8a49d1a33d464d14efd8dcdae4f5f09316b",
    "2025.2.4": "79917aed043a62f1c86b98940e886c61792fce4a704ff51c0740d6eac41a9fa2",
    "2025.4.4": "25147a40c218af7c83d0a52e5cb024ce99088c671bc57bab80e8ff5967b101a0",
    "2025.6.4": "07f2c426ea6f5e5db3907d6a9c0e00dc271a42828f7824cb3c6bcef8dd6ec237",
    "2025.8.6": "8a80360a6fb650835fee40443e1c52b6a3b97967efb8909b2d76553bb590094b",
    "2025.10.4": "1535f008f9654914108388707b67861aece56ecb314a50099ac79d496872fc2d",
    "2025.12.6": "50b9c78a4a3c2818c5acf6f2dbc80faef4c20c62901562a7a98ebb15251d153d",
    "2026.2.7": "91a195e4695d4149c1824d10af6b02c6f1492974a63bec4fd9e2b9fa9aca8207",
    "2026.5.8": "b65a9a9e1a9ed93ce088f1f3f05d42432b327b0f6c1f2c18b0743995dd8b11fa",
    "2026.8.5": "1ffe03e3650de36497946fcc2229d0d913ac46fc49236583b0bbf15f91505cfe",
}
# Kenmerken die per versie verschillen (uit dezelfde schemacontrole)
GRANT_TYPES_SINCE = (2026, 5)  # veld OAuth2Provider.grant_types
EVENTS_MULTI_ACTION_SINCE = (2025, 8)  # queryparameter ?actions=… op /events/events/

# Vaste namen uit de officiële standaard-blueprints (blueprints/system/providers-oauth2.yaml en
# blueprints/default/flow-default-provider-*.yaml, tag version/2026.8.5)
MANAGED_SCOPE_OPENID = "goauthentik.io/providers/oauth2/scope-openid"
MANAGED_SCOPE_EMAIL = "goauthentik.io/providers/oauth2/scope-email"
MANAGED_SCOPE_PROFILE = "goauthentik.io/providers/oauth2/scope-profile"  # bevat de claim 'groups'
DEFAULT_AUTHZ_FLOW = "default-provider-authorization-explicit-consent"
DEFAULT_INVALIDATION_FLOW = "default-provider-invalidation-flow"
EMBEDDED_OUTPOST_MANAGED = "goauthentik.io/outposts/embedded"
# Uit de OAuth2-docs: deze slugs botsen met de vaste endpoints onder /application/o/
RESERVED_APP_SLUGS = frozenset({"authorize", "token", "device", "userinfo", "introspect", "revoke"})

_VERSION_RE = re.compile(r"^(\d{4})\.(\d{1,2})\.(\d{1,3})$")

Support = Literal["geverifieerd", "nieuwer_dan_geverifieerd", "te_oud", "onbekende_lijn", "onleesbaar"]


@dataclass(frozen=True, order=True)
class Version:
    year: int
    minor: int
    patch: int

    @property
    def line(self) -> tuple[int, int]:
        return (self.year, self.minor)

    def __str__(self) -> str:
        return f"{self.year}.{self.minor}.{self.patch}"


def parse_version(raw: object) -> Version | None:
    """Alleen stabiele versies ``JJJJ.M.P``; release candidates en vrije tekst → ``None``."""
    if not isinstance(raw, str):
        return None
    m = _VERSION_RE.match(raw.strip())
    if not m:
        return None
    return Version(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _line_index(line: tuple[int, int]) -> int | None:
    for i, (y, mi, _p) in enumerate(RELEASE_LINES):
        if (y, mi) == line:
            return i
    return None


def latest_patch(line: tuple[int, int]) -> Version | None:
    idx = _line_index(line)
    return None if idx is None else Version(*RELEASE_LINES[idx])


@dataclass(frozen=True)
class ApiCapabilities:
    version: str | None
    support: Support
    oauth2_grant_types: bool = False
    events_multi_action_filter: bool = False
    notes_nl: tuple[str, ...] = field(default_factory=tuple)

    @property
    def readable(self) -> bool:
        """Lezen mag bij een geverifieerde of nieuwere lijn (met waarschuwing)."""
        return self.support in ("geverifieerd", "nieuwer_dan_geverifieerd")

    @property
    def proposals_allowed(self) -> bool:
        """Voorstellen (preview van schrijfacties) alleen voor geverifieerde lijnen."""
        return self.support == "geverifieerd"

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "support": self.support,
            "readable": self.readable,
            "proposals_allowed": self.proposals_allowed,
            "oauth2_grant_types": self.oauth2_grant_types,
            "events_multi_action_filter": self.events_multi_action_filter,
            "verified_on": VERIFIED_ON,
            "verified_lines": [f"{y}.{m}" for y, m, _p in RELEASE_LINES],
            "notes_nl": list(self.notes_nl),
        }


def capabilities_for(raw_version: object) -> ApiCapabilities:
    v = parse_version(raw_version)
    if v is None:
        return ApiCapabilities(
            str(raw_version) if raw_version else None,
            "onleesbaar",
            notes_nl=("Versie onleesbaar of geen stabiele release; alleen-lezen is niet veilig vast te stellen.",),
        )
    common = {
        "oauth2_grant_types": v.line >= GRANT_TYPES_SINCE,
        "events_multi_action_filter": v.line >= EVENTS_MULTI_ACTION_SINCE,
    }
    if v.line < MIN_LINE:
        return ApiCapabilities(
            str(v),
            "te_oud",
            notes_nl=(f"Ouder dan {MIN_LINE[0]}.{MIN_LINE[1]}: het OAuth2-schema wijkt af; eerst upgraden.",),
        )
    idx = _line_index(v.line)
    if idx is None:
        newest = RELEASE_LINES[-1]
        if v.line > (newest[0], newest[1]):
            return ApiCapabilities(
                str(v),
                "nieuwer_dan_geverifieerd",
                notes_nl=(
                    f"Nieuwer dan de laatst gecontroleerde lijn {newest[0]}.{newest[1]}: lezen met voorbehoud, "
                    "voorstellen pas na een nieuwe schemacontrole.",
                ),
                **common,
            )
        return ApiCapabilities(
            str(v), "onbekende_lijn", notes_nl=("Deze release-lijn staat niet in de gecontroleerde lijst.",), **common
        )
    notes: list[str] = []
    top = Version(*RELEASE_LINES[idx])
    if v.patch > top.patch:
        notes.append(f"Patch {v} is nieuwer dan de gecontroleerde {top}; aangenomen API-gelijk binnen de lijn.")
    elif v.patch < top.patch:
        notes.append(f"Patch binnen de lijn aangenomen API-gelijk aan de gecontroleerde {top}.")
    return ApiCapabilities(str(v), "geverifieerd", notes_nl=tuple(notes), **common)


# ------------------------------------------------------------------ upgradepad (B13-005)
@dataclass(frozen=True)
class UpgradePathCheck:
    status: Literal["ok", "fout", "onbekend"]
    code: str
    message_nl: str
    next_step: str | None = None


def check_upgrade_path(current: Version, target: Version) -> UpgradePathCheck:
    """Officiële regel: geen downgrade; per release-lijn; eerst de nieuwste patch van de huidige lijn."""
    if target < current:
        return UpgradePathCheck(
            "fout", "downgrade", "Authentik ondersteunt geen downgrade; herstel kan alleen via back-up."
        )
    if target == current:
        return UpgradePathCheck("fout", "zelfde_versie", "De doelversie is gelijk aan de huidige versie.")
    ci, ti = _line_index(current.line), _line_index(target.line)
    if ci is None or ti is None:
        return UpgradePathCheck(
            "onbekend",
            "lijn_onbekend",
            "De huidige of de doel-release-lijn staat niet in de gecontroleerde lijst; upgradepad niet te beoordelen.",
        )
    top_target = Version(*RELEASE_LINES[ti])
    if target.patch > top_target.patch:
        return UpgradePathCheck(
            "onbekend",
            "patch_onbekend",
            f"Doelversie {target} is nieuwer dan de laatst bekende patch {top_target} van die lijn.",
        )
    if ti == ci:
        return UpgradePathCheck("ok", "patch_binnen_lijn", "Patch-upgrade binnen dezelfde release-lijn.")
    if ti > ci + 1:
        nxt = Version(*RELEASE_LINES[ci]) if current.patch < RELEASE_LINES[ci][2] else Version(*RELEASE_LINES[ci + 1])
        return UpgradePathCheck(
            "fout",
            "lijn_overgeslagen",
            "Een release-lijn overslaan mag niet (officiële upgraderegel); upgrade stap voor stap.",
            next_step=str(nxt),
        )
    top_current = Version(*RELEASE_LINES[ci])
    if current < top_current:
        return UpgradePathCheck(
            "fout",
            "eerst_nieuwste_patch",
            f"Eerst naar de nieuwste patch van de huidige lijn ({top_current}), daarna naar {target.year}.{target.minor}.",
            next_step=str(top_current),
        )
    return UpgradePathCheck("ok", "volgende_lijn", "Upgrade naar de volgende release-lijn vanaf de nieuwste patch.")


# ------------------------------------------------------------------ gebruikt API-oppervlak (voor de schemacontrole)
@dataclass(frozen=True)
class ApiUse:
    method: str
    path: str
    purpose_nl: str
    tasks: tuple[str, ...]
    params: tuple[str, ...] = ()
    schema: str | None = None  # componentnaam van het antwoord-/verzoekobject
    fields: tuple[str, ...] = ()
    required_request_fields: tuple[str, ...] | None = None  # alleen bij schrijven: exact deze verplichte velden
    since: tuple[int, int] | None = None  # alleen vanaf deze lijn (versieafhankelijk)
    executed: bool = True  # False = alleen beschreven in een voorstel (uitvoeren komt in P2)


USED_API: tuple[ApiUse, ...] = (
    ApiUse(
        "get",
        "/admin/version/",
        "versiedetectie",
        ("B13-002", "B13-005"),
        schema="Version",
        fields=("version_current", "build_hash"),
    ),
    ApiUse(
        "get",
        "/core/users/me/",
        "rechten van het API-token (least privilege: superuser en systeemrechten)",
        ("B13-004",),
        schema="UserSelf",
        fields=("username", "is_superuser", "system_permissions"),
    ),
    ApiUse(
        "get",
        "/core/users/",
        "gebruikers met groepen (rechtenkaart)",
        ("B13-004", "B13-005"),
        params=("include_groups", "page", "page_size"),
        schema="User",
        fields=("pk", "username", "is_active", "is_superuser", "groups_obj", "type"),
    ),
    ApiUse(
        "get",
        "/core/groups/",
        "groepen met leden (rechtenkaart, groepen → rollen)",
        ("B13-003", "B13-004", "B13-005"),
        params=("include_users", "page", "page_size"),
        schema="Group",
        fields=("pk", "name", "is_superuser", "users_obj"),
    ),
    ApiUse(
        "get",
        "/flows/instances/",
        "flows (autorisatie/invalidatie)",
        ("B13-002", "B13-005"),
        params=("designation", "slug"),
        schema="Flow",
        fields=("pk", "slug", "designation", "name"),
    ),
    ApiUse("get", "/flows/instances/{slug}/export/", "flow-export als blueprint", ("B13-005",)),
    ApiUse(
        "get",
        "/providers/oauth2/",
        "bestaande OAuth2-providers",
        ("B13-002", "B13-005"),
        params=("name", "client_id"),
        schema="OAuth2Provider",
        fields=(
            "pk",
            "name",
            "client_id",
            "client_type",
            "redirect_uris",
            "authorization_flow",
            "invalidation_flow",
            "property_mappings",
            "signing_key",
            "sub_mode",
            "issuer_mode",
            "include_claims_in_id_token",
            "access_code_validity",
            "access_token_validity",
            "assigned_application_slug",
        ),
    ),
    ApiUse(
        "get",
        "/core/applications/",
        "bestaande applicaties",
        ("B13-002", "B13-005"),
        params=("slug",),
        schema="Application",
        # Application.pk is de primaire sleutel van PolicyBindingModel (pbm_uuid) en dus het doel van bindingen
        # (authentik/policies/models.py; 'pbm_uuid' staat pas vanaf 2026.8 apart in het antwoord).
        fields=("pk", "slug", "name", "provider", "meta_launch_url", "policy_engine_mode"),
    ),
    ApiUse(
        "get",
        "/propertymappings/provider/scope/",
        "standaard OIDC-scopes",
        ("B13-002",),
        params=("managed",),
        schema="ScopeMapping",
        fields=("pk", "name", "managed", "scope_name", "expression"),
    ),
    ApiUse(
        "get",
        "/crypto/certificatekeypairs/",
        "ondertekeningssleutels (alleen vingerafdruk)",
        ("B13-002", "B13-005"),
        params=("has_key",),
        schema="CertificateKeyPair",
        fields=("pk", "name", "fingerprint_sha256", "cert_expiry", "private_key_available"),
    ),
    ApiUse(
        "get",
        "/events/events/",
        "logins en wijzigingen (audit)",
        ("B13-004",),
        params=("ordering", "action", "page", "page_size"),
        schema="Event",
        fields=("pk", "action", "app", "context", "client_ip", "created", "user"),
    ),
    ApiUse(
        "get",
        "/events/events/",
        "meerdere acties per verzoek",
        ("B13-004",),
        params=("actions",),
        since=EVENTS_MULTI_ACTION_SINCE,
    ),
    ApiUse(
        "get",
        "/authenticators/admin/all/",
        "MFA-apparaten van beheerders (alleen type/naam)",
        ("B13-005",),
        params=("user",),
        schema="Device",
        fields=("type", "name", "confirmed"),
    ),
    ApiUse(
        "get",
        "/core/authenticated_sessions/",
        "sessies (voorstel intrekken)",
        ("B13-005",),
        params=("user__username",),
        schema="AuthenticatedSession",
        fields=("uuid", "user", "last_used", "expires"),
    ),
    ApiUse(
        "get",
        "/core/brands/",
        "brand-flows",
        ("B13-005",),
        schema="Brand",
        fields=(
            "brand_uuid",
            "domain",
            "default",
            "flow_authentication",
            "flow_invalidation",
            "flow_recovery",
            "web_certificate",
        ),
    ),
    ApiUse(
        "get",
        "/managed/blueprints/",
        "blueprint-instanties",
        ("B13-005",),
        schema="BlueprintInstance",
        fields=("pk", "name", "path", "enabled", "status", "last_applied_hash"),
    ),
    ApiUse(
        "get",
        "/outposts/instances/",
        "outposts (moeten mee-upgraden)",
        ("B13-005",),
        schema="Outpost",
        fields=("pk", "name", "type", "providers", "managed"),
    ),
    ApiUse(
        "get",
        "/policies/bindings/",
        "groepsbindingen aan een applicatie",
        ("B13-002",),
        params=("target",),
        schema="PolicyBinding",
        fields=("pk", "target", "group", "order", "enabled", "negate"),
    ),
    # Alleen beschreven in voorstellen (preview); uitvoeren komt pas met een door de Hub ondertekend ExecutionRequest.
    ApiUse(
        "post",
        "/providers/oauth2/",
        "OIDC-provider voor de Hub aanmaken",
        ("B13-002",),
        schema="OAuth2ProviderRequest",
        fields=(
            "name",
            "authorization_flow",
            "invalidation_flow",
            "client_type",
            "redirect_uris",
            "property_mappings",
            "signing_key",
            "sub_mode",
            "issuer_mode",
            "include_claims_in_id_token",
            "access_code_validity",
            "access_token_validity",
        ),
        required_request_fields=("authorization_flow", "invalidation_flow", "name", "redirect_uris"),
        executed=False,
    ),
    ApiUse(
        "post",
        "/providers/oauth2/",
        "grant types beperken",
        ("B13-002",),
        schema="OAuth2ProviderRequest",
        fields=("grant_types",),
        since=GRANT_TYPES_SINCE,
        executed=False,
    ),
    ApiUse("patch", "/providers/oauth2/{id}/", "bestaande provider bijwerken", ("B13-002",), executed=False),
    ApiUse(
        "post",
        "/core/applications/",
        "applicatie voor de Hub aanmaken",
        ("B13-002",),
        schema="ApplicationRequest",
        fields=("name", "slug", "provider", "meta_launch_url", "policy_engine_mode"),
        required_request_fields=("name", "slug"),
        executed=False,
    ),
    ApiUse("patch", "/core/applications/{slug}/", "bestaande applicatie bijwerken", ("B13-002",), executed=False),
    ApiUse(
        "post",
        "/policies/bindings/",
        "groep aan de applicatie binden",
        ("B13-002",),
        schema="PolicyBindingRequest",
        fields=("target", "group", "order", "enabled", "negate"),
        executed=False,
    ),
    ApiUse("delete", "/core/authenticated_sessions/{uuid}/", "sessie intrekken", ("B13-005",), executed=False),
)
