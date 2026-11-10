"""B13-003 — SSO-mapping per app: loginroute (native/oidc) en Authentik-groep → rol.

Regels (fail-closed):
- Loginroute ``oidc`` alleen voor apps waarvan de bron OIDC (met voorwaarden) bevestigt; anders blijft de eigen login.
- Groep → rol alleen voor apps die OIDC (gaan) ondersteunen en alleen met een rol uit de catalogus van die app.
- Vertrouwde-header-SSO bestaat niet in dit model (nooit toegestaan).
- Rollen/privileges wijzigen is een beheerdershandeling (rol ``admin``); de Hub (service) en AI kunnen dat niet.
- **Alleen advies** (contract 1.3 §4.1, C1.3-HCH-11): de koppeling groep → rol stelt een beheerder in de **Hub** in
  (eigen tabel, audit). Deze dienst toont zijn koppelingen als advies (en gebruikt ze voor de bindingen in het
  OIDC-voorstel en de rechtenkaart); ze geven nergens zelf toegang. Elke koppeling zegt dat in ``advies``.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...deps import etag
from ...errors import ApiError
from ...timeutil import iso
from .catalog import APP_BY_ID, APP_COVERAGE, AppSsoCoverage
from .models import SsoAppSetting, SsoGroupRoleMapping


def app_spec(app_id: str) -> AppSsoCoverage:
    spec = APP_BY_ID.get(app_id)
    if spec is None:
        raise ApiError(404, "not_found", "Onbekende app in de SSO-dekkingsmatrix.", {"app_id": app_id})
    return spec


def setting_dict(row: SsoAppSetting | None) -> dict[str, Any]:
    if row is None:
        return {
            "login_mode": "native",
            "installation_check": "niet_getest",
            "checked_at": None,
            "checked_by": None,
            "notes": "",
            "version": 0,
            "etag": None,
        }
    return {
        "login_mode": row.login_mode,
        "installation_check": row.installation_check,
        "checked_at": iso(row.checked_at),
        "checked_by": row.checked_by,
        "notes": row.notes,
        "version": row.version,
        "etag": etag(row.version),
        "updated_at": iso(row.updated_at),
        "updated_by": row.updated_by,
    }


#: contract 1.3 §4.1: wie de koppeling groep → rol werkelijk vastlegt
ADVIES_NL = (
    "Advies: de koppeling groep → rol stelt een beheerder in de Hub in (eigen tabel, audit); deze koppeling geeft zelf "
    "geen toegang."
)


def mapping_dict(m: SsoGroupRoleMapping) -> dict[str, Any]:
    return {
        "id": str(m.id),
        "app_id": m.app_id,
        "authentik_group": m.authentik_group,
        "role": m.role,
        "advies": True,
        "advies_nl": ADVIES_NL,
        "version": m.version,
        "etag": etag(m.version),
        "created_at": iso(m.created_at),
        "created_by": m.created_by,
        "updated_at": iso(m.updated_at),
        "updated_by": m.updated_by,
    }


def effective_status(spec: AppSsoCoverage, setting: SsoAppSetting | None) -> str:
    """Samenvatting voor de dekkingskaart: nooit 'sso_actief' zonder handmatige bevestiging na een echte test."""
    if setting is None or setting.login_mode == "native":
        return "eigen_login"
    if setting.installation_check == "handmatig_bevestigd":
        return "oidc_handmatig_bevestigd"
    return "oidc_gekozen_niet_getest"


def coverage(session: Session) -> list[dict[str, Any]]:
    settings = {r.app_id: r for r in session.scalars(select(SsoAppSetting))}
    mappings: dict[str, list[dict[str, Any]]] = {}
    for m in session.scalars(
        select(SsoGroupRoleMapping).order_by(SsoGroupRoleMapping.app_id, SsoGroupRoleMapping.authentik_group)
    ):
        mappings.setdefault(m.app_id, []).append(mapping_dict(m))
    out = []
    for spec in APP_COVERAGE:
        row = settings.get(spec.app_id)
        out.append(
            {
                **spec.to_dict(),
                "setting": setting_dict(row),
                "effective_status": effective_status(spec, row),
                "role_mappings": mappings.get(spec.app_id, []),
            }
        )
    return out


def validate_login_mode(spec: AppSsoCoverage, mode: str) -> None:
    if mode == "oidc" and not spec.oidc_allowed:
        raise ApiError(
            409,
            "oidc_niet_ondersteund",
            f"{spec.display_name} ondersteunt volgens de bron geen OIDC; de eigen login blijft.",
            {"oidc_support": spec.oidc_support, "source": spec.source.url},
        )


def validate_mapping(session: Session, app_id: str, group: str, role: str) -> AppSsoCoverage:
    spec = app_spec(app_id)
    if not spec.mapping_allowed:
        raise ApiError(
            409,
            "koppeling_niet_mogelijk",
            f"Voor {spec.display_name} kunnen geen groepen aan rollen gekoppeld worden (geen OIDC); de eigen login "
            "en rollen van die app blijven leidend.",
            {"oidc_support": spec.oidc_support},
        )
    if role not in spec.roles:
        raise ApiError(
            422,
            "validation_error",
            f"Onbekende rol voor {spec.display_name}; kies uit: {', '.join(spec.roles)}.",
            {"veld": "role", "toegestaan": list(spec.roles)},
        )
    return spec
