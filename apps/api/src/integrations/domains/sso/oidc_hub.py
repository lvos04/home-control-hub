"""B13-002 — OIDC voor de Hub: voorstel voor een OAuth2/OIDC-provider + applicatie in Authentik, en een
alleen-lezen controle van een bestaande Hub-client.

Het voorstel is **R2**: preview, diff, de exacte API-verzoeken (zonder geheimen), ``resource_etag`` en ``preview_hash``.
Toepassen kan in deze versie niet (zie ``proposals.py``). Alles is puur (geen I/O) zodat het los te testen is.

Keuzes (ADR-0007):
- Confidential client, Authorization Code; PKCE (S256) dwingt de Hub zelf af — Authentik ondersteunt PKCE (officiële
  OAuth2-docs) maar het provider-schema heeft geen veld om het af te dwingen (geverifieerd in de schema's).
- ``client_secret`` staat nooit in preview of diff: Authentik genereert het bij aanmaken; overdracht naar de vault van
  de Hub hoort bij het toepassen (P2).
- Asymmetrische ondertekening (sleutelpaar uit Authentik), ``issuer_mode=per_provider``, ``sub_mode=hashed_user_id``,
  scopes openid/email/profile (profile levert de claim ``groups``), korte geldigheid van code (1 min) en token (5 min).
- Alleen gebruikers in groepen die in B13-003 aan een Hub-rol gekoppeld zijn krijgen een binding; zonder koppelingen is
  er geen voorstel (anders kan iedere Authentik-gebruiker de Hub-client gebruiken).
- Een bestaande applicatie/provider van iets anders wordt nooit overgenomen (blokkade i.p.v. overschrijven).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .authentik import compat
from .authentik.reader import AuthentikState

ACTION_ID = "sso.oidc.hub.register"
HUB_APP_ID = "ai-server-manager"
ACCESS_CODE_VALIDITY = "minutes=1"
ACCESS_TOKEN_VALIDITY = "minutes=5"  # noqa: S105 - geldigheidsduur, geen geheim
REQUIRED_SCOPES = (compat.MANAGED_SCOPE_OPENID, compat.MANAGED_SCOPE_EMAIL, compat.MANAGED_SCOPE_PROFILE)


def canonical(obj: Any) -> bytes:
    """Canonieke JSON zoals contract §8: sleutels gesorteerd, UTF-8, geen spaties."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256_obj(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def check_https_url(url: str, label: str) -> str:
    """Alleen absolute https-URL's zonder inloggegevens, fragment of jokertekens; geen localhost."""
    url = url.strip()
    parts = urlsplit(url)
    if len(url) > 300:
        raise ValueError(f"{label} is te lang")
    if parts.scheme != "https":
        raise ValueError(f"{label} moet met https:// beginnen (OIDC alleen via HTTPS; D17)")
    host = (parts.hostname or "").lower()
    if not host or host == "localhost" or host.endswith(".localhost"):
        raise ValueError(f"{label} mist een geldige hostnaam (geen localhost)")
    if parts.username or parts.password or parts.fragment or "*" in url:
        raise ValueError(f"{label} mag geen inloggegevens, #-deel of jokertekens bevatten")
    return url


@dataclass(frozen=True)
class HubOidcParams:
    redirect_uris: tuple[str, ...]
    application_slug: str = "hub"
    application_name: str = "Hub"
    provider_name: str = "Hub (OIDC)"
    launch_url: str | None = None
    authorization_flow_slug: str = compat.DEFAULT_AUTHZ_FLOW
    invalidation_flow_slug: str = compat.DEFAULT_INVALIDATION_FLOW
    signing_key_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "redirect_uris": list(self.redirect_uris),
            "application_slug": self.application_slug,
            "application_name": self.application_name,
            "provider_name": self.provider_name,
            "launch_url": self.launch_url,
            "authorization_flow_slug": self.authorization_flow_slug,
            "invalidation_flow_slug": self.invalidation_flow_slug,
            "signing_key_name": self.signing_key_name,
        }


@dataclass
class Plan:
    action_id: str
    target: dict[str, Any]
    parameters: dict[str, Any]
    authentik_version: str
    blockers: list[dict[str, Any]] = field(default_factory=list)
    diff: list[dict[str, Any]] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    rollback_recipe: list[dict[str, Any]] = field(default_factory=list)
    blast_radius: dict[str, Any] = field(default_factory=dict)
    notes_nl: list[str] = field(default_factory=list)
    warnings: list[dict[str, Any]] = field(default_factory=list)
    resource_basis: dict[str, Any] = field(default_factory=dict)
    risk_claim: str = "R2"
    requires_backup: bool = True

    @property
    def resource_etag(self) -> str:
        return sha256_obj(self.resource_basis)

    @property
    def changes(self) -> int:
        return sum(1 for d in self.diff if d["operation"] != "ongewijzigd")

    @property
    def preview_hash(self) -> str:
        return sha256_obj(
            {
                "action_id": self.action_id,
                "target": self.target,
                "parameters": self.parameters,
                "diff": self.diff,
                "requests": self.requests,
                "resource_etag": self.resource_etag,
                "authentik_version": self.authentik_version,
                "risk_claim": self.risk_claim,
                "blast_radius": self.blast_radius,
            }
        )

    def preview(self) -> dict[str, Any]:
        return {
            "diff": self.diff,
            "requests": self.requests,
            "rollback_recipe": self.rollback_recipe,
            "blast_radius": self.blast_radius,
            "notes_nl": self.notes_nl,
            "warnings": self.warnings,
            "changes": self.changes,
        }


def _block(plan: Plan, code: str, message_nl: str, **details: Any) -> None:
    plan.blockers.append({"code": code, "message_nl": message_nl, **details})


def _changes(before: dict[str, Any] | None, after: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for k in sorted(after):
        old = None if before is None else before.get(k)
        new = after[k]
        if isinstance(old, list) and isinstance(new, list):
            same = sorted(map(str, old)) == sorted(map(str, new)) if k != "redirect_uris" else old == new
        else:
            same = old == new
        if before is None or not same:
            out.append({"field": k, "before": old, "after": new})
    return out


def build_hub_oidc_plan(
    state: AuthentikState,
    params: HubOidcParams,
    hub_role_groups: list[tuple[str, str]],
    existing_bindings: list[dict[str, Any]] | None,
) -> Plan:
    """``hub_role_groups`` = [(Authentik-groep, Hub-rol)] uit B13-003. ``existing_bindings`` van de applicatie (of None)."""
    caps = state.caps
    plan = Plan(
        action_id=ACTION_ID,
        target={"system": "authentik", "app_id": HUB_APP_ID, "application_slug": params.application_slug},
        parameters=params.to_dict(),
        authentik_version=str(state.version),
    )
    for part in ("flows", "scope_mappings", "signing_keys", "providers", "applications", "groups"):
        if state.get(part) is None:
            _block(plan, "onvolledig_gelezen", f"Onderdeel '{part}' kon niet uit Authentik gelezen worden.", part=part)
    if plan.blockers:
        return plan
    flows = state.parts["flows"]
    scopes = state.parts["scope_mappings"]
    keys = state.parts["signing_keys"]
    providers = state.parts["providers"]
    apps = state.parts["applications"]
    groups = {g["name"]: g for g in state.parts["groups"]}

    if params.application_slug in compat.RESERVED_APP_SLUGS:
        _block(plan, "slug_gereserveerd", "Deze slug is in Authentik gereserveerd (OAuth2-endpoints).")

    def flow(slug: str, designation: str) -> dict[str, Any] | None:
        return next((f for f in flows if f.get("slug") == slug and f.get("designation") == designation), None)

    authz = flow(params.authorization_flow_slug, "authorization")
    inval = flow(params.invalidation_flow_slug, "invalidation")
    if authz is None:
        _block(plan, "autorisatieflow_ontbreekt", f"Autorisatieflow '{params.authorization_flow_slug}' bestaat niet.")
    if inval is None:
        _block(plan, "invalidatieflow_ontbreekt", f"Invalidatieflow '{params.invalidation_flow_slug}' bestaat niet.")

    scope_pks: list[str] = []
    for managed in REQUIRED_SCOPES:
        m = next((s for s in scopes if s.get("managed") == managed), None)
        if m is None:
            _block(plan, "scope_ontbreekt", f"Standaard-scope '{managed}' ontbreekt in Authentik.", managed=managed)
        else:
            scope_pks.append(str(m["pk"]))

    usable = [k for k in keys if k.get("private_key_available")]
    key: dict[str, Any] | None = None
    if params.signing_key_name:
        key = next((k for k in usable if k.get("name") == params.signing_key_name), None)
        if key is None:
            _block(
                plan, "sleutel_onbekend", "De gekozen ondertekeningssleutel bestaat niet of heeft geen privésleutel."
            )
    elif len(usable) == 1:
        key = usable[0]
    elif not usable:
        _block(
            plan, "geen_ondertekeningssleutel", "Authentik heeft geen sleutelpaar met privésleutel om te ondertekenen."
        )
    else:
        _block(
            plan,
            "kies_ondertekeningssleutel",
            "Er zijn meerdere sleutelparen; kies er één (signing_key_name).",
            choices=sorted(str(k.get("name")) for k in usable),
        )

    if not hub_role_groups:
        _block(
            plan,
            "geen_groepen_gekoppeld",
            "Koppel eerst Authentik-groepen aan Hub-rollen (B13-003); zonder koppeling zou iedere Authentik-gebruiker "
            "de Hub-client kunnen gebruiken.",
        )
    bound_groups: list[dict[str, Any]] = []
    for gname, _role in hub_role_groups:
        g = groups.get(gname)
        if g is None:
            _block(plan, "groep_ontbreekt", f"Gekoppelde groep '{gname}' bestaat niet in Authentik.", group=gname)
        else:
            bound_groups.append(g)

    app = next((a for a in apps if a.get("slug") == params.application_slug), None)
    provider = next((p for p in providers if p.get("name") == params.provider_name), None)
    if app is not None:
        app_provider = next((p for p in providers if p.get("pk") == app.get("provider")), None)
        if app.get("provider") is not None and (
            app_provider is None or app_provider.get("name") != params.provider_name
        ):
            _block(
                plan,
                "slug_in_gebruik",
                "Er bestaat al een applicatie met deze slug die een andere provider gebruikt; die wordt niet overgenomen.",
            )
    if provider is not None and provider.get("assigned_application_slug") not in (None, params.application_slug):
        _block(plan, "providernaam_in_gebruik", "Een provider met deze naam hoort al bij een andere applicatie.")

    plan.resource_basis = {
        "version": str(state.version),
        "provider": provider,
        "application": app,
        "bindings": sorted(existing_bindings or [], key=lambda b: str(b.get("pk"))),
        "flows": [authz and authz.get("pk"), inval and inval.get("pk")],
        "scopes": scope_pks,
        "signing_key": key and {k: key.get(k) for k in ("pk", "fingerprint_sha256")},
        "groups": sorted(({"name": g["name"], "pk": g.get("pk")} for g in bound_groups), key=lambda x: x["name"]),
    }
    if plan.blockers or authz is None or inval is None or key is None:
        return plan

    desired_provider: dict[str, Any] = {
        "name": params.provider_name,
        "authorization_flow": authz["pk"],
        "invalidation_flow": inval["pk"],
        "client_type": "confidential",
        "redirect_uris": [{"matching_mode": "strict", "url": u} for u in params.redirect_uris],
        "property_mappings": sorted(scope_pks),
        "signing_key": key["pk"],
        "sub_mode": "hashed_user_id",
        "issuer_mode": "per_provider",
        "include_claims_in_id_token": True,
        "access_code_validity": ACCESS_CODE_VALIDITY,
        "access_token_validity": ACCESS_TOKEN_VALIDITY,
    }
    if caps.oauth2_grant_types:
        desired_provider["grant_types"] = ["authorization_code"]
    else:
        plan.notes_nl.append(
            "Deze Authentik-versie kent geen veld grant_types; refresh-tokens komen alleen met de scope offline_access, "
            "die dit voorstel niet koppelt."
        )

    if provider is None:
        plan.diff.append(
            {
                "object": "oauth2_provider",
                "key": params.provider_name,
                "operation": "aanmaken",
                "changes": _changes(None, desired_provider),
            }
        )
        plan.requests.append({"method": "POST", "path": "/api/v3/providers/oauth2/", "body": desired_provider})
        plan.rollback_recipe.append(
            {
                "method": "DELETE",
                "path": "/api/v3/providers/oauth2/<pk na aanmaken>/",
                "toelichting_nl": "provider verwijderen",
            }
        )
        provider_ref: Any = "<pk van de nieuwe provider>"
    else:
        ch = _changes(provider, desired_provider)
        plan.diff.append(
            {
                "object": "oauth2_provider",
                "key": params.provider_name,
                "operation": "wijzigen" if ch else "ongewijzigd",
                "changes": ch,
            }
        )
        if ch:
            body = {c["field"]: c["after"] for c in ch}
            plan.requests.append(
                {"method": "PATCH", "path": f"/api/v3/providers/oauth2/{provider['pk']}/", "body": body}
            )
            plan.rollback_recipe.append(
                {
                    "method": "PATCH",
                    "path": f"/api/v3/providers/oauth2/{provider['pk']}/",
                    "body": {c["field"]: c["before"] for c in ch},
                    "toelichting_nl": "vorige waarden terugzetten",
                }
            )
        provider_ref = provider["pk"]

    desired_app: dict[str, Any] = {
        "name": params.application_name,
        "slug": params.application_slug,
        "provider": provider_ref,
        "policy_engine_mode": "any",
    }
    if params.launch_url:
        desired_app["meta_launch_url"] = params.launch_url
    if app is None:
        plan.diff.append(
            {
                "object": "application",
                "key": params.application_slug,
                "operation": "aanmaken",
                "changes": _changes(None, desired_app),
            }
        )
        plan.requests.append({"method": "POST", "path": "/api/v3/core/applications/", "body": desired_app})
        plan.rollback_recipe.insert(
            0,
            {
                "method": "DELETE",
                "path": f"/api/v3/core/applications/{params.application_slug}/",
                "toelichting_nl": "applicatie verwijderen (eerst, vóór de provider)",
            },
        )
        app_ref: Any = "<pk van de nieuwe applicatie>"
    else:
        ch = _changes(app, desired_app)
        plan.diff.append(
            {
                "object": "application",
                "key": params.application_slug,
                "operation": "wijzigen" if ch else "ongewijzigd",
                "changes": ch,
            }
        )
        if ch:
            plan.requests.append(
                {
                    "method": "PATCH",
                    "path": f"/api/v3/core/applications/{params.application_slug}/",
                    "body": {c["field"]: c["after"] for c in ch},
                }
            )
            plan.rollback_recipe.insert(
                0,
                {
                    "method": "PATCH",
                    "path": f"/api/v3/core/applications/{params.application_slug}/",
                    "body": {c["field"]: c["before"] for c in ch},
                    "toelichting_nl": "vorige waarden terugzetten",
                },
            )
        app_ref = app["pk"]

    existing = existing_bindings or []
    bound_pks = {
        str(b.get("group"))
        for b in existing
        if b.get("kind") == "groep" and b.get("enabled", True) and not b.get("negate")
    }
    order = max([int(b.get("order") or 0) for b in existing] + [-1]) + 1
    for g in sorted(bound_groups, key=lambda x: x["name"]):
        if str(g.get("pk")) in bound_pks:
            plan.diff.append({"object": "policy_binding", "key": g["name"], "operation": "ongewijzigd", "changes": []})
            continue
        body = {"target": app_ref, "group": g.get("pk"), "order": order, "enabled": True, "negate": False}
        order += 1
        plan.diff.append(
            {"object": "policy_binding", "key": g["name"], "operation": "aanmaken", "changes": _changes(None, body)}
        )
        plan.requests.append({"method": "POST", "path": "/api/v3/policies/bindings/", "body": body})
        plan.rollback_recipe.insert(
            0,
            {
                "method": "DELETE",
                "path": "/api/v3/policies/bindings/<uuid na aanmaken>/",
                "toelichting_nl": f"binding van groep {g['name']} verwijderen",
            },
        )
    mapped = {str(g.get("pk")) for g in bound_groups}
    extra = [b for b in existing if b.get("kind") != "groep" or str(b.get("group")) not in mapped]
    if extra:
        plan.warnings.append(
            {
                "code": "extra_bindingen",
                "message_nl": "De applicatie heeft bindingen die niet uit de groep→rol-koppeling komen; die blijven "
                "staan (dit voorstel verwijdert niets). Controleer ze in Authentik.",
                "count": len(extra),
            }
        )
    members = sorted({m for g in bound_groups for m in (g.get("members") or [])})
    plan.blast_radius = {
        "apps": [HUB_APP_ID],
        "authentik_objects": [d["object"] for d in plan.diff if d["operation"] != "ongewijzigd"],
        "groups": sorted(g["name"] for g in bound_groups),
        "users_with_access": len(members),
        "local_login_unchanged": True,
        "toelichting_nl": "Alleen een extra inlogroute voor de Hub. Het lokale Hub-account en de noodtoegang (B13-001) "
        "blijven werken; andere applicaties in Authentik worden niet gewijzigd.",
    }
    plan.notes_nl.extend(
        [
            "Het client_secret maakt Authentik bij het aanmaken; het komt nooit in dit voorstel en gaat bij toepassen "
            "(P2) rechtstreeks naar de vault van de Hub.",
            "PKCE (S256) dwingt de Hub zelf af; Authentik ondersteunt het, maar heeft er geen providerinstelling voor.",
            f"Verwachte issuer voor de Hub: <Authentik-adres>/application/o/{params.application_slug}/ "
            "(issuer_mode per_provider).",
            "Groepen → Hub-rollen komen uit de koppeling van B13-003 (claim 'groups' via de scope profile).",
        ]
    )
    return plan


# ------------------------------------------------------------------ alleen-lezen controle van een bestaande Hub-client
def check_hub_client(
    state: AuthentikState,
    slug: str,
    expected_redirect_uris: list[str] | None,
    bindings: list[dict[str, Any]] | None,
    discovery: dict[str, Any] | None,
    discovery_error: str | None,
    hub_role_groups: list[tuple[str, str]],
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(check: str, status: str, message_nl: str, **detail: Any) -> None:
        checks.append({"name": check, "status": status, "message_nl": message_nl, "detail": detail})

    apps = state.get("applications")
    providers = state.get("providers")
    if apps is None or providers is None:
        add("gelezen", "onbekend", "Applicaties/providers konden niet gelezen worden.", missing=state.missing)
        return {"slug": slug, "outcome": "onbekend", "checks": checks}
    app = next((a for a in apps if a.get("slug") == slug), None)
    if app is None:
        add("applicatie", "afwijking", f"Er is geen applicatie met slug '{slug}'.")
        return {"slug": slug, "outcome": "afwijking", "checks": checks}
    add("applicatie", "ok", "Applicatie gevonden.", name=app.get("name"))
    prov = next((p for p in providers if p.get("pk") == app.get("provider")), None)
    if prov is None:
        add("provider", "afwijking", "De applicatie heeft geen OAuth2/OIDC-provider.")
        return {"slug": slug, "outcome": "afwijking", "checks": checks}
    add("provider", "ok", "OAuth2/OIDC-provider gekoppeld.", name=prov.get("name"))
    add(
        "client_type",
        "ok" if prov.get("client_type") == "confidential" else "afwijking",
        "Confidential client (server-side Hub)."
        if prov.get("client_type") == "confidential"
        else "Geen confidential client.",
    )
    uris = prov.get("redirect_uris") or []
    bad = [u for u in uris if u.get("matching_mode") != "strict" or not str(u.get("url", "")).startswith("https://")]
    add(
        "redirect_uris",
        "afwijking" if bad or not uris else "ok",
        "Alleen exacte https-redirect-URI's." if not bad and uris else "Redirect-URI's niet strikt of niet via https.",
        count=len(uris),
    )
    if expected_redirect_uris is not None:
        same = sorted(u.get("url") for u in uris) == sorted(expected_redirect_uris)
        add(
            "redirect_uris_verwacht",
            "ok" if same else "afwijking",
            "Redirect-URI's gelijk aan de Hub-instelling."
            if same
            else "Redirect-URI's wijken af van de Hub-instelling.",
        )
    add(
        "ondertekening",
        "ok" if prov.get("signing_key") else "afwijking",
        "Asymmetrisch ondertekend (sleutelpaar)."
        if prov.get("signing_key")
        else "Geen sleutelpaar: tokens zouden met het client_secret (HS256) ondertekend worden.",
    )
    scope_by_pk = {str(s.get("pk")): s for s in state.get("scope_mappings") or []}
    managed = {scope_by_pk[pk].get("managed") for pk in prov.get("property_mappings") or [] if pk in scope_by_pk}
    if not scope_by_pk:
        add("scopes", "onbekend", "Scope-koppelingen konden niet gelezen worden.")
    else:
        missing = [m for m in REQUIRED_SCOPES if m not in managed]
        add(
            "scopes",
            "afwijking" if missing else "ok",
            "openid, email en profile (met groups) gekoppeld." if not missing else "Scopes ontbreken.",
            missing=missing,
        )
    add(
        "issuer_mode",
        "ok" if prov.get("issuer_mode") == "per_provider" else "afwijking",
        "Issuer per provider."
        if prov.get("issuer_mode") == "per_provider"
        else "Globale issuer: de Hub moet dan een andere issuer controleren.",
    )
    groups_read = state.get("groups")
    if bindings is None or groups_read is None:
        add("toegang", "onbekend", "Bindingen of groepen konden niet gelezen worden.")
    else:
        # Alleen ingeschakelde, niet-omgekeerde bindingen beperken de toegang. Zonder zulke bindingen laat Authentik
        # iedere gebruiker toe; een 'negate'-binding op een groep betekent juist "iedereen behalve die groep".
        active = [b for b in bindings if b.get("enabled", True) is True and not b.get("negate")]
        groups = {g["name"]: str(g.get("pk")) for g in groups_read}
        mapped = sorted({n for n, _r in hub_role_groups})
        missing_groups = [n for n in mapped if n not in groups]
        wanted = {groups[n] for n in mapped if n in groups}
        bound = {str(b.get("group")) for b in active if b.get("kind") == "groep"}
        if not active:
            add(
                "toegang",
                "afwijking",
                "Geen actieve bindingen: iedere Authentik-gebruiker kan deze client gebruiken.",
                bindings=len(bindings),
            )
        elif not mapped:
            add(
                "toegang",
                "onbekend",
                "Er is nog geen groep → Hub-rol gekoppeld (B13-003); niet te beoordelen of de bindingen kloppen.",
                bindings=len(active),
            )
        elif missing_groups:
            add(
                "toegang",
                "afwijking",
                "Aan Hub-rollen gekoppelde groepen bestaan niet in Authentik.",
                missing_groups=missing_groups,
            )
        elif not wanted <= bound:
            add("toegang", "afwijking", "Niet alle aan Hub-rollen gekoppelde groepen zijn gebonden.")
        else:
            add("toegang", "ok", "Toegang beperkt via bindingen.", bindings=len(active))
    if discovery is None:
        add("discovery", "onbekend", "OpenID-configuratie niet opgehaald.", reason=discovery_error)
    else:
        methods = discovery.get("code_challenge_methods_supported") or []
        add(
            "pkce_s256",
            "ok" if "S256" in methods else "afwijking",
            "PKCE S256 aangeboden." if "S256" in methods else "PKCE S256 niet aangeboden.",
        )
        rtypes = discovery.get("response_types_supported") or []
        add(
            "code_flow",
            "ok" if "code" in rtypes else "afwijking",
            "Authorization Code aangeboden." if "code" in rtypes else "Authorization Code niet aangeboden.",
        )
        issuer = discovery.get("issuer")
        issuer_ok = isinstance(issuer, str) and issuer.rstrip("/").endswith(f"/application/o/{slug}")
        add(
            "issuer",
            "ok" if issuer_ok else "afwijking",
            "Issuer volgt het per-provider-patroon."
            if issuer_ok
            else f"Issuer wijkt af van het verwachte patroon …/application/o/{slug}/.",
            issuer=issuer,
        )
    statuses = {c["status"] for c in checks}
    outcome = "afwijking" if "afwijking" in statuses else ("onbekend" if "onbekend" in statuses else "ok")
    return {"slug": slug, "outcome": outcome, "checks": checks}
