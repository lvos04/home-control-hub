"""Lezen uit Authentik: versiedetectie, least-privilege-controle en een **geschoonde** toestand.

Alles wat deze dienst uit Authentik bewaart of doorgeeft gaat door een *whitelist*: alleen genoemde velden, nooit
``client_secret``, sleutels, wachtwoorden, e-mailadressen of vrije ``attributes``. Ontbreekt een onderdeel (geen rechten,
time-out, te veel pagina's), dan staat het in ``missing`` en is de toestand ``complete=False`` — nooit "leeg = niets".
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote_from_bytes, unquote, urlsplit

from ....redact import redact_text
from ....timeutil import iso, utcnow
from . import compat
from .client import AuthentikClient, AuthentikError

MAX_STR = 300
FLOW_EXPORT_MAX_BYTES = 512 * 1024
FLOW_EXPORT_SECRET_LINE = re.compile(
    r"^(\s*-?\s*[A-Za-z0-9_]*(password|secret|token|private_key|api_key|apikey)[A-Za-z0-9_]*\s*:\s*)(\S.*)$",
    re.IGNORECASE,
)

ALL_PARTS = (
    "providers",
    "applications",
    "groups",
    "users",
    "flows",
    "scope_mappings",
    "signing_keys",
    "brands",
    "blueprints",
    "outposts",
)
PART_PATHS = {
    "providers": ("/providers/oauth2/", {}),
    "applications": ("/core/applications/", {}),
    "groups": ("/core/groups/", {"include_users": "true"}),
    "users": ("/core/users/", {"include_groups": "true"}),
    "flows": ("/flows/instances/", {}),
    "scope_mappings": ("/propertymappings/provider/scope/", {}),
    "signing_keys": ("/crypto/certificatekeypairs/", {"has_key": "true"}),
    "brands": ("/core/brands/", {}),
    "blueprints": ("/managed/blueprints/", {}),
    "outposts": ("/outposts/instances/", {}),
}

PROVIDER_CHOICES = {
    "client_type": {"confidential", "public"},
    "sub_mode": {"hashed_user_id", "user_id", "user_uuid", "user_username", "user_email", "user_upn"},
    "issuer_mode": {"global", "per_provider"},
}
GRANT_TYPES = {
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "implicit",
    "hybrid",
    "password",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
}
UUID_TEXT = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
DURATION = re.compile(r"(?:(?:weeks|days|hours|minutes|seconds|milliseconds|microseconds)=[0-9]+[,; ]*)+")
SLUG = re.compile(r"[a-zA-Z0-9_-]+")
AUTH_HEADER = re.compile(r"(?i)\bauthorization\s*:|\bbasic\s+[A-Za-z0-9+/]{8,}={0,2}\b")


def _s(value: Any) -> Any:
    """Korte, veilige scalaire waarde (strings ingekort)."""
    if isinstance(value, str):
        return value[:MAX_STR]
    if isinstance(value, bool | int | float) or value is None:
        return value
    return str(value)[:MAX_STR]


def _pick(obj: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {k: _s(obj.get(k)) for k in keys if k in obj}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ whitelists per objectsoort
def _protected_provider_values(p: dict[str, Any]) -> set[str]:
    secret = p.get("client_secret")
    if not isinstance(secret, str) or not secret:
        return set()
    raw = secret.encode("utf-8", errors="surrogatepass")
    return {
        secret,
        quote_from_bytes(raw, safe=""),
        raw.hex(),
        hashlib.sha256(raw).hexdigest(),
        base64.b64encode(raw).decode("ascii"),
        json.dumps(secret)[1:-1],
    }


def _plain_provider_text(value: Any, protected: set[str]) -> bool:
    if not isinstance(value, str) or len(value) > MAX_STR or not value.isprintable():
        return False
    decoded = unquote(value)
    return (
        redact_text(decoded) == decoded
        and AUTH_HEADER.search(decoded) is None
        and not any(secret in value or secret in decoded for secret in protected)
    )


def _safe_redirect(value: str) -> bool:
    try:
        url = urlsplit(value)
        return (
            url.scheme in {"https", "http"}
            and url.hostname is not None
            and url.port != 0
            and url.username is None
            and url.password is None
            and not url.fragment
            and "\\" not in value
            and not any(char.isspace() for char in value)
        )
    except ValueError:
        return False


def clean_provider(p: dict[str, Any]) -> dict[str, Any]:
    protected = _protected_provider_values(p)
    out: dict[str, Any] = {}
    invalid: set[str] = set()
    for key in ("name", "client_id", "assigned_application_slug"):
        if key in p:
            value = p[key]
            if (key == "assigned_application_slug" and value in (None, "")) or (
                _plain_provider_text(value, protected) and (key != "assigned_application_slug" or SLUG.fullmatch(value))
            ):
                out[key] = value
            else:
                invalid.add(key)
    for key, allowed in PROVIDER_CHOICES.items():
        if key in p:
            value = p[key]
            if isinstance(value, str) and value in allowed and _plain_provider_text(value, protected):
                out[key] = value
            else:
                invalid.add(key)
    for key in (
        "authorization_flow",
        "invalidation_flow",
        "signing_key",
        "access_code_validity",
        "access_token_validity",
    ):
        if key in p:
            value = p[key]
            allows_null = key in ("authorization_flow", "invalidation_flow", "signing_key")
            pattern = UUID_TEXT if allows_null else DURATION
            if (value is None and allows_null) or (_plain_provider_text(value, protected) and pattern.fullmatch(value)):
                out[key] = value
            else:
                invalid.add(key)
    for key, expected in (("pk", int), ("include_claims_in_id_token", bool)):
        if key in p:
            if type(p[key]) is expected and (key != "pk" or p[key] > 0):
                out[key] = p[key]
            else:
                invalid.add(key)

    uris = p.get("redirect_uris")
    out["redirect_uris"] = redirects = []
    if isinstance(uris, list):
        for uri in uris:
            if isinstance(uri, dict):
                kind = uri.get("redirect_uri_type", "authorization")
                mode, url = uri.get("matching_mode"), uri.get("url")
                if kind == "logout":
                    continue
                if (
                    kind == "authorization"
                    and mode == "strict"
                    and isinstance(url, str)
                    and _plain_provider_text(url, protected)
                    and _safe_redirect(url)
                ):
                    redirects.append({"matching_mode": "strict", "url": url})
                    continue
            # Houd het aantal zichtbaar zonder onverwachte of reguliere expressiewaarden over te nemen.
            invalid.add("redirect_uris")
            redirects.append({"matching_mode": "onbekend", "url": ""})
    elif "redirect_uris" in p:
        invalid.add("redirect_uris")

    for key in ("property_mappings", "grant_types"):
        if key not in p:
            continue
        values = p[key]
        if not isinstance(values, list):
            invalid.add(key)
            continue
        kept = []
        for value in values:
            if key == "property_mappings" and type(value) is int and value > 0:
                value = str(value)
            if _plain_provider_text(value, protected) and (
                (UUID_TEXT.fullmatch(value) or re.fullmatch(r"[1-9][0-9]*", value))
                if key == "property_mappings"
                else value in GRANT_TYPES
            ):
                kept.append(value)
            else:
                invalid.add(key)
        out[key] = sorted(kept)
    out.setdefault("property_mappings", [])
    if invalid:
        out["onvolledige_velden"] = sorted(invalid)
    return out


def clean_application(a: dict[str, Any]) -> dict[str, Any]:
    return _pick(a, ("pk", "slug", "name", "provider", "meta_launch_url", "policy_engine_mode"))


def clean_group(g: dict[str, Any]) -> dict[str, Any]:
    out = _pick(g, ("pk", "name", "is_superuser"))
    members = g.get("users_obj")
    out["members"] = (
        sorted(str(u.get("username")) for u in members if isinstance(u, dict) and u.get("username"))
        if isinstance(members, list)
        else None
    )
    return out


def clean_user(u: dict[str, Any]) -> dict[str, Any]:
    # uid (= sha256(id + installatie-ID), de OIDC-sub bij sub_mode=hashed_user_id) en uuid: om de 'sub' van de Hub-client
    # te bepalen voor sso.access.* (contract 1.3 §7; authentik/core/models.py User.uid, providers/oauth2/id_token.py)
    out = _pick(u, ("pk", "username", "is_active", "is_superuser", "type", "uid", "uuid"))
    groups = u.get("groups_obj")
    out["groups"] = (
        sorted(str(g.get("name")) for g in groups if isinstance(g, dict) and g.get("name"))
        if isinstance(groups, list)
        else None
    )
    return out


def clean_flow(f: dict[str, Any]) -> dict[str, Any]:
    return _pick(f, ("pk", "slug", "designation", "name"))


def clean_scope_mapping(m: dict[str, Any]) -> dict[str, Any]:
    out = _pick(m, ("pk", "name", "managed", "scope_name"))
    expr = m.get("expression")
    out["expression_sha256"] = sha256_text(expr) if isinstance(expr, str) else None
    return out


def clean_signing_key(k: dict[str, Any]) -> dict[str, Any]:
    return _pick(k, ("pk", "name", "fingerprint_sha256", "cert_expiry", "private_key_available"))


def clean_brand(b: dict[str, Any]) -> dict[str, Any]:
    return _pick(
        b,
        (
            "brand_uuid",
            "domain",
            "default",
            "flow_authentication",
            "flow_invalidation",
            "flow_recovery",
            "web_certificate",
        ),
    )


def clean_blueprint(b: dict[str, Any]) -> dict[str, Any]:
    return _pick(b, ("pk", "name", "path", "enabled", "status", "last_applied_hash"))


def clean_outpost(o: dict[str, Any]) -> dict[str, Any]:
    out = _pick(o, ("pk", "name", "type", "managed"))
    out["providers"] = sorted(str(x) for x in o.get("providers") or [])
    return out


def clean_binding(b: dict[str, Any]) -> dict[str, Any]:
    out = _pick(b, ("pk", "target", "group", "order", "enabled", "negate"))
    out["kind"] = "groep" if b.get("group") else ("gebruiker" if b.get("user") else "beleid")
    return out


def clean_device(d: dict[str, Any]) -> dict[str, Any]:
    return _pick(d, ("type", "name", "confirmed"))


CLEANERS = {
    "providers": clean_provider,
    "applications": clean_application,
    "groups": clean_group,
    "users": clean_user,
    "flows": clean_flow,
    "scope_mappings": clean_scope_mapping,
    "signing_keys": clean_signing_key,
    "brands": clean_brand,
    "blueprints": clean_blueprint,
    "outposts": clean_outpost,
}


def redact_flow_export(text: str) -> str:
    """Regels met een geheim-achtige sleutel (password/secret/token/private_key/api_key) krijgen ``***``."""
    return "\n".join(FLOW_EXPORT_SECRET_LINE.sub(r"\1***", line) for line in text.splitlines())


# ------------------------------------------------------------------ detectie
def token_privileges(user: dict[str, Any]) -> dict[str, Any]:
    """Wat ``/core/users/me/`` over de rechten van het API-token zegt — en wat niet.

    Automatisch te controleren: superuser en de systeemrechten (``system_permissions``; in Authentik alleen de
    rechten van ``authentik_rbac``, zoals ``edit_system_settings``; authentik/core/api/users.py, tag version/2026.8.5).
    Alles behalve ``view_*`` telt als te ruim. **Niet** te controleren via dit endpoint: model-/objectrechten via rollen
    (bv. ``authentik_core.change_user``). Daarom is de uitkomst zonder bevinding ``deels_gecontroleerd`` en nooit
    ``ok``: dat de rollen van het serviceaccount alleen leesrechten geven, moet een beheerder op de echte installatie
    nagaan (B13-004, NIET GEVALIDEERD (account)).
    """
    superuser = bool(user.get("is_superuser"))
    raw = user.get("system_permissions")
    perms = sorted(_s(p) for p in raw if isinstance(p, str)) if isinstance(raw, list) else None
    too_wide = [p for p in perms or [] if not p.startswith("view_")]
    if superuser:
        verdict, msg = (
            "te_ruim",
            "Het API-token hoort bij een superuser. Gebruik een serviceaccount met alleen leesrechten "
            "(least privilege, B13-004).",
        )
    elif too_wide:
        verdict, msg = (
            "te_ruim",
            "Het API-token heeft systeemrechten die meer dan lezen toestaan ("
            + ", ".join(too_wide[:10])
            + "). Gebruik een serviceaccount met alleen leesrechten (least privilege, B13-004).",
        )
    elif perms is None:
        verdict, msg = (
            "onbekend",
            "Authentik gaf geen systeemrechten terug; de rechten van het token zijn niet vast te stellen.",
        )
    else:
        verdict, msg = (
            "deels_gecontroleerd",
            "Geen superuser en geen schrijvende systeemrechten. Rolrechten op objecten (RBAC) zijn via de API niet "
            "volledig te controleren: ga in Authentik na dat de rollen van dit serviceaccount alleen 'view'-rechten "
            "geven.",
        )
    return {
        "username": _s(user.get("username")),
        "is_superuser": superuser,
        "system_permissions": perms,
        "rbac_object_permissions": "niet_gecontroleerd",
        "least_privilege": verdict,
        "message_nl": msg,
    }


def detect(client: AuthentikClient) -> dict[str, Any]:
    """Bereikbaarheid, versie (``/admin/version/``), API-capabilities en de rechten van het token."""
    result: dict[str, Any] = {
        "observed_at": iso(utcnow()),
        "base_url": client.base_url,
        "health": {"ready": None},
        "version": None,
        "build_hash": None,
        "compat": compat.capabilities_for(None).to_dict(),
        "token": {"username": None, "is_superuser": None, "least_privilege": "onbekend"},
        "status": "unknown",
        "reason_code": None,
        "findings": [],
    }
    ready = client.health("ready")
    result["health"]["ready"] = ready
    try:
        version = client.get_json("/admin/version/", token_endpoint=True)
    except AuthentikError as exc:
        result["status"] = "down" if exc.reason in ("onbereikbaar", "timeout") else "degraded"
        result["reason_code"] = exc.reason
        result["error"] = exc.to_dict()
        return result
    raw = version.get("version_current") if isinstance(version, dict) else None
    caps = compat.capabilities_for(raw)
    result["version"] = caps.version
    result["build_hash"] = _s(version.get("build_hash")) if isinstance(version, dict) else None
    result["compat"] = caps.to_dict()
    findings: list[dict[str, str]] = []
    if not caps.readable:
        findings.append({"code": f"versie_{caps.support}", "message_nl": " ".join(caps.notes_nl)})
    elif caps.support != "geverifieerd":
        findings.append({"code": "versie_niet_geverifieerd", "message_nl": " ".join(caps.notes_nl)})
    try:
        me = client.get_json("/core/users/me/")
        user = me.get("user") if isinstance(me, dict) else None
        if isinstance(user, dict):
            result["token"] = token_privileges(user)
            verdict = result["token"]["least_privilege"]
            if verdict in ("te_ruim", "onbekend"):
                code = "token_te_ruim" if verdict == "te_ruim" else "token_rechten_onbekend"
                findings.append({"code": code, "message_nl": result["token"]["message_nl"]})
        else:
            findings.append(
                {"code": "token_rechten_onbekend", "message_nl": "Authentik gaf geen tokengebruiker terug."}
            )
    except AuthentikError as exc:
        findings.append({"code": f"token_rechten_{exc.reason}", "message_nl": exc.message_nl})
    if ready != 200:
        findings.append({"code": "niet_gereed", "message_nl": "Authentik meldt zich niet gereed (/-/health/ready/)."})
    result["findings"] = findings
    result["status"] = "healthy" if not findings and caps.support == "geverifieerd" else "degraded"
    result["reason_code"] = findings[0]["code"] if findings else None
    return result


# ------------------------------------------------------------------ toestand
@dataclass
class AuthentikState:
    version: str | None
    caps: compat.ApiCapabilities
    parts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    missing: list[dict[str, Any]] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return not self.missing

    def get(self, part: str) -> list[dict[str, Any]] | None:
        return self.parts.get(part)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "complete": self.complete,
            "missing": self.missing,
            **{k: v for k, v in self.parts.items()},
            **self.extra,
        }


def read_version(client: AuthentikClient) -> compat.ApiCapabilities:
    data = client.get_json("/admin/version/", token_endpoint=True)
    return compat.capabilities_for(data.get("version_current") if isinstance(data, dict) else None)


def read_state(
    client: AuthentikClient, parts: tuple[str, ...] = ALL_PARTS, caps: compat.ApiCapabilities | None = None
) -> AuthentikState:
    """Leest de gevraagde onderdelen. Een versiefout stopt alles (fail-closed); een onderdeelfout → ``missing``."""
    caps = caps or read_version(client)
    state = AuthentikState(caps.version, caps)
    if not caps.readable:
        state.missing.append({"part": "*", "reason": f"versie_{caps.support}"})
        return state
    for part in parts:
        path, params = PART_PATHS[part]
        try:
            rows, complete = client.list_all(path, params)
        except AuthentikError as exc:
            state.missing.append({"part": part, "reason": exc.reason, "http_status": exc.http_status})
            continue
        state.parts[part] = [CLEANERS[part](r) for r in rows]
        if part == "providers" and any(row.get("onvolledige_velden") for row in state.parts[part]):
            state.missing.append({"part": part, "reason": "providergegevens_onvolledig"})
        if not complete:
            state.missing.append({"part": part, "reason": "te_veel_paginas"})
    return state


def read_bindings(client: AuthentikClient, target: str) -> list[dict[str, Any]]:
    rows, complete = client.list_all("/policies/bindings/", {"target": target})
    if not complete:
        raise AuthentikError("antwoord_te_groot", 200, "/api/v3/policies/bindings/")
    return [clean_binding(r) for r in rows]


def read_devices(client: AuthentikClient, user_pk: Any) -> list[dict[str, Any]]:
    data = client.get_json("/authenticators/admin/all/", {"user": user_pk})
    if not isinstance(data, list):
        raise AuthentikError("antwoord_ongeldig", 200, "/api/v3/authenticators/admin/all/")
    return [clean_device(d) for d in data if isinstance(d, dict)]


def read_flow_export(client: AuthentikClient, slug: str) -> dict[str, Any]:
    text = client.get_text(f"/flows/instances/{slug}/export/")
    raw = text.encode("utf-8")
    if len(raw) > FLOW_EXPORT_MAX_BYTES:
        raise AuthentikError("antwoord_te_groot", 200, f"/api/v3/flows/instances/{slug}/export/")
    return {
        "slug": slug,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "redacted": redact_flow_export(text),
    }
