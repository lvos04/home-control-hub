"""Lezen uit Authentik: versiedetectie, least-privilege-controle en een **geschoonde** toestand.

Alles wat deze dienst uit Authentik bewaart of doorgeeft gaat door een *whitelist*: alleen genoemde velden, nooit
``client_secret``, sleutels, wachtwoorden, e-mailadressen of vrije ``attributes``. Ontbreekt een onderdeel (geen rechten,
time-out, te veel pagina's), dan staat het in ``missing`` en is de toestand ``complete=False`` — nooit "leeg = niets".
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

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
def clean_provider(p: dict[str, Any]) -> dict[str, Any]:
    out = _pick(
        p,
        (
            "pk",
            "name",
            "client_id",
            "client_type",
            "authorization_flow",
            "invalidation_flow",
            "signing_key",
            "sub_mode",
            "issuer_mode",
            "include_claims_in_id_token",
            "access_code_validity",
            "access_token_validity",
            "assigned_application_slug",
        ),
    )
    uris = p.get("redirect_uris")
    out["redirect_uris"] = (
        [
            {"matching_mode": _s(u.get("matching_mode")), "url": _s(u.get("url"))}
            for u in uris
            if isinstance(u, dict) and u.get("redirect_uri_type", "authorization") == "authorization"
        ]
        if isinstance(uris, list)
        else []
    )
    out["property_mappings"] = sorted(str(x) for x in p.get("property_mappings") or [])
    if isinstance(p.get("grant_types"), list):
        out["grant_types"] = sorted(str(x) for x in p["grant_types"])
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
    out = _pick(u, ("pk", "username", "is_active", "is_superuser", "type"))
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
            superuser = bool(user.get("is_superuser"))
            result["token"] = {
                "username": _s(user.get("username")),
                "is_superuser": superuser,
                "least_privilege": "te_ruim" if superuser else "ok",
            }
            if superuser:
                findings.append(
                    {
                        "code": "token_te_ruim",
                        "message_nl": "Het API-token hoort bij een superuser. Gebruik een serviceaccount met alleen "
                        "leesrechten (least privilege, B13-004).",
                    }
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
