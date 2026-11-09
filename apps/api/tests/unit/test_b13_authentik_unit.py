"""Unit B13-002…005: versies/upgradepad, Authentik-client (fail-closed), schoning, OIDC-voorstel, rechten-diff.

Alles tegen de in-repo nep-Authentik (``tests/fakes/authentik_fake.py``); geen echte Authentik of account.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from integrations.config import Settings
from integrations.domains.sso import authaudit
from integrations.domains.sso.authentik import compat
from integrations.domains.sso.authentik.client import AuthentikClient, AuthentikError
from integrations.domains.sso.authentik.reader import (
    ALL_PARTS,
    detect,
    read_flow_export,
    read_state,
    redact_flow_export,
)
from integrations.domains.sso.oidc_hub import HubOidcParams, build_hub_oidc_plan, check_https_url, check_hub_client
from tests.fakes.authentik_fake import CLIENT_SECRET, DEFAULT_TOKEN, FLOW_PASSWORD, AuthentikFake

V = compat.parse_version
REDIRECT = "https://hub.lan.invalid/api/v1/auth/oidc/callback"  # testwaarde (.invalid), geen echte NAS-waarde
HUB_GROUPS = [("hub-beheerders", "admin"), ("hub-lezers", "viewer"), ("hub-operators", "operator")]


def client(fake: AuthentikFake, token: str = DEFAULT_TOKEN, **kw: Any) -> AuthentikClient:
    return AuthentikClient(
        "http://authentik.test", token, Settings(), transport=fake.transport, sleep=lambda _s: None, **kw
    )


# ------------------------------------------------------------------ versies en upgradepad
@pytest.mark.parametrize(
    ("raw", "support"),
    [
        ("2026.8.5", "geverifieerd"),
        ("2026.8.9", "geverifieerd"),
        ("2024.10.1", "geverifieerd"),
        ("2027.2.0", "nieuwer_dan_geverifieerd"),
        ("2024.8.6", "te_oud"),
        ("2026.3.1", "onbekende_lijn"),
        ("2026.8.0-rc1", "onleesbaar"),
        ("latest", "onleesbaar"),
        (None, "onleesbaar"),
    ],
)
def test_version_support(raw: Any, support: str) -> None:
    caps = compat.capabilities_for(raw)
    assert caps.support == support
    assert caps.proposals_allowed == (support == "geverifieerd")
    assert caps.readable == (support in ("geverifieerd", "nieuwer_dan_geverifieerd"))


def test_version_dependent_api_features_follow_the_schemas() -> None:
    assert (
        not compat.capabilities_for("2026.2.7").oauth2_grant_types
        and compat.capabilities_for("2026.5.0").oauth2_grant_types
    )
    assert not compat.capabilities_for("2025.6.4").events_multi_action_filter
    assert compat.capabilities_for("2025.8.0").events_multi_action_filter


@pytest.mark.parametrize(
    ("current", "target", "status", "code", "nxt"),
    [
        ("2026.8.5", "2026.5.8", "fout", "downgrade", None),
        ("2026.8.5", "2026.8.5", "fout", "zelfde_versie", None),
        ("2026.5.2", "2026.5.8", "ok", "patch_binnen_lijn", None),
        ("2026.5.8", "2026.8.5", "ok", "volgende_lijn", None),
        ("2026.5.2", "2026.8.5", "fout", "eerst_nieuwste_patch", "2026.5.8"),
        ("2025.12.6", "2026.8.5", "fout", "lijn_overgeslagen", "2026.2.7"),
        ("2025.12.1", "2026.8.5", "fout", "lijn_overgeslagen", "2025.12.6"),
        ("2026.8.5", "2026.8.99", "onbekend", "patch_onbekend", None),
        ("2026.8.5", "2026.11.1", "onbekend", "lijn_onbekend", None),
    ],
)
def test_upgrade_path_follows_official_rules(
    current: str, target: str, status: str, code: str, nxt: str | None
) -> None:
    c, t = V(current), V(target)
    assert c is not None and t is not None
    result = compat.check_upgrade_path(c, t)
    assert (result.status, result.code, result.next_step) == (status, code, nxt)


# ------------------------------------------------------------------ client: fail-closed, geen token-lek
def test_client_reads_paginated_and_never_follows_redirects() -> None:
    fake = AuthentikFake()
    for i in range(7):
        fake.add_group(f"extra-{i}", [])
    rows, complete = client(fake).list_all("/core/groups/", page_size=3)
    assert complete and len(rows) == len(fake.groups)
    rows, complete = client(fake).list_all("/core/groups/", page_size=3, max_pages=2)
    assert not complete and len(rows) == 6  # nooit stil afkappen alsof dat alles was
    fake.redirect.add("/api/v3/core/groups/")
    with pytest.raises(AuthentikError) as exc:
        client(fake).list_all("/core/groups/")
    assert exc.value.reason == "redirect"
    assert DEFAULT_TOKEN not in repr(client(fake))


def test_client_error_reasons() -> None:
    fake = AuthentikFake()
    with pytest.raises(AuthentikError) as exc:
        client(fake, token="fout-token").get_json("/admin/version/", token_endpoint=True)
    assert exc.value.reason == "token_ongeldig"
    fake.forbidden.add("/api/v3/core/users/")
    with pytest.raises(AuthentikError) as exc:
        client(fake).get_json("/core/users/")
    assert exc.value.reason == "geen_rechten"
    fake.fail["/api/v3/core/groups/"] = 503
    with pytest.raises(AuthentikError) as exc:
        client(fake).get_json("/core/groups/")
    assert exc.value.reason == "http_5xx"
    fake.timeouts.add("/api/v3/flows/instances/")
    calls = len(fake.calls)
    with pytest.raises(AuthentikError) as exc:
        client(fake).get_json("/flows/instances/")
    assert exc.value.reason == "timeout" and len(fake.calls) - calls == 3  # max. 3 pogingen (contract §5)
    fake.up = False
    with pytest.raises(AuthentikError) as exc:
        client(fake).get_json("/core/groups/")
    assert exc.value.reason == "onbereikbaar"


def test_client_refuses_oversized_answers() -> None:
    fake = AuthentikFake()
    with pytest.raises(AuthentikError) as exc:
        client(fake, max_bytes=200).get_json("/core/users/")
    assert exc.value.reason == "antwoord_te_groot"


def test_health_is_called_without_token() -> None:
    fake = AuthentikFake()
    assert client(fake).health("ready") == 200
    assert ("GET", "/-/health/ready/", False) in fake.calls
    fake.ready = False
    assert client(fake).health("ready") == 503


# ------------------------------------------------------------------ schoning (whitelist) en detectie
def test_state_is_sanitized_whitelist_only() -> None:
    fake = AuthentikFake()
    state = read_state(client(fake), ALL_PARTS)
    assert state.complete
    text = json.dumps(state.to_dict())
    for secret in (CLIENT_SECRET, "nooit-bewaren", "@voorbeeld.invalid", "view_private_key", "ak-outpost-x", "nooit"):
        assert secret not in text
    providers = state.parts["providers"]
    assert providers and all("client_secret" not in p for p in providers)
    assert all("attributes" not in u and "email" not in u for u in state.parts["users"])
    exp = read_flow_export(client(fake), "default-authentication-flow")
    assert FLOW_PASSWORD not in exp["redacted"] and "password: ***" in exp["redacted"] and len(exp["sha256"]) == 64


def test_redact_flow_export_lines() -> None:
    text = "attrs:\n  password: x\n  api_key: y\n  secret_key: z\n  name: zichtbaar\n  - private_key: k"
    out = redact_flow_export(text)
    assert "x" not in out.split("password:")[1].split("\n")[0] and "name: zichtbaar" in out
    assert out.count("***") == 4


def test_state_missing_part_is_incomplete_not_empty() -> None:
    fake = AuthentikFake()
    fake.forbidden.add("/api/v3/core/users/")
    state = read_state(client(fake), ("users", "groups"))
    assert not state.complete and state.get("users") is None and state.get("groups")
    assert state.missing == [{"part": "users", "reason": "geen_rechten", "http_status": 403}]


def test_detect_version_and_least_privilege() -> None:
    fake = AuthentikFake()
    d = detect(client(fake))
    assert d["version"] == "2026.8.5" and d["status"] == "healthy"
    # nooit 'ok': rolrechten op objecten zijn via /core/users/me/ niet te controleren (eerlijk 'deels')
    assert d["token"]["least_privilege"] == "deels_gecontroleerd"
    assert d["token"]["rbac_object_permissions"] == "niet_gecontroleerd"
    assert d["token"]["system_permissions"] == ["view_system_info"]
    fake.token_user = {"pk": 1, "username": "akadmin", "is_superuser": True, "system_permissions": []}
    d = detect(client(fake))
    assert d["status"] == "degraded" and d["reason_code"] == "token_te_ruim"
    assert d["token"]["least_privilege"] == "te_ruim"
    fake.version = "2027.2.1"
    assert detect(client(fake))["compat"]["support"] == "nieuwer_dan_geverifieerd"
    d = detect(client(fake, token="fout"))
    assert d["status"] == "degraded" and d["reason_code"] == "token_ongeldig" and d["version"] is None
    fake.up = False
    assert detect(client(fake))["status"] == "down"


@pytest.mark.parametrize(
    ("user", "verdict"),
    [
        ({"is_superuser": False, "system_permissions": []}, "deels_gecontroleerd"),
        (
            {"is_superuser": False, "system_permissions": ["view_system_info", "view_system_settings"]},
            "deels_gecontroleerd",
        ),
        ({"is_superuser": False, "system_permissions": ["view_system_info", "edit_system_settings"]}, "te_ruim"),
        ({"is_superuser": False, "system_permissions": ["manage_media_files"]}, "te_ruim"),
        ({"is_superuser": False, "system_permissions": ["access_admin_interface"]}, "te_ruim"),
        ({"is_superuser": True, "system_permissions": []}, "te_ruim"),
        ({"is_superuser": False}, "onbekend"),
        ({"is_superuser": False, "system_permissions": "alles"}, "onbekend"),
    ],
)
def test_token_privileges_never_claims_full_least_privilege(user: dict[str, Any], verdict: str) -> None:
    fake = AuthentikFake()
    fake.token_user = {"pk": 90, "username": "hch-lezer", **user}
    d = detect(client(fake))
    assert d["token"]["least_privilege"] == verdict
    assert d["token"]["least_privilege"] != "ok"
    if verdict == "deels_gecontroleerd":
        assert d["status"] == "healthy" and "rollen" in d["token"]["message_nl"]
    else:
        assert d["status"] == "degraded"
        assert d["reason_code"] == ("token_te_ruim" if verdict == "te_ruim" else "token_rechten_onbekend")


# ------------------------------------------------------------------ B13-002: voorstel en controle
def _plan(fake: AuthentikFake, groups: list[tuple[str, str]] = HUB_GROUPS, **params: Any) -> Any:
    c = client(fake)
    state = read_state(c, ("flows", "scope_mappings", "signing_keys", "providers", "applications", "groups"))
    p = HubOidcParams(redirect_uris=(REDIRECT,), **params)
    app = next((a for a in state.parts["applications"] if a["slug"] == p.application_slug), None)
    bindings = None if app is None else [b for b in fake.bindings if b["target"] == app["pk"]]
    return build_hub_oidc_plan(state, p, groups, bindings)


def test_hub_oidc_plan_creates_provider_app_and_group_bindings() -> None:
    fake = AuthentikFake()
    plan = _plan(fake)
    assert not plan.blockers and plan.risk_claim == "R2" and plan.requires_backup
    ops = [(d["object"], d["operation"]) for d in plan.diff]
    assert ops == [("oauth2_provider", "aanmaken"), ("application", "aanmaken")] + [("policy_binding", "aanmaken")] * 3
    body = plan.requests[0]["body"]
    assert body["client_type"] == "confidential" and body["redirect_uris"] == [
        {"matching_mode": "strict", "url": REDIRECT}
    ]
    assert body["grant_types"] == ["authorization_code"] and body["issuer_mode"] == "per_provider"
    assert "client_secret" not in json.dumps(plan.requests) and "client_id" not in body
    assert [r["method"] for r in plan.requests] == ["POST"] * 5
    assert plan.rollback_recipe[-1]["path"].startswith("/api/v3/providers/oauth2/")
    assert plan.blast_radius["local_login_unchanged"] and plan.blast_radius["users_with_access"] == 4
    assert len(plan.preview_hash) == 64 and plan.preview_hash == _plan(fake).preview_hash  # deterministisch
    fake.set_members("hub-lezers", ["carla"])  # meer/minder gebruikers met toegang: andere preview (blast radius)
    fewer = _plan(fake)
    assert fewer.preview_hash != plan.preview_hash and fewer.resource_etag == plan.resource_etag
    fake.add_hub_app("hub")  # de te wijzigen objecten veranderen → andere resource_etag
    fake.providers[-1]["name"] = "Hub (OIDC)"
    other = _plan(fake)
    assert other.resource_etag != plan.resource_etag and other.preview_hash != plan.preview_hash


def test_hub_oidc_plan_respects_version_features() -> None:
    plan = _plan(AuthentikFake(version="2025.10.4"))
    assert "grant_types" not in plan.requests[0]["body"] and any("grant_types" in n for n in plan.notes_nl)


def test_hub_oidc_plan_blockers_never_overwrite() -> None:
    fake = AuthentikFake()
    assert {b["code"] for b in _plan(fake, groups=[]).blockers} == {"geen_groepen_gekoppeld"}
    assert {b["code"] for b in _plan(fake, groups=[("bestaat-niet", "admin")]).blockers} == {"groep_ontbreekt"}
    assert {b["code"] for b in _plan(fake, application_slug="immich").blockers} == {"slug_in_gebruik"}
    assert {b["code"] for b in _plan(fake, provider_name="Immich").blockers} == {"providernaam_in_gebruik"}
    assert {b["code"] for b in _plan(fake, application_slug="token").blockers} == {"slug_gereserveerd"}
    assert {b["code"] for b in _plan(fake, authorization_flow_slug="nee").blockers} == {"autorisatieflow_ontbreekt"}
    fake.keys.append({**fake.keys[0], "pk": "k2", "name": "Tweede"})
    blockers = _plan(fake).blockers
    assert [b["code"] for b in blockers] == ["kies_ondertekeningssleutel"] and blockers[0]["choices"] == [
        "Tweede",
        "authentik Self-signed Certificate",
    ]
    assert not _plan(fake, signing_key_name="Tweede").blockers


def test_hub_oidc_plan_updates_existing_client_and_is_unchanged_when_equal() -> None:
    fake = AuthentikFake()
    fake.add_hub_app("hub", redirect="https://oud.lan.invalid/cb")
    fake.providers[-1]["name"] = "Hub (OIDC)"
    plan = _plan(fake)
    prov = plan.diff[0]
    assert prov["operation"] == "wijzigen" and {c["field"] for c in prov["changes"]} >= {"redirect_uris"}
    assert plan.requests[0]["method"] == "PATCH" and "redirect_uris" in plan.requests[0]["body"]
    assert plan.rollback_recipe[-1]["body"]["redirect_uris"] == [
        {"matching_mode": "strict", "url": "https://oud.lan.invalid/cb"}
    ]


@pytest.mark.parametrize(
    "url",
    [
        "http://hub.lan.invalid/cb",
        "https://localhost/cb",
        "https://u:p@hub.invalid/cb",
        "https://hub.invalid/*",
        "https://hub.invalid/cb#x",
    ],
)
def test_redirect_uri_must_be_strict_https(url: str) -> None:
    with pytest.raises(ValueError):
        check_https_url(url, "redirect_uri")


def test_check_existing_hub_client_flags_open_access() -> None:
    fake = AuthentikFake()
    fake.add_hub_app()
    c = client(fake)
    state = read_state(c, ("applications", "providers", "scope_mappings", "groups"))
    disc = c.get_public_json("/application/o/hub/.well-known/openid-configuration")
    res = check_hub_client(state, "hub", [REDIRECT], [], disc, None, HUB_GROUPS)
    status = {x["name"]: x["status"] for x in res["checks"]}
    assert status["toegang"] == "afwijking" and status["pkce_s256"] == "ok" and status["issuer"] == "ok"
    assert status["redirect_uris"] == "ok" and status["scopes"] == "ok" and res["outcome"] == "afwijking"
    res = check_hub_client(state, "hub", None, None, None, "onbereikbaar", HUB_GROUPS)
    assert res["outcome"] == "onbekend"


def test_check_hub_client_access_is_never_ok_on_weak_bindings() -> None:
    """Review P1: uitgeschakelde of omgekeerde bindingen beperken niets; ontbrekende groepen zijn geen 'ok'."""
    fake = AuthentikFake()
    fake.add_hub_app()
    c = client(fake)
    state = read_state(c, ("applications", "providers", "scope_mappings", "groups"))
    gpk = {g["name"]: g["pk"] for g in state.parts["groups"]}
    app_pk = next(a["pk"] for a in state.parts["applications"] if a["slug"] == "hub")

    def binding(group: str, **kw: Any) -> dict[str, Any]:
        return {"pk": f"b-{group}", "target": app_pk, "group": gpk[group], "kind": "groep", "enabled": True, **kw}

    def access(bindings: list[dict[str, Any]] | None, groups: list[tuple[str, str]] = HUB_GROUPS) -> tuple[str, Any]:
        res = check_hub_client(state, "hub", None, bindings, None, "niet_opgehaald", groups)
        check = next(x for x in res["checks"] if x["name"] == "toegang")
        return check["status"], check["detail"]

    every = [binding(g) for g, _r in HUB_GROUPS]
    assert access(every)[0] == "ok"
    assert access([{**b, "enabled": False} for b in every])[0] == "afwijking"  # alles uit = open voor iedereen
    assert access([{**b, "negate": True} for b in every])[0] == "afwijking"  # 'iedereen behalve' = open
    assert access(every[:2])[0] == "afwijking"  # een gekoppelde groep is niet gebonden
    status, detail = access(every, [*HUB_GROUPS, ("bestaat-niet", "admin")])
    assert status == "afwijking" and detail["missing_groups"] == ["bestaat-niet"]
    assert access(every, [])[0] == "onbekend"  # zonder groep→rol-koppeling niet te beoordelen
    assert access(None)[0] == "onbekend"
    no_groups = read_state(c, ("applications", "providers", "scope_mappings"))
    res = check_hub_client(no_groups, "hub", None, every, None, "niet_opgehaald", HUB_GROUPS)
    assert next(x for x in res["checks"] if x["name"] == "toegang")["status"] == "onbekend"


# ------------------------------------------------------------------ B13-004: rechtenkaart en events
def test_rights_diff_detects_gain_loss_and_deactivation() -> None:
    role_map = {"hub-beheerders": {"ai-server-manager": ["admin"]}, "hub-lezers": {"ai-server-manager": ["viewer"]}}
    groups = [{"name": "hub-beheerders"}, {"name": "hub-lezers"}, {"name": "authentik Admins", "is_superuser": True}]
    before = authaudit.build_rights(
        [
            {"username": "anna", "is_active": True, "groups": ["hub-beheerders"]},
            {"username": "kim", "is_active": True, "groups": ["hub-lezers"]},
        ],
        groups,
        role_map,
    )
    after = authaudit.build_rights(
        [
            {"username": "anna", "is_active": False, "groups": ["hub-beheerders"]},
            {"username": "kim", "is_active": True, "groups": ["hub-lezers", "hub-beheerders", "authentik Admins"]},
        ],
        groups,
        role_map,
    )
    diff = {d["username"]: d for d in authaudit.diff_rights(before, after)}
    assert diff["anna"]["roles_lost"] == {"ai-server-manager": ["admin"]} and diff["anna"]["active_after"] is False
    assert diff["kim"]["roles_gained"] == {"ai-server-manager": ["admin"]} and diff["kim"]["superuser_after"]


def test_old_versions_filter_events_per_action() -> None:
    """Vóór 2025.8 negeert Authentik ?actions=; dan zou álles terugkomen. Deze dienst vraagt dan per actie."""
    fake = AuthentikFake(version="2025.6.4")
    fake.add_event("login", "anna")
    fake.add_event("email_sent", "anna")
    caps = compat.capabilities_for(fake.version)
    evs, complete, wm = authaudit.fetch_new_events(client(fake), caps, {"created": "2026-11-08T00:00:00+00:00"})
    assert complete and [e["action"] for e in evs] == ["login"]
    assert wm["pks_at"] == [evs[0]["pk"]]
    queries = [p for (m, p, _a) in fake.calls if p == "/api/v3/events/events/"]
    assert len(queries) == len(authaudit.EVENT_ACTIONS)
    again, _c, _wm = authaudit.fetch_new_events(client(fake), caps, wm)
    assert again == []  # watermerk: niets dubbel


def test_event_paging_stops_and_reports_incomplete() -> None:
    fake = AuthentikFake()
    for i in range(authaudit.MAX_PAGES * 100 + 5):
        fake.add_event("login_failed", "bram", minutes_ago=i / 100)
    evs, complete, _wm = authaudit.fetch_new_events(
        client(fake), compat.capabilities_for(fake.version), {"created": "2020-01-01T00:00:00+00:00"}
    )
    assert not complete and len(evs) == authaudit.MAX_PAGES * 100


def test_httpx_transport_is_the_only_network_path() -> None:
    """De client gebruikt alleen de meegegeven transport (tests raken nooit het netwerk)."""
    fake = AuthentikFake(host="ander.test")
    with pytest.raises(AuthentikError):
        AuthentikClient(
            "http://authentik.test",
            DEFAULT_TOKEN,
            Settings(),
            transport=httpx.MockTransport(fake.handle),
            sleep=lambda _s: None,
        ).get_json("/admin/version/")


def test_login_failed_uses_attempted_username_from_context() -> None:
    """Authentik zet bij login_failed de geprobeerde naam in context.username; bij een onbekende naam is 'user'
    AnonymousUser (authentik/events/signals.py, 2026.8.5)."""
    from integrations.domains.sso.authaudit import _event_username

    assert _event_username("login_failed", {"username": "AnonymousUser"}, {"username": "aanvaller"}) == "aanvaller"
    assert _event_username("login", {"username": "anna"}, {}) == "anna"
    assert _event_username("login", {"username": "AnonymousUser"}, {}) is None
    fake = AuthentikFake()
    ev = fake.add_event("login_failed", "bestaat-niet")
    assert ev["user"]["username"] == "AnonymousUser" and ev["context"]["username"] == "bestaat-niet"
