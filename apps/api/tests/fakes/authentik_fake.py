"""Nep-Authentik voor tests (ALLEEN tests; geen productiecode, geen echte Authentik).

Bootst het deel van de officiële Authentik-API (``/api/v3``) na dat home-control-hub gebruikt, met de vorm uit de
officiële ``schema.yml`` (paginering ``{"pagination": {"next": n|0, …}, "results": […]}``, veldnamen, filters) en de
niet-API-routes ``/-/health/{live,ready}/`` en ``/application/o/<slug>/.well-known/openid-configuration``.

- Ongeldig token → 403 (zoals Authentik's TokenAuthentication zonder ``WWW-Authenticate``).
- Versieafhankelijk: ``grant_types`` pas vanaf 2026.5; ``?actions=`` pas vanaf 2025.8 — oudere versies **negeren**
  een onbekende filter (zoals Django REST Framework), en geven dan dus álle events terug.
- Elke niet-GET op ``/api/v3`` wordt vastgelegd in ``writes`` en geweigerd: deze dienst schrijft in deze versie nooit.
- Bevat bewust geheimen (``client_secret``, wachtwoord in een flow-export, ``attributes``) om de schoning te testen.

Bruikbaar als ``httpx.MockTransport(fake.handle)`` (in-process) en via ``asgi_app(fake)`` als echte HTTP-dienst (E2E).
Zonder imports uit het testpakket, zodat de E2E-simulator dit bestand los kan laden.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

NS = uuid.UUID("6f1c2d3e-0000-4000-8000-00000000a7a7")
DEFAULT_TOKEN = "ak-nep-token-" + "0123456789abcdef" * 3
CLIENT_SECRET = "nep-client-secret-" + "f" * 40
FLOW_PASSWORD = "nep-smtp-wachtwoord-123"


def _id(name: str) -> str:
    return str(uuid.uuid5(NS, name))


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _line(version: str) -> tuple[int, int]:
    y, m, *_ = version.split(".")
    return int(y), int(m)


class AuthentikFake:
    def __init__(self, version: str = "2026.8.5", token: str = DEFAULT_TOKEN, host: str = "authentik.test") -> None:
        self.version = version
        self.token = token
        self.host = host
        self.base = f"http://{host}"
        self.up = True
        self.ready = True
        self.forbidden: set[str] = set()
        self.fail: dict[str, int] = {}
        self.timeouts: set[str] = set()
        self.redirect: set[str] = set()
        self.calls: list[tuple[str, str, bool]] = []
        self.writes: list[tuple[str, str]] = []
        self.token_user: dict[str, Any] = {"pk": 90, "username": "hch-lezer", "is_superuser": False}
        self.now = datetime.now(UTC).replace(microsecond=0)  # events liggen altijd rond 'nu'
        self._seed()

    # ------------------------------------------------------------------ begintoestand (lijkt op een verse installatie)
    def _seed(self) -> None:
        self.flows = [
            self._flow("default-authentication-flow", "authentication"),
            self._flow("default-provider-authorization-explicit-consent", "authorization"),
            self._flow("default-provider-authorization-implicit-consent", "authorization"),
            self._flow("default-provider-invalidation-flow", "invalidation"),
            self._flow("default-invalidation-flow", "invalidation"),
            self._flow("default-recovery-flow", "recovery"),
        ]
        self.scope_mappings = [
            self._scope("openid", "goauthentik.io/providers/oauth2/scope-openid", "return {}"),
            self._scope("email", "goauthentik.io/providers/oauth2/scope-email", "return {'email': request.user.email}"),
            self._scope(
                "profile",
                "goauthentik.io/providers/oauth2/scope-profile",
                "return {'groups': [group.name for group in request.user.groups.all()]}",
            ),
            self._scope("offline_access", "goauthentik.io/providers/oauth2/scope-offline_access", "return {}"),
        ]
        self.keys = [
            {
                "pk": _id("key-self-signed"),
                "name": "authentik Self-signed Certificate",
                "fingerprint_sha256": "aa:bb:cc:dd",
                "fingerprint_sha1": "aa:bb",
                "cert_expiry": "2027-11-09T00:00:00Z",
                "cert_subject": "CN=authentik",
                "private_key_available": True,
                "key_type": "rsa",
                "certificate_download_url": "/api/v3/crypto/certificatekeypairs/x/view_certificate/",
                "private_key_download_url": "/api/v3/crypto/certificatekeypairs/x/view_private_key/",
                "managed": None,
            }
        ]
        names = [("akadmin", 1), ("anna", 2), ("bram", 3), ("carla", 4), ("kim", 5), ("nood-ak", 6)]
        self.users: dict[str, dict[str, Any]] = {
            n: {
                "pk": pk,
                "username": n,
                "name": n.title(),
                "is_active": True,
                "email": f"{n}@voorbeeld.invalid",
                "attributes": {"api_secret": "nooit-bewaren"},
                "type": "internal",
                "uuid": _id("user-" + n),
            }
            for n, pk in names
        }
        self.users["hch-lezer"] = {
            "pk": 90,
            "username": "hch-lezer",
            "name": "home-control-hub (alleen lezen)",
            "is_active": True,
            "email": "",
            "attributes": {},
            "type": "service_account",
            "uuid": _id("user-hch-lezer"),
        }
        self.groups: dict[str, dict[str, Any]] = {}
        for gname, superuser, members in (
            ("authentik Admins", True, ["akadmin"]),
            ("hub-beheerders", False, ["anna"]),
            ("hub-operators", False, ["bram"]),
            ("hub-lezers", False, ["carla", "kim"]),
            ("immich-gebruikers", False, ["anna", "kim"]),
        ):
            self.groups[gname] = {
                "pk": _id("group-" + gname),
                "num_pk": len(self.groups) + 1,
                "name": gname,
                "is_superuser": superuser,
                "attributes": {"notitie": "x"},
                "members": list(members),
            }
        immich_provider = {
            "pk": 11,
            "name": "Immich",
            "authentication_flow": None,
            "authorization_flow": self._flow_pk("default-provider-authorization-implicit-consent"),
            "invalidation_flow": self._flow_pk("default-provider-invalidation-flow"),
            "property_mappings": [m["pk"] for m in self.scope_mappings[:3]],
            "component": "ak-provider-oauth2-form",
            "client_type": "confidential",
            "client_id": "immich-client-id",
            "client_secret": CLIENT_SECRET,
            "access_code_validity": "minutes=1",
            "access_token_validity": "minutes=5",
            "refresh_token_validity": "days=30",
            "include_claims_in_id_token": True,
            "signing_key": self.keys[0]["pk"],
            "encryption_key": None,
            "redirect_uris": [{"matching_mode": "strict", "url": "https://immich.lan.invalid/auth/login"}],
            "sub_mode": "hashed_user_id",
            "issuer_mode": "per_provider",
            "jwt_federation_sources": [],
            "jwt_federation_providers": [],
        }
        self.providers: list[dict[str, Any]] = [immich_provider]
        self.applications: list[dict[str, Any]] = [
            {
                "pk": _id("app-immich"),
                "name": "Immich",
                "slug": "immich",
                "provider": 11,
                "meta_launch_url": "https://immich.lan.invalid/",
                "policy_engine_mode": "any",
                "group": "",
                "open_in_new_tab": False,
            }
        ]
        self.bindings: list[dict[str, Any]] = []
        self.brands = [
            {
                "brand_uuid": _id("brand-default"),
                "domain": "authentik-default",
                "default": True,
                "flow_authentication": self._flow_pk("default-authentication-flow"),
                "flow_invalidation": self._flow_pk("default-invalidation-flow"),
                "flow_recovery": self._flow_pk("default-recovery-flow"),
                "web_certificate": self.keys[0]["pk"],
                "attributes": {"geheim": "nooit"},
            }
        ]
        self.blueprints = [
            {
                "pk": _id("bp-providers-oauth2"),
                "name": "System - OAuth2 Provider - Scopes",
                "path": "system/providers-oauth2.yaml",
                "enabled": True,
                "status": "successful",
                "last_applied_hash": "abc123",
                "content": "",
                "context": {},
            }
        ]
        self.outposts = [
            {
                "pk": _id("outpost-embedded"),
                "name": "authentik Embedded Outpost",
                "type": "proxy",
                "providers": [],
                "managed": "goauthentik.io/outposts/embedded",
                "config": {"authentik_host": "http://authentik.test"},
                "token_identifier": "ak-outpost-x",
            }
        ]
        self.devices: dict[str, list[dict[str, Any]]] = {
            "akadmin": [
                {
                    "pk": "1",
                    "name": "Telefoon",
                    "type": "authentik_stages_authenticator_totp.totpdevice",
                    "confirmed": True,
                },
                {
                    "pk": "2",
                    "name": "Sleutel",
                    "type": "authentik_stages_authenticator_webauthn.webauthndevice",
                    "confirmed": True,
                },
            ],
            "anna": [
                {
                    "pk": "3",
                    "name": "Telefoon",
                    "type": "authentik_stages_authenticator_totp.totpdevice",
                    "confirmed": True,
                }
            ],
        }
        self.sessions = [
            {
                "uuid": _id("sess-anna"),
                "user": 2,
                "last_ip": "10.1.1.5",
                "last_used": _iso(self.now),
                "expires": _iso(self.now + timedelta(hours=8)),
            },
            {
                "uuid": _id("sess-kim"),
                "user": 5,
                "last_ip": "10.1.1.6",
                "last_used": _iso(self.now),
                "expires": _iso(self.now + timedelta(hours=8)),
            },
        ]
        self.events: list[dict[str, Any]] = []

    def _flow(self, slug: str, designation: str) -> dict[str, Any]:
        return {
            "pk": _id("flow-" + slug),
            "slug": slug,
            "name": slug.replace("-", " ").title(),
            "title": slug,
            "designation": designation,
        }

    def _flow_pk(self, slug: str) -> str:
        return next(f["pk"] for f in self.flows if f["slug"] == slug)

    def _scope(self, scope: str, managed: str, expr: str) -> dict[str, Any]:
        return {
            "pk": _id("scope-" + scope),
            "managed": managed,
            "name": f"authentik default OAuth Mapping: OpenID '{scope}'",
            "expression": expr,
            "scope_name": scope,
            "description": "",
        }

    # ------------------------------------------------------------------ hulpmiddelen voor tests
    def add_event(
        self,
        action: str,
        username: str | None = None,
        *,
        minutes_ago: float = 0,
        client_ip: str | None = "10.1.1.5",
        context: dict[str, Any] | None = None,
        app: str = "authentik.events.signals",
    ) -> dict[str, Any]:
        created = self.now - timedelta(minutes=minutes_ago)
        user = self.users.get(username or "", {})
        ctx = dict(context or {})
        if username and username not in self.users:
            ev_user: dict[str, Any] = {"pk": -1, "username": "AnonymousUser", "email": ""}
        else:
            ev_user = {"pk": user.get("pk"), "username": username, "email": user.get("email")} if username else {}
        if action == "login_failed":  # zoals authentik/events/signals.py: geprobeerde naam in de context
            ctx.setdefault("username", username)
            ctx.setdefault("password", "********************")
        ev = {
            "pk": str(uuid.uuid4()),
            "user": ev_user,
            "action": action,
            "app": app,
            "context": ctx,
            "client_ip": client_ip,
            "created": _iso(created),
            "expires": _iso(created + timedelta(days=365)),
            "brand": {"pk": "x", "app": "authentik_brands", "name": "Default", "model_name": "brand"},
        }
        self.events.append(ev)
        return ev

    def set_members(self, group: str, members: list[str]) -> None:
        self.groups[group]["members"] = list(members)

    def add_group(self, name: str, members: list[str], superuser: bool = False) -> None:
        self.groups[name] = {
            "pk": _id("group-" + name),
            "num_pk": len(self.groups) + 1,
            "name": name,
            "is_superuser": superuser,
            "attributes": {},
            "members": list(members),
        }

    def add_hub_app(
        self, slug: str = "hub", redirect: str = "https://hub.lan.invalid/api/v1/auth/oidc/callback"
    ) -> None:
        """Simuleert een Hub-client die een beheerder handmatig in Authentik aanmaakte."""
        pk = 20 + len(self.providers)
        self.providers.append(
            {
                "pk": pk,
                "name": "Hub",
                "authentication_flow": None,
                "authorization_flow": self._flow_pk("default-provider-authorization-explicit-consent"),
                "invalidation_flow": self._flow_pk("default-provider-invalidation-flow"),
                "property_mappings": [m["pk"] for m in self.scope_mappings[:3]],
                "client_type": "confidential",
                "client_id": "hub-client-id",
                "client_secret": CLIENT_SECRET,
                "access_code_validity": "minutes=1",
                "access_token_validity": "minutes=5",
                "include_claims_in_id_token": True,
                "signing_key": self.keys[0]["pk"],
                "redirect_uris": [{"matching_mode": "strict", "url": redirect}],
                "sub_mode": "hashed_user_id",
                "issuer_mode": "per_provider",
            }
        )
        self.applications.append(
            {
                "pk": _id("app-" + slug),
                "name": "Hub",
                "slug": slug,
                "provider": pk,
                "meta_launch_url": "",
                "policy_engine_mode": "any",
                "group": "",
            }
        )

    # ------------------------------------------------------------------ HTTP
    def handle(self, request: httpx.Request) -> httpx.Response:
        if request.url.host != self.host:
            raise httpx.ConnectError("onbekende host", request=request)
        if not self.up:
            raise httpx.ConnectError("authentik offline", request=request)
        path, method = request.url.path, request.method
        auth = request.headers.get("Authorization")
        self.calls.append((method, path, auth is not None))
        if path in self.timeouts:
            raise httpx.ReadTimeout("te traag", request=request)
        if path in self.redirect:
            return httpx.Response(302, headers={"Location": "http://elders.invalid/"})
        if path == "/-/health/live/":
            return httpx.Response(200)
        if path == "/-/health/ready/":
            return httpx.Response(200 if self.ready else 503)
        m = re.match(r"^/application/o/([^/]+)/\.well-known/openid-configuration$", path)
        if m:
            return self._discovery(m.group(1))
        if not path.startswith("/api/v3/"):
            return httpx.Response(404)
        if method != "GET":
            self.writes.append((method, path))
            return httpx.Response(403, json={"detail": "nep-Authentik: schrijven is in deze test niet toegestaan"})
        if auth != f"Bearer {self.token}":
            return httpx.Response(403, json={"detail": "Token invalid/expired"})
        if path in self.fail:
            return httpx.Response(self.fail[path], json={"detail": "nep-fout"})
        if path in self.forbidden:
            return httpx.Response(403, json={"detail": "You do not have permission to perform this action."})
        q = request.url.params
        sub = path[len("/api/v3") :]
        if sub == "/admin/version/":
            return httpx.Response(
                200,
                json={
                    "version_current": self.version,
                    "version_latest": self.version,
                    "version_latest_valid": True,
                    "build_hash": "nepbuild",
                    "outdated": False,
                    "outpost_outdated": False,
                },
            )
        if sub == "/core/users/me/":
            return httpx.Response(200, json={"user": {**self.token_user, "groups": [], "is_active": True}, "users": []})
        mexp = re.match(r"^/flows/instances/([^/]+)/export/$", sub)
        if mexp:
            return self._export(mexp.group(1))
        if sub == "/authenticators/admin/all/":
            user = next((u for u in self.users.values() if str(u["pk"]) == q.get("user")), None)
            return httpx.Response(200, json=self.devices.get(user["username"], []) if user else [])
        lists = {
            "/core/users/": self._users,
            "/core/groups/": self._groups,
            "/flows/instances/": lambda q: self._filter(self.flows, q, ("designation", "slug")),
            "/providers/oauth2/": self._providers,
            "/core/applications/": lambda q: self._filter(self.applications, q, ("slug",)),
            "/propertymappings/provider/scope/": lambda q: self._filter(self.scope_mappings, q, ("managed",)),
            "/crypto/certificatekeypairs/": self._keys,
            "/events/events/": self._events,
            "/core/authenticated_sessions/": self._sessions,
            "/core/brands/": lambda q: list(self.brands),
            "/managed/blueprints/": lambda q: list(self.blueprints),
            "/outposts/instances/": lambda q: list(self.outposts),
            "/policies/bindings/": lambda q: self._filter(self.bindings, q, ("target",)),
        }
        fn = lists.get(sub)
        if fn is None:
            return httpx.Response(404, json={"detail": "Not found."})
        return self._page(fn(q), q)

    def _page(self, rows: list[dict[str, Any]], q: httpx.QueryParams) -> httpx.Response:
        page = int(q.get("page", "1"))
        size = min(int(q.get("page_size", "20")), 1000)
        start = (page - 1) * size
        chunk = rows[start : start + size]
        total_pages = max(1, -(-len(rows) // size))
        pagination = {
            "next": page + 1 if start + size < len(rows) else 0,
            "previous": page - 1 if page > 1 else 0,
            "count": len(rows),
            "current": page,
            "total_pages": total_pages,
            "start_index": start + 1 if chunk else 0,
            "end_index": start + len(chunk),
        }
        return httpx.Response(200, json={"pagination": pagination, "results": chunk, "autocomplete": {}})

    @staticmethod
    def _filter(rows: list[dict[str, Any]], q: httpx.QueryParams, keys: tuple[str, ...]) -> list[dict[str, Any]]:
        out = list(rows)
        for k in keys:
            if k in q:
                out = [r for r in out if str(r.get(k)) == q[k]]
        return out

    def _user_groups(self, username: str) -> list[dict[str, Any]]:
        return [g for g in self.groups.values() if username in g["members"]]

    def _users(self, q: httpx.QueryParams) -> list[dict[str, Any]]:
        out = []
        for u in self.users.values():
            groups = self._user_groups(u["username"])
            row = {**u, "is_superuser": any(g["is_superuser"] for g in groups), "groups": [g["pk"] for g in groups]}
            if q.get("include_groups") == "true":
                row["groups_obj"] = [
                    {
                        "pk": g["pk"],
                        "num_pk": g["num_pk"],
                        "name": g["name"],
                        "is_superuser": g["is_superuser"],
                        "attributes": {},
                    }
                    for g in groups
                ]
            out.append(row)
        return self._filter(out, q, ("username",))

    def _groups(self, q: httpx.QueryParams) -> list[dict[str, Any]]:
        out = []
        for g in self.groups.values():
            row = {k: v for k, v in g.items() if k != "members"}
            row["users"] = [self.users[m]["pk"] for m in g["members"] if m in self.users]
            if q.get("include_users", "true") == "true":
                row["users_obj"] = [
                    {
                        "pk": self.users[m]["pk"],
                        "username": m,
                        "name": m,
                        "is_active": True,
                        "email": "x@y.invalid",
                        "attributes": {},
                        "uid": "u",
                    }
                    for m in g["members"]
                    if m in self.users
                ]
            out.append(row)
        return self._filter(out, q, ("name",))

    def _providers(self, q: httpx.QueryParams) -> list[dict[str, Any]]:
        rows = []
        for p in self.providers:
            row = dict(p)
            row["assigned_application_slug"] = next(
                (a["slug"] for a in self.applications if a["provider"] == p["pk"]), None
            )
            if _line(self.version) >= (2026, 5):
                row.setdefault("grant_types", ["authorization_code", "refresh_token"])
            else:
                row.pop("grant_types", None)
            rows.append(row)
        return self._filter(rows, q, ("name", "client_id"))

    def _keys(self, q: httpx.QueryParams) -> list[dict[str, Any]]:
        if q.get("has_key") == "true":
            return [k for k in self.keys if k["private_key_available"]]
        return list(self.keys)

    def _events(self, q: httpx.QueryParams) -> list[dict[str, Any]]:
        rows = sorted(self.events, key=lambda e: e["created"], reverse=q.get("ordering", "-created") == "-created")
        if "action" in q:
            rows = [e for e in rows if e["action"] == q["action"]]
        if "actions" in q and _line(self.version) >= (2025, 8):  # oudere versies negeren dit filter
            wanted = set(q.get_list("actions"))
            rows = [e for e in rows if e["action"] in wanted]
        if "username" in q:
            rows = [e for e in rows if e["user"].get("username") == q["username"]]
        return rows

    def _sessions(self, q: httpx.QueryParams) -> list[dict[str, Any]]:
        rows = list(self.sessions)
        if "user__username" in q:
            pk = self.users.get(q["user__username"], {}).get("pk")
            rows = [s for s in rows if s["user"] == pk]
        return rows

    def _export(self, slug: str) -> httpx.Response:
        flow = next((f for f in self.flows if f["slug"] == slug), None)
        if flow is None:
            return httpx.Response(404, json={"detail": "Not found."})
        text = (
            "version: 1\nmetadata:\n  name: " + flow["name"] + "\nentries:\n- model: authentik_flows.flow\n"
            "  identifiers:\n    slug: " + slug + "\n  attrs:\n    designation: " + flow["designation"] + "\n"
            "- model: authentik_stages_email.emailstage\n  attrs:\n    password: " + FLOW_PASSWORD + "\n"
            "    use_global_settings: false\n"
        )
        return httpx.Response(200, content=text.encode(), headers={"Content-Type": "application/json"})

    def _discovery(self, slug: str) -> httpx.Response:
        app = next((a for a in self.applications if a["slug"] == slug), None)
        if app is None:
            return httpx.Response(404)
        base = f"{self.base}/application/o"
        return httpx.Response(
            200,
            json={
                "issuer": f"{base}/{slug}/",
                "authorization_endpoint": f"{base}/authorize/",
                "token_endpoint": f"{base}/token/",
                "userinfo_endpoint": f"{base}/userinfo/",
                "end_session_endpoint": f"{base}/{slug}/end-session/",
                "jwks_uri": f"{base}/{slug}/jwks/",
                "response_types_supported": ["code", "id_token", "id_token token", "code token", "code id_token"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "code_challenge_methods_supported": ["plain", "S256"],
                "scopes_supported": ["openid", "email", "profile"],
                "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "groups", "preferred_username"],
            },
        )

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)


def asgi_app(fake: AuthentikFake) -> Any:
    """Dezelfde nep-Authentik als ASGI-app (voor de dienst-E2E via uvicorn), plus ``/sim/*``-bediening."""

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            msg = await receive()
            body += msg.get("body", b"")
            if not msg.get("more_body"):
                break
        path = scope["path"]
        qs = scope.get("query_string", b"").decode()
        headers = {k.decode(): v.decode() for k, v in scope["headers"]}
        if path.startswith("/sim/"):
            status, payload = _sim(fake, scope["method"], path, json.loads(body) if body else {})
            await _send_json(send, status, payload)
            return
        req = httpx.Request(scope["method"], f"http://{fake.host}{path}?{qs}", headers=headers, content=body)
        try:
            resp = fake.handle(req)
        except httpx.HTTPError:
            await _send_json(send, 503, {"detail": "nep-Authentik offline"})
            return
        await send(
            {
                "type": "http.response.start",
                "status": resp.status_code,
                "headers": [(k.encode(), v.encode()) for k, v in resp.headers.items() if k.lower() != "content-length"]
                + [(b"content-length", str(len(resp.content)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": resp.content})

    return app


async def _send_json(send: Any, status: int, payload: Any) -> None:
    raw = json.dumps(payload).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": raw})


def _sim(fake: AuthentikFake, method: str, path: str, body: dict[str, Any]) -> tuple[int, Any]:
    if path == "/sim/state" and method == "POST":
        for k in ("ready", "version"):
            if k in body:
                setattr(fake, k, body[k])
        return 200, {"ready": fake.ready, "version": fake.version}
    if path == "/sim/events" and method == "POST":
        ev = fake.add_event(body["action"], body.get("username"), minutes_ago=float(body.get("minutes_ago", 0)))
        return 201, ev
    if path == "/sim/members" and method == "POST":
        fake.set_members(body["group"], body["members"])
        return 200, {"group": body["group"], "members": body["members"]}
    if path == "/sim/writes":
        return 200, fake.writes
    if path == "/sim/token":
        return 200, {"token": fake.token}
    return 404, {"detail": "onbekend"}
