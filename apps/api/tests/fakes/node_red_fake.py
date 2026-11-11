"""Nep-Node-RED (simulator) voor unit-, integratie- en E2E-tests. ALLEEN voor tests; geen productiecode.

De vorm van de antwoorden volgt de admin-API van de gepinde image ``nodered/node-red:5.0.9`` zoals die met
``tools/node_red_verify.py`` tegen een lokale container is gemeten (``docs/b11/node-red-verificatie.json``):

- zonder ``adminAuth``: ``GET /auth/login`` → ``{}``, alles anoniem leesbaar, exec-node geladen, ``externalModules: {}``,
  ``functionExternalModules: true``, ``flowEncryptionType: "system"``, diagnostics ``adminAuth: "UNSET"``;
- met het beveiligingsprofiel (``--define=...``): anoniem 401, ``GET /auth/login`` → ``{"type": "credentials", ...}``,
  ``POST /auth/token`` (formulier, lege scope; fout wachtwoord → 403; scope ``*`` voor een beperkt account → 403),
  ``POST /auth/revoke``, ``GET /flows`` (v2) → ``{"flows", "rev"}``, ``POST /flows`` (v2) met ``rev`` (verouderd → 409
  ``version_mismatch``), credentials als ``{"$": "<32 hex><base64>"}`` (andere ``credentialSecret`` → 400
  ``credentials_load_failed``), ``GET /flows`` geeft nooit credentials terug, een flow met een niet-geladen ``exec``-node
  wordt door ``POST /flows`` aangenomen, ``POST /nodes`` (palette) → 404 als installeren uit staat.

De "versleuteling" van het credentials-bestand is hier een eenvoudige, omkeerbare codering die aan de
``credentialSecret`` gebonden is; het gaat om het gedrag (onleesbaar voor de dienst, geweigerd bij een andere sleutel),
niet om echte cryptografie. Resultaten met deze simulator heten "Sim-getest"; een echte Node-RED op de NAS is
NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import bcrypt
import httpx

VERSION = "5.0.9"
ALL_PERMISSIONS = "*"
CORE_SETS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("node-red/junction", ("junction",)),
    ("node-red/inject", ("inject",)),
    ("node-red/debug", ("debug",)),
    ("node-red/complete", ("complete",)),
    ("node-red/catch", ("catch",)),
    ("node-red/status", ("status",)),
    ("node-red/link", ("link in", "link out", "link call")),
    ("node-red/comment", ("comment",)),
    ("node-red/global-config", ("global-config",)),
    ("node-red/unknown", ("unknown",)),
    ("node-red/function", ("function",)),
    ("node-red/switch", ("switch",)),
    ("node-red/change", ("change",)),
    ("node-red/range", ("range",)),
    ("node-red/template", ("template",)),
    ("node-red/delay", ("delay",)),
    ("node-red/trigger", ("trigger",)),
    ("node-red/exec", ("exec",)),
    ("node-red/rbe", ("rbe",)),
    ("node-red/tls", ("tls-config",)),
    ("node-red/httpproxy", ("http proxy",)),
    ("node-red/mqtt", ("mqtt in", "mqtt out", "mqtt-broker")),
    ("node-red/httpin", ("http in", "http response")),
    ("node-red/httprequest", ("http request",)),
    ("node-red/websocket", ("websocket in", "websocket out", "websocket-listener", "websocket-client")),
    ("node-red/tcpin", ("tcp in", "tcp out", "tcp request")),
    ("node-red/udp", ("udp in", "udp out")),
    ("node-red/CSV", ("csv",)),
    ("node-red/HTML", ("html",)),
    ("node-red/JSON", ("json",)),
    ("node-red/XML", ("xml",)),
    ("node-red/YAML", ("yaml",)),
    ("node-red/split", ("split", "join")),
    ("node-red/sort", ("sort",)),
    ("node-red/batch", ("batch",)),
    ("node-red/file", ("file", "file in")),
    ("node-red/watch", ("watch",)),
)
#: bestand → node-set (voor ``nodesExcludes``)
SET_FILES = {"90-exec.js": "node-red/exec"}


def _rev(flows: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(flows, separators=(",", ":")).encode()).hexdigest()  # gemeten: 64 hex


@dataclass
class NodeRedFake:
    """Eén nep-Node-RED. Standaard **zonder** beveiliging (zoals een verse installatie); ``apply_arguments`` zet het
    beveiligingsprofiel precies zoals de container-argumenten uit het formulier dat doen."""

    host: str = "nodered.test"
    version: str = VERSION
    admin_auth: dict[str, Any] | None = None
    nodes_excludes: list[str] = field(default_factory=list)
    function_external_modules: bool = True
    external_modules: dict[str, Any] = field(default_factory=dict)
    credential_secret: str | None = None
    flows: list[dict[str, Any]] = field(default_factory=list)
    #: de (onversleutelde) inloggegevens per node zoals alleen Node-RED ze kent; nooit via de API terug te lezen
    credentials: dict[str, Any] = field(default_factory=dict)
    data_dir: Path | None = None
    extra_sets: list[dict[str, Any]] = field(default_factory=list)
    up: bool = True
    #: test-knoppen: eerstvolgende POST /flows faalt met deze status, of verliest het antwoord ná het verwerken
    fail_next_post: int | None = None
    drop_next_post_response: bool = False
    tokens: dict[str, dict[str, Any]] = field(default_factory=dict)
    requests: list[tuple[str, str]] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)
    revoked: list[str] = field(default_factory=list)
    seen_passwords: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------ inrichten (zoals het formulier)
    def apply_arguments(self, arguments: list[str]) -> None:
        """Verwerkt ``--define=sleutel=<JSON of tekst>`` zoals de officiële image dat doet (gemeten)."""
        for arg in arguments:
            if not arg.startswith("--define="):
                continue
            key, _, raw = arg.removeprefix("--define=").partition("=")
            try:
                value: Any = json.loads(raw)
            except ValueError:
                value = raw
            if key == "adminAuth":
                self.admin_auth = value
            elif key == "nodesExcludes":
                self.nodes_excludes = list(value)
            elif key == "functionExternalModules":
                self.function_external_modules = bool(value)
            elif key == "externalModules":
                self.external_modules = dict(value)
            elif key == "credentialSecret":
                self.credential_secret = str(value)
        self.tokens.clear()  # een herstart met nieuwe argumenten maakt bestaande sessies ongeldig
        self._write_cred_file()

    def deploy(self, flows: list[dict[str, Any]], credentials: dict[str, Any] | None = None) -> str:
        """Een beheerder zet flows in de editor (buiten deze dienst om)."""
        self.flows = copy.deepcopy(flows)
        if credentials is not None:
            self.credentials = copy.deepcopy(credentials)
        self._write_cred_file()
        return self.rev

    @property
    def rev(self) -> str:
        return _rev(self.flows)

    # ------------------------------------------------------------------ credentials-bestand
    def _key_id(self, secret: str | None = None) -> str:
        return hashlib.sha256(("nep-credentialSecret:" + (secret or self.credential_secret or "")).encode()).hexdigest()

    def encrypted_credentials(self) -> dict[str, str]:
        """``{"$": "<32 hex IV><base64>"}`` — dezelfde vorm als het echte bestand; gebonden aan de credentialSecret."""
        iv = secrets.token_hex(16)
        payload = json.dumps({"k": self._key_id(), "c": self.credentials}, separators=(",", ":")).encode()
        mask = hashlib.sha256((iv + self._key_id()).encode()).digest()
        data = bytes(b ^ mask[i % len(mask)] for i, b in enumerate(payload))
        return {"$": iv + base64.b64encode(data).decode()}

    def _decrypt(self, blob: Any) -> dict[str, Any] | None:
        if not (isinstance(blob, dict) and isinstance(blob.get("$"), str) and len(blob["$"]) > 32):
            return None
        iv, body = blob["$"][:32], blob["$"][32:]
        try:
            data = base64.b64decode(body, validate=True)
        except ValueError:
            return None
        mask = hashlib.sha256((iv + self._key_id()).encode()).digest()
        raw = bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))
        try:
            doc = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(doc, dict) or doc.get("k") != self._key_id() or not isinstance(doc.get("c"), dict):
            return None
        return dict(doc["c"])

    def _write_cred_file(self) -> None:
        if self.data_dir is None:
            return
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path = self.data_dir / "flows_cred.json"
        if self.credential_secret:
            path.write_text(json.dumps(self.encrypted_credentials()), encoding="utf-8")
        else:
            # zonder eigen credentialSecret: hier als onversleuteld bestand (een afwijking van het profiel)
            path.write_text(json.dumps(self.credentials), encoding="utf-8")

    # ------------------------------------------------------------------ gegevens
    def node_sets(self) -> list[dict[str, Any]]:
        excluded = {SET_FILES[f] for f in self.nodes_excludes if f in SET_FILES}
        sets = [
            {
                "id": set_id,
                "name": set_id.split("/", 1)[1],
                "types": list(types),
                "enabled": True,
                "local": False,
                "user": False,
                "module": "node-red",
                "version": self.version,
            }
            for set_id, types in CORE_SETS
            if set_id not in excluded
        ]
        return sets + copy.deepcopy(self.extra_sets)

    def _settings(self, user: dict[str, Any] | None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "httpNodeRoot": "/",
            "version": self.version,
            "context": {"default": "memory", "stores": ["memory"]},
            "codeEditor": {"lib": "monaco", "options": {}},
            "markdownEditor": {"mermaid": {"enabled": True}},
            "libraries": [
                {"id": "local", "label": "editor:library.types.local", "user": False, "icon": "font-awesome/fa-hdd-o"}
            ],
            "flowFilePretty": True,
            "externalModules": copy.deepcopy(self.external_modules),
            "flowEncryptionType": "user" if self.credential_secret else "system",
            "diagnostics": {"enabled": True, "ui": True},
            "runtimeState": {"enabled": False, "ui": False},
            "functionExternalModules": self.function_external_modules,
            "functionTimeout": 0,
            "tlsConfigDisableLocalFiles": False,
            "editorTheme": {"languages": ["en-US"], "palette": {}},
        }
        if user is not None:
            out["user"] = {"username": user["username"], "permissions": user["permissions"]}
        return out

    def _diagnostics(self) -> dict[str, Any]:
        return {
            "report": "diagnostics",
            "scope": "basic",
            "time": {"utc": "nep", "local": "nep"},
            "intl": {"locale": "en-US", "timeZone": "UTC"},
            "nodejs": {"version": "nep", "arch": "x64", "platform": "linux", "memoryUsage": {}},
            "os": {
                "containerised": True,
                "wsl": False,
                "totalmem": 0,
                "freemem": 0,
                "arch": "x64",
                "platform": "linux",
            },
            "runtime": {
                "version": self.version,
                "isStarted": True,
                "flows": {"state": "start", "started": True},
                "modules": {"node-red": self.version},
                "settings": {
                    "available": True,
                    "apiMaxLength": "UNSET",
                    "disableEditor": False,
                    "contextStorage": {},
                    "debugMaxLength": 1000,
                    "editorTheme": "UNSET",
                    "flowFile": "flows.json",
                    "mqttReconnectTime": 15000,
                    "serialReconnectTime": 15000,
                    "socketReconnectTime": "UNSET",
                    "socketTimeout": "UNSET",
                    "tcpMsgQueueSize": "UNSET",
                    "inboundWebSocketTimeout": "UNSET",
                    "runtimeState": "UNSET",
                    "adminAuth": "SET" if self.admin_auth else "UNSET",
                    "httpAdminRoot": "/",
                    "httpAdminCors": "UNSET",
                    "httpNodeAuth": "UNSET",
                    "httpNodeRoot": "/",
                    "httpNodeCors": "UNSET",
                    "httpStatic": "UNSET",
                    "httpStaticRoot": "UNSET",
                    "httpStaticCors": "UNSET",
                    "uiHost": "SET",
                    "uiPort": "SET",
                    "userDir": "SET",
                    "nodesDir": "UNSET",
                },
            },
        }

    # ------------------------------------------------------------------ aanmelding
    def _user(self, username: str) -> dict[str, Any] | None:
        for user in (self.admin_auth or {}).get("users", []):
            if user.get("username") == username:
                return dict(user)
        return None

    def login(self, username: str, password: str, scope: str = "") -> str | None:
        """Geeft een token of ``None`` (zoals ``POST /auth/token``); ook handig om in een test als beheerder in te
        loggen."""
        user = self._user(username)
        if user is None:
            return None
        try:
            ok = bcrypt.checkpw(password.encode("utf-8"), str(user["password"]).encode("ascii"))
        except ValueError:
            ok = False
        if not ok:
            return None
        if scope == "*" and user["permissions"] != ALL_PERMISSIONS:
            return None  # gemeten: een beperkt account krijgt met scope '*' invalid_grant
        token = secrets.token_urlsafe(48)
        self.tokens[token] = {"username": username, "permissions": user["permissions"]}
        return token

    def _principal(self, request: httpx.Request) -> dict[str, Any] | None:
        auth = request.headers.get("authorization", "")
        if not auth.lower().startswith("bearer "):
            return None
        return self.tokens.get(auth[7:].strip())

    @staticmethod
    def _allowed(principal: dict[str, Any], permission: str) -> bool:
        perms = principal["permissions"]
        if perms == ALL_PERMISSIONS:
            return True
        granted = [perms] if isinstance(perms, str) else list(perms)
        return permission in granted or "*" in granted or permission.split(".")[0] + ".*" in granted

    # ------------------------------------------------------------------ HTTP
    def handle(self, request: httpx.Request) -> httpx.Response:
        if not self.up:
            raise httpx.ConnectError("nep-Node-RED offline", request=request)
        method, path = request.method, request.url.path.rstrip("/") or "/"
        self.requests.append((method, path))
        if method == "GET" and path == "/":
            return httpx.Response(
                200, text="<!DOCTYPE html><title>Node-RED</title>", headers={"content-type": "text/html"}
            )
        if method == "GET" and path == "/auth/login":
            if not self.admin_auth:
                return httpx.Response(200, json={})
            return httpx.Response(
                200,
                json={
                    "type": "credentials",
                    "prompts": [
                        {"id": "username", "type": "text", "label": "Username"},
                        {"id": "password", "type": "password", "label": "Password"},
                    ],
                },
            )
        if method == "POST" and path == "/auth/token":
            return self._token(request)
        if method == "POST" and path == "/auth/revoke":
            if self.admin_auth and self._principal(request) is None:
                return httpx.Response(401, text="Unauthorized")
            try:
                token = json.loads(request.content or b"{}").get("token")
            except ValueError:
                token = None
            if isinstance(token, str):
                self.tokens.pop(token, None)
                self.revoked.append(hashlib.sha256(token.encode()).hexdigest())
            return httpx.Response(200, json={})
        routes: dict[tuple[str, str], str] = {
            ("GET", "/flows"): "flows.read",
            ("POST", "/flows"): "flows.write",
            ("GET", "/nodes"): "nodes.read",
            ("POST", "/nodes"): "nodes.write",
            ("GET", "/settings"): "settings.read",
            ("GET", "/diagnostics"): "diagnostics.read",
        }
        permission = routes.get((method, path))
        if permission is None:
            return httpx.Response(404, text="Not Found")
        principal: dict[str, Any] | None = None
        if self.admin_auth:
            principal = self._principal(request)
            if principal is None or not self._allowed(principal, permission):
                return httpx.Response(401, text="Unauthorized")
        if (method, path) == ("GET", "/flows"):
            if request.headers.get("node-red-api-version") == "v2":
                return httpx.Response(200, json={"flows": copy.deepcopy(self.flows), "rev": self.rev})
            return httpx.Response(200, json=copy.deepcopy(self.flows))
        if (method, path) == ("POST", "/flows"):
            return self._post_flows(request, principal)
        if (method, path) == ("GET", "/nodes"):
            return httpx.Response(200, json=self.node_sets())
        if (method, path) == ("POST", "/nodes"):
            palette = self.external_modules.get("palette") if isinstance(self.external_modules, dict) else None
            if isinstance(palette, dict) and palette.get("allowInstall") is False:
                return httpx.Response(404, text="Not Found")
            return httpx.Response(400, json={"code": "module_not_found", "message": "nep: geen registry"})
        if (method, path) == ("GET", "/settings"):
            return httpx.Response(200, json=self._settings(principal))
        return httpx.Response(200, json=self._diagnostics())

    def _token(self, request: httpx.Request) -> httpx.Response:
        if not self.admin_auth:
            return httpx.Response(404, text="Not Found")
        form = {k: v[0] for k, v in parse_qs(request.content.decode("utf-8"), keep_blank_values=True).items()}
        if form.get("client_id") not in ("node-red-admin", "node-red-editor") or form.get("grant_type") != "password":
            return httpx.Response(401, json={"error": "unauthorized_client"})
        self.seen_passwords.append(form.get("password", ""))
        token = self.login(form.get("username", ""), form.get("password", ""), form.get("scope", ""))
        if token is None:
            return httpx.Response(
                403, json={"error": "invalid_grant", "error_description": "Invalid resource owner credentials"}
            )
        return httpx.Response(200, json={"access_token": token, "expires_in": 3600, "token_type": "Bearer"})

    def _post_flows(self, request: httpx.Request, principal: dict[str, Any] | None) -> httpx.Response:
        if self.fail_next_post is not None:
            status, self.fail_next_post = self.fail_next_post, None
            return httpx.Response(status, json={"code": "unexpected_error", "message": "nep: gevraagde fout"})
        try:
            body = json.loads(request.content)
        except ValueError:
            return httpx.Response(400, json={"code": "invalid_request", "message": "Invalid JSON"})
        v2 = request.headers.get("node-red-api-version") == "v2"
        flows = body.get("flows") if v2 and isinstance(body, dict) else body
        if not isinstance(flows, list):
            return httpx.Response(400, json={"code": "invalid_request", "message": "Invalid flow configuration"})
        credentials: dict[str, Any] | None = None
        if v2:
            if "rev" in body and body["rev"] != self.rev:
                return httpx.Response(409, json={"code": "version_mismatch"})
            if "credentials" in body:
                blob = body["credentials"]
                if isinstance(blob, dict) and "$" in blob:
                    credentials = self._decrypt(blob)
                    if credentials is None:
                        return httpx.Response(
                            400, json={"code": "credentials_load_failed", "message": "Failed to decrypt credentials"}
                        )
                elif isinstance(blob, dict):
                    credentials = dict(blob)
        # gemeten: een flow met een niet-geladen node-type (bv. exec) wordt gewoon aangenomen
        self.flows = copy.deepcopy(flows)
        if credentials is not None:
            self.credentials = credentials
        else:
            ids = {str(n.get("id")) for n in self.flows}
            self.credentials = {k: v for k, v in self.credentials.items() if k in ids}
        self._write_cred_file()
        self.writes.append(
            {
                "door": principal["username"] if principal else None,
                "rev": self.rev,
                "nodes": len(self.flows),
                "met_credentials": credentials is not None,
                "deployment_type": request.headers.get("node-red-deployment-type"),
            }
        )
        if self.drop_next_post_response:
            self.drop_next_post_response = False
            raise httpx.ReadTimeout("nep: antwoord verloren", request=request)
        return httpx.Response(200, json={"rev": self.rev} if v2 else None)


# ----------------------------------------------------------------------------------------------- voorbeeldflows
def tab(tab_id: str, label: str, *, disabled: bool = False) -> dict[str, Any]:
    return {"id": tab_id, "type": "tab", "label": label, "disabled": disabled, "info": ""}


def node(node_id: str, node_type: str, z: str, wires: list[list[str]] | None = None, **props: Any) -> dict[str, Any]:
    return {"id": node_id, "type": node_type, "z": z, "name": props.pop("name", ""), "wires": wires or [], **props}


def simple_flow(tab_id: str = "tab0000000000001", label: str = "Melding bij storing") -> list[dict[str, Any]]:
    """Een onschuldige flow: inject → function → debug."""
    return [
        tab(tab_id, label),
        node(tab_id[:8] + "inject01", "inject", tab_id, [[tab_id[:8] + "functi01"]], repeat="", once=False),
        node(tab_id[:8] + "functi01", "function", tab_id, [[tab_id[:8] + "debug001"]], func="return msg;"),
        node(tab_id[:8] + "debug001", "debug", tab_id, active=True),
    ]


def exec_flow(tab_id: str = "tabexec000000001", label: str = "Shell (verboden)") -> list[dict[str, Any]]:
    return [
        tab(tab_id, label),
        node(tab_id[:8] + "inject01", "inject", tab_id, [[tab_id[:8] + "exec0001"]]),
        node(tab_id[:8] + "exec0001", "exec", tab_id, [[], [], []], command="id", addpay=""),
    ]


# ----------------------------------------------------------------------------------------------- ASGI (dienst-E2E)
def asgi_app(fake: NodeRedFake) -> Any:
    """Dezelfde nep-Node-RED als ASGI-app (voor de dienst-E2E via uvicorn), plus ``/sim/*``-bediening."""

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
            await _send(send, status, json.dumps(payload).encode(), "application/json")
            return
        req = httpx.Request(scope["method"], f"http://{fake.host}{path}?{qs}", headers=headers, content=body)
        try:
            resp = fake.handle(req)
        except httpx.HTTPError:
            await _send(send, 503, b'{"detail":"nep-Node-RED offline"}', "application/json")
            return
        await _send(send, resp.status_code, resp.content, resp.headers.get("content-type", "application/json"))

    return app


async def _send(send: Any, status: int, raw: bytes, content_type: str) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", content_type.encode()), (b"content-length", str(len(raw)).encode())],
        }
    )
    await send({"type": "http.response.body", "body": raw})


def _sim(fake: NodeRedFake, method: str, path: str, body: dict[str, Any]) -> tuple[int, Any]:
    if path == "/sim/arguments" and method == "POST":
        fake.apply_arguments(list(body["arguments"]))
        return 200, {"beveiligd": bool(fake.admin_auth)}
    if path == "/sim/deploy" and method == "POST":
        return 200, {"rev": fake.deploy(body["flows"], body.get("credentials"))}
    if path == "/sim/state" and method == "POST":
        if "up" in body:
            fake.up = bool(body["up"])
        return 200, {"up": fake.up}
    if path == "/sim/state" and method == "GET":
        return 200, {
            "up": fake.up,
            "rev": fake.rev,
            "flows": fake.flows,
            "credentials": fake.credentials,
            "writes": fake.writes,
            "beveiligd": bool(fake.admin_auth),
            "exec_geladen": any("exec" in s["types"] for s in fake.node_sets()),
        }
    return 404, {"detail": "onbekend sim-pad"}
