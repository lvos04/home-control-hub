"""Client voor de admin-API van Node-RED (B11).

Het gedrag hieronder is gecontroleerd tegen de gepinde image ``nodered/node-red:5.0.9`` in een lokale container
(``docs/b11/node-red-verificatie.json``, gemaakt met ``tools/node_red_verify.py``); een Node-RED op een echte NAS is
NIET GEVALIDEERD.

- Aanmelden: ``POST /auth/token`` (formulier, ``client_id=node-red-admin``, ``grant_type=password``, **lege** ``scope``
  zodat het dienstaccount precies zijn eigen, beperkte rechten krijgt) → ``access_token`` (Bearer). Het token leeft
  alleen in deze client en wordt bij het sluiten ingetrokken (``POST /auth/revoke``); het wordt nooit gelogd.
- De aanmeldgegevens staan in de vault als ``gebruikersnaam:wachtwoord`` (``vault://source/node-red``).
- Deze dienst praat alleen met een Node-RED waarvan de editor om een aanmelding vraagt (``GET /auth/login`` geeft
  ``type: credentials``). Zonder die beveiliging is elke aanroep ``niet_beveiligd``: er wordt niets gelezen of gezet.
- Flows: ``GET /flows`` met ``Node-RED-API-Version: v2`` → ``{"flows": [...], "rev": "<hash>"}``. Schrijven kan alleen
  met de ``rev`` van de laatst gelezen toestand; Node-RED weigert een verouderde ``rev`` met 409 ``version_mismatch``.
- Contract §5: 5 s connect / 15 s read; alleen GET en het aanmelden worden herhaald (max. 3 pogingen) en alleen bij een
  netwerkfout of 429/502/503/504. ``POST /flows`` wordt **nooit** herhaald. Geen redirects, proxy-variabelen genegeerd.
- Elke fout wordt ``NodeRedError`` met een vaste ``reason``; nooit een lege lijst als "geen flows". Uitzondering: een
  antwoord dat te diep genest is voor ``json.loads`` (RecursionError); de synchronisatie blokkeert dan alle flows.
"""

from __future__ import annotations

import json
import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import TracebackType
from typing import Any

import httpx
from sqlalchemy.orm import Session

from ... import __version__
from ...config import Settings
from ...errors import ApiError
from ...hubclient import HubUrlError, validate_hub_url
from ...models import IntegrationSource
from ...security.vault import Vault

SOURCE_ID = "node_red"
RETRY_STATUS = {429, 502, 503, 504}
MAX_BYTES = 16 * 1024 * 1024
REV_RE = re.compile(r"^[0-9a-f]{8,64}$")
API_HEADERS = {"Node-RED-API-Version": "v2"}

REASONS_NL = {
    "niet_geconfigureerd": "Node-RED is nog niet als bron ingesteld (adres ontbreekt).",
    "uitgeschakeld": "De bron Node-RED staat uit.",
    "geen_aanmelding": "Er zijn geen aanmeldgegevens voor Node-RED opgeslagen (maak eerst het beveiligingsprofiel).",
    "aanmelding_ongeldig": "De opgeslagen aanmeldgegevens voor Node-RED hebben niet de vorm gebruikersnaam:wachtwoord.",
    "ongeldig_adres": "Het adres van Node-RED is ongeldig.",
    "onbereikbaar": "Node-RED is niet bereikbaar.",
    "timeout": "Node-RED antwoordde niet op tijd.",
    "niet_beveiligd": "De editor van Node-RED vraagt geen aanmelding; deze dienst werkt alleen met een beveiligde "
    "Node-RED.",
    "aanmelding_geweigerd": "Node-RED weigerde de aanmelding van het dienstaccount.",
    "geen_rechten": "Het dienstaccount mist in Node-RED de rechten voor dit onderdeel.",
    "niet_gevonden": "Dit onderdeel bestaat niet in deze Node-RED-versie.",
    "http_5xx": "Node-RED gaf een serverfout.",
    "onverwacht_antwoord": "Node-RED gaf een onverwacht antwoord.",
    "antwoord_ongeldig": "Het antwoord van Node-RED was geen geldige JSON of had een onverwacht formaat.",
    "antwoord_te_groot": "Het antwoord van Node-RED was groter dan toegestaan.",
    "redirect": "Node-RED antwoordde met een doorverwijzing; die wordt bewust niet gevolgd.",
    "versie_conflict": "De flows in Node-RED zijn intussen gewijzigd; er is niets overschreven.",
    "credentials_niet_te_ontsleutelen": "Node-RED kan de credentials uit de momentopname niet ontsleutelen (een "
    "andere credentialSecret); de flows zijn niet gewijzigd.",
    "flows_geweigerd": "Node-RED weigerde de flows; er is niets gewijzigd.",
    "synchronisatie_mislukt": "De synchronisatie met Node-RED is vastgelopen; alle flows van Node-RED zijn geblokkeerd "
    "tot een synchronisatie weer slaagt en een beheerder ze hervat.",
}


class NodeRedError(Exception):
    def __init__(self, reason: str, http_status: int | None = None, path: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.path = path

    @property
    def message_nl(self) -> str:
        return REASONS_NL.get(self.reason, "Onbekende fout bij Node-RED.")

    def to_dict(self) -> dict[str, Any]:
        return {"reason": self.reason, "http_status": self.http_status, "path": self.path}


@dataclass(frozen=True)
class FlowsDoc:
    """De volledige flowconfiguratie zoals Node-RED hem geeft (zonder credentials: die geeft de API nooit terug). De
    elementen worden hier niet gekeurd: een element met een andere vorm is configuratie, en de flowscan blokkeert dan
    alle flows (``policy.scan``, ``vorm_ongeldig``) in plaats van dat de synchronisatie stopt."""

    rev: str
    flows: list[Any]


class NodeRedClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        settings: Settings,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_bytes: int = MAX_BYTES,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self.settings = settings
        self.transport = transport
        self.sleep = sleep
        self.max_bytes = max_bytes
        self._token: str | None = None

    def __enter__(self) -> NodeRedClient:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()

    # ------------------------------------------------------------------ transport
    def _client(self) -> httpx.Client:
        s = self.settings
        timeout = httpx.Timeout(
            connect=s.http_connect_timeout_s,
            read=s.http_read_timeout_s,
            write=s.http_read_timeout_s,
            pool=s.http_connect_timeout_s,
        )
        return httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=self.transport,
            follow_redirects=False,
            trust_env=False,  # contract §5: proxy-omgevingsvariabelen negeren
            headers={"User-Agent": f"home-control-hub/{__version__}", "Accept": "application/json"},
        )

    def _send(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        form: dict[str, str] | None = None,
        retry: bool = False,
    ) -> tuple[int, bytes]:
        last: NodeRedError | None = None
        attempts = max(1, self.settings.http_max_attempts) if retry else 1
        with self._client() as client:
            for attempt in range(1, attempts + 1):
                try:
                    req = client.build_request(method, path, headers=headers or {}, json=json_body, data=form)
                    resp = client.send(req, stream=True)
                    try:
                        status = resp.status_code
                        declared = resp.headers.get("Content-Length")
                        if declared and declared.isdigit() and int(declared) > self.max_bytes:
                            raise NodeRedError("antwoord_te_groot", status, path)
                        body = bytearray()
                        for chunk in resp.iter_bytes():
                            body.extend(chunk)
                            if len(body) > self.max_bytes:
                                raise NodeRedError("antwoord_te_groot", status, path)
                    finally:
                        resp.close()
                except httpx.TimeoutException:
                    last = NodeRedError("timeout", None, path)
                except httpx.TransportError:
                    last = NodeRedError("onbereikbaar", None, path)
                except httpx.DecodingError as exc:
                    # bv. "Content-Encoding: gzip" met een body die geen gzip is: geen netwerkfout, niet herhalen
                    raise NodeRedError("antwoord_ongeldig", None, path) from exc
                else:
                    if status not in RETRY_STATUS or attempt == attempts:
                        return status, bytes(body)
                    last = NodeRedError("http_5xx" if status >= 500 else "onverwacht_antwoord", status, path)
                if attempt < attempts:
                    self.sleep(min(8.0, 0.5 * (2 ** (attempt - 1))) * random.uniform(0.5, 1.5))  # noqa: S311
        raise last or NodeRedError("onbereikbaar", None, path)

    @staticmethod
    def _json(status: int, body: bytes, path: str) -> Any:
        # alleen ongeldige JSON is antwoord_ongeldig; een RecursionError (te diep genest) gaat bewust door: dan
        # blokkeert de synchronisatie alle flows (snapshots.sync, vorm A van R-VEILIG-8) en blijft de oude stand niet
        try:
            return json.loads(body)
        except ValueError as exc:
            raise NodeRedError("antwoord_ongeldig", status, path) from exc

    @staticmethod
    def _check(status: int, path: str) -> None:
        if 200 <= status < 300:
            return
        if 300 <= status < 400:
            raise NodeRedError("redirect", status, path)
        if status == 401:
            raise NodeRedError("aanmelding_geweigerd", status, path)
        if status == 403:
            raise NodeRedError("geen_rechten", status, path)
        if status == 404:
            raise NodeRedError("niet_gevonden", status, path)
        if status >= 500:
            raise NodeRedError("http_5xx", status, path)
        raise NodeRedError("onverwacht_antwoord", status, path)

    # ------------------------------------------------------------------ zonder aanmelding (isolatiecontrole)
    def anonymous_status(self, path: str) -> int:
        """HTTP-status van een GET **zonder** aanmelding (B11-001: een anonieme lezer hoort 401 te krijgen)."""
        status, _body = self._send("GET", path, retry=True)
        return status

    def login_scheme(self) -> dict[str, Any]:
        """``GET /auth/login``: ``{"type": "credentials", ...}`` als de editor om een aanmelding vraagt, anders ``{}``."""
        status, body = self._send("GET", "/auth/login", retry=True)
        self._check(status, "/auth/login")
        data = self._json(status, body, "/auth/login")
        if not isinstance(data, dict):
            raise NodeRedError("antwoord_ongeldig", status, "/auth/login")
        return data

    # ------------------------------------------------------------------ aanmelden
    def login(self) -> None:
        if self.login_scheme().get("type") != "credentials":
            raise NodeRedError("niet_beveiligd", 200, "/auth/login")
        form = {
            "client_id": "node-red-admin",
            "grant_type": "password",
            "scope": "",  # leeg: precies de rechten van het account (met '*' weigert Node-RED een beperkt account)
            "username": self._username,
            "password": self._password,
        }
        status, body = self._send("POST", "/auth/token", form=form, retry=True)
        if status in (400, 401, 403):
            raise NodeRedError("aanmelding_geweigerd", status, "/auth/token")
        self._check(status, "/auth/token")
        data = self._json(status, body, "/auth/token")
        token = data.get("access_token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise NodeRedError("antwoord_ongeldig", status, "/auth/token")
        self._token = token

    def close(self) -> None:
        """Trekt het token in (best effort); een fout hierbij verandert niets aan de uitkomst van het werk."""
        token, self._token = self._token, None
        if token is None:
            return
        try:
            self._send("POST", "/auth/revoke", headers={"Authorization": f"Bearer {token}"}, json_body={"token": token})
        except NodeRedError:
            return

    def _authed(self, method: str, path: str, *, json_body: Any = None, extra: dict[str, str] | None = None) -> Any:
        if self._token is None:
            self.login()
        retry = method == "GET"
        for second_try in (False, True):
            headers = {"Authorization": f"Bearer {self._token}", **(extra or {})}
            status, body = self._send(method, path, headers=headers, json_body=json_body, retry=retry)
            if status == 401 and not second_try and method == "GET":
                self._token = None  # token verlopen of ingetrokken: één keer opnieuw aanmelden
                self.login()
                continue
            break
        if method == "POST" and path == "/flows":
            self._check_flows_post(status, body)
        self._check(status, path)
        return self._json(status, body, path)

    def _check_flows_post(self, status: int, body: bytes) -> None:
        if status == 409:
            raise NodeRedError("versie_conflict", status, "/flows")
        if status == 400:
            code = None
            try:
                data = json.loads(body)
                code = data.get("code") if isinstance(data, dict) else None
            except ValueError:
                code = None
            if code == "credentials_load_failed":
                raise NodeRedError("credentials_niet_te_ontsleutelen", status, "/flows")
            raise NodeRedError("flows_geweigerd", status, "/flows")

    # ------------------------------------------------------------------ lezen
    def get_flows(self) -> FlowsDoc:
        data = self._authed("GET", "/flows", extra=API_HEADERS)
        if not isinstance(data, dict):
            raise NodeRedError("antwoord_ongeldig", 200, "/flows")
        rev, flows = data.get("rev"), data.get("flows")
        if not isinstance(rev, str) or not REV_RE.fullmatch(rev) or not isinstance(flows, list):
            raise NodeRedError("antwoord_ongeldig", 200, "/flows")
        return FlowsDoc(rev=rev, flows=flows)

    def get_nodes(self) -> list[dict[str, Any]]:
        """Geïnstalleerde node-sets: ``[{id, name, types: [...], enabled, module, version, ...}]``."""
        data = self._authed("GET", "/nodes")
        if not isinstance(data, list) or not all(isinstance(n, dict) for n in data):
            raise NodeRedError("antwoord_ongeldig", 200, "/nodes")
        for entry in data:
            types = entry.get("types")
            if not isinstance(entry.get("module"), str) or not isinstance(types, list):
                raise NodeRedError("antwoord_ongeldig", 200, "/nodes")
            if not all(isinstance(t, str) for t in types):
                raise NodeRedError("antwoord_ongeldig", 200, "/nodes")
        return data

    def get_settings(self) -> dict[str, Any]:
        data = self._authed("GET", "/settings")
        if not isinstance(data, dict):
            raise NodeRedError("antwoord_ongeldig", 200, "/settings")
        return data

    def get_diagnostics(self) -> dict[str, Any]:
        data = self._authed("GET", "/diagnostics")
        if not isinstance(data, dict):
            raise NodeRedError("antwoord_ongeldig", 200, "/diagnostics")
        return data

    # ------------------------------------------------------------------ schrijven (alleen herstel, B11-005)
    def post_flows(self, rev: str, flows: list[dict[str, Any]], credentials: dict[str, Any] | None = None) -> str:
        """Zet de volledige flowconfiguratie. ``rev`` is de laatst gelezen revisie: Node-RED weigert met 409 als de
        flows intussen gewijzigd zijn. ``credentials`` is het door Node-RED zélf versleutelde blok (``{"$": ...}``)
        uit een momentopname; deze dienst kan het niet lezen. Wordt nooit herhaald: bij een netwerkfout is de uitkomst
        onbekend en leest de aanroeper terug."""
        body: dict[str, Any] = {"rev": rev, "flows": flows}
        if credentials is not None:
            body["credentials"] = credentials
        data = self._authed("POST", "/flows", json_body=body, extra={**API_HEADERS, "Node-RED-Deployment-Type": "full"})
        new_rev = data.get("rev") if isinstance(data, dict) else None
        if not isinstance(new_rev, str) or not REV_RE.fullmatch(new_rev):
            raise NodeRedError("antwoord_ongeldig", 200, "/flows")
        return new_rev


def client_from_source(
    session: Session, settings: Settings, vault: Vault, transport: httpx.BaseTransport | None
) -> NodeRedClient:
    """Bouwt een client uit de bronconfiguratie (adres + aanmeldgegevens in de vault). Fail-closed."""
    row = session.get(IntegrationSource, SOURCE_ID)
    if row is None or not row.base_url:
        raise NodeRedError("niet_geconfigureerd")
    if not row.enabled:
        raise NodeRedError("uitgeschakeld")
    try:
        base = validate_hub_url(row.base_url, settings.allow_loopback_hub, label="Het Node-RED-adres", allow_path=True)
    except HubUrlError as exc:
        raise NodeRedError("ongeldig_adres") from exc
    if not row.credential_ref:
        raise NodeRedError("geen_aanmelding")
    credential = vault.get(session, row.credential_ref)
    if not credential:
        raise NodeRedError("geen_aanmelding")
    username, sep, password = credential.partition(":")
    if not sep or not username or not password:
        raise NodeRedError("aanmelding_ongeldig")
    return NodeRedClient(base, username, password, settings, transport=transport)


CONFIG_REASONS = ("niet_geconfigureerd", "uitgeschakeld", "ongeldig_adres", "geen_aanmelding", "aanmelding_ongeldig")
UNREACHABLE_REASONS = ("onbereikbaar", "timeout", "http_5xx")


def api_error(exc: NodeRedError) -> ApiError:
    """Vertaalt een Node-RED-fout naar het contractfoutformaat; nooit een gesimuleerd resultaat."""
    if exc.reason in CONFIG_REASONS:
        return ApiError(409, "node_red_niet_ingesteld", exc.message_nl, exc.to_dict())
    if exc.reason in UNREACHABLE_REASONS:
        return ApiError(503, "node_red_unavailable", exc.message_nl, exc.to_dict(), headers={"Retry-After": "30"})
    return ApiError(502, "node_red_fout", exc.message_nl, exc.to_dict())
