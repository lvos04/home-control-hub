"""Client voor de officiële Authentik-API (``/api/v3``). In deze versie **alleen lezen** (GET).

- Token uit de vault (``vault://source/authentik``) als ``Authorization: Bearer``; nooit gelogd of teruggegeven.
- Contract §5: 5 s connect / 15 s read; alleen GET wordt herhaald (max. 3 pogingen, backoff + jitter) en alleen bij een
  netwerkfout of 429/502/503/504.
- Geen redirects volgen (een redirect naar een andere host zou het token kunnen lekken); antwoord max. 5 MiB.
- Paginering (``{"pagination": {"next": n|0}, "results": [...]}``) met een maximum aantal pagina's; wordt dat bereikt,
  dan is het resultaat ``volledig=False`` — nooit stil afkappen alsof dat alles was.
- Elke fout wordt ``AuthentikError`` met een vaste ``reason``; nooit een lege lijst als "geen data".
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from typing import Any

import httpx
from sqlalchemy.orm import Session

from .... import __version__
from ....config import Settings
from ....hubclient import HubUrlError, validate_hub_url
from ....models import IntegrationSource
from ....security.vault import Vault

API = "/api/v3"
SOURCE_ID = "authentik"
RETRY_STATUS = {429, 502, 503, 504}
MAX_BYTES = 5 * 1024 * 1024

REASONS_NL = {
    "niet_geconfigureerd": "Authentik is nog niet als bron ingesteld (adres ontbreekt).",
    "uitgeschakeld": "De bron Authentik staat uit.",
    "geen_token": "Er is geen Authentik-API-token opgeslagen (voer het in bij de bron Authentik).",
    "ongeldig_adres": "Het adres van Authentik is ongeldig.",
    "onbereikbaar": "Authentik is niet bereikbaar.",
    "timeout": "Authentik antwoordde niet op tijd.",
    "token_ongeldig": "Authentik weigerde het API-token (verlopen, ingetrokken of ongeldig).",
    "geen_rechten": "Het API-token mist de rechten voor dit onderdeel.",
    "niet_gevonden": "Dit onderdeel bestaat niet in deze Authentik-versie.",
    "http_5xx": "Authentik gaf een serverfout.",
    "onverwacht_antwoord": "Authentik gaf een onverwacht antwoord.",
    "antwoord_ongeldig": "Het antwoord van Authentik was geen geldige JSON of had een onverwacht formaat.",
    "antwoord_te_groot": "Het antwoord van Authentik was groter dan toegestaan.",
    "redirect": "Authentik antwoordde met een doorverwijzing; die wordt bewust niet gevolgd.",
}


class AuthentikError(Exception):
    def __init__(self, reason: str, http_status: int | None = None, path: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.http_status = http_status
        self.path = path

    @property
    def message_nl(self) -> str:
        return REASONS_NL.get(self.reason, "Onbekende fout bij Authentik.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "message_nl": self.message_nl,
            "http_status": self.http_status,
            "path": self.path,
        }


class AuthentikClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        settings: Settings,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        max_bytes: int = MAX_BYTES,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.settings = settings
        self.transport = transport
        self.sleep = sleep
        self.max_bytes = max_bytes

    def __repr__(self) -> str:  # nooit het token tonen
        return f"AuthentikClient({self.base_url!r})"

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
            headers={"User-Agent": f"home-control-hub/{__version__}", "Accept": "application/json"},
        )

    def _send(self, path: str, params: Any, auth: bool) -> tuple[int, bytes]:
        headers = {"Authorization": f"Bearer {self._token}"} if auth else {}
        last: AuthentikError | None = None
        attempts = max(1, self.settings.http_max_attempts)
        with self._client() as client:
            for attempt in range(1, attempts + 1):
                try:
                    req = client.build_request("GET", path, params=params, headers=headers)
                    resp = client.send(req, stream=True)
                    try:
                        status = resp.status_code
                        declared = resp.headers.get("Content-Length")
                        if declared and declared.isdigit() and int(declared) > self.max_bytes:
                            raise AuthentikError("antwoord_te_groot", status, path)
                        body = bytearray()
                        for chunk in resp.iter_bytes():
                            body.extend(chunk)
                            if len(body) > self.max_bytes:
                                raise AuthentikError("antwoord_te_groot", status, path)
                    finally:
                        resp.close()
                except httpx.TimeoutException:
                    last = AuthentikError("timeout", None, path)
                except httpx.TransportError:
                    last = AuthentikError("onbereikbaar", None, path)
                else:
                    if status not in RETRY_STATUS or attempt == attempts:
                        return status, bytes(body)
                    last = AuthentikError("http_5xx" if status >= 500 else "onverwacht_antwoord", status, path)
                if attempt < attempts:
                    self.sleep(min(8.0, 0.5 * (2 ** (attempt - 1))) * random.uniform(0.5, 1.5))  # noqa: S311
        raise last or AuthentikError("onbereikbaar", None, path)

    @staticmethod
    def _check(status: int, path: str, *, token_endpoint: bool = False) -> None:
        if 200 <= status < 300:
            return
        if 300 <= status < 400:
            raise AuthentikError("redirect", status, path)
        if status == 401 or (status == 403 and token_endpoint):
            raise AuthentikError("token_ongeldig", status, path)
        if status == 403:
            raise AuthentikError("geen_rechten", status, path)
        if status == 404:
            raise AuthentikError("niet_gevonden", status, path)
        if status >= 500:
            raise AuthentikError("http_5xx", status, path)
        raise AuthentikError("onverwacht_antwoord", status, path)

    def get_json(self, path: str, params: Any = None, *, token_endpoint: bool = False) -> Any:
        full = API + path
        status, body = self._send(full, params, auth=True)
        self._check(status, full, token_endpoint=token_endpoint)
        try:
            return json.loads(body)
        except ValueError as exc:
            raise AuthentikError("antwoord_ongeldig", status, full) from exc

    def get_text(self, path: str, params: Any = None) -> str:
        full = API + path
        status, body = self._send(full, params, auth=True)
        self._check(status, full)
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AuthentikError("antwoord_ongeldig", status, full) from exc

    def get_public_json(self, path: str) -> Any:
        """Niet-API-route zonder token (bv. ``/application/o/<slug>/.well-known/openid-configuration``)."""
        status, body = self._send(path, None, auth=False)
        self._check(status, path)
        try:
            return json.loads(body)
        except ValueError as exc:
            raise AuthentikError("antwoord_ongeldig", status, path) from exc

    def list_all(
        self, path: str, params: dict[str, Any] | None = None, page_size: int = 100, max_pages: int = 20
    ) -> tuple[list[dict[str, Any]], bool]:
        """Alle pagina's; geeft (items, volledig). ``volledig=False`` als ``max_pages`` bereikt is."""
        items: list[dict[str, Any]] = []
        page = 1
        for _ in range(max_pages):
            data = self.get_json(path, {**(params or {}), "page": page, "page_size": page_size})
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                raise AuthentikError("antwoord_ongeldig", 200, API + path)
            items.extend(x for x in data["results"] if isinstance(x, dict))
            nxt = (data.get("pagination") or {}).get("next")
            if not nxt:
                return items, True
            if not isinstance(nxt, int | float) or int(nxt) <= page:
                raise AuthentikError("antwoord_ongeldig", 200, API + path)
            page = int(nxt)
        return items, False

    def health(self, kind: str = "ready") -> int | None:
        """Statuscode van ``/-/health/<kind>/`` (zonder token); ``None`` als onbereikbaar."""
        try:
            status, _ = self._send(f"/-/health/{kind}/", None, auth=False)
        except AuthentikError:
            return None
        return status


def client_from_source(
    session: Session, settings: Settings, vault: Vault, transport: httpx.BaseTransport | None
) -> AuthentikClient:
    """Bouwt een client uit de bronconfiguratie (adres + token in de vault). Fail-closed bij ontbrekende delen."""
    row = session.get(IntegrationSource, SOURCE_ID)
    if row is None or not row.base_url:
        raise AuthentikError("niet_geconfigureerd")
    if not row.enabled:
        raise AuthentikError("uitgeschakeld")
    try:
        base = validate_hub_url(row.base_url, settings.allow_loopback_hub, label="Het Authentik-adres")
    except HubUrlError as exc:
        raise AuthentikError("ongeldig_adres") from exc
    if not row.credential_ref:
        raise AuthentikError("geen_token")
    token = vault.get(session, row.credential_ref)
    if not token:
        raise AuthentikError("geen_token")
    return AuthentikClient(base, token, settings, transport=transport)
