"""Afgeschermde Authentik-verbinding voor een vooraf bevestigd uitvoerdoel (ADR-0033).

Beschikbaar voor gecontroleerde readback. Alleen de vaste providerroute is bereikbaar. De aanroeper
levert de bevestigde binding uit vertrouwde configuratie aan, onafhankelijk van het uitvoeringsverzoek.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import certifi

from ....config import Settings
from ....hubclient import validate_hub_url
from .client import API, MAX_BYTES, AuthentikClient, AuthentikError
from .reader import clean_provider

BASE_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")


@dataclass(frozen=True)
class ProviderTarget:
    base_url: str
    provider_pk: int
    client_id: str


def _https_base(value: str, settings: Settings) -> str:
    try:
        if any(ord(char) < 33 or ord(char) > 126 for char in value) or "\\" in value:
            raise ValueError
        base = validate_hub_url(value, settings.allow_loopback_hub, label="Het Authentik-adres", allow_path=True)
        parts = urlsplit(base)
        if not BASE_PATH.fullmatch(parts.path) or {".", ".."}.intersection(parts.path.split("/")):
            raise ValueError
    except ValueError:
        raise AuthentikError("authentik_doel_ongeldig") from None
    if parts.scheme != "https":
        raise AuthentikError("https_verplicht")
    return base


def _tls_context() -> ssl.SSLContext:
    # De vaste publieke CA-bundel, zoals bij de bestaande httpx-client met trust_env=False.
    return ssl.create_default_context(cafile=certifi.where())


def read_provider(
    source_url: str,
    confirmed: ProviderTarget,
    requested: ProviderTarget,
    settings: Settings,
    get_credential: Callable[[], str | None],
) -> dict[str, Any]:
    """Valideert het doel en voltooit TLS op dezelfde verbinding vóór het beheercredential wordt opgehaald."""
    base = _https_base(source_url, settings)
    confirmed_base = _https_base(confirmed.base_url, settings)
    requested_base = _https_base(requested.base_url, settings)
    if (
        base != confirmed_base
        or base != requested_base
        or type(confirmed.provider_pk) is not int
        or type(requested.provider_pk) is not int
        or confirmed.provider_pk <= 0
        or confirmed.provider_pk != requested.provider_pk
        or not isinstance(confirmed.client_id, str)
        or not confirmed.client_id
        or confirmed.client_id != requested.client_id
    ):
        raise AuthentikError("authentik_doel_ongeldig")

    parts = urlsplit(base)
    path = f"{parts.path}{API}/providers/oauth2/{confirmed.provider_pk}/"
    connection = http.client.HTTPSConnection(
        parts.hostname or "", parts.port, timeout=settings.http_connect_timeout_s, context=_tls_context()
    )
    try:
        connection.connect()
        if connection.sock is None:
            raise AuthentikError("onbereikbaar")
        connection.sock.settimeout(settings.http_read_timeout_s)
        connection.auto_open = 0  # uitsluitend de zojuist geverifieerde verbinding gebruiken
        credential = get_credential()
        if not credential:
            raise AuthentikError("geen_token")
        connection.request("GET", path, headers={"Authorization": f"Bearer {credential}", "Accept": "application/json"})
        with connection.getresponse() as response:
            AuthentikClient._check(response.status, path)
            body = response.read(MAX_BYTES + 1)
    except ssl.SSLCertVerificationError:
        raise AuthentikError("tls_ongeverifieerd") from None
    except TimeoutError:
        raise AuthentikError("timeout") from None
    except (OSError, http.client.HTTPException):
        raise AuthentikError("onbereikbaar") from None
    except ValueError:
        raise AuthentikError("onverwacht_antwoord") from None
    finally:
        connection.close()

    if len(body) > MAX_BYTES:
        raise AuthentikError("antwoord_te_groot")
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise AuthentikError("antwoord_ongeldig") from None
    if not isinstance(data, dict):
        raise AuthentikError("antwoord_ongeldig")
    if (
        type(data.get("pk")) is not int
        or data["pk"] != confirmed.provider_pk
        or data.get("client_id") != confirmed.client_id
    ):
        raise AuthentikError("authentik_doel_ongeldig")
    return clean_provider(data)
