"""Afgeschermde Authentik-verbinding voor een vooraf bevestigd uitvoerdoel (ADR-0033).

Beschikbaar voor gecontroleerde readback. Alleen de vaste providerroute is bereikbaar. De aanroeper
levert de bevestigde binding uit vertrouwde configuratie aan, onafhankelijk van het uitvoeringsverzoek.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import certifi
import httpx

from ....config import Settings
from ....hubclient import forbidden_ip, resolve_host, validate_hub_url
from .client import API, MAX_BYTES, AuthentikClient, AuthentikError
from .reader import clean_provider

BASE_PATH = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProviderTarget:
    base_url: str
    provider_pk: int
    client_id: str
    peer_address: str = ""
    certificate_sha256: str = ""
    redirect_uris: tuple[str, ...] = ()


BindingCheck = Callable[[http.client.HTTPSConnection, str], tuple[int, str] | None]


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
    # PROTOCOL_TLS_CLIENT vereist een vertrouwde keten en passende servernaam, zonder SSLKEYLOGFILE te lezen.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        context.load_verify_locations(cafile=certifi.where())
    except OSError:
        raise AuthentikError("tls_ongeverifieerd") from None
    return context


def _connect(
    host: str, port: int, target: ProviderTarget, settings: Settings, context: ssl.SSLContext
) -> ssl.SSLSocket:
    address = ipaddress.ip_address(target.peer_address)
    resolved = {ipaddress.ip_address(value) for value in resolve_host(host, port)}
    if (
        address not in resolved
        or getattr(address, "scope_id", None) is not None
        or any(
            forbidden_ip(candidate, settings.allow_loopback_hub)
            or candidate.is_multicast
            or (isinstance(candidate, ipaddress.IPv6Address) and candidate.ipv4_mapped is not None)
            for candidate in resolved
        )
    ):
        raise AuthentikError("authentik_doel_ongeldig")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as raw:
        raw.settimeout(settings.http_connect_timeout_s)
        raw.connect((str(address), port))
        tls = context.wrap_socket(raw, server_hostname=host)
    try:
        peer = ipaddress.ip_address(tls.getpeername()[0])
        certificate = tls.getpeercert(binary_form=True)
        if peer != address or not certificate or hashlib.sha256(certificate).hexdigest() != target.certificate_sha256:
            raise AuthentikError("authentik_doel_ongeldig")
        tls.settimeout(settings.http_read_timeout_s)
    except (ValueError, OSError, AuthentikError):
        tls.close()
        raise
    return tls


def read_provider(
    source_url: str,
    confirmed: ProviderTarget,
    requested: ProviderTarget,
    settings: Settings,
    get_credential: Callable[[], str | None],
    *,
    confirm_binding: BindingCheck | None = None,
) -> dict[str, Any]:
    """Leest alleen met een onafhankelijke, actuele provider-/clientcontrole op de bevestigde TLS-verbinding."""
    try:
        result = _read_provider(source_url, confirmed, requested, settings, get_credential, confirm_binding)
    except AuthentikError:
        log.info("Authentik-providerlezing geweigerd.")
        raise
    log.info("Authentik-providerlezing voltooid.")
    return result


def _read_provider(
    source_url: str,
    confirmed: ProviderTarget,
    requested: ProviderTarget,
    settings: Settings,
    get_credential: Callable[[], str | None],
    confirm_binding: BindingCheck | None,
) -> dict[str, Any]:
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
    if (
        confirm_binding is None
        or not confirmed.peer_address
        or re.fullmatch(r"[a-f0-9]{64}", confirmed.certificate_sha256) is None
    ):
        raise AuthentikError("authentik_binding_onbevestigd")

    parts = urlsplit(base)
    host, port = parts.hostname or "", parts.port or 443
    path = f"{parts.path}{API}/providers/oauth2/{confirmed.provider_pk}/"
    context = _tls_context()
    connection = http.client.HTTPSConnection(host, port, context=context)
    connection.auto_open = 0
    try:
        tls = _connect(host, port, confirmed, settings, context)
        connection.sock = tls
        # Bij een redirect of andere fout gaat er geen beheercredential naar deze route.
        connection.request("HEAD", path)
        with connection.getresponse() as response:
            AuthentikClient._check(response.status, path)
        if connection.sock is not tls:
            raise AuthentikError("authentik_binding_onbevestigd")
        binding = confirm_binding(connection, path)
        if binding != (confirmed.provider_pk, confirmed.client_id) or connection.sock is not tls:
            raise AuthentikError("authentik_binding_onbevestigd")
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
    except (OSError, http.client.HTTPException, httpx.ConnectError):
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
    result = clean_provider(
        {key: value for key, value in data.items() if key not in {"name", "assigned_application_slug"}}
    )
    if result.pop("onvolledige_velden", None):
        raise AuthentikError("antwoord_ongeldig")
    redirects = result.pop("redirect_uris")
    if confirmed.redirect_uris:
        expected = sorted(confirmed.redirect_uris)
        if sorted(uri["url"] for uri in redirects) != expected:
            raise AuthentikError("authentik_doel_ongeldig")
        result["redirect_uris"] = redirects
    return result
