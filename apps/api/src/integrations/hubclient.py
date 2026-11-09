"""Uitgaande HTTP-calls naar de Hub (contract 1.2 §3.2 en §5).

- 5 s connect / 15 s read; **nooit** een redirect volgen (3xx = storing); proxy-omgevingsvariabelen worden genegeerd
  (``trust_env=False``): de dienst praat rechtstreeks met het Hub-adres uit het formulier of de statuspagina.
- Elke aanroep doet één poging; herhalen (met backoff en jitter) regelt de aanroeper, zodat de regels van §3.3
  (``Retry-After`` bij 429, start 5 s en max. 15 min bij storingen, stoppen na 60 min) op één plek staan.
- Het Hub-adres volgt dezelfde regels voor ``HUB_URL`` en voor de statuspagina: ``http(s)://<host>[:<poort>]`` zonder
  pad, query, fragment of inloggegevens; geen loopback, geen link-local (``169.254.0.0/16``, ``fe80::/10``) en geen
  ``0.0.0.0``/``::`` (loopback alleen met de ontwikkelvlag ``HCH_ALLOW_LOOPBACK_HUB``).
"""

from __future__ import annotations

import contextlib
import ipaddress
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__
from .config import Settings


class HubUrlError(ValueError):
    """Ongeldig adres; de boodschap is Nederlands en mag aan de gebruiker getoond worden."""


def validate_hub_url(
    url: str, allow_loopback: bool = False, label: str = "Het Hub-adres", allow_path: bool = False
) -> str:
    """Geeft het genormaliseerde adres (``scheme://host[:poort]`` zonder slot-``/``) of gooit :class:`HubUrlError`.

    ``allow_path`` alleen voor adressen van bronnen (bv. Authentik achter een pad); het Hub-adres heeft nooit een pad.
    """
    url = (url or "").strip()
    if not url:
        raise HubUrlError(f"{label} ontbreekt.")
    if len(url) > 500 or any(ch.isspace() for ch in url):
        raise HubUrlError(f"{label} is te lang of bevat spaties.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise HubUrlError(f"{label} moet met http:// of https:// beginnen.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise HubUrlError(f"Zet geen gebruikersnaam of wachtwoord in {label.lower().removeprefix('het ')}.")
    if parts.query or parts.fragment or "?" in url or "#" in url:
        raise HubUrlError(f"{label} mag geen ?-parameters of #-deel bevatten.")
    if parts.path not in ("", "/") and not allow_path:
        raise HubUrlError(f"{label} mag geen pad bevatten: alleen http(s)://<NAS-adres>:<poort>.")
    host = (parts.hostname or "").lower()
    if not host:
        raise HubUrlError(f"{label} mist een hostnaam of IP-adres.")
    try:
        port = parts.port
    except ValueError as exc:
        raise HubUrlError(f"{label} heeft een ongeldige poort.") from exc
    if port == 0:
        raise HubUrlError(f"{label} heeft een ongeldige poort.")
    loopback = host == "localhost" or host.endswith(".localhost")
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
    with contextlib.suppress(ValueError):
        ip = ipaddress.ip_address(host)
    if ip is not None:
        if ip.is_unspecified:
            raise HubUrlError(f"{label} mag niet 0.0.0.0 of :: zijn; gebruik het LAN-adres van de NAS.")
        if ip.is_link_local:
            raise HubUrlError(f"{label} mag geen link-local-adres (169.254.x.x of fe80::) zijn.")
        loopback = loopback or ip.is_loopback
    if loopback and not allow_loopback:
        raise HubUrlError(
            "Loopback-adressen (localhost/127.0.0.1) wijzen naar deze container zelf. Gebruik het LAN-adres van de NAS "
            "met de poort van de Hub."
        )
    path = parts.path.rstrip("/") if allow_path else ""
    return f"{parts.scheme}://{parts.netloc}{path}"


class HubClient:
    """Maakt HTTP-clients voor Hub-aanroepen (één poging per aanroep; zie de moduledocstring)."""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.transport = transport

    @contextlib.contextmanager
    def client(self) -> Iterator[httpx.Client]:
        s = self.settings
        timeout = httpx.Timeout(
            connect=s.http_connect_timeout_s,
            read=s.http_read_timeout_s,
            write=s.http_read_timeout_s,
            pool=s.http_connect_timeout_s,
        )
        with httpx.Client(
            timeout=timeout,
            transport=self.transport,
            follow_redirects=False,
            trust_env=False,
            headers={"User-Agent": f"home-control-hub/{__version__}", "Accept": "application/json"},
        ) as c:
            yield c

    def request(
        self,
        method: str,
        base_url: str,
        path: str,
        *,
        json: Any = None,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> httpx.Response:
        with self.client() as c:
            return c.request(method, f"{base_url}{path}", json=json, headers=headers, params=params)
