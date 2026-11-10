"""Uitgaande HTTP-calls naar de Hub (contract 1.2 §3.2 en §5).

- 5 s connect / 15 s read; **nooit** een redirect volgen (3xx = storing); proxy-omgevingsvariabelen worden genegeerd
  (``trust_env=False``): de dienst praat rechtstreeks met het Hub-adres uit het formulier of de statuspagina.
- Elke aanroep doet één poging; herhalen (met backoff en jitter) regelt de aanroeper, zodat de regels van §3.3
  (``Retry-After`` bij 429, start 5 s en max. 15 min bij storingen, stoppen na 60 min) op één plek staan.
- Het Hub-adres volgt dezelfde regels voor ``HUB_URL`` en voor de statuspagina: ``http(s)://<host>[:<poort>]`` zonder
  pad, query, fragment of inloggegevens; geen loopback, geen link-local (``169.254.0.0/16``, ``fe80::/10``) en geen
  ``0.0.0.0``/``::`` (loopback alleen met de ontwikkelvlag ``HCH_ALLOW_LOOPBACK_HUB``).
- **Ook na DNS-resolutie, bij elke verbinding** (contract 1.3 §3.2): bij een hostnaam lost de dienst de naam zelf op,
  controleert **elk** opgelost adres op dezelfde verboden bereiken en verbindt dan met dat adres (``Host``-header en
  TLS-SNI blijven de naam). Zo kan een naam die later (DNS-rebinding) naar loopback of link-local wijst, nooit een
  verbinding naar zo'n adres opleveren.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import re
import socket
from collections.abc import Callable, Iterator
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from . import __version__
from .config import Settings

#: alleen cijfers, punten en hexadecimale delen: een IPv4-adres in welke vorm dan ook (geen geldige DNS-naam)
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+))*")


log = logging.getLogger("integrations.hubclient")

#: (host, poort) → opgeloste IP-adressen (tekst); te vervangen in tests
Resolver = Callable[[str, int], list[str]]


class HubUrlError(ValueError):
    """Ongeldig adres; de boodschap is Nederlands en mag aan de gebruiker getoond worden."""


class ForbiddenAddressError(httpx.ConnectError):
    """De hostnaam van de Hub wijst (nu) naar een verboden adres (§3.2): geen verbinding, telt als storing."""


def resolve_host(host: str, port: int) -> list[str]:
    """Alle adressen van ``host`` (IPv4 en IPv6), in de volgorde van de resolver, zonder dubbele."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise httpx.ConnectError(f"naam niet op te lossen ({type(exc).__name__})") from exc
    out: list[str] = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        if addr not in out:
            out.append(addr)
    return out


def forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_loopback: bool) -> str | None:
    """De reden waarom de dienst niet met dit adres mag verbinden (§3.2), of ``None``."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_unspecified:
        return "0.0.0.0/::"
    if ip.is_link_local:
        return "link-local"
    if ip.is_loopback and not allow_loopback:
        return "loopback"
    return None


def validate_hub_url(
    url: str, allow_loopback: bool = False, label: str = "Het Hub-adres", allow_path: bool = False
) -> str:
    """Geeft het genormaliseerde adres (``scheme://host[:poort]`` zonder slot-``/``) of gooit :class:`HubUrlError`.

    ``allow_path`` alleen voor adressen van bronnen (bv. Authentik achter een pad); het Hub-adres heeft nooit een pad.
    """
    url = (url or "").strip()
    if not url:
        raise HubUrlError(f"{label} ontbreekt.")
    if len(url) > 512 or any(ch.isspace() for ch in url):  # §3.7: Hub-adres ≤ 512 tekens
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
    # 'localhost.' en '127.0.0.1.' (punt achteraan) zijn dezelfde adressen; verkorte, decimale, octale of hexadecimale
    # IPv4-vormen ('127.1', '2130706433', '0x7f000001', '0', '010.0.0.1') zet de resolver om naar bv. loopback of
    # 0.0.0.0 en zouden de regels hieronder omzeilen: die worden geweigerd (alleen a.b.c.d; review contract 1.2)
    host = host.rstrip(".")
    if _NUMERIC_HOST.fullmatch(host):
        try:
            ipaddress.IPv4Address(host)
        except ValueError as exc:
            raise HubUrlError(
                f"{label} bevat een IP-adres in een afwijkende vorm; schrijf het als vier getallen van 0 tot 255 met "
                "punten ertussen."
            ) from exc
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
    """Maakt HTTP-clients voor Hub-aanroepen (één poging per aanroep; zie de moduledocstring).

    ``resolver``: standaard de systeemresolver, maar alleen zonder eigen ``transport``; tests met een nep-transport
    (namen als ``hub.test``) geven een eigen resolver mee om de DNS-regel te toetsen."""

    def __init__(
        self,
        settings: Settings,
        transport: httpx.BaseTransport | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self.resolver: Resolver | None = resolver if resolver is not None else (None if transport else resolve_host)

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
        url, hdrs, extensions = self._pin_address(base_url, path, dict(headers or {}))
        with self.client() as c:
            return c.request(method, url, json=json, headers=hdrs, params=params, extensions=extensions)

    def _pin_address(self, base_url: str, path: str, headers: dict[str, str]) -> tuple[str, dict[str, str], Any]:
        """§3.2: bij een hostnaam het opgeloste adres controleren en daarmee verbinden (per verbinding opnieuw)."""
        parts = urlsplit(base_url)
        host = (parts.hostname or "").rstrip(".")
        url = f"{base_url}{path}"
        try:
            ipaddress.ip_address(host)
            return url, headers, {}  # al een IP-adres: gecontroleerd door validate_hub_url
        except ValueError:
            pass
        if self.resolver is None or not host:
            return url, headers, {}
        port = parts.port or (443 if parts.scheme == "https" else 80)
        addrs = self.resolver(host, port)
        if not addrs:
            raise httpx.ConnectError("naam niet op te lossen")
        for addr in addrs:
            reden = forbidden_ip(ipaddress.ip_address(addr), self.settings.allow_loopback_hub)
            if reden is not None:
                log.warning("Hub-adres %s wijst naar een verboden adres (%s); geen verbinding (§3.2)", host, reden)
                raise ForbiddenAddressError(f"{host} wijst naar een verboden adres ({reden})")
        ip = addrs[0]
        netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        url = urlunsplit((parts.scheme, netloc, parts.path.rstrip("/") + path, "", ""))
        headers.setdefault("Host", parts.netloc)
        return url, headers, ({"sni_hostname": host} if parts.scheme == "https" else {})
