"""Uitgaande HTTP-calls naar de Hub (contract §5: 5 s connect / 15 s read, retry met backoff + jitter, max 3)."""

from __future__ import annotations

import contextlib
import ipaddress
import random
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx

from . import __version__
from .config import Settings

RETRY_STATUS = {429, 502, 503, 504}


class HubUrlError(ValueError):
    """Ongeldig adres; de boodschap is Nederlands en mag aan de gebruiker getoond worden."""


def validate_hub_url(url: str, allow_loopback: bool = False, label: str = "Het Hub-adres") -> str:
    url = url.strip().rstrip("/")
    if len(url) > 500:
        raise HubUrlError(f"{label} is te lang.")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise HubUrlError(f"{label} moet met http:// of https:// beginnen.")
    if not parts.hostname:
        raise HubUrlError(f"{label} mist een hostnaam of IP-adres.")
    if parts.username or parts.password:
        raise HubUrlError(f"Zet geen gebruikersnaam of wachtwoord in {label.lower().removeprefix('het ')}.")
    if parts.query or parts.fragment:
        raise HubUrlError(f"{label} mag geen ?-parameters of #-deel bevatten.")
    host = parts.hostname.lower()
    loopback = host == "localhost" or host.endswith(".localhost")
    with contextlib.suppress(ValueError):
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    if loopback and not allow_loopback:
        raise HubUrlError(
            "Loopback-adressen (localhost/127.0.0.1) wijzen naar deze container zelf. Gebruik het LAN-adres van de NAS "
            "met de poort van de app."
        )
    return url


class HubClient:
    def __init__(
        self,
        settings: Settings,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self.sleep = sleep

    def _client(self, base_url: str) -> httpx.Client:
        s = self.settings
        timeout = httpx.Timeout(
            connect=s.http_connect_timeout_s,
            read=s.http_read_timeout_s,
            write=s.http_read_timeout_s,
            pool=s.http_connect_timeout_s,
        )
        return httpx.Client(
            base_url=base_url,
            timeout=timeout,
            transport=self.transport,
            follow_redirects=False,
            headers={"User-Agent": f"home-control-hub/{__version__}", "Accept": "application/json"},
        )

    def request(
        self,
        method: str,
        base_url: str,
        path: str,
        *,
        json: Any = None,
        headers: dict[str, str] | None = None,
        attempts: int | None = None,
    ) -> httpx.Response:
        """Voert een call uit met maximaal ``http_max_attempts`` pogingen bij netwerkfouten en 429/5xx-gateway-fouten."""
        max_attempts = attempts or self.settings.http_max_attempts
        last_exc: Exception | None = None
        with self._client(base_url) as client:
            for attempt in range(1, max_attempts + 1):
                try:
                    resp = client.request(method, path, json=json, headers=headers)
                except httpx.TransportError as exc:
                    last_exc = exc
                else:
                    if resp.status_code not in RETRY_STATUS or attempt == max_attempts:
                        return resp
                if attempt < max_attempts:
                    self.sleep(min(8.0, 0.5 * (2 ** (attempt - 1))) * random.uniform(0.5, 1.5))  # noqa: S311
        if last_exc is None:  # pragma: no cover - onbereikbaar: de lus geeft altijd een respons of een fout
            raise RuntimeError("geen respons")
        raise last_exc

    def get_json(self, base_url: str, path: str, headers: dict[str, str] | None = None) -> Any:
        resp = self.request("GET", base_url, path, headers=headers)
        resp.raise_for_status()
        return resp.json()
