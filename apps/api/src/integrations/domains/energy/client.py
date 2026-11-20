"""De vijf GET-routes van de eigen my_house-viewerkoppeling (ADR-0034, Energie)."""

from __future__ import annotations

import json
import random
import re
import time
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from ...bodylimit import MAX_BODY_BYTES
from ...config import Settings
from ...hubclient import ForbiddenAddressError, HubClient, validate_hub_url


class EnergyRoute(Enum):
    SUMMARY = "energy/summary"
    LIVE = "energy/live"
    EXPORT = "energy/export"
    TARIFFS = "tariffs"
    LIMITS = "energy/limits"


class EnergyReadError(ValueError):
    """Uitsluitend vaste Nederlandstalige redenen, zonder broninhoud of aanmeldgegevens."""


class ViewerDenied(EnergyReadError):
    """De bron accepteert de koppeling niet meer, ook eerder ontvangen gegevens vervallen."""


class EnergyClient:
    def __init__(self, address: str, token: str, settings: Settings, transport: httpx.BaseTransport | None) -> None:
        try:
            parts = urlsplit(validate_hub_url(address, settings.allow_loopback_hub, allow_path=True))
            suffix = parts.path.removeprefix("/api/v1/homes/")
            self.home = UUID(suffix)
            if parts.path != f"/api/v1/homes/{self.home}":
                raise ValueError
        except ValueError:
            raise EnergyReadError("Vul het my_house-bronadres met /api/v1/homes/<woning-UUID> in.") from None
        if not re.fullmatch(r"shc_[A-Za-z0-9_-]{43}", token):
            raise EnergyReadError("Het viewer-token heeft een ongeldig formaat.")
        self._origin = parts._replace(path="").geturl()
        self._token = token
        self._http = HubClient(settings, transport)

    def read(self, route: EnergyRoute, *, day: date | None = None) -> Any:
        if not isinstance(route, EnergyRoute):
            raise EnergyReadError("Onbekende energieleesroute.")
        path = "/api/v1/energy/limits" if route is EnergyRoute.LIMITS else f"/api/v1/homes/{self.home}/{route.value}"
        params: dict[str, str] = {}
        if route is EnergyRoute.EXPORT:
            selected = (day or datetime.now(UTC).date()).isoformat()
            params = {"format": "json", "resolution": "hour", "from": selected, "to": selected}
        headers = {"Authorization": f"Bearer {self._token}", "Accept-Encoding": "identity"}
        for attempt in range(3):
            try:
                with self._http.stream_get(self._origin, path, headers=headers, params=params) as response:
                    if response.status_code == 200:
                        return _json(response)
                    if response.status_code in (401, 403):
                        raise ViewerDenied("my_house weigert de viewer-koppeling.")
                    if response.status_code not in (429, 502, 503, 504) or "Retry-After" in response.headers:
                        # Geen wachttijd van de bron verkorten binnen een interactief verzoek.
                        raise EnergyReadError("my_house heeft de energielezing geweigerd.")
            except ForbiddenAddressError:
                raise EnergyReadError("Het bronadres is niet toegestaan.") from None
            except (httpx.InvalidURL, httpx.DecodingError):
                raise EnergyReadError("De bron of het energieantwoord heeft een ongeldig formaat.") from None
            except httpx.TransportError:
                pass
            if attempt < 2:
                time.sleep(0.15 * 2**attempt * random.uniform(0.5, 1.5))  # noqa: S311 - jitter
        raise EnergyReadError("my_house is niet bereikbaar voor de energielezing.")


def _json(response: httpx.Response) -> Any:
    body = bytearray()
    for block in response.iter_bytes(chunk_size=65536):
        if len(body) + len(block) > MAX_BODY_BYTES:
            raise EnergyReadError("Het energieantwoord is te groot.")
        body.extend(block)
    try:
        return json.loads(body)
    except (ValueError, RecursionError):
        raise EnergyReadError("my_house gaf een ongeldig JSON-antwoord.") from None
