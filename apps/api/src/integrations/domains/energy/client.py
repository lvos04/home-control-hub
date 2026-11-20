"""De vijf GET-routes van de eigen my_house-viewerkoppeling (ADR-0034, Energie)."""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import re
import secrets
import time
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field

from ...bodylimit import MAX_BODY_BYTES
from ...config import Settings
from ...hubclient import HubClient, validate_hub_url


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


class ViewerPairing(BaseModel):
    """De drie ID's uit het bevestigde my_house-koppelantwoord."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    server_id: UUID
    client_id: UUID
    home_id: UUID


class BoundViewer(BaseModel):
    """Eén versleutelde kluiswaarde bindt het credential ook aan het bevestigde HTTPS-adres."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    address: str
    pairing: ViewerPairing
    token: str = Field(repr=False)


def stored_viewer(value: str | None) -> BoundViewer:
    try:
        return BoundViewer.model_validate_json(value or "")
    except ValueError:
        raise ViewerDenied("Bevestig de my_house-koppeling opnieuw met de server-ID, client-ID en woning.") from None


def energy_address(address: str, settings: Settings) -> tuple[str, UUID]:
    try:
        parts = urlsplit(validate_hub_url(address, settings.allow_loopback_hub, allow_path=True))
        home = UUID(parts.path.removeprefix("/api/v1/homes/"))
        if parts.path != f"/api/v1/homes/{home}":
            raise ValueError
    except ValueError:
        raise EnergyReadError("Vul het my_house-bronadres met /api/v1/homes/<woning-UUID> in.") from None
    if parts.scheme != "https":
        raise EnergyReadError("Een my_house-koppeling vereist HTTPS.")
    return parts._replace(path="").geturl(), home


class EnergyClient:
    def __init__(
        self, address: str, viewer: BoundViewer | str, settings: Settings, transport: httpx.BaseTransport | None
    ) -> None:
        self._origin, self.home = energy_address(address, settings)
        if not isinstance(viewer, BoundViewer):
            raise ViewerDenied("De bevestigde server-ID, client-ID en woning ontbreken.")
        if viewer.address != address or viewer.pairing.home_id != self.home:
            raise ViewerDenied("Het bronadres of de woning wijkt af van de bevestigde koppeling.")
        if not re.fullmatch(r"shc_[A-Za-z0-9_-]{43}", viewer.token):
            raise ViewerDenied("Het viewer-token heeft een ongeldig formaat.")
        self._viewer = viewer
        self._http = HubClient(settings, transport)

    def verify(self) -> None:
        """Dezelfde poort voor het bewaren van een koppeling en voor iedere poging tot lezen."""
        with self._viewer_session():
            pass

    @contextmanager
    def _viewer_session(self) -> Iterator[tuple[httpx.Client, dict[str, Any]]]:
        pairing = self._viewer.pairing
        with ExitStack() as stack:
            try:
                client, tls = stack.enter_context(self._http.pinned_client(self._origin))
                client.headers["Accept-Encoding"] = "identity"

                def check(path: str, params: dict[str, str] | None = None) -> Any:
                    client.cookies.clear()
                    with client.stream("GET", path, params=params, extensions=tls) as response:
                        if response.status_code != 200:
                            raise ViewerDenied("my_house weigert de controle van de viewer-koppeling.")
                        return _json(response)

                nonce = secrets.token_urlsafe(24)
                identity = check("/api/v1/pairing/identity", {"client_id": str(pairing.client_id), "nonce": nonce})
                key = hashlib.sha256(self._viewer.token.encode()).hexdigest().encode()
                message = f"shc-identity-v1\n{pairing.server_id}\n{nonce}".encode()
                expected = hmac.digest(key, message, "sha256").hex()
                proof = identity.get("proof") if isinstance(identity, dict) else None
                if (
                    not isinstance(proof, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", proof)
                    or identity.get("server_id") != str(pairing.server_id)
                    or identity.get("proof_alg") != "hmac-sha256-v1"
                    or not hmac.compare_digest(expected, proof)
                ):
                    raise ViewerDenied("De bevestigde my_house-instantie heeft haar identiteit niet bewezen.")

                client.headers["Authorization"] = f"Bearer {self._viewer.token}"
                own = check("/api/v1/clients/self")
                if (
                    not isinstance(own, dict)
                    or own.get("id") != str(pairing.client_id)
                    or own.get("role") != "viewer"
                    or own.get("purpose") != "hub"
                    or own.get("revoked", False) is not False
                    or own.get("expired", False) is not False
                ):
                    raise ViewerDenied("De bevestigde client heeft geen geldige viewer-koppeling voor de Hub.")
                homes = check("/api/v1/homes")
                if not isinstance(homes, list) or not any(
                    isinstance(home, dict) and home.get("id") == str(pairing.home_id) for home in homes
                ):
                    raise ViewerDenied("my_house bevestigt de gekoppelde woning niet.")
                client.cookies.clear()
            except ViewerDenied:
                raise
            except (httpx.HTTPError, httpx.InvalidURL, EnergyReadError):
                raise ViewerDenied("De viewer-koppeling met my_house kon niet worden bevestigd.") from None
            yield client, tls

    def read(self, route: EnergyRoute, *, day: date | None = None) -> Any:
        if not isinstance(route, EnergyRoute):
            raise EnergyReadError("Onbekende energieleesroute.")
        path = "/api/v1/energy/limits" if route is EnergyRoute.LIMITS else f"/api/v1/homes/{self.home}/{route.value}"
        params: dict[str, str] = {}
        if route is EnergyRoute.EXPORT:
            selected = (day or datetime.now(UTC).date()).isoformat()
            params = {"format": "json", "resolution": "hour", "from": selected, "to": selected}
        for attempt in range(3):
            try:
                with (
                    self._viewer_session() as (client, tls),
                    client.stream("GET", path, params=params, extensions=tls) as response,
                ):
                    if response.status_code == 200:
                        return _json(response)
                    if response.status_code in (401, 403):
                        raise ViewerDenied("my_house weigert de viewer-koppeling.")
                    if response.status_code not in (429, 502, 503, 504) or "Retry-After" in response.headers:
                        # Geen wachttijd van de bron verkorten binnen een interactief verzoek.
                        raise EnergyReadError("my_house heeft de energielezing geweigerd.")
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
