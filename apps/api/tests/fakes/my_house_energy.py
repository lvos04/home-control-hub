"""Lokale my_house-leesbron met de vorm van views.energy.live_power en energy_summary."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import httpx


class MyHouseEnergy:
    def __init__(self) -> None:
        self.home = uuid.uuid4()
        self.server_id = uuid.uuid4()
        self.client_id = uuid.uuid4()
        self.homes = [self.home]
        self.role = "viewer"
        self.purpose = "hub"
        self.path = f"/api/v1/homes/{self.home}"
        self.address = f"https://woning.test{self.path}"
        self.token = "shc_" + secrets.token_urlsafe(32)
        self.at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        self.summary = {"meters": [{"role": "grid", "unit": "kWh", "quality": "estimated", "kwh": 3.1}]}
        self.summary.update(timezone="Europe/Amsterdam", currency="EUR")
        self.hour_rows: dict[date, list[dict[str, Any]]] = {}
        self.tariffs: list[dict[str, Any]] = []
        self.live: dict[str, Any] = {
            "at": self.at,
            "total_w": -42.5,
            "total_observed_at": self.at,
            "total_source_quality": "measured",
            "complete": True,
            "parts": [
                {
                    "role": "airco",
                    "watts": 74,
                    "at": self.at,
                    "quality": "measured",
                    "source_quality": "measured",
                    "stale": False,
                },
                {
                    "role": "boiler",
                    "watts": 0,
                    "at": self.at,
                    "quality": "measured",
                    "source_quality": "measured",
                    "stale": False,
                },
                {"role": "rest", "watts": 0, "at": self.at, "quality": "derived", "stale": False},
            ],
        }
        self.status = 200
        self.summary_status = 200
        self.reachable = True
        self.checks: list[str] = []
        self.nonces: list[str] = []
        self.calls: list[tuple[str, str]] = []

    @property
    def pairing(self) -> dict[str, str]:
        return {"server_id": str(self.server_id), "client_id": str(self.client_id), "home_id": str(self.home)}

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        assert request.method == "GET"
        assert request.url.host == "woning.test"
        assert "cookie" not in request.headers
        if not self.reachable:
            raise httpx.ConnectError("Testbron niet bereikbaar")
        if path == "/api/v1/pairing/identity":
            assert "Authorization" not in request.headers
            self.checks.append(path)
            nonce = request.url.params["nonce"]
            self.nonces.append(nonce)
            proof = None
            if request.url.params["client_id"] == str(self.client_id):
                key = hashlib.sha256(self.token.encode()).hexdigest().encode()
                message = f"shc-identity-v1\n{self.server_id}\n{nonce}".encode()
                proof = hmac.digest(key, message, "sha256").hex()
            return httpx.Response(
                200, json={"server_id": str(self.server_id), "proof_alg": "hmac-sha256-v1", "proof": proof}
            )
        assert request.headers.get("Authorization") == f"Bearer {self.token}"
        if path == "/api/v1/clients/self":
            self.checks.append(path)
            return httpx.Response(200, json={"id": str(self.client_id), "role": self.role, "purpose": self.purpose})
        if path == "/api/v1/homes":
            self.checks.append(path)
            return httpx.Response(200, json=[{"id": str(home)} for home in self.homes])
        self.calls.append((request.method, path))
        status = self.summary_status if path.endswith("/energy/summary") and self.status == 200 else self.status
        if status != 200:
            return httpx.Response(status, text=self.token, headers={"Location": "https://elders.test/"})
        if path == f"{self.path}/energy/export":
            assert request.url.params["format"] == "json"
            assert request.url.params["resolution"] == "hour"
            assert request.url.params["from"] == request.url.params["to"]
            day = date.fromisoformat(request.url.params["from"])
            zone = ZoneInfo(str(self.summary["timezone"]))
            start = datetime.combine(day, time.min, zone)
            return httpx.Response(
                200,
                json={
                    "schema": "shc.energy.v2",
                    "resolution": "hour",
                    "timezone": zone.key,
                    "from": start.astimezone(UTC).isoformat(),
                    "to": (start + timedelta(days=1)).astimezone(UTC).isoformat(),
                    "rows": self.hour_rows.get(day, []),
                },
            )
        data: dict[str, Any] = {
            f"{self.path}/energy/live": self.live,
            f"{self.path}/energy/summary": self.summary,
            f"{self.path}/tariffs": self.tariffs,
            "/api/v1/energy/limits": {"grid": 20},
        }
        return httpx.Response(200, json=data[path])
