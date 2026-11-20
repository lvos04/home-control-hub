"""Lokale my_house-leesbron met de vorm van views.energy.live_power en energy_summary."""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx


class MyHouseEnergy:
    def __init__(self) -> None:
        self.home = uuid.uuid4()
        self.path = f"/api/v1/homes/{self.home}"
        self.address = f"https://woning.test{self.path}"
        self.token = "shc_" + secrets.token_urlsafe(32)
        self.at = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
        self.summary = {"meters": [{"role": "grid", "unit": "kWh", "quality": "estimated", "kwh": 3.1}]}
        self.live: dict[str, Any] = {
            "at": self.at,
            "total_w": -42.5,
            "complete": True,
            "parts": [
                {"role": "airco", "watts": 74, "at": self.at, "quality": "measured", "stale": False},
                {"role": "boiler", "watts": 0, "at": self.at, "quality": "measured", "stale": False},
                {"role": "rest", "watts": 0, "at": self.at, "quality": "derived", "stale": False},
            ],
        }
        self.status = 200
        self.summary_status = 200
        self.reachable = True
        self.calls: list[tuple[str, str]] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        assert request.method == "GET"
        assert request.url.host == "woning.test"
        assert request.headers.get("Authorization") == f"Bearer {self.token}"
        assert "cookie" not in request.headers
        if not self.reachable:
            raise httpx.ConnectError("Testbron niet bereikbaar")
        status = self.summary_status if path.endswith("/energy/summary") and self.status == 200 else self.status
        if status != 200:
            return httpx.Response(status, text=self.token, headers={"Location": "https://elders.test/"})
        if path == f"{self.path}/energy/export":
            assert request.url.params["format"] == "json"
            assert request.url.params["from"] == request.url.params["to"]
            return httpx.Response(200, json={"rows": []})
        data: dict[str, Any] = {
            f"{self.path}/energy/live": self.live,
            f"{self.path}/energy/summary": self.summary,
            f"{self.path}/tariffs": [],
            "/api/v1/energy/limits": {"grid": 20},
        }
        return httpx.Response(200, json=data[path])
