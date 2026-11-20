"""Bronkwaliteit van echte my_house-bronrij tot B14; draai met beide API-pakketten op het Python-pad."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.encoders import jsonable_encoder

from integrations.domains.energy.readings import live_readings


@pytest.mark.parametrize(
    ("grid", "boiler", "expected"),
    [
        ("measured", "estimated", ("gemeten", "geschat")),
        ("estimated", "derived", ("geschat", "onbekend")),
        ("derived", "measured", ("onbekend", "gemeten")),
        (None, None, ("onbekend", "onbekend")),
    ],
)
def test_bronkwaliteit(monkeypatch, grid, boiler, expected):
    pytest.importorskip("shc_api", reason="De lokale werkkopie van my_house ontbreekt op het Python-pad.")
    from shc_api.models import Device, SensorReading
    from shc_api.views import energy

    home = uuid4()
    devices = {role: Device(id=uuid4()) for role in ("grid", "boiler")}
    now = datetime.now(UTC)
    at = now - timedelta(seconds=12)
    stored = {
        devices[role].id: SensorReading(
            device_id=devices[role].id, metric="power_w", value=value, unit="W", observed_at=at, quality=quality
        )
        for role, value, quality in (("grid", 34, grid), ("boiler", 0, boiler))
    }

    async def device_for_role(_db, home_id, role):
        assert home_id == home
        return devices.get(role)

    async def latest_reading(_db, device_id, metric):
        assert metric == "power_w"
        return stored[device_id]

    monkeypatch.setattr(energy, "device_for_role", device_for_role)
    monkeypatch.setattr(energy, "latest_reading", latest_reading)
    payload = jsonable_encoder(asyncio.run(energy.live_power(None, home)))
    readings = live_readings(payload, {"grid"}, now)
    for role, quality, watts in zip(("p1_net", "boiler_socket"), expected, (34, 0), strict=True):
        reading = readings[role]
        assert (reading.quality, reading.at, reading.value) == (quality, at, None if quality == "onbekend" else watts)
