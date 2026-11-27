"""Bronkwaliteit van echte my_house-bronrij tot B14; draai met beide API-pakketten op het Python-pad."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.encoders import jsonable_encoder

from integrations.domains.energy.readings import live_readings


def koppel_bronmetingen(monkeypatch, home, metingen):
    from shc_api.models import Device, SensorReading
    from shc_api.views import energy

    devices = {role: Device(id=uuid4()) for role in metingen}
    stored = {
        devices[role].id: SensorReading(
            device_id=devices[role].id, metric="power_w", value=value, unit="W", observed_at=at, quality=quality
        )
        for role, (value, quality, at) in metingen.items()
    }

    async def device_for_role(_db, home_id, role):
        assert home_id == home
        return devices.get(role)

    async def latest_reading(_db, device_id, metric):
        assert metric == "power_w"
        return stored[device_id]

    monkeypatch.setattr(energy, "device_for_role", device_for_role)
    monkeypatch.setattr(energy, "latest_reading", latest_reading)


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
    from shc_api.views import energy

    home = uuid4()
    now = datetime.now(UTC)
    at = now - timedelta(seconds=12)
    koppel_bronmetingen(monkeypatch, home, {"grid": (34, grid, at), "boiler": (0, boiler, at)})
    payload = jsonable_encoder(asyncio.run(energy.live_power(None, home)))
    readings = live_readings(payload, {"grid"}, now)
    for role, quality, watts in zip(("p1_net", "boiler_socket"), expected, (34, 0), strict=True):
        reading = readings[role]
        assert (reading.quality, reading.at, reading.value) == (quality, at, None if quality == "onbekend" else watts)


def test_hubroute_bewaart_brontijd_per_verlopen_meterrol(monkeypatch):
    pytest.importorskip("shc_api", reason="De lokale werkkopie van my_house ontbreekt op het Python-pad.")
    from shc_api.deps import Principal
    from shc_api.models import User
    from shc_api.routers import energy

    home = uuid4()
    now = datetime.now(UTC)
    tijden = {
        rol: now - timedelta(seconds=leeftijd) for rol, leeftijd in (("grid", 390), ("boiler", 370), ("airco", 350))
    }
    koppel_bronmetingen(monkeypatch, home, {rol: (42, "measured", at) for rol, at in tijden.items()})

    async def get_home(_db, home_id):
        assert home_id == home

    monkeypatch.setattr(energy, "get_home", get_home)
    viewer = User(role="viewer")
    assert asyncio.run(energy.live(home, None, Principal(user=viewer, via="cookie"))) is None
    hub = Principal(user=viewer, via="token", client_role="viewer", client_purpose="hub")
    payload = jsonable_encoder(asyncio.run(energy.live(home, None, hub)))
    uitkomst = live_readings(payload, set(tijden), now)
    for bronrol, meterrol in (("grid", "p1_net"), ("boiler", "boiler_socket"), ("airco", "airco_outdoor")):
        meting = uitkomst[meterrol]
        assert (meting.at, meting.value, meting.quality, meting.reason_code) == (
            tijden[bronrol],
            None,
            "onbekend",
            "meting_verouderd",
        )
