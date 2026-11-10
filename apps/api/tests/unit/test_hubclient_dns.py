"""Unit (contract 1.3 §3.2, adresregels A11): bij een hostnaam gelden de verboden bereiken ook voor het opgeloste adres,
bij elke verbinding. De dienst lost de naam zelf op, controleert elk adres en verbindt met dat adres (``Host`` en
TLS-SNI blijven de naam). Geen netwerk: een nep-resolver en ``httpx.MockTransport``."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import httpx
import pytest

from integrations.config import Settings
from integrations.hubclient import ForbiddenAddressError, HubClient, forbidden_ip


def _client(tmp_path: Path, adressen: dict[str, list[str]], allow_loopback: bool = False) -> tuple[HubClient, list]:
    gezien: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        gezien.append(request)
        return httpx.Response(200, json={"ok": True})

    settings = Settings(data_dir=tmp_path, allow_loopback_hub=allow_loopback)
    hub = HubClient(settings, transport=httpx.MockTransport(handler), resolver=lambda h, _p: adressen[h])
    return hub, gezien


def test_hostname_is_pinned_to_the_checked_address(tmp_path: Path) -> None:
    hub, gezien = _client(tmp_path, {"hub.lan": ["192.168.1.20"]})
    r = hub.request("GET", "http://hub.lan:30400", "/api/v1/services/self")
    assert r.status_code == 200
    req = gezien[0]
    assert str(req.url) == "http://192.168.1.20:30400/api/v1/services/self" and req.headers["host"] == "hub.lan:30400"


def test_https_keeps_the_name_for_sni(tmp_path: Path) -> None:
    hub, gezien = _client(tmp_path, {"hub.lan": ["fd00::20"]})
    hub.request("GET", "https://hub.lan", "/x")
    req = gezien[0]
    assert str(req.url) == "https://[fd00::20]/x" and req.extensions.get("sni_hostname") == "hub.lan"
    assert req.headers["host"] == "hub.lan"


@pytest.mark.parametrize(
    "adres",
    ["127.0.0.1", "127.8.9.1", "::1", "169.254.169.254", "fe80::1", "0.0.0.0", "::", "::ffff:127.0.0.1"],  # noqa: S104
)
def test_forbidden_resolved_address_never_connects(tmp_path: Path, adres: str) -> None:
    hub, gezien = _client(tmp_path, {"rebind.example": ["192.168.1.20", adres]})
    with pytest.raises(ForbiddenAddressError):
        hub.request("POST", "http://rebind.example:30400", "/api/v1/services/enroll", json={})
    assert gezien == []  # nooit verbonden, ook niet met het toegestane adres ernaast


def test_resolution_is_checked_on_every_connection(tmp_path: Path) -> None:
    """DNS-rebinding: eerst een LAN-adres, bij de volgende verbinding loopback → geweigerd."""
    antwoorden = [["192.168.1.20"], ["127.0.0.1"]]
    gezien: list[httpx.Request] = []
    settings = Settings(data_dir=tmp_path)
    hub = HubClient(
        settings,
        transport=httpx.MockTransport(lambda r: (gezien.append(r), httpx.Response(200))[1]),
        resolver=lambda _h, _p: antwoorden.pop(0),
    )
    assert hub.request("GET", "http://hub.lan:30400", "/a").status_code == 200
    with pytest.raises(ForbiddenAddressError):
        hub.request("GET", "http://hub.lan:30400", "/b")
    assert len(gezien) == 1


def test_loopback_only_with_the_development_flag(tmp_path: Path) -> None:
    hub, _gezien = _client(tmp_path, {"localhost-alias": ["127.0.0.1"]}, allow_loopback=True)
    assert hub.request("GET", "http://localhost-alias:30400", "/a").status_code == 200
    assert forbidden_ip(ipaddress.ip_address("169.254.0.1"), True) == "link-local"  # link-local nooit


def test_ip_literals_are_not_resolved(tmp_path: Path) -> None:
    def nooit(_h: str, _p: int) -> list[str]:
        raise AssertionError("een IP-adres wordt niet opnieuw opgelost")

    gezien: list[httpx.Request] = []
    hub = HubClient(
        Settings(data_dir=tmp_path),
        transport=httpx.MockTransport(lambda r: (gezien.append(r), httpx.Response(200))[1]),
        resolver=nooit,
    )
    assert hub.request("GET", "http://192.168.1.20:30400", "/a").status_code == 200
    assert str(gezien[0].url) == "http://192.168.1.20:30400/a"


def test_default_resolver_only_without_a_custom_transport(tmp_path: Path) -> None:
    assert HubClient(Settings(data_dir=tmp_path)).resolver is not None
    assert (
        HubClient(Settings(data_dir=tmp_path), transport=httpx.MockTransport(lambda r: httpx.Response(200))).resolver
        is None
    )
