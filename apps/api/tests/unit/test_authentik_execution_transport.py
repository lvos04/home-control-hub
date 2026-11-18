"""De eerste verbinding uit ADR-0033, met een nep-Authentik op lokaal TLS."""

from __future__ import annotations

import base64
import ipaddress
import json
import ssl
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import quote

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from integrations.config import Settings
from integrations.domains.sso.authentik import execution
from integrations.domains.sso.authentik.client import AuthentikError
from tests.fakes.authentik_fake import CLIENT_SECRET, AuthentikFake

LOOPBACK = "127.0.0.1"
CLIENT_ID = "hub-client-id"


@pytest.fixture
def tls_authentik(tmp_path: Path) -> Iterator[tuple[AuthentikFake, str, Path]]:
    fake = AuthentikFake(host=LOOPBACK)
    fake.add_hub_app()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Nep-Authentik")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(LOOPBACK))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(pem)
    key_path.touch(mode=0o600)
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            response = fake.handle(httpx.Request("GET", f"https://{LOOPBACK}{self.path}", headers=dict(self.headers)))
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(response.content)

        def log_message(self, _format: str, *args: object) -> None:
            pass  # geen verzoekgegevens in het testlog

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    with HTTPServer((LOOPBACK, 0), Handler) as server:
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            yield fake, f"https://{LOOPBACK}:{server.server_port}", cert_path
        finally:
            server.shutdown()
            worker.join()


@pytest.mark.parametrize(
    ("variant", "reason"),
    [
        ("http", "https_verplicht"),
        ("certificaat", "tls_ongeverifieerd"),
        ("servernaam", "tls_ongeverifieerd"),
        ("instantie", "authentik_doel_ongeldig"),
        ("provider", "authentik_doel_ongeldig"),
        ("client", "authentik_doel_ongeldig"),
        ("bron", "authentik_doel_ongeldig"),
    ],
)
def test_rejects_before_fetching_credential_or_using_http(
    tls_authentik: tuple[AuthentikFake, str, Path],
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
    reason: str,
) -> None:
    fake, url, cert_path = tls_authentik
    if variant == "servernaam":
        url = url.replace(LOOPBACK, "localhost")
    if variant == "http":
        url = url.replace("https://", "http://")
    confirmed = execution.ProviderTarget(url, fake.providers[-1]["pk"], CLIENT_ID)
    requested, source_url = confirmed, url
    if variant == "instantie":
        requested = replace(confirmed, base_url=url + "/andere-instantie")
    elif variant == "provider":
        requested = replace(confirmed, provider_pk=fake.providers[0]["pk"])
    elif variant == "client":
        requested = replace(confirmed, client_id="andere-client")
    elif variant == "bron":
        source_url += "/andere-instantie"
    if variant != "certificaat":
        monkeypatch.setattr(execution.certifi, "where", lambda: str(cert_path))

    def credential() -> str:
        pytest.fail("Het beheercredential werd opgehaald vóór weigering.")

    with pytest.raises(AuthentikError) as error:
        execution.read_provider(source_url, confirmed, requested, Settings(allow_loopback_hub=True), credential)
    assert error.value.reason == reason
    assert fake.calls == [] and fake.writes == []


def _lekken(text: str, secret: str) -> set[str]:
    import hashlib
    import re

    forms = {
        "waarde": secret,
        "url": quote(secret, safe=""),
        "hex": secret.encode().hex(),
        "sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "json": json.dumps(secret)[1:-1],
    }
    hits = {label for label, form in forms.items() if form and form in text}
    if re.search(r"\bauthorization\b", text, re.IGNORECASE):
        hits.add("authorization")
    for token in re.findall(r"\bBasic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE):
        try:
            decoded = base64.b64decode(token, validate=True).decode()
        except (ValueError, UnicodeError):
            continue
        if any(form in decoded for form in forms.values()):
            hits.add("basic")
    return hits


def test_bound_provider_filters_raw_values_and_ignores_upstream_error_bodies(
    tls_authentik: tuple[AuthentikFake, str, Path],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    fake, url, cert_path = tls_authentik
    monkeypatch.setattr(execution.certifi, "where", lambda: str(cert_path))
    raw = fake.providers[-1]
    assert raw["client_secret"] == CLIENT_SECRET
    raw["name"] = {"onbekend_veld": CLIENT_SECRET}
    target = execution.ProviderTarget(url, raw["pk"], CLIENT_ID)
    settings = Settings(allow_loopback_hub=True)
    calls = 0

    def credential() -> str:
        nonlocal calls
        calls += 1
        return fake.token

    # Kalibratie gebeurt uitsluitend in het geheugen.
    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode()).decode()
    assert "waarde" in _lekken(CLIENT_SECRET, CLIENT_SECRET)
    assert {"basic", "authorization"} <= _lekken(f"Authorization: Basic {basic}", CLIENT_SECRET)
    afwijkend = f"{CLIENT_SECRET}:%"
    for client in (CLIENT_ID, f"{CLIENT_ID}:", f"{CLIENT_ID}::"):
        gecombineerd = f"{quote(client, safe='')}:{quote(afwijkend, safe='')}"
        encoded = base64.b64encode(gecombineerd.encode()).decode()
        assert {"basic", "authorization"} <= _lekken(f"Authorization: Basic {encoded}", afwijkend)
    assert "authorization" in _lekken("Authorization: Bearer synthetisch", CLIENT_SECRET)
    caplog.set_level("DEBUG")
    result = execution.read_provider(url, target, target, settings, credential)
    path = f"/api/v3/providers/oauth2/{raw['pk']}/"
    assert calls == 1 and fake.calls == [("GET", path, True)]
    assert result["pk"] == raw["pk"] and result["client_id"] == CLIENT_ID
    assert result["redirect_uris"] and "name" not in result
    assert "client_secret" not in result
    fake.fail[path] = 403
    fake.echo_auth_in_errors = True
    with pytest.raises(AuthentikError) as error:
        execution.read_provider(url, target, target, settings, credential)
    assert error.value.reason == "geen_rechten"
    assert error.value.message_nl and calls == 2 and len(fake.calls) == 2
    assert not _lekken(json.dumps(result) + json.dumps(error.value.to_dict()) + caplog.text, CLIENT_SECRET)
    assert fake.token not in caplog.text and fake.writes == []
    fake.fail.clear()
    fake.redirect.add(path)
    with pytest.raises(AuthentikError) as redirected:
        execution.read_provider(url, target, target, settings, credential)
    assert redirected.value.reason == "redirect" and len(fake.calls) == 3
    fake.redirect.clear()
    raw["client_id"] = "gewijzigde-client"
    with pytest.raises(AuthentikError) as swapped:
        execution.read_provider(url, target, target, settings, credential)
    assert swapped.value.reason == "authentik_doel_ongeldig"
    assert len(fake.calls) == 4 and fake.writes == []
