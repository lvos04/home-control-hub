"""De eerste verbinding uit ADR-0033, met een nep-Authentik op lokaal TLS."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import ssl
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import quote, unquote

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
TlsAuthentik = tuple[AuthentikFake, str, Path, list[tuple[str, bool]]]


@pytest.fixture
def tls_authentik(tmp_path: Path) -> Iterator[TlsAuthentik]:
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

    heads: list[tuple[str, bool]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_HEAD(self) -> None:
            heads.append((self.path, "Authorization" in self.headers))
            self.send_response(302 if self.path in fake.redirect else 200)
            self.end_headers()

        def do_GET(self) -> None:
            response = fake.handle(httpx.Request("GET", f"https://{LOOPBACK}{self.path}", headers=dict(self.headers)))
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                self.send_header(name, value)
            if "Content-Length" not in response.headers:
                self.send_header("Content-Length", str(len(response.content)))
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
            yield fake, f"https://{LOOPBACK}:{server.server_port}", cert_path, heads
        finally:
            server.shutdown()
            worker.join()


def _confirmed(fake: AuthentikFake, url: str, cert_path: Path) -> execution.ProviderTarget:
    provider = fake.providers[-1]
    certificate = ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    return execution.ProviderTarget(
        url,
        provider["pk"],
        CLIENT_ID,
        peer_address=LOOPBACK,
        certificate_sha256=hashlib.sha256(certificate).hexdigest(),
        redirect_uris=tuple(uri["url"] for uri in provider["redirect_uris"]),
    )


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
        ("dns", "authentik_doel_ongeldig"),
        ("vingerafdruk", "authentik_doel_ongeldig"),
        ("geen_binding", "authentik_binding_onbevestigd"),
    ],
)
def test_rejects_before_fetching_credential_or_using_http(
    tls_authentik: TlsAuthentik,
    monkeypatch: pytest.MonkeyPatch,
    variant: str,
    reason: str,
) -> None:
    fake, url, cert_path, heads = tls_authentik
    if variant == "servernaam":
        url = url.replace(LOOPBACK, "localhost")
    if variant == "http":
        url = url.replace("https://", "http://")
    confirmed = _confirmed(fake, url, cert_path)
    if variant == "vingerafdruk":
        confirmed = replace(confirmed, certificate_sha256="0" * 64)
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
    if variant == "dns":
        monkeypatch.setattr(execution, "resolve_host", lambda *_: ["0.0.0.0"])  # noqa: S104 - resolverwaarde

        def refuse_connect(*_: object) -> None:
            pytest.fail("De socket werd geopend voor een afgewezen DNS-bestemming.")

        monkeypatch.setattr(execution.socket.socket, "connect", refuse_connect)

    def binding(*_: object) -> tuple[int, str]:
        pytest.fail("Doelbinding werd gelezen vóór weigering.")

    def credential() -> str:
        pytest.fail("Het beheercredential werd opgehaald vóór weigering.")

    with pytest.raises(AuthentikError) as error:
        execution.read_provider(
            source_url,
            confirmed,
            requested,
            Settings(allow_loopback_hub=True),
            credential,
            confirm_binding=None if variant == "geen_binding" else binding,
        )
    assert error.value.reason == reason
    assert heads == [] and fake.calls == [] and fake.writes == []


def test_tls_context_verifieert_zonder_sleutellog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    keylog = tmp_path / "tls-registratie"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    context = execution._tls_context()
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert context.keylog_filename is None
    assert not keylog.exists()


def _lekken(text: str, secret: str) -> set[str]:
    forms = {
        "waarde": secret,
        "url": quote(secret, safe=""),
        "hex": secret.encode().hex(),
        "sha256": hashlib.sha256(secret.encode()).hexdigest(),
        "json": json.dumps(secret)[1:-1],
    }
    hits = {label for label, form in forms.items() if form and (form in text or form in unquote(text))}
    if re.search(r"""(?im)(?:^|[\s{,])["']?authorization["']?\s*:|\(\s*["']authorization["']\s*,""", text):
        hits.add("authorization")
    for token in re.findall(r"\bBasic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE):
        try:
            decoded = base64.b64decode(token, validate=True).decode()
        except (ValueError, UnicodeError):
            continue
        if ":" in decoded and any(form in decoded or form in unquote(decoded) for form in forms.values()):
            hits.add("basic")
    return hits


def _controleer_opvang(text: str, *secrets: str) -> None:
    assert text.strip(), "De opvang is leeg."
    assert not any(_lekken(text, secret) for secret in secrets), "De opvang bevat een beschermde waarde of kop."


def test_bound_provider_filters_raw_values_and_ignores_upstream_error_bodies(
    tls_authentik: TlsAuthentik,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    fake, url, cert_path, heads = tls_authentik
    monkeypatch.setattr(execution.certifi, "where", lambda: str(cert_path))
    keylog = tmp_path / "tls-registratie"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    raw = fake.providers[-1]
    assert raw["client_secret"] == CLIENT_SECRET
    raw["name"] = {"onbekend_veld": CLIENT_SECRET}
    target = _confirmed(fake, url, cert_path)
    settings = Settings(allow_loopback_hub=True)
    calls = 0
    binding_calls = 0
    path = f"/api/v3/providers/oauth2/{raw['pk']}/"

    def binding(connection: object, provider_path: str) -> tuple[int, str]:
        nonlocal binding_calls
        assert connection is not None and provider_path == path
        binding_calls += 1
        return raw["pk"], raw["client_id"]

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
    assert not _lekken('{"grant_types":["authorization_code"], "designation":"authorization"}', CLIENT_SECRET)
    with pytest.raises(AssertionError, match="leeg"):
        _controleer_opvang("", CLIENT_SECRET)
    with pytest.raises(AssertionError, match="beschermde"):
        _controleer_opvang(f"Authorization: Basic {basic}", CLIENT_SECRET)
    caplog.set_level("DEBUG")
    result = execution.read_provider(url, target, target, settings, credential, confirm_binding=binding)
    assert calls == 1 and fake.calls == [("GET", path, True)]
    assert result["pk"] == raw["pk"] and result["client_id"] == CLIENT_ID
    assert result["redirect_uris"] and "name" not in result
    assert "client_secret" not in result
    _controleer_opvang(caplog.text, CLIENT_SECRET, fake.token)
    _controleer_opvang(json.dumps(result), CLIENT_SECRET, fake.token)
    caplog.clear()
    fake.fail[path] = 403
    fake.echo_auth_in_errors = True
    with pytest.raises(AuthentikError) as error:
        execution.read_provider(url, target, target, settings, credential, confirm_binding=binding)
    assert error.value.reason == "geen_rechten"
    assert error.value.message_nl and calls == 2 and len(fake.calls) == 2
    _controleer_opvang(caplog.text, CLIENT_SECRET, fake.token)
    _controleer_opvang(json.dumps(error.value.to_dict()), CLIENT_SECRET, fake.token)
    assert not keylog.exists()
    fake.fail.clear()
    fake.redirect.add(path)
    with pytest.raises(AuthentikError) as redirected:
        execution.read_provider(url, target, target, settings, credential, confirm_binding=binding)
    assert redirected.value.reason == "redirect" and calls == 2 and len(fake.calls) == 2
    fake.redirect.clear()
    raw["client_id"] = "gewijzigde-client"
    with pytest.raises(AuthentikError) as swapped:
        execution.read_provider(url, target, target, settings, credential, confirm_binding=binding)
    assert swapped.value.reason == "authentik_binding_onbevestigd"
    assert heads == [(path, False)] * 4 and binding_calls == 3
    assert calls == 2 and len(fake.calls) == 2 and fake.writes == []
