"""First-start-init van ``<data>/secrets`` (contract §3).

- Ontbrekende geheimen worden aangemaakt; bestaande worden **nooit** overschreven.
- Bestanden 0600, map 0700, eigenaar de draaiende gebruiker (in de image 568; de procesbewaker regelt dat).
- Inhoud komt nooit in logs.

Bestanden:
- ``vault.key``         32 willekeurige bytes (AES-256-GCM voor opgeslagen credentials van andere apps)
- ``identity.ed25519``  eigen Ed25519-identiteit (PEM, PKCS#8); de publieke sleutel gaat bij het koppelen naar de Hub
                        als ``{kty, crv, x, kid}`` met ``kid`` = RFC 7638-thumbprint (contract 1.2 §3.3)
- ``hub-link.json``     koppelstatus met de Hub (§3.5); géén gegenereerd geheim: wordt door ``hublink_store`` atomair
                        vervangen en hier nooit aangemaakt
"""

from __future__ import annotations

import contextlib
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .hubkeys import enroll_jwk

VAULT_KEY = "vault.key"
IDENTITY_KEY = "identity.ed25519"


class SecretsError(RuntimeError):
    pass


def _write_new(path: Path, data: bytes) -> bool:
    """Schrijft alleen als het bestand nog niet bestaat (O_EXCL). Geeft True als het nieuw is."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    return True


def _tighten(path: Path) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            os.chmod(path, 0o600)
    except PermissionError:  # pragma: no cover - alleen als een andere gebruiker eigenaar is
        pass


def ensure_secrets(secrets_dir: Path) -> list[str]:
    """Maakt ontbrekende geheimen aan. Geeft de namen van nieuw aangemaakte bestanden terug (nooit inhoud)."""
    secrets_dir.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(PermissionError):
        os.chmod(secrets_dir, 0o700)
    created: list[str] = []
    if _write_new(secrets_dir / VAULT_KEY, secrets.token_bytes(32)):
        created.append(VAULT_KEY)
    pem = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    if _write_new(secrets_dir / IDENTITY_KEY, pem):
        created.append(IDENTITY_KEY)
    for name in (VAULT_KEY, IDENTITY_KEY):
        _tighten(secrets_dir / name)
    return created


def load_vault_key(secrets_dir: Path) -> bytes:
    path = secrets_dir / VAULT_KEY
    try:
        key = path.read_bytes()
    except FileNotFoundError as exc:
        raise SecretsError(f"{path} ontbreekt; start de app opnieuw zodat de first-start-init draait") from exc
    if len(key) != 32:
        raise SecretsError(f"{path} heeft een ongeldige lengte; herstel het bestand uit de back-up")
    return key


def load_identity(secrets_dir: Path) -> Ed25519PrivateKey:
    path = secrets_dir / IDENTITY_KEY
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except FileNotFoundError as exc:
        raise SecretsError(f"{path} ontbreekt; start de app opnieuw zodat de first-start-init draait") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SecretsError(f"{path} bevat geen Ed25519-sleutel")
    return key


def enroll_public_jwk(private_key: Ed25519PrivateKey) -> dict[str, str]:
    """Publieke JWK voor het enroll-verzoek: precies ``kty, crv, x, kid`` (geen ``use``/``alg``; contract 1.2 §3.3)."""
    return enroll_jwk(private_key.public_key())


def secrets_present(secrets_dir: Path) -> dict[str, bool]:
    return {name: (secrets_dir / name).is_file() for name in (VAULT_KEY, IDENTITY_KEY)}
