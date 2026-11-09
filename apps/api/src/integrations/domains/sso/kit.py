"""Versleutelde herstelkit (B13-001: "export versleuteld herstelmateriaal").

Inhoud: het herstelregister (accounts, methodes, waar het materiaal ligt, noodtoegang, laatste oefeningen) plus de
Nederlandse noodprocedure — **geen geheimen en geen sleutels** (key-export is R3 en wordt niet aangeboden).
Versleuteling: scrypt (N=2^15, r=8, p=1) → AES-256-GCM. De wachtwoordzin wordt nooit opgeslagen of gelogd.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KIT_FORMAT = "hch-herstelkit/1"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
MIN_PASSPHRASE = 16
MAX_PASSPHRASE = 1024

PROCEDURE_NL: tuple[str, ...] = (
    "1. Zorg dat je op het thuisnetwerk (LAN) of via de VPN verbonden bent; noodtoegang werkt alleen binnen de "
    "geregistreerde bereiken.",
    "2. Open de Hub en log in met het lokale noodaccount (niet via SSO). Authentik hoeft daarvoor niet te werken.",
    "3. Gebruik de herstelmethode uit de plek die in deze kit staat (wachtwoordmanager, verzegelde envelop, kluis of "
    "hardwaresleutel). De kit zelf bevat geen wachtwoorden of codes.",
    "4. Na echt gebruik: wijzig het wachtwoord van het noodaccount en registreer 'rotatie bevestigd'.",
    "5. Is de Hub zelf onbereikbaar: TrueNAS-web-UI → Apps → app → Logs, of de TrueNAS-console lokaal.",
    "6. Oefen dit periodiek met Authentik uitgeschakeld en registreer de oefening.",
)


class KitError(ValueError):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise KitError("ongeldig veld")
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise KitError("ongeldig base64-veld") from exc


def check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE:
        raise KitError(f"De wachtwoordzin moet minstens {MIN_PASSPHRASE} tekens hebben.")
    if len(passphrase) > MAX_PASSPHRASE:
        raise KitError("De wachtwoordzin is te lang.")
    if len(set(passphrase)) < 6:
        raise KitError("De wachtwoordzin is te eenvoudig (te weinig verschillende tekens).")


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def encrypt_kit(content: dict[str, Any], passphrase: str) -> dict[str, Any]:
    check_passphrase(passphrase)
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    plaintext = canonical({"format": KIT_FORMAT, **content})
    ct = AESGCM(key).encrypt(nonce, plaintext, KIT_FORMAT.encode("ascii"))
    return {
        "format": KIT_FORMAT,
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": _b64(salt)},
        "cipher": {"name": "AES-256-GCM", "nonce": _b64(nonce)},
        "ciphertext": _b64(ct),
        "ciphertext_sha256": hashlib.sha256(ct).hexdigest(),
    }


def decrypt_kit(kit: dict[str, Any], passphrase: str) -> dict[str, Any]:
    if kit.get("format") != KIT_FORMAT:
        raise KitError("Onbekend formaat van de herstelkit.")
    kdf, cipher = kit.get("kdf") or {}, kit.get("cipher") or {}
    if kdf.get("name") != "scrypt" or cipher.get("name") != "AES-256-GCM":
        raise KitError("Onbekende versleuteling in de herstelkit.")
    n, r, p = kdf.get("n"), kdf.get("r"), kdf.get("p")
    if not (isinstance(n, int) and isinstance(r, int) and isinstance(p, int)):
        raise KitError("Ongeldige sleutelafleiding in de herstelkit.")
    if not (2**14 <= n <= 2**20 and 1 <= r <= 16 and 1 <= p <= 4):
        raise KitError("Ongeldige sleutelafleiding in de herstelkit.")
    ct = _unb64(kit.get("ciphertext"))
    expected = kit.get("ciphertext_sha256")
    if expected is not None and hashlib.sha256(ct).hexdigest() != expected:
        raise KitError("De herstelkit is beschadigd (controlesom klopt niet).")
    key = _derive(passphrase, _unb64(kdf.get("salt")), n, r, p)
    try:
        plaintext = AESGCM(key).decrypt(_unb64(cipher.get("nonce")), ct, KIT_FORMAT.encode("ascii"))
    except InvalidTag as exc:
        raise KitError("De herstelkit kan niet worden geopend: verkeerde wachtwoordzin of beschadigd bestand.") from exc
    data: dict[str, Any] = json.loads(plaintext)
    return data
