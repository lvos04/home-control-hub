"""Versleutelde opslag van credentials (AES-256-GCM, sleutel ``secrets/vault.key``).

Tabellen bewaren alleen ``vault://<scope>/<naam>``; de API geeft nooit de waarde terug, alleen de laatste 4 tekens.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from ..models import VaultSecret

REF_PATTERN = re.compile(r"^vault://[a-z0-9][a-z0-9_-]{0,40}/[a-z0-9][a-z0-9_.-]{0,80}$")


class Vault:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("vault-sleutel moet 32 bytes zijn")
        self._aead = AESGCM(key)
        self._hmac_key = hmac.new(key, b"hch-request-hash-v1", hashlib.sha256).digest()

    @staticmethod
    def check_ref(ref: str) -> str:
        if not REF_PATTERN.match(ref):
            raise ValueError(f"ongeldige vault-referentie: {ref!r}")
        return ref

    def put(self, session: Session, ref: str, plaintext: str) -> str:
        self.check_ref(ref)
        nonce = os.urandom(12)
        ct = self._aead.encrypt(nonce, plaintext.encode("utf-8"), ref.encode("utf-8"))
        last4 = plaintext[-4:] if len(plaintext) >= 8 else ""
        row = session.get(VaultSecret, ref)
        if row is None:
            session.add(VaultSecret(ref=ref, nonce=nonce, ciphertext=ct, last4=last4, version=1))
        else:
            row.nonce, row.ciphertext, row.last4, row.version = nonce, ct, last4, row.version + 1
        return last4

    def get(self, session: Session, ref: str) -> str | None:
        row = session.get(VaultSecret, self.check_ref(ref))
        if row is None:
            return None
        return self._aead.decrypt(row.nonce, row.ciphertext, ref.encode("utf-8")).decode("utf-8")

    def delete(self, session: Session, ref: str) -> None:
        row = session.get(VaultSecret, self.check_ref(ref))
        if row is not None:
            session.delete(row)

    def seal(self, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        """Versleutelt een blob (bv. een momentopname van flows) gebonden aan ``aad``; geeft ``(nonce, ciphertext)``."""
        nonce = os.urandom(12)
        return nonce, self._aead.encrypt(nonce, plaintext, aad)

    def unseal(self, aad: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        """Ontsleutelt een blob van :meth:`seal`; een andere ``aad`` of gewijzigde data geeft ``InvalidTag``."""
        return self._aead.decrypt(nonce, ciphertext, aad)

    def request_hmac(self, data: bytes) -> str:
        """Gesleutelde hash (bv. voor Idempotency-records): niet terug te rekenen zonder de vault-sleutel."""
        return hmac.new(self._hmac_key, data, hashlib.sha256).hexdigest()
