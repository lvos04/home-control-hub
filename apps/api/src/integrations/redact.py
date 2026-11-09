"""Redactie van logs, audit en evidence: nooit geheimen (contract §3)."""

from __future__ import annotations

import re
from typing import Any

SECRET_KEY_PATTERN = re.compile(
    r"(secret|token|passw|passphrase|wachtwoord|credential|api[_-]?key|private|koppelcode|code_hash|authorization)",
    re.IGNORECASE,
)
BEARER_PATTERN = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
# Lange, willekeurig ogende reeksen (tokens/sleutels): minstens 24 tekens met cijfers én letters.
TOKENISH_PATTERN = re.compile(r"(?=[A-Za-z0-9+/=_-]{24,})(?=[^\s]*\d)(?=[^\s]*[A-Za-z])[A-Za-z0-9+/=_-]{24,}")

MASK = "***"


def redact_text(value: str) -> str:
    value = BEARER_PATTERN.sub("Bearer " + MASK, value)
    value = JWT_PATTERN.sub(MASK, value)
    return value


def looks_like_secret(value: str) -> bool:
    """Heuristiek voor vrije tekstvelden: weiger invoer die op een token, sleutel of JWT lijkt."""
    if BEARER_PATTERN.search(value) or JWT_PATTERN.search(value):
        return True
    return bool(TOKENISH_PATTERN.search(value))


def redact(obj: Any, _depth: int = 0) -> Any:
    """Recursief: waarden onder 'geheime' sleutels worden gemaskeerd, tekst wordt op tokens gescand."""
    if _depth > 20:
        return MASK
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if isinstance(k, str) and SECRET_KEY_PATTERN.search(k) and not k.endswith(("_last4", "_ref", "_present")):
                out[k] = MASK if v not in (None, "", [], {}) else v
            else:
                out[k] = redact(v, _depth + 1)
        return out
    if isinstance(obj, list | tuple):
        return [redact(v, _depth + 1) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
