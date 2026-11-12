"""Cursor-paginering (contract §5: ``cursor``/``limit``, max 200)."""

from __future__ import annotations

import base64
import json
from typing import Any

from fastapi import Query

from .errors import ApiError

MAX_LIMIT = 200


def encode_cursor(value: Any) -> str:
    raw = json.dumps({"k": value}, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _storable(value: Any) -> bool:
    """Geen NUL-teken en geen losse surrogaat, in tekst en sleutels, op elke diepte (zonder recursie). Een cursor van
    deze dienst bevat alleen opgeslagen waarden; zo'n teken komt dus alleen uit een zelfgemaakte cursor, en PostgreSQL
    of UTF-8 zou er een serverfout van maken (R-VEILIG-2 en R-TECH-2 van S-P2-310)."""
    todo = [value]
    while todo:
        item = todo.pop()
        if isinstance(item, dict):
            todo.extend(item.keys())
            todo.extend(item.values())
        elif isinstance(item, list):
            todo.extend(item)
        elif isinstance(item, str):
            if "\x00" in item:
                return False
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                return False
    return True


def decode_cursor(cursor: str | None) -> Any:
    if not cursor:
        return None
    try:
        pad = "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(cursor + pad))
        value = data["k"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.") from exc
    if not _storable(value):
        raise ApiError(400, "invalid_cursor", "De cursor is ongeldig; begin opnieuw zonder cursor.")
    return value


def limit_param(limit: int = Query(default=50, ge=1, le=MAX_LIMIT)) -> int:
    return limit


def page(items: list[Any], limit: int, key_of: Any) -> dict[str, Any]:
    """Verwacht ``limit + 1`` opgehaalde items; geeft ``{items, next_cursor}``."""
    has_more = len(items) > limit
    items = items[:limit]
    return {"items": items, "next_cursor": encode_cursor(key_of(items[-1])) if has_more and items else None}
