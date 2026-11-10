"""Idempotency-Key voor mutaties (contract 1.3 §5, foutcatalogus).

- Header ``Idempotency-Key`` (UUID) is verplicht op elke mutatie; ontbreekt hij → 400 ``idempotency_key_required``.
- Zelfde principal + key + zelfde verzoek → hetzelfde opgeslagen resultaat (header ``Idempotent-Replay: true``),
  géén tweede uitvoering. Zelfde key met een ánder verzoek → 422 ``idempotency_key_reused`` (foutcatalogus §5).
- Volgorde (§4.7, RV9): deze controles komen pas ná de authenticatie (``security.auth.AuthFirstRoute``).
- Gelijktijdige dubbele verzoeken: de unieke index in PostgreSQL laat er één winnen; de verliezer draait zijn
  wijzigingen terug en krijgt het resultaat van de winnaar.
- De verzoek-hash is een HMAC met een sleutel uit de vault: ook een wachtwoordzin in het verzoek is daaruit niet
  terug te rekenen. Mislukte verzoeken (fout) worden niet opgeslagen en hebben niets gewijzigd.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from fastapi import Header, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from .errors import ApiError
from .models import IdempotencyRecord
from .security.auth import Principal
from .timeutil import utcnow

REPLAY_HEADER = "Idempotent-Replay"
RETENTION = timedelta(days=7)

Result = tuple[int, Any, dict[str, str]]


def idempotency_key(idempotency_key: str | None = Header(default=None, alias="Idempotency-Key")) -> uuid.UUID:
    if not idempotency_key:
        raise ApiError(400, "idempotency_key_required", "Header 'Idempotency-Key' (UUID) is verplicht bij wijzigingen.")
    try:
        return uuid.UUID(idempotency_key)
    except ValueError as exc:
        raise ApiError(400, "idempotency_key_invalid", "Header 'Idempotency-Key' moet een UUID zijn.") from exc


def _replay(record: IdempotencyRecord) -> JSONResponse:
    headers = {**(record.response_headers or {}), REPLAY_HEADER: "true"}
    return JSONResponse(record.response_body, status_code=record.status_code, headers=headers)


def run_idempotent(
    request: Request,
    session: Session,
    principal: Principal,
    key: uuid.UUID,
    payload: Any,
    action: Callable[[], Result],
) -> JSONResponse:
    vault = request.app.state.vault
    canonical = json.dumps(
        {"m": request.method, "p": request.url.path, "b": jsonable_encoder(payload)},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    req_hash = vault.request_hmac(canonical)
    pk = (principal.audit_id, key)

    existing = session.get(IdempotencyRecord, pk)
    if existing is not None:
        if existing.request_hash != req_hash:
            raise ApiError(
                422,
                "idempotency_key_reused",
                "Deze Idempotency-Key is al gebruikt voor een ander verzoek; gebruik een nieuwe key.",
            )
        return _replay(existing)

    try:
        status_code, body, headers = action()
    except Exception:
        session.rollback()
        raise
    body_json = jsonable_encoder(body)
    stmt = (
        insert(IdempotencyRecord)
        .values(
            principal=principal.audit_id,
            key=key,
            method=request.method,
            path=request.url.path[:500],
            request_hash=req_hash,
            status_code=status_code,
            response_body=body_json,
            response_headers=headers,
            created_at=utcnow(),
        )
        .on_conflict_do_nothing(index_elements=["principal", "key"])
        .returning(IdempotencyRecord.key)
    )
    won = session.execute(stmt).first()
    if won is None:
        # een gelijktijdig verzoek met dezelfde key was eerder klaar: onze wijzigingen vervallen
        session.rollback()
        winner = session.get(IdempotencyRecord, pk)
        if winner is None or winner.request_hash != req_hash:
            raise ApiError(422, "idempotency_key_reused", "Deze Idempotency-Key is al gebruikt voor een ander verzoek.")
        return _replay(winner)
    session.commit()
    return JSONResponse(body_json, status_code=status_code, headers=headers)


def purge_expired(session: Session) -> int:
    result = session.execute(delete(IdempotencyRecord).where(IdempotencyRecord.created_at < utcnow() - RETENTION))
    return int(getattr(result, "rowcount", 0) or 0)
