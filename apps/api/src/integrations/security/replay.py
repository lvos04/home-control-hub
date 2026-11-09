"""Persistente replaycache voor Hub-JWT's (contract 1.2 §4.6; B13-002 "replay rejected").

- Gedeeld door alle processen (tabel ``jwt_jti_use`` in PostgreSQL) op ``(iss, jti)`` tot ``exp`` + 30 s.
- Een **mutatie** (POST/PUT/PATCH/DELETE) met een al gebruikte ``jti`` → 401 ``token_replayed``, behalve een exacte
  herhaling (zelfde ``jti``, principal, methode, pad en ``Idempotency-Key``): die beantwoordt de idempotency-laag met
  het opgeslagen resultaat (netwerk-retry). Zonder ``Idempotency-Key`` is er geen exacte herhaling.
- Lezen (GET/HEAD) mag binnen de levensduur vaker en wordt niet vastgelegd.
- Controle niet mogelijk (database weg) → 503 ``replay_check_unavailable`` (fail-closed).
- Geldt voor gebruikers-JWT's én dienst-JWT's van de Hub: de Hub haalt dus per mutatie een nieuwe JWT.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..db import Database
from ..errors import ApiError
from ..models import JwtJtiUse
from ..timeutil import utcnow
from .auth import auth_error

log = logging.getLogger("integrations.replay")


def valid_idempotency_key(raw: str | None) -> str | None:
    if not raw:
        return None
    try:
        return str(uuid.UUID(raw))
    except ValueError:
        return None


class ReplayGuard:
    def __init__(self, db: Database, leeway_s: int) -> None:
        self.db = db
        self.leeway_s = leeway_s

    def check(
        self,
        *,
        iss: str,
        jti: str,
        exp: float,
        subject: str,
        method: str,
        path: str,
        idempotency_key: str | None,
    ) -> None:
        expires = datetime.fromtimestamp(exp, UTC) + timedelta(seconds=self.leeway_s)
        key = valid_idempotency_key(idempotency_key) or ((idempotency_key or "").strip()[:64] or None)
        values = {
            "iss": iss[:40],
            "jti": jti[:200],
            "subject": subject[:200],
            "method": method[:10],
            "path": path[:500],
            "idempotency_key": key,
        }
        try:
            with self.db.sessions() as s:
                won = s.execute(
                    insert(JwtJtiUse)
                    .values(**values, first_seen_at=utcnow(), expires_at=expires)
                    .on_conflict_do_nothing(index_elements=["iss", "jti"])
                    .returning(JwtJtiUse.jti)
                ).first()
                s.commit()
                if won is not None:
                    return
                row = s.get(JwtJtiUse, (values["iss"], values["jti"]))
                seen = None if row is None else (row.subject, row.method, row.path, row.idempotency_key)
        except Exception as exc:  # database weg → nooit doorlaten
            log.error("replaycontrole niet mogelijk (%s); verzoek geweigerd", type(exc).__name__)
            raise ApiError(
                503,
                "replay_check_unavailable",
                "De controle op hergebruik van tokens is tijdelijk niet beschikbaar; probeer het later opnieuw.",
                headers={"Retry-After": "5"},
            ) from exc
        exact = key is not None and seen == (values["subject"], values["method"], values["path"], key)
        if not exact:
            raise auth_error("token_replayed")


def purge_expired(db_session: Session) -> int:
    result = db_session.execute(delete(JwtJtiUse).where(JwtJtiUse.expires_at < utcnow()))
    return int(getattr(result, "rowcount", 0) or 0)
