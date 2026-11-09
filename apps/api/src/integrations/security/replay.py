"""Replaybescherming voor Hub-JWT's bij mutaties (B13-002 "replay rejected"; verenigbaar met contract 1.2).

Regel (veiligste interpretatie, ADR-0007): een JWT (``jti``) mag voor **één** mutatie gebruikt worden. Een mutatie is
een POST/PUT/PATCH/DELETE met een geldige ``Idempotency-Key``. Een herhaling met hetzelfde token, dezelfde methode,
hetzelfde pad en dezelfde ``Idempotency-Key`` (netwerk-retry) blijft toegestaan; de idempotency-laag geeft dan het
opgeslagen resultaat. Elk ander hergebruik → ``401 unauthorized`` (``token_hergebruikt``). Lezen (GET) mag binnen de
levensduur (≤ 120 s) vaker. Een mutatie-JWT zonder ``jti`` wordt geweigerd. Is de controle niet mogelijk (database
weg), dan **fail-closed** met 503.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ..db import Database
from ..errors import ApiError, unauthorized
from ..models import JwtJtiUse
from ..timeutil import utcnow
from .auth import Principal

MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


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

    def check(self, principal: Principal, method: str, path: str, idempotency_key: str) -> None:
        if principal.kind != "user":
            return
        jti = principal.token_id
        if not jti:
            raise unauthorized(
                "jti_ontbreekt", "Niet geautoriseerd: een token voor een wijziging moet een 'jti' hebben."
            )
        exp = principal.expires_at or utcnow().timestamp()
        expires = datetime.fromtimestamp(exp, UTC) + timedelta(seconds=self.leeway_s)
        try:
            with self.db.sessions() as s:
                won = s.execute(
                    insert(JwtJtiUse)
                    .values(
                        jti=jti[:200],
                        subject=principal.subject[:200],
                        method=method[:10],
                        path=path[:500],
                        idempotency_key=idempotency_key,
                        first_seen_at=utcnow(),
                        expires_at=expires,
                    )
                    .on_conflict_do_nothing(index_elements=["jti"])
                    .returning(JwtJtiUse.jti)
                ).first()
                s.commit()
                if won is not None:
                    return
                row = s.get(JwtJtiUse, jti[:200])
        except ApiError:
            raise
        except Exception as exc:  # database weg → nooit doorlaten
            raise ApiError(
                503,
                "replay_check_unavailable",
                "De controle op hergebruik van tokens is tijdelijk niet beschikbaar; probeer het later opnieuw.",
            ) from exc
        if (
            row is not None
            and row.subject == principal.subject[:200]
            and row.method == method[:10]
            and row.path == path[:500]
            and row.idempotency_key == idempotency_key
        ):
            return  # zelfde verzoek opnieuw (retry): de idempotency-laag geeft het opgeslagen resultaat
        raise unauthorized(
            "token_hergebruikt",
            "Niet geautoriseerd: dit token is al voor een andere wijziging gebruikt; vraag een nieuw token aan de Hub.",
        )


def purge_expired(db_session: Session) -> int:
    result = db_session.execute(delete(JwtJtiUse).where(JwtJtiUse.expires_at < utcnow()))
    return int(getattr(result, "rowcount", 0) or 0)
