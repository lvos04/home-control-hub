"""Auditspoor (geredigeerd) voor elke mutatie in deze dienst."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from .models import AuditEvent
from .redact import redact
from .security.auth import Principal


def record(
    session: Session,
    *,
    domain: str,
    action: str,
    entity_type: str,
    entity_id: str,
    principal: Principal | None,
    trace_id: str,
    message_nl: str,
    details: dict[str, Any] | None = None,
    actor_override: tuple[str, str] | None = None,
) -> AuditEvent:
    if actor_override is not None:
        actor_type, actor_id = actor_override
    elif principal is not None:
        actor_type, actor_id = principal.actor_type, principal.audit_id
    else:
        actor_type, actor_id = "system", "home-control-hub"
    ev = AuditEvent(
        id=uuid.uuid4(),
        domain=domain,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        actor_type=actor_type,
        actor_id=actor_id,
        trace_id=uuid.UUID(trace_id),
        details=redact(details or {}),
        message_nl=message_nl,
    )
    session.add(ev)
    return ev
