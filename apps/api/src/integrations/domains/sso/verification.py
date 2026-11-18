"""Lokale verificatie van een SSO-uitvoeringsverzoek. Er is geen uitvoer of nonceclaim."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...errors import ApiError, forbidden
from ...idempotency import too_deep, unstorable_text
from ...security import execreq
from ..automation.models import AutomationExecutionNonce
from .authentik_router import PARAMETER_MODELS, validate_parameters
from .models import SsoProposal
from .proposals import ACTIONS


def verify(
    session: Session, body: dict[str, Any], action_id: str, keys: Sequence[Ed25519PublicKey], now: datetime
) -> None:
    if not keys:
        raise forbidden("geen_gepinde_policy_sleutel", "Er is geen gepinde policy-sleutel van de Hub.")
    spec = ACTIONS.get(action_id)
    if spec is None:
        raise forbidden("actie_niet_toegestaan", "Deze Authentik-actie is niet toegestaan.")

    # De gesloten route slaat de werkingshash niet op. Onbekende velden komen ook niet in de handtekeningcontrole.
    invalid = too_deep(body) or unstorable_text(body)
    if invalid is not None:
        raise ApiError(422, "validation_error", "De invoer is ongeldig.")
    proposal = body["proposal"]
    params = proposal.get("parameters")
    if isinstance(params, dict) and set(params) - PARAMETER_MODELS[action_id].model_fields.keys():
        raise ApiError(422, "validation_error", "De parameters bevatten een onbekend veld.")
    try:
        execreq.check_envelope(body, keys, now=now)
    except execreq.Refusal as exc:
        # De vormcontrole mag willekeurige aangeleverde veldnamen niet teruggeven.
        details = exc.details if exc.status == 403 else {}
        raise ApiError(exc.status, exc.code, exc.message, details) from None

    parameters = validate_parameters(action_id, params)
    if session.get(AutomationExecutionNonce, uuid.UUID(body["nonce"])) is not None:
        raise ApiError(409, "nonce_al_gebruikt", "Dit uitvoeringsverzoek is al eerder aangeboden.")

    approval = body["approval"]
    preview_hash = approval["preview_hash"] if approval is not None else ""
    try:
        checked_approval = execreq.check_approval(
            body,
            min_risk_class=spec.risk_class,
            preview_hash=preview_hash,
            requires_backup=spec.requires_backup,
            now=now,
        )
    except execreq.Refusal as exc:
        raise ApiError(exc.status, exc.code, exc.message, exc.details) from None
    approval_nonce = execreq.approval_replay_key(str(checked_approval["one_time_nonce"]))
    if session.get(AutomationExecutionNonce, approval_nonce) is not None:
        raise ApiError(409, "goedkeuring_al_gebruikt", "Deze goedkeuring is al eerder gebruikt.")

    rows = session.scalars(
        select(SsoProposal)
        .where(SsoProposal.action_id == action_id, SsoProposal.preview_hash == preview_hash.removeprefix("sha256:"))
        .order_by(SsoProposal.created_at.desc())
    )
    for row in rows:
        if (
            row.target == proposal["target"]
            and row.parameters == params == parameters
            and f"sha256:{row.resource_etag}" == proposal["expected_version"]
        ):
            if row.status != "voorstel" or row.expires_at <= now:
                raise ApiError(409, "voorstel_verlopen", "Dit Authentik-voorstel is niet meer geldig.")
            return
    raise ApiError(
        409, "goedkeuring_past_niet", "De goedkeuring hoort niet bij een Authentik-voorstel van deze dienst."
    )
