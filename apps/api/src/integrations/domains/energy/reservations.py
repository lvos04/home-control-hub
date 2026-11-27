"""Een R1-reservering is een lokaal voorstel. Alleen de eigenaar kan een werklast bedienen."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ... import APP_ID, audit
from ...errors import ApiError, not_found
from ...idempotency import Result, run_idempotent
from ...security.auth import Principal
from ...security.execreq import canonical_sha256
from .models import EnergyWorkload, EnergyWorkloadReservation
from .readings import source_timestamp
from .workloads import WORKLOAD_TYPES, Workload

ACTION_ID = "energy.reservations.propose"
APPLY_STATUS = "alleen_voorstel"
APPLY_STATUS_NL = "De reservering is een plan. Uitvoering vereist goedkeuring in de Hub en bediening door de eigenaar."


class ReservationParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workload_id: UUID
    window_start: datetime
    window_end: datetime

    @field_validator("window_start", "window_end", mode="before")
    @classmethod
    def utc_timestamp(cls, raw: object) -> datetime:
        value = source_timestamp(raw)
        if value is None:
            raise ValueError("Een tijdstip met tijdzone is verplicht.")
        return value

    @model_validator(mode="after")
    def ordered(self) -> ReservationParameters:
        if self.window_end <= self.window_start:
            raise ValueError("Het einde moet na het begin van de reservering liggen.")
        return self


def _lock_workload(session: Session, workload_id: UUID) -> EnergyWorkload:
    """Vergrendel dezelfde rij vóór zowel de herhalings- als de overlapcontrole, ook bij het eerste voorstel."""
    kind = next((w for w in WORKLOAD_TYPES if w.id == workload_id), None)
    if kind is not None:
        session.execute(insert(EnergyWorkload).values(**kind.model_dump()).on_conflict_do_nothing())
    workload = session.get(EnergyWorkload, workload_id, with_for_update=True)
    if workload is None:
        raise not_found("Werklast")
    return workload


def propose(
    request: Request,
    session: Session,
    principal: Principal,
    key: UUID,
    tid: str,
    payload: dict[str, Any],
) -> JSONResponse:
    try:
        params = ReservationParameters.model_validate(payload["parameters"])
    except ValidationError:
        raise ApiError(
            422, "parameters_ongeldig", "Geef een werklast-ID en een geldig tijdvenster met tijdzone op."
        ) from None
    target = {"app_id": APP_ID, "resource": str(params.workload_id)}
    if payload.get("target") is not None and payload["target"] != target:
        raise ApiError(422, "parameters_ongeldig", "Het doel moet overeenkomen met de werklast in dit voorstel.")
    workload = _lock_workload(session, params.workload_id)

    def action() -> Result:
        # Halfopen vensters: een venster mag beginnen op het eindtijdstip van zijn voorganger.
        conflict = session.scalar(
            select(EnergyWorkloadReservation.id)
            .where(
                EnergyWorkloadReservation.workload_id == workload.id,
                EnergyWorkloadReservation.window_start < params.window_end,
                EnergyWorkloadReservation.window_end > params.window_start,
            )
            .limit(1)
        )
        if conflict is not None:
            raise ApiError(
                409, "reservering_overlapt", "Voor deze werklast overlapt het venster een bestaande reservering."
            )
        parameters = params.model_dump(mode="json")
        resource_etag = canonical_sha256(
            {
                "werklast": Workload.model_validate(workload, from_attributes=True).model_dump(mode="json"),
                "venster": parameters,
                "beschikbaar": True,
            }
        )
        if payload.get("expected_version") is not None and payload["expected_version"] != resource_etag:
            raise ApiError(409, "resource_gewijzigd", "Het tijdvenster of de werklast wijkt af van de vorige preview.")
        row = EnergyWorkloadReservation(**params.model_dump(), status="voorstel")
        session.add(row)
        session.flush()
        diff = [
            {
                "object": "energy_workload_reservation",
                "operation": "voorstellen",
                "before": None,
                "after": {**parameters, "status": "voorstel"},
            }
        ]
        preview_hash = canonical_sha256(
            {"action_id": ACTION_ID, "target": target, "diff": diff, "resource_etag": resource_etag}
        )
        audit.record(
            session,
            domain="energy",
            action="reservation.proposed",
            entity_type="energy_workload_reservation",
            entity_id=str(row.id),
            principal=principal,
            trace_id=tid,
            message_nl="Een reserveringsvoorstel is vastgelegd.",
            details={"workload_id": str(workload.id)},
        )
        view = {
            "proposal_id": str(row.id),
            "action_id": ACTION_ID,
            "task_id": "B14-003",
            "target": target,
            "parameters": parameters,
            "status": row.status,
            "risk_class_min": "R1",
            "risk_claim": "R1",
            "resource_etag": resource_etag,
            "preview_hash": preview_hash,
            "diff": diff,
            "apply_status": APPLY_STATUS,
            "apply_status_nl": APPLY_STATUS_NL,
        }
        return 201, view, {"ETag": f'"{preview_hash}"'}

    return run_idempotent(request, session, principal, key, payload, action)
