"""B11-003 — de flow-API: het enige pad van een flow naar deze dienst.

Een flow in Node-RED haalt hier zijn events op en **vraagt** hier acties aan. Uitvoeren kan een flow nooit: een
verzoek gaat als event ``flow.action.requested`` naar de Hub, die het beleid toepast en zo nodig een mens laat
goedkeuren.

**Aanmelding.** Een flow heeft geen Hub-JWT (hij is geen gebruiker en geen dienst van de Hub). Hij meldt zich met een
eigen **flow-token** (``Authorization: Bearer flw_…``): door een beheerder uitgegeven, per flow, met een vaste lijst van
acties die de flow mag aanvragen, één keer getoond en daarna alleen als SHA-256 bewaard. Een flow-token geeft
uitsluitend toegang tot de routes in dit bestand; elke andere route van deze dienst blijft alleen met een Hub-JWT
bereikbaar (contract §4). De afwijking van "alleen Hub-JWT's" staat in ADR-0016 en is gemeld als contractpunt.

Volgorde per verzoek (als bij de Hub-JWT-routes): eerst de 1 MiB-grens, dan het token, dan pas de body, de
``Idempotency-Key`` en de inhoud. Zonder geldig token is het antwoord altijd 401.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, ValidatorFunctionWrapHandler, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from ... import API_PREFIX
from ...deps import get_session, trace_id
from ...errors import ApiError, not_found
from ...idempotency import idempotency_key, run_idempotent
from ...security.auth import MUTATING_METHODS, Principal
from ...timeutil import iso, utcnow
from . import actions, inbox, simulate
from .models import (
    AutomationActionRequest,
    AutomationDelivery,
    AutomationFlow,
    AutomationFlowRun,
    AutomationFlowToken,
    AutomationRateLimit,
    AutomationTrigger,
)

PREFIX = f"{API_PREFIX}/automation/flow-api"
TOKEN_PREFIX = "flw_"  # noqa: S105 - een voorvoegsel, geen geheim
FLOW_ROLE = "flow"
LAST_USED_STEP = timedelta(minutes=1)
Result = tuple[int, Any, dict[str, str]]

AUTH_REASONS_NL = {
    "flow_token_ontbreekt": "Niet geautoriseerd: deze route vraagt een flow-token (Authorization: Bearer flw_…).",
    "flow_token_ongeldig": "Niet geautoriseerd: dit flow-token is onbekend.",
    "flow_token_ingetrokken": "Niet geautoriseerd: dit flow-token is ingetrokken.",
}


def _unauthorized(reason: str) -> ApiError:
    return ApiError(401, "unauthorized", AUTH_REASONS_NL[reason], {"reason": reason}, {"WWW-Authenticate": "Bearer"})


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> tuple[str, str, str]:
    """Een nieuw flow-token: ``(token, sha256, laatste 4 tekens)``. Het token zelf wordt nergens bewaard."""
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return token, hash_token(token), token[-4:]


@dataclass(frozen=True)
class FlowIdentity:
    principal: Principal
    flow_id: uuid.UUID
    token_id: uuid.UUID


def flow_identity(request: Request) -> FlowIdentity:
    """De flow van dit verzoek. Al aangemeld in dit verzoek (``FlowAuthFirstRoute``) → dezelfde identiteit."""
    existing = getattr(request.state, "flow_identity", None)
    if isinstance(existing, FlowIdentity):
        return existing
    scheme, _, token = (request.headers.get("Authorization") or "").partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise _unauthorized("flow_token_ontbreekt")
    if not token.startswith(TOKEN_PREFIX) or len(token) > 200:
        raise _unauthorized("flow_token_ongeldig")
    digest = hash_token(token)
    now = utcnow()
    with request.app.state.db.sessions() as session:
        row = session.scalars(select(AutomationFlowToken).where(AutomationFlowToken.token_sha256 == digest)).first()
        if row is None:
            raise _unauthorized("flow_token_ongeldig")
        if row.status != "actief":
            raise _unauthorized("flow_token_ingetrokken")
        identity = FlowIdentity(
            Principal("flow", str(row.flow_id), frozenset({FLOW_ROLE}), str(row.id)), row.flow_id, row.id
        )
        if row.last_used_at is None or now - row.last_used_at > LAST_USED_STEP:
            row.last_used_at = now
            session.commit()
    request.state.flow_identity = identity
    return identity


class FlowAuthFirstRoute(APIRoute):
    """Elke route van de flow-API meldt eerst de flow aan: vóór het lezen van de body en vóór de Idempotency-Key."""

    def get_route_handler(self) -> Callable[[Request], Any]:
        handler = super().get_route_handler()

        async def authenticate_first(request: Request) -> Response:
            if request.method in MUTATING_METHODS:
                await request.body()  # alleen begrensd inlezen (BodyLimitMiddleware); nog niet geparsed
            await run_in_threadpool(flow_identity, request)
            response: Response = await handler(request)
            return response

        return authenticate_first


router = APIRouter(prefix=PREFIX, tags=["automation-flow-api"], route_class=FlowAuthFirstRoute)


class ClaimIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(default=10, ge=1, le=inbox.MAX_CLAIM)


class NackIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9_.-]+$")


class ActionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str = Field(min_length=3, max_length=80, pattern=actions.ACTION_ID_RE.pattern)
    target: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=1, max_length=500)
    #: wordt alleen vastgelegd; telt nooit mee voor de beslissing (EX18)
    risk_claim: Literal["R0", "R1", "R2", "R3"] | None = None
    #: de aflevering waar dit verzoek een gevolg van is: daarmee wordt ontdubbeld (EX46) en de keten bewaakt
    trigger_delivery_id: uuid.UUID | None = None

    @field_validator("target", "parameters")
    @classmethod
    def _not_too_deep(cls, value: dict[str, Any]) -> dict[str, Any]:
        """Dieper genest dan ``actions.MAX_NESTING`` (objecten en lijsten) is een invoerfout (422
        ``validation_error``), geen serverfout bij het vastleggen van de Idempotency-Key (vervolgpunt R-VEILIG van
        S-P2-300: vanaf ongeveer 255 niveaus gaf dat een 500). Zonder recursie geteld, zodat de telling zelf nooit
        vastloopt."""
        stack: list[tuple[Any, int]] = [(value, 1)]
        while stack:
            item, depth = stack.pop()
            if depth > actions.MAX_NESTING:
                raise ValueError(f"is dieper genest dan {actions.MAX_NESTING} niveaus")
            children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
            stack.extend((child, depth + 1) for child in children if isinstance(child, dict | list))
        return value

    @field_validator("target", "parameters")
    @classmethod
    def _utf8_text(cls, value: dict[str, Any], info: ValidationInfo) -> dict[str, Any]:
        """Een losse surrogaat (een geldige JSON-escape zoals ``\\ud800``, maar geen tekst die in UTF-8 kan), ook in
        een sleutel of diep genest, is een invoerfout (422 ``validation_error``), geen serverfout bij de
        groottecontrole (vervolgpunt R-VEILIG-5 van S-P2-295). Hetzelfde geldt voor een NUL-teken, dat PostgreSQL niet
        opslaat (S-P2-310). Met een geldige ``action_id`` beslist :func:`request_action` dat, met het hele verzoek:
        zie :func:`_judged_with_the_whole_request`."""
        return value if _judged_with_the_whole_request(info) else actions.storable(value)

    @field_validator("reason", mode="wrap")
    @classmethod
    def _reason_text(cls, value: Any, handler: ValidatorFunctionWrapHandler, info: ValidationInfo) -> str:
        """Een NUL-teken in de reden is een invoerfout (422), geen serverfout in de database (S-P2-310); een losse
        surrogaat weigert de tekstcontrole van pydantic zelf al (422). Met een geldige ``action_id`` beslist
        :func:`request_action` dat (zie :func:`_judged_with_the_whole_request`); de reden wordt dan niet op lengte
        gecontroleerd: wordt het verzoek geweigerd, dan wordt hij niet bewaard, en anders is het een 422."""
        if isinstance(value, str) and actions.unstorable(value) and _judged_with_the_whole_request(info):
            return value
        return actions.storable(handler(value))


def _judged_with_the_whole_request(info: ValidationInfo) -> bool:
    """Is de ``action_id`` al geldig? Dan laat :class:`ActionIn` een NUL-teken of losse surrogaat in doel, parameters
    of reden door en beslist :func:`request_action` met het hele verzoek: weigert de harde weigerlijst het ook met een
    opgeschoonde kopie van doel en parameters (:func:`actions.cleaned`; op inhoud tot 8 kB, daarboven op naam), dan
    is het de gewone vastgelegde weigering zonder doel, parameters en reden; anders dezelfde ``422 validation_error``
    met het veld als hier (R-VEILIG-3 en R-VEILIG-4 van S-P2-310). Een veldcontrole ziet alleen de velden vóór zich;
    zo telt ook een boiler in de parameters als het teken in het doel staat."""
    return isinstance(info.data.get("action_id"), str)


#: de tekstvelden van een actieverzoek die niet worden bewaard als er tekst in staat die niet op te slaan is (het
#: verzoek wordt dan geweigerd en vastgelegd, of het is een 422)
TEXT_FIELDS = ("target", "parameters", "reason")


def _unstorable_text(fields: list[str]) -> RequestValidationError:
    """Dezelfde ``422 validation_error`` als :func:`actions.storable` in een veldcontrole geeft: per veld het veld en
    de vaste melding, zonder de invoer."""
    return RequestValidationError(
        [
            {"type": "value_error", "loc": ("body", name), "msg": f"Value error, {actions.UNSTORABLE_NL}"}
            for name in fields
        ]
    )


def _param_bytes(target: dict[str, Any], parameters: dict[str, Any]) -> int:
    """Grootte van doel en parameters samen in UTF-8, zoals tegen ``actions.MAX_PARAM_BYTES`` gemeten (alleen voor
    tekst die op te slaan is: een losse surrogaat kan niet in UTF-8)."""
    return len(json.dumps({"p": parameters, "t": target}, ensure_ascii=False).encode("utf-8"))


def _flow(session: Session, identity: FlowIdentity, *, lock: bool = False) -> AutomationFlow:
    flow = session.get(AutomationFlow, identity.flow_id, with_for_update=lock)
    if flow is None:  # het token verdwijnt met de flow (ON DELETE CASCADE); dit is alleen een race
        raise _unauthorized("flow_token_ongeldig")
    return flow


def _token(session: Session, identity: FlowIdentity) -> AutomationFlowToken:
    token = session.get(AutomationFlowToken, identity.token_id)
    if token is None or token.status != "actief":
        raise _unauthorized("flow_token_ingetrokken")
    return token


@router.get("/me", summary="Wie ben ik: de flow van dit token, zijn triggers, scope en grenzen")
def me(session: Session = Depends(get_session), identity: FlowIdentity = Depends(flow_identity)) -> dict[str, Any]:
    flow = _flow(session, identity)
    token = _token(session, identity)
    now = utcnow()
    run = inbox.dry_run_for(session, flow, now)
    triggers = session.scalars(
        select(AutomationTrigger).where(AutomationTrigger.flow_id == flow.id).order_by(AutomationTrigger.event_type)
    ).all()
    limits = session.scalars(
        select(AutomationRateLimit)
        .where(AutomationRateLimit.flow_id == flow.id)
        .order_by(AutomationRateLimit.action_id)
    ).all()
    return {
        "flow": {
            "id": str(flow.id),
            "label": flow.label,
            "owner": flow.owner,
            "status": flow.status,
            "blocked_reason": flow.blocked_reason,
            "version": flow.version,
        },
        "token": {
            "id": str(token.id),
            "last4": token.last4,
            "label": token.label,
            "allowed_actions": list(token.allowed_actions or []),
        },
        "triggers": [
            {"event_type": t.event_type, "schema_version": t.schema_version, "filter": t.filter or {}} for t in triggers
        ],
        "rate_limits": {
            "standaard_max_per_uur": actions.DEFAULT_MAX_PER_HOUR,
            "standaard_max_per_uur_per_flow": actions.FLOW_MAX_PER_HOUR,
            "eigen": [
                {"action_id": r.action_id, "max_per_hour": r.max_per_hour, "cooldown_s": r.cooldown_s} for r in limits
            ],
        },
        "dry_run": {"run_id": str(run.id), "expires_at": iso(run.expires_at)} if run is not None else None,
        "uitvoering": "Deze dienst voert niets uit: een actie wordt aangevraagd bij de Hub.",
        "nooit": sorted(actions.REFUSALS_NL),
    }


@router.post("/deliveries/claim", summary="Events ophalen: per bron hooguit het oudste openstaande event")
def claim(
    body: ClaimIn,
    request: Request,
    session: Session = Depends(get_session),
    identity: FlowIdentity = Depends(flow_identity),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    def action() -> Result:
        flow = _flow(session, identity, lock=True)
        items, run = inbox.claim(session, flow, limit=body.limit, now=utcnow(), trace_id=tid)
        return (
            200,
            {
                "items": items,
                "flow_status": flow.status,
                "dry_run": run is not None,
                "run_id": str(run.id) if run is not None else None,
                "lease_seconds": int(inbox.LEASE.total_seconds()),
                "bevestigen_nl": "Bevestig elke aflevering met ack (verwerkt) of nack (mislukt) binnen de leasetijd.",
            },
            {},
        )

    return run_idempotent(request, session, identity.principal, key, body.model_dump(), action)


def _refuse_closed_dry_run(session: Session, identity: FlowIdentity, delivery_id: uuid.UUID) -> None:
    """Een voorbeeld-aflevering van een proefrun die is afgesloten (bij het blokkeren, na verlopen of klaar), of van een
    geblokkeerde flow, wordt niet bevestigd: 409 ``proefrun_afgesloten``, en de run blijft zoals hij is (R-TECH-1 en
    R-VEILIG-2 van S-P2-300). Sloten in dezelfde volgorde als ``simulate.close_for_block``: flow, proefrun, en daarna
    (bij de aanroeper) de aflevering. ``run_id`` van een aflevering verandert nooit; die wordt zonder slot gelezen."""
    run_id = session.scalar(
        select(AutomationDelivery.run_id).where(
            AutomationDelivery.id == delivery_id, AutomationDelivery.flow_id == identity.flow_id
        )
    )
    if run_id is None:
        return  # een gewone aflevering (of een onbekende: die geeft hierna 404)
    flow = _flow(session, identity, lock=True)
    run = session.get(AutomationFlowRun, run_id, with_for_update=True)
    if flow.status == "geblokkeerd" or run is None or run.status != "bezig":
        raise ApiError(
            409,
            "proefrun_afgesloten",
            "Deze aflevering hoort bij een proefrun die is afgesloten (de flow is geblokkeerd, of de proefrun is "
            "verlopen of klaar); er is niets bevestigd.",
            {"run_id": str(run_id), "run_status": run.status if run is not None else None, "flow_status": flow.status},
        )


def _delivery_result(
    session: Session, identity: FlowIdentity, delivery_id: uuid.UUID, error: str | None, tid: str
) -> Result:
    now = utcnow()
    _refuse_closed_dry_run(session, identity, delivery_id)
    delivery = inbox.get_delivery(session, identity.flow_id, delivery_id)
    if delivery is None:
        raise not_found("Aflevering")
    done = inbox.ack(session, delivery, now) if error is None else inbox.nack(session, delivery, error, now, tid)
    if not done:
        raise ApiError(
            409,
            "aflevering_niet_geclaimd",
            "Deze aflevering is niet (meer) door deze flow geclaimd; haal de events opnieuw op.",
            {"status": delivery.status},
        )
    session.flush()
    simulate.settle(session, delivery, now=now)
    return 200, inbox.delivery_view(delivery), {}


@router.post("/deliveries/{delivery_id}/ack", summary="Aflevering verwerkt")
def ack(
    delivery_id: uuid.UUID,
    request: Request,
    session: Session = Depends(get_session),
    identity: FlowIdentity = Depends(flow_identity),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    return run_idempotent(
        request,
        session,
        identity.principal,
        key,
        {},
        lambda: _delivery_result(session, identity, delivery_id, None, tid),
    )


@router.post("/deliveries/{delivery_id}/nack", summary="Aflevering mislukt (wordt met oplopende wachttijd herhaald)")
def nack(
    delivery_id: uuid.UUID,
    body: NackIn,
    request: Request,
    session: Session = Depends(get_session),
    identity: FlowIdentity = Depends(flow_identity),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    return run_idempotent(
        request,
        session,
        identity.principal,
        key,
        body.model_dump(),
        lambda: _delivery_result(session, identity, delivery_id, body.error, tid),
    )


def _hub_linked(request: Request) -> bool:
    return bool(request.app.state.hublink_store.read().linked)


@router.post(
    "/actions",
    summary="Actie aanvragen bij de Hub (nooit uitvoeren)",
    responses={
        200: {"description": "Al eerder aangevraagd voor hetzelfde event (ontdubbeld), of proefrun (gesimuleerd)"},
        202: {"description": "Aangevraagd bij de Hub (event flow.action.requested)"},
        403: {"description": "forbidden — geweigerd en vastgelegd (details.reason)"},
        429: {"description": "rate_limited — te veel verzoeken van deze flow (voor deze actie of in totaal)"},
        503: {"description": "hub_unavailable — deze dienst is niet met de Hub gekoppeld"},
    },
)
def request_action(
    body: ActionIn,
    request: Request,
    session: Session = Depends(get_session),
    identity: FlowIdentity = Depends(flow_identity),
    key: uuid.UUID = Depends(idempotency_key),
    tid: str = Depends(trace_id),
) -> Any:
    target, parameters, reason = body.target, body.parameters, body.reason
    refused: str | None = None
    fingerprint: dict[str, Any]
    unstorable = [name for name in TEXT_FIELDS if actions.unstorable(getattr(body, name))]
    if unstorable:
        # Een NUL-teken of losse surrogaat (ActionIn laat die bij een geldige action_id door). De harde weigerlijst
        # beoordeelt het verzoek met een kopie van doel en parameters waarin die tekens een "?" zijn; op inhoud alleen
        # tot 8 kB, net als zonder die tekens (daarboven alleen op naam). Weigert ze het, dan wordt de weigering
        # gewoon vastgelegd (rij, audit, flow.action.rejected), maar zonder doel, parameters en reden; de reden is de
        # weigerreden. Anders een 422 zonder vastlegging. De Idempotency-Key herkent het verzoek aan de ingevoerde
        # tekst, als ASCII-escapes (R-VEILIG-3 en R-VEILIG-4 van S-P2-310).
        clean_target, clean_parameters = actions.cleaned(body.target), actions.cleaned(body.parameters)
        if _param_bytes(clean_target, clean_parameters) <= actions.MAX_PARAM_BYTES:
            refused = actions.local_refusal(body.action_id, clean_target, clean_parameters)
        else:
            refused = actions.local_refusal(body.action_id, {}, {})
        if refused is None:
            raise _unstorable_text(unstorable)
        target, parameters, reason = {}, {}, refused
        fingerprint = {
            **body.model_dump(mode="json", exclude=set(TEXT_FIELDS)),
            "niet_op_te_slaan": json.dumps(
                {name: getattr(body, name) for name in TEXT_FIELDS}, ensure_ascii=True, sort_keys=True
            ),
        }
    else:
        size = _param_bytes(target, parameters)
        if size > actions.MAX_PARAM_BYTES:
            raise ApiError(
                422,
                "parameters_te_groot",
                f"Doel en parameters samen zijn te groot (maximaal {actions.MAX_PARAM_BYTES // 1024} kB).",
                {"bytes": size, "max_bytes": actions.MAX_PARAM_BYTES},
            )
        fingerprint = body.model_dump(mode="json")

    def action() -> Result:
        now = utcnow()
        flow = _flow(session, identity, lock=True)
        token = _token(session, identity)
        if inbox.dry_run_for(session, flow, now) is None and not _hub_linked(request):
            raise ApiError(
                503,
                "hub_unavailable",
                "Deze dienst is niet met de Hub gekoppeld; een actie kan nu niet worden aangevraagd.",
                {"reason": "niet_gekoppeld"},
                {"Retry-After": "60"},
            )
        used = session.scalars(
            select(AutomationActionRequest.id).where(AutomationActionRequest.idempotency_key == key)
        ).first()
        if used is not None:
            raise ApiError(
                422,
                "idempotency_key_reused",
                "Deze Idempotency-Key hoort al bij een eerder actieverzoek; gebruik een nieuwe key.",
            )
        try:
            outcome = actions.request_action(
                session,
                flow=flow,
                token=token,
                key=key,
                action_id=body.action_id,
                target=target,
                parameters=parameters,
                reason=reason,
                risk_claim=body.risk_claim,
                trigger_delivery_id=body.trigger_delivery_id,
                trace_id=tid,
                now=now,
                refused=refused,
            )
        except actions.RateLimited as exc:
            raise ApiError(
                429,
                "rate_limited",
                "Te veel verzoeken van deze flow (voor deze actie of in totaal); probeer het later opnieuw.",
                {"limiet": exc.limit, "retry_after_s": exc.retry_after},
                {"Retry-After": str(exc.retry_after)},
            ) from exc
        result = dict(outcome.body)
        if outcome.status_code >= 400:
            result["trace_id"] = tid  # een weigering wordt vastgelegd en bij dezelfde key identiek teruggegeven
        return outcome.status_code, result, {}

    return run_idempotent(request, session, identity.principal, key, fingerprint, action)


@router.get("/actions/{request_id}", summary="Stand van een eigen actieverzoek (zoals de Hub die terugmeldde)")
def get_action(
    request_id: uuid.UUID, session: Session = Depends(get_session), identity: FlowIdentity = Depends(flow_identity)
) -> dict[str, Any]:
    row = session.get(AutomationActionRequest, request_id)
    if row is None or row.flow_id != identity.flow_id:
        raise not_found("Actieverzoek")
    return actions.request_view(row)
