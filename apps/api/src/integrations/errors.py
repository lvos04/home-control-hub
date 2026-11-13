"""Foutformaat (contract §5): ``{"code", "message", "details", "trace_id"}`` met Nederlandse meldingen."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .bodylimit import MAX_BODY_BYTES
from .logfilter import db_error_text

log = logging.getLogger("integrations")

TRACE_HEADER = "X-Trace-Id"


class ApiError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}
        self.headers = headers or {}


def unauthorized(reason: str, message: str = "Niet geautoriseerd.") -> ApiError:
    return ApiError(401, "unauthorized", message, {"reason": reason}, {"WWW-Authenticate": "Bearer"})


def forbidden(reason: str, message: str = "Geen toestemming voor deze handeling.") -> ApiError:
    return ApiError(403, "forbidden", message, {"reason": reason})


def not_found(what: str = "Object") -> ApiError:
    return ApiError(404, "not_found", f"{what} niet gevonden.")


def capability_unavailable(capability: str, message: str | None = None) -> ApiError:
    return ApiError(
        501,
        "capability_unavailable",
        message or f"Functie '{capability}' is in deze versie niet beschikbaar.",
        {"capability": capability},
    )


def trace_id_for(request: Request) -> str:
    existing = getattr(request.state, "trace_id", None)
    if existing:
        return str(existing)
    raw = request.headers.get(TRACE_HEADER, "")
    try:
        tid = str(uuid.UUID(raw))
    except ValueError:
        tid = str(uuid.uuid4())
    request.state.trace_id = tid
    return tid


def error_body(request: Request, code: str, message: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"code": code, "message": message, "details": details or {}, "trace_id": trace_id_for(request)}


def error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    tid = trace_id_for(request)
    hdrs = {TRACE_HEADER: tid, **(headers or {})}
    return JSONResponse(error_body(request, code, message, details), status_code=status_code, headers=hdrs)


_STATUS_CODES = {
    400: ("bad_request", "Ongeldig verzoek."),
    401: ("unauthorized", "Niet geautoriseerd."),
    403: ("forbidden", "Geen toestemming voor deze handeling."),
    404: ("not_found", "Niet gevonden."),
    405: ("method_not_allowed", "Deze methode is niet toegestaan op dit adres."),
    409: ("conflict", "Conflict met de huidige toestand."),
    413: ("payload_too_large", "Het verzoek is te groot."),
    415: ("unsupported_media_type", "Dit inhoudstype wordt niet ondersteund."),
    429: ("rate_limited", "Te veel verzoeken; probeer het later opnieuw."),
}


def install_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
        return error_response(request, exc.status_code, exc.code, exc.message, exc.details, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: RequestValidationError) -> JSONResponse:
        problems = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ()) if p != "body")
            msg = str(err.get("msg", "ongeldig")).removeprefix("Value error, ")
            problems.append({"veld": loc, "probleem": msg, "type": err.get("type")})
        return error_response(request, 422, "validation_error", "De invoer is ongeldig.", {"fouten": problems})

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code, message = _STATUS_CODES.get(exc.status_code, ("http_error", "Fout bij verwerken van het verzoek."))
        details = {"max_bytes": MAX_BODY_BYTES} if exc.status_code == 413 else None  # foutcatalogus §5
        return error_response(request, exc.status_code, code, message, details, getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        if isinstance(exc, DBAPIError):
            # KLEIN-32: geen str(exc)/traceback; daarin staat de DETAIL-regel van PostgreSQL (sleutelwaarde of rij)
            log.error("onverwachte fout (trace %s): %s", trace_id_for(request), db_error_text(exc))
        else:
            log.exception("onverwachte fout (trace %s)", trace_id_for(request))
        return error_response(request, 500, "internal_error", "Interne fout; zie de app-log met dit trace-id.")
