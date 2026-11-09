"""Maximale grootte van een verzoek (body), al vóór de authenticatie.

FastAPI leest en parseert de body vóórdat de auth-afhankelijkheden draaien. Zonder grens kan iedereen op het LAN
(ook zonder login) de dienst grote bodies laten inlezen. Daarom begrenst deze ASGI-laag de grootte:

- ``Content-Length`` groter dan de grens → direct ``413 payload_too_large`` (de app ziet het verzoek niet);
- zonder ``Content-Length`` (chunked) wordt meegeteld; boven de grens breekt het inlezen af met dezelfde 413.

Geldige verzoeken van deze dienst zijn klein (de grootste is een herstelkit van enkele tientallen kB).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from starlette.exceptions import HTTPException as StarletteHTTPException

MAX_BODY_BYTES = 1024 * 1024  # 1 MiB

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class PayloadTooLarge(StarletteHTTPException):
    """Een subklasse van HTTPException: FastAPI geeft die ongewijzigd door aan de foutafhandeling (→ 413)."""

    def __init__(self) -> None:
        super().__init__(status_code=413)


def _trace_id(scope: Scope) -> str:
    for name, value in scope.get("headers", []):
        if name == b"x-trace-id":
            try:
                return str(uuid.UUID(value.decode("latin-1")))
            except ValueError:
                break
    return str(uuid.uuid4())


class BodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def _reject(self, scope: Scope, send: Send) -> None:
        tid = _trace_id(scope)
        body = json.dumps(
            {
                "code": "payload_too_large",
                "message": f"Het verzoek is te groot (maximaal {self.max_bytes // 1024} kB).",
                "details": {"max_bytes": self.max_bytes},
                "trace_id": tid,
            }
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"x-trace-id", tid.encode("ascii")),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = self.max_bytes + 1  # ongeldige lengte: weigeren, nooit doorlaten
                if declared > self.max_bytes:
                    await self._reject(scope, send)
                    return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise PayloadTooLarge()
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message.get("type") == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except PayloadTooLarge:
            if started:
                raise
            await self._reject(scope, send)
