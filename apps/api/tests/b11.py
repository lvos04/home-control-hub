"""Gedeelde hulpfuncties voor de B11-tests (automatisering met de nep-Node-RED en de nep-Hub).

Alles hier doet wat een beheerder, de Hub of een flow via de API doet; er wordt niets rechtstreeks in de database gezet.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from tests.conftest import FakeHub, idem

A = "/integrations/v1/automation"
FLOW_API = A + "/flow-api"
CONNECTOR = "/connector/v1"
RESTORE = "automation.flows.restore"
NODE_RED_TARGET = {"type": "source", "id": "node_red"}

Auth = Callable[..., dict[str, str]]


def now_ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def snapshot(client: Any, auth: Auth, role: str = "admin") -> dict[str, Any]:
    """Node-RED uitlezen en een momentopname vastleggen (ook de synchronisatie van het flowregister)."""
    r = client.post(f"{A}/snapshots", headers=idem(auth(role)))
    assert r.status_code == 201, r.text
    body: dict[str, Any] = r.json()
    return body


def flows(client: Any, auth: Auth) -> list[dict[str, Any]]:
    r = client.get(f"{A}/flows", headers=auth("viewer"))
    assert r.status_code == 200, r.text
    items: list[dict[str, Any]] = r.json()["items"]
    return items


def flow_by_tab(client: Any, auth: Auth, tab_id: str) -> dict[str, Any]:
    for item in flows(client, auth):
        if item["source_flow_id"] == tab_id:
            return flow_detail(client, auth, item["id"])
    raise AssertionError(f"flow voor tabblad {tab_id} niet gevonden")


def flow_detail(client: Any, auth: Auth, flow_id: str) -> dict[str, Any]:
    r = client.get(f"{A}/flows/{flow_id}", headers=auth("viewer"))
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def put_flow(client: Any, auth: Auth, flow_id: str, part: str, body: dict[str, Any], role: str = "admin") -> Any:
    return client.put(f"{A}/flows/{flow_id}/{part}", json=body, headers=idem(auth(role), **{"If-Match": "*"}))


def set_owner(client: Any, auth: Auth, flow_id: str, owner: str = "user-1") -> dict[str, Any]:
    r = put_flow(client, auth, flow_id, "owner", {"owner": owner, "eigenaren": []})
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def set_triggers(client: Any, auth: Auth, flow_id: str, *event_types: str, version: str = "1.0") -> dict[str, Any]:
    triggers = [{"event_type": t, "schema_version": version, "filter": {}} for t in event_types]
    r = put_flow(client, auth, flow_id, "triggers", {"triggers": triggers})
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def issue_token(client: Any, auth: Auth, flow_id: str, *allowed_actions: str, label: str = "test") -> dict[str, Any]:
    r = client.post(
        f"{A}/flows/{flow_id}/tokens",
        json={"label": label, "allowed_actions": list(allowed_actions)},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 201, r.text
    body: dict[str, Any] = r.json()
    return body


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def ready_flow(
    client: Any, auth: Auth, tab_id: str, *allowed_actions: str, triggers: tuple[str, ...] = ()
) -> tuple[dict[str, Any], str]:
    """Flow met eigenaar, triggers en een flow-token; geeft (flow, token)."""
    flow = flow_by_tab(client, auth, tab_id)
    set_owner(client, auth, flow["id"])
    if triggers:
        set_triggers(client, auth, flow["id"], *triggers)
    issued = issue_token(client, auth, flow["id"], *allowed_actions)
    return flow_detail(client, auth, flow["id"]), str(issued["flow_token"])


def envelope(
    event_type: str = "energy.reading.recorded",
    *,
    source_app: str = "home-control-hub",
    entity: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    schema_version: str = "1.0",
    classification: str = "internal",
    source_event_id: str | None = None,
    correlation_id: str | None = None,
    event_id: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "event_id": event_id or str(uuid.uuid4()),
        "source_app": source_app,
        "source_event_id": source_event_id or f"test:{uuid.uuid4()}",
        "event_type": event_type,
        "entity": entity or {"type": "meter", "id": "meter-1"},
        "timestamp_utc": now_ts(),
        "trace_id": str(uuid.uuid4()),
        "correlation_id": correlation_id,
        "actor": {"type": "system", "id": "test"},
        "classification": classification,
        "payload": payload if payload is not None else {"vermogen_w": 100, "eenheid": "W"},
        "payload_ref": None,
    }


def post_event(client: Any, fake_hub: FakeHub, env: dict[str, Any]) -> Any:
    """Zoals de Hub een event aanbiedt: met een dienst-JWT."""
    return client.post(f"{A}/events", json=env, headers=idem(fake_hub.service_auth()))


def claim(client: Any, token: str, limit: int = 5) -> dict[str, Any]:
    r = client.post(f"{FLOW_API}/deliveries/claim", json={"limit": limit}, headers=idem(bearer(token)))
    assert r.status_code == 200, r.text
    body: dict[str, Any] = r.json()
    return body


def ack(client: Any, token: str, delivery_id: str) -> Any:
    return client.post(f"{FLOW_API}/deliveries/{delivery_id}/ack", headers=idem(bearer(token)))


def nack(client: Any, token: str, delivery_id: str, error: str = "tijdelijk") -> Any:
    return client.post(f"{FLOW_API}/deliveries/{delivery_id}/nack", json={"error": error}, headers=idem(bearer(token)))


def request_action(
    client: Any,
    token: str,
    action_id: str,
    *,
    target: dict[str, Any] | None = None,
    parameters: dict[str, Any] | None = None,
    reason: str = "test",
    key: str | None = None,
    **extra: Any,
) -> Any:
    body = {
        "action_id": action_id,
        "target": target if target is not None else {"type": "app", "id": "jellyfin"},
        "parameters": parameters or {},
        "reason": reason,
        **extra,
    }
    return client.post(f"{FLOW_API}/actions", json=body, headers=idem(bearer(token), key=key))


def propose_restore(client: Any, auth: Auth, snapshot_id: str, role: str = "admin") -> Any:
    return client.post(
        f"{CONNECTOR}/propose",
        json={"action_id": RESTORE, "target": NODE_RED_TARGET, "parameters": {"snapshot_id": snapshot_id}},
        headers=idem(auth(role)),
    )


def signed_restore(fake_hub: FakeHub, view: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    """Door de nep-Hub ondertekend ExecutionRequest voor precies dit herstelvoorstel."""
    request: dict[str, Any] = fake_hub.sim.execution_request(
        action_id=RESTORE,
        target=dict(NODE_RED_TARGET),
        parameters=dict(view["parameters"]),
        preview_hash=view["preview_hash"],
        resource_etag=view["resource_etag"],
        **kwargs,
    )
    return request


def apply(client: Any, fake_hub: FakeHub, request: dict[str, Any], key: str | None = None) -> Any:
    return client.post(f"{CONNECTOR}/apply", json=request, headers=idem(fake_hub.service_auth(), key=key))


def audit_rows(client: Any) -> list[dict[str, Any]]:
    """Alle auditregels, rechtstreeks uit de database (alleen lezen)."""
    from sqlalchemy import select

    from integrations.models import AuditEvent

    with client.app.state.db.sessions() as session:
        return [
            {"action": r.action, "message_nl": r.message_nl, "details": r.details, "entity_id": r.entity_id}
            for r in session.scalars(select(AuditEvent).order_by(AuditEvent.at))
        ]


def outbox(client: Any, event_type: str | None = None) -> list[dict[str, Any]]:
    """De eigen events (outbox) als envelopes, rechtstreeks uit de database (alleen lezen)."""
    from sqlalchemy import select

    from integrations import events
    from integrations.models import OutboxEvent

    with client.app.state.db.sessions() as session:
        out = [events.envelope(r) for r in session.scalars(select(OutboxEvent).order_by(OutboxEvent.seq))]
    return [e for e in out if event_type is None or e["event_type"] == event_type]


def idempotency_bodies(client: Any) -> list[Any]:
    """Alle bewaarde antwoorden voor Idempotency-Keys (om te bewijzen dat er geen geheim in staat)."""
    from sqlalchemy import select

    from integrations.models import IdempotencyRecord

    with client.app.state.db.sessions() as session:
        return [r.response_body for r in session.scalars(select(IdempotencyRecord))]


def everything_stored(client: Any) -> str:
    """Audit, events en idempotency-antwoorden als één tekst: voor 'dit geheim staat nergens'-controles."""
    import json

    return json.dumps(
        {"audit": audit_rows(client), "events": outbox(client), "idempotency": idempotency_bodies(client)},
        ensure_ascii=False,
        default=str,
    )
