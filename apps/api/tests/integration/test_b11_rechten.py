"""B11 — rechten op de schrijvende routes van de beheer-API (stap S-P2-310, bouwpunt 5).

Indeling (ADR-0016 kop 2, aanvulling "Rechten op de beheer-API"; keuze van de regisseur op 2026-11-12): beleid en
toegang (beveiligingsprofiel, eigenaar, triggers, grenzen, flow-tokens; ook het adres van de editor) alleen voor de
beheerder; bediening (pauzeren en hervatten, isolatie meten, momentopname, opnieuw aanbieden, proefrun) voor de
beheerder en de operator; events aanbieden en de uitkomst van een actieverzoek melden alleen voor de Hub (dienst-JWT).
Een viewer of een kind krijgt op elke schrijvende route ``403``; een operator op elke route die alleen voor de
beheerder is; de Hub (dienst-JWT, rol ``service``, contract §4.3: "service is nooit admin") op elke route van de
beheerder en van de operator. Een geweigerde aanvraag legt niets vast (geen auditregel, geen event, de flow blijft
gelijk); dezelfde aanvraag van de beheerder lukt en legt de auditregel vast die de route belooft. De lijst met routes
komt uit de app zelf (de OpenAPI-beschrijving én de routers): een nieuwe schrijvende route zonder plaats in deze
indeling, ook een die niet in de OpenAPI-beschrijving staat, laat de eerste test falen.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.routing import APIRoute

from integrations.domains.automation import flowapi
from integrations.domains.automation import router as automation_api
from tests import b11
from tests.b11 import FLOW_API, A
from tests.conftest import idem, setup_node_red
from tests.fakes.node_red_fake import simple_flow

TAB = "tab0000000000001"
WRITING = {"POST", "PUT", "PATCH", "DELETE"}

#: (methode, pad) -> de auditregel die de route bij succes vastlegt
ADMIN_ONLY = {
    ("POST", f"{A}/hardening-profile"): "automation.hardening_profile.issued",
    ("PUT", f"{A}/flows/{{flow_id}}/owner"): "automation.flow.owner_changed",
    ("PUT", f"{A}/flows/{{flow_id}}/triggers"): "automation.flow.triggers_changed",
    ("PUT", f"{A}/flows/{{flow_id}}/rate-limits"): "automation.flow.rate_limits_changed",
    ("POST", f"{A}/flows/{{flow_id}}/tokens"): "automation.flow_token.issued",
    ("POST", f"{A}/flows/{{flow_id}}/tokens/{{token_id}}/revoke"): "automation.flow_token.revoked",
}
ADMIN_OR_OPERATOR = {
    ("POST", f"{A}/isolation/check"): "automation.isolation.checked",
    ("PUT", f"{A}/flows/{{flow_id}}/state"): "automation.flow.state_changed",
    ("POST", f"{A}/snapshots"): "automation.snapshot.created",
    ("POST", f"{A}/deliveries/{{delivery_id}}/requeue"): "automation.delivery.requeued",
    ("POST", f"{A}/flows/{{flow_id}}/runs"): "automation.simulation.started",
}
HUB_ONLY = {
    ("POST", f"{A}/events"): None,
    ("POST", f"{A}/action-requests/{{request_id}}/result"): "automation.action.result_recorded",
}


@pytest.fixture
def flow(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> tuple[dict[str, Any], str]:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    return b11.ready_flow(linked, auth, TAB, "notification.send", triggers=("energy.reading.recorded",))


def _token_id(linked: Any, auth: Any, flow_id: str) -> str:
    items = linked.get(f"{A}/flows/{flow_id}/tokens", headers=auth("admin")).json()["items"]
    active = [t["id"] for t in items if t["status"] == "actief"]
    assert active, items
    return str(active[0])


def _request(linked: Any, auth: Any, flow_id: str, route: tuple[str, str], headers: dict[str, str]) -> Any:
    """Een verder geldige aanvraag op de route: zonder de rolcontrole zou die slagen (of 404 geven bij een onbekend
    kenmerk), nooit 403."""
    method, template = route
    path = template.format(
        flow_id=flow_id,
        token_id=_token_id(linked, auth, flow_id) if "{token_id}" in template else "",
        delivery_id=uuid.uuid4(),
        request_id=uuid.uuid4(),
    )
    bodies: dict[str, Any] = {
        "/hardening-profile": {},
        "/owner": {"owner": "user-2", "eigenaren": []},
        "/state": {"status": "gepauzeerd", "reden": "test"},
        "/triggers": {"triggers": [{"event_type": "backup.run.failed", "schema_version": "1.0", "filter": {}}]},
        "/rate-limits": {"rate_limits": [{"action_id": "notification.send", "max_per_hour": 5}]},
        "/tokens": {"label": "rol", "allowed_actions": ["notification.send"]},
        "/runs": {"sample_ids": ["energie-meting"], "bevestig_niet_afgeschermd": True},
        "/events": b11.envelope(),
        "/result": {"status": "uitgevoerd"},
    }
    body = next((b for suffix, b in bodies.items() if path.endswith(suffix)), None)
    return linked.request(method, path, json=body, headers=idem(headers, **{"If-Match": "*"}))


def _recorded(linked: Any, auth: Any, flow_id: str) -> tuple[Any, ...]:
    """Wat een geweigerde aanvraag niet mag veranderen."""
    detail = b11.flow_detail(linked, auth, flow_id)
    tokens = linked.get(f"{A}/flows/{flow_id}/tokens", headers=auth("admin")).json()["items"]
    runs = linked.get(f"{A}/runs", headers=auth("viewer")).json()["items"]
    return (
        [a["action"] for a in b11.audit_rows(linked)],
        len(b11.outbox(linked)),
        detail["etag"],
        detail["status"],
        [(t["id"], t["status"]) for t in tokens],
        len(runs),
    )


def _assert_forbidden(r: Any, route: tuple[str, str], role: str) -> None:
    assert r.status_code == 403, (route, role, r.status_code, r.text)
    assert r.json()["code"] == "forbidden" and r.json()["details"]["reason"] == "rol_ontbreekt", (route, role)


def test_every_writing_route_of_the_automation_api_has_a_place_in_the_role_table(linked: Any) -> None:
    """De indeling hieronder dekt precies de schrijvende routes van de app (gelezen uit de OpenAPI-beschrijving die de
    app zelf maakt en uit de router van de beheer-API; de flow-API heeft een eigen aanmelding en staat in
    ``test_b11_003_veilige_acties.py``)."""
    paths = linked.app.openapi()["paths"]
    found = {
        (method.upper(), path)
        for path, operations in paths.items()
        if path.startswith(A + "/") and not path.startswith(FLOW_API)
        for method in operations
        if method.upper() in WRITING
    }
    assert len(found) >= 13, "de lijst met routes is niet leeg of half gelezen"
    table = set(ADMIN_ONLY) | set(ADMIN_OR_OPERATOR) | set(HUB_ONLY)
    assert found == table, {"niet_in_de_indeling": sorted(found - table), "bestaat_niet": sorted(table - found)}
    # een route met include_in_schema=False staat niet in de OpenAPI-beschrijving; daarom ook uit de routers zelf
    # (R-TECH-1 van S-P2-310): geen route van de beheer-API of de flow-API is verborgen, en de router van de
    # beheer-API heeft precies dezelfde schrijvende routes
    routes = [r for r in [*automation_api.router.routes, *flowapi.router.routes] if isinstance(r, APIRoute)]
    assert len(routes) >= 20, "de routers zijn niet leeg of half gelezen"
    hidden = sorted((sorted(r.methods), r.path) for r in routes if not r.include_in_schema)
    assert hidden == [], {"verborgen_routes": hidden}
    in_router = {
        (method, r.path)
        for r in automation_api.router.routes
        if isinstance(r, APIRoute)
        for method in r.methods
        if method in WRITING
    }
    assert in_router == table, {
        "niet_in_de_indeling": sorted(in_router - table),
        "bestaat_niet": sorted(table - in_router),
    }
    assert not set(ADMIN_ONLY) & set(ADMIN_OR_OPERATOR) and not set(HUB_ONLY) & (
        set(ADMIN_ONLY) | set(ADMIN_OR_OPERATOR)
    )


@pytest.mark.parametrize("role", ["viewer", "kind"])
@pytest.mark.parametrize("route", [*ADMIN_ONLY, *ADMIN_OR_OPERATOR, *HUB_ONLY], ids=lambda r: f"{r[0]} {r[1]}")
def test_viewer_and_child_get_403_on_every_writing_route_and_nothing_is_recorded(
    linked: Any, auth: Any, flow: Any, route: tuple[str, str], role: str
) -> None:
    detail, _ = flow
    before = _recorded(linked, auth, detail["id"])
    r = _request(linked, auth, detail["id"], route, auth(role))
    _assert_forbidden(r, route, role)
    assert _recorded(linked, auth, detail["id"]) == before, (route, role)


@pytest.mark.parametrize("route", list(ADMIN_ONLY), ids=lambda r: f"{r[0]} {r[1]}")
def test_operator_gets_403_on_every_admin_only_route_and_only_the_admin_gets_the_audit(
    linked: Any, auth: Any, flow: Any, route: tuple[str, str]
) -> None:
    detail, _ = flow
    before = _recorded(linked, auth, detail["id"])
    r = _request(linked, auth, detail["id"], route, auth("operator"))
    _assert_forbidden(r, route, "operator")
    assert _recorded(linked, auth, detail["id"]) == before, route
    # dezelfde aanvraag van de beheerder lukt en legt de beloofde auditregel vast (de 403 kwam dus door de rol)
    ok = _request(linked, auth, detail["id"], route, auth("admin"))
    assert ok.status_code in (200, 201), (route, ok.status_code, ok.text)
    actions = [a["action"] for a in b11.audit_rows(linked)]
    assert actions[: len(before[0])] == before[0] and actions[len(before[0]) :] == [ADMIN_ONLY[route]], actions


@pytest.mark.parametrize("route", [*ADMIN_ONLY, *ADMIN_OR_OPERATOR], ids=lambda r: f"{r[0]} {r[1]}")
def test_the_hub_gets_403_on_every_admin_and_operator_route_and_nothing_is_recorded(
    linked: Any, fake_hub: Any, auth: Any, flow: Any, route: tuple[str, str]
) -> None:
    """R-VEILIG-1 van S-P2-310: de Hub meldt zich met een dienst-JWT (rol ``service``) en die rol is nooit ``admin``
    (contract §4.3). Op elke route van de beheerder en van de operator krijgt de Hub ``403`` en wordt er niets
    vastgelegd; alleen events aanbieden en een uitkomst melden zijn voor de Hub (zie de test hierna)."""
    detail, _ = flow
    before = _recorded(linked, auth, detail["id"])
    r = _request(linked, auth, detail["id"], route, fake_hub.service_auth())
    _assert_forbidden(r, route, "service")
    assert _recorded(linked, auth, detail["id"]) == before, route


@pytest.mark.parametrize("route", list(ADMIN_OR_OPERATOR), ids=lambda r: f"{r[0]} {r[1]}")
def test_operator_may_operate_flows_with_audit(linked: Any, auth: Any, flow: Any, route: tuple[str, str]) -> None:
    """Bediening blijft ook voor de operator (keuze van de regisseur, 2026-11-12), met de auditregel van de route. Een
    onbekende aflevering geeft de operator 404 (de rol is dan al toegelaten)."""
    detail, _ = flow
    r = _request(linked, auth, detail["id"], route, auth("operator"))
    if route[1].endswith("/requeue"):
        assert r.status_code == 404, r.text
        return
    assert r.status_code in (200, 201), (route, r.status_code, r.text)
    assert ADMIN_OR_OPERATOR[route] in [a["action"] for a in b11.audit_rows(linked)]


@pytest.mark.parametrize("role", ["admin", "operator"])
@pytest.mark.parametrize("route", list(HUB_ONLY), ids=lambda r: f"{r[0]} {r[1]}")
def test_only_the_hub_reports_events_and_results(
    linked: Any, auth: Any, flow: Any, route: tuple[str, str], role: str
) -> None:
    detail, _ = flow
    before = _recorded(linked, auth, detail["id"])
    _assert_forbidden(_request(linked, auth, detail["id"], route, auth(role)), route, role)
    assert _recorded(linked, auth, detail["id"]) == before
