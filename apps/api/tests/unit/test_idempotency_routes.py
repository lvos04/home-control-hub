"""Contract 1.3 §5 (C1.3-HCH-09) en de foutcatalogus (A20/A21): statische controles over alle routes en foutcodes.

1. Elke muterende route (POST/PUT/PATCH/DELETE) vraagt een ``Idempotency-Key`` (afhankelijkheid ``idempotency_key``),
   tenzij hij hieronder **met reden** is uitgezonderd. Een nieuwe route zonder sleutel laat deze test falen. Let op
   §4.6: ook zonder ``Idempotency-Key`` verbruikt een POST de ``jti``.
2. Elke route met een aanmelding authenticeert eerst (``AuthFirstRoute``): vóór body, rol en ``Idempotency-Key``.
3. Foutcatalogus: 401 alleen ``unauthorized``; 403 alleen ``forbidden`` of een vaste eigen code; 400 alleen de
   ``Idempotency-Key``-codes en de cursor/type-codes van de referentie (de Hub gebruikt ook 400 ``invalid_cursor``);
   een gedeelde situatie heeft één code (``idempotency_key_reused`` 422, ``precondition_failed`` 412 met
   ``huidige_etag``).
"""

from __future__ import annotations

import ast
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute

from integrations.app import create_app
from integrations.config import Settings
from integrations.domains.automation.flowapi import PREFIX as FLOW_API_PREFIX
from integrations.domains.automation.flowapi import FlowAuthFirstRoute, flow_identity
from integrations.idempotency import idempotency_key
from integrations.security.auth import AuthFirstRoute, current_principal

SRC = Path(__file__).resolve().parents[2] / "src" / "integrations"
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}

#: uitzonderingen op Idempotency-Key, elk met de reden uit contract 1.3 §5 (andere alleen met een ADR)
EXEMPT: dict[tuple[str, str], str] = {
    ("POST", "/koppelen"): "formulier-POST van de statuspagina: een browserformulier kan geen header meesturen; "
    "bescherming via formuliertoken, herkomstcontrole, pogingenlimiet, koppelen_bezig en eenmalige code (§5, RV10)",
    ("POST", "/connector/v1/rollback"): "geeft altijd 501 capability_unavailable (§5: alleen zolang dat zo is)",
    ("POST", "/integrations/v1/sso/break-glass/evaluate"): "geen bijwerking behalve audit en tellers: …/evaluate (§5)",
    ("POST", "/integrations/v1/sso/recovery/kit/verify"): "geen bijwerking behalve audit en tellers: …/verify (§5)",
}


def _app() -> Any:
    data = Path(tempfile.mkdtemp(prefix="hch-routes-"))
    return create_app(Settings(data_dir=data, database_url="postgresql+psycopg://x@127.0.0.1:1/x"))


def _routes(routes: Any) -> Iterator[APIRoute]:
    for r in routes:
        if hasattr(r, "original_router"):  # FastAPI 0.16x: ingesloten routers
            yield from _routes(r.original_router.routes)
        elif isinstance(r, APIRoute):
            yield r


def _uses(dependant: Dependant, call: Any) -> bool:
    return any(d.call is call or _uses(d, call) for d in dependant.dependencies)


def test_every_mutating_route_requires_an_idempotency_key_or_is_exempt_with_reason() -> None:
    gevonden: set[tuple[str, str]] = set()
    zonder: list[str] = []
    for route in _routes(_app().routes):
        for method in sorted(set(route.methods) & MUTATING):
            gevonden.add((method, route.path))
            if (method, route.path) in EXEMPT:
                assert not _uses(route.dependant, idempotency_key), f"{method} {route.path} staat onterecht in EXEMPT"
                continue
            if not _uses(route.dependant, idempotency_key):
                zonder.append(f"{method} {route.path}")
    assert len(gevonden) >= 25, "te weinig muterende routes gevonden: klopt de routeverzameling nog?"
    assert not zonder, f"muterende routes zonder Idempotency-Key (of zonder reden in EXEMPT): {zonder}"
    assert set(EXEMPT) <= gevonden, f"verouderde uitzonderingen: {sorted(set(EXEMPT) - gevonden)}"
    assert all(len(reden) > 20 for reden in EXEMPT.values())


def test_every_authenticated_route_authenticates_first() -> None:
    """RV9/§4.7: aanmelding vóór body, rol en Idempotency-Key; alleen /koppelen, /healthz, /readyz en / zonder."""
    zonder_aanmelding = set()
    flow_api = set()
    for route in _routes(_app().routes):
        if _uses(route.dependant, current_principal):
            assert isinstance(route, AuthFirstRoute), route.path
        elif _uses(route.dependant, flow_identity):
            # B11: de flow-API kent alleen flow-tokens (nooit een Hub-JWT) en authenticeert net zo eerst (ADR-0016)
            assert isinstance(route, FlowAuthFirstRoute), route.path
            assert route.path.startswith(FLOW_API_PREFIX + "/"), route.path
            flow_api.add(route.path)
        else:
            zonder_aanmelding.add(route.path)
    assert zonder_aanmelding == {"/", "/koppelen", "/healthz", "/readyz"}
    assert flow_api == {
        f"{FLOW_API_PREFIX}/me",
        f"{FLOW_API_PREFIX}/deliveries/claim",
        f"{FLOW_API_PREFIX}/deliveries/{{delivery_id}}/ack",
        f"{FLOW_API_PREFIX}/deliveries/{{delivery_id}}/nack",
        f"{FLOW_API_PREFIX}/actions",
        f"{FLOW_API_PREFIX}/actions/{{request_id}}",
    }
    # en omgekeerd: buiten de flow-API accepteert geen enkele route een flow-token
    for route in _routes(_app().routes):
        if not route.path.startswith(FLOW_API_PREFIX + "/"):
            assert not _uses(route.dependant, flow_identity), route.path


def _api_errors() -> list[tuple[str, int, str, int]]:
    """Alle ``ApiError(status, code, …)`` met letterlijke status en code: (bestand, status, code, regel)."""
    out = []
    for pad in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(pad.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "ApiError"):
                continue
            args = node.args
            if len(args) >= 2 and isinstance(args[0], ast.Constant) and isinstance(args[1], ast.Constant):
                out.append((pad.name, int(args[0].value), str(args[1].value), node.lineno))
    return out


#: eigen codes die de catalogus toestaat: 403 vaste eigen codes, 400 zoals de referentie, 422 foute invoer binnen een
#: geldige aanmelding, 502/503 van bestaande Authentik-routes (P1; de catalogus geldt voor nieuwe routes, §5)
TOEGESTAAN: dict[int, set[str]] = {
    400: {"idempotency_key_required", "idempotency_key_invalid", "invalid_cursor", "invalid_type", "invalid_domain"},
    401: {"unauthorized"},
    403: {"forbidden", "scope_ontbreekt", "source_mismatch", "host_niet_toegestaan"},
    404: {"not_found"},
    412: {"precondition_failed"},
    413: {"payload_too_large"},
    428: {"precondition_required"},
    429: {"rate_limited"},
    501: {"capability_unavailable"},
}


def test_error_codes_follow_the_catalogue() -> None:
    fouten = []
    for bestand, status, code, regel in _api_errors():
        plek = f"{bestand}:{regel} {status} {code}"
        if status in TOEGESTAAN and code not in TOEGESTAAN[status]:
            fouten.append(plek)
        if status == 503 and not (code.endswith("_unavailable") or code == "authentik_onbereikbaar"):
            fouten.append(plek)
        if code in ("idempotency_key_reused",) and status != 422:
            fouten.append(plek)
    assert not fouten, "codes buiten de foutcatalogus (§5):\n" + "\n".join(fouten)
    codes = {code for _b, _s, code, _r in _api_errors()}
    assert "idempotency_key_conflict" not in codes and "noodtoegang_geweigerd" not in codes
