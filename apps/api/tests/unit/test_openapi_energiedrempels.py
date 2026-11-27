"""B14-005. De gepubliceerde beschrijving van de drempelroute volgt het HTTP-contract."""

import json

from integrations.cli import export_openapi


def test_beschrijving_energiedrempels():
    spec = json.loads(export_openapi())
    put = spec["paths"]["/integrations/v1/energy/alert-thresholds"]["put"]
    (key,) = [p for p in put["parameters"] if p["in"] == "header" and p["name"] == "Idempotency-Key"]
    assert key["required"] and key["schema"]["type"] == "string" and key["schema"]["format"] == "uuid"
    (scheme,) = put["security"]
    (name,) = scheme
    assert not scheme[name]
    bearer = spec["components"]["securitySchemes"][name]
    assert (bearer["type"], bearer["scheme"], bearer["bearerFormat"]) == ("http", "bearer", "JWT")
    assert put["x-required-roles"] == ["admin"]
    assert "ETag" in put["responses"]["200"]["headers"]
    for status in ("400", "401", "403", "412", "413", "422", "428", "503"):
        response = put["responses"][status]
        shape = response["content"]["application/json"]["schema"]["$ref"].split("/")[-1]
        assert set(spec["components"]["schemas"][shape]["required"]) == {"code", "message", "details", "trace_id"}
