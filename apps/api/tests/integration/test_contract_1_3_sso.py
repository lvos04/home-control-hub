"""Integratie (PostgreSQL): groep → rol is in deze dienst alleen advies (contract 1.3 §4.1, C1.3-HCH-11).

De koppeling groep → rol stelt een beheerder in de Hub in (eigen tabel, audit); home-control-hub toont zijn koppelingen
alleen als advies en zegt dat bij elke koppeling (API en connector-items). Sim-getest."""

from __future__ import annotations

from typing import Any

import pytest

from integrations.domains.sso.mapping import ADVIES_NL
from tests.conftest import idem

pytestmark = pytest.mark.integration


def test_group_role_mappings_are_marked_as_advice(paired_client: Any, auth: Any, fake_hub: Any) -> None:
    c, h = paired_client, auth("admin")
    r = c.post(
        "/integrations/v1/sso/role-mappings",
        json={"app_id": "ai-server-manager", "authentik_group": "hub-beheerders", "role": "admin"},
        headers=idem(h),
    )
    assert r.status_code == 201
    assert r.json()["advies"] is True and r.json()["advies_nl"] == ADVIES_NL and "Hub" in ADVIES_NL
    lijst = c.get("/integrations/v1/sso/role-mappings", headers=h).json()["items"]
    assert lijst and all(m["advies"] is True for m in lijst)
    items = c.get("/connector/v1/items", params={"type": "sso.role_mapping"}, headers=fake_hub.service_auth()).json()[
        "items"
    ]
    assert items and all(m["advies"] is True for m in items)
