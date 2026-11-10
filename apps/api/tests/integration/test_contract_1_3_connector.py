"""Integratie (PostgreSQL, Hub-simulator): connector-health en versheid volgens contract 1.3 §6/§6.2 (C1.3-HCH-07).

- ``status`` = de slechtste check (``healthy`` < ``unknown`` < ``degraded`` < ``down``), met de ``reason_code`` van die
  check; vaste namen ``database``, ``worker`` (``observed_at`` = laatste hartslag), ``jobs`` (wachtrij, bezig,
  laatste job klaar) en ``hub_link``.
- Niet ingesteld (geen bron, leeg herstelregister) is geen check; een ingestelde bron zonder verse meting is ``unknown``
  met ``meting_verouderd``. ``discover`` noemt ``limits.max_age_s``.

Sim-getest."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from integrations.models import IntegrationSource, ServiceState
from integrations.timeutil import iso, utcnow
from integrations.worker import HEARTBEAT_KEY, Worker
from tests.conftest import idem

pytestmark = pytest.mark.integration


def _health(c: Any, h: Any) -> dict[str, Any]:
    r = c.get("/connector/v1/health", headers=h)
    assert r.status_code == 200
    return dict(r.json())


def _checks(health: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {x["name"]: x for x in health["checks"]}


def _hartslag(c: Any, *, at: Any, mislukt: list[str] | None = None) -> None:
    with c.app.state.db.sessions() as s:
        row = s.get(ServiceState, HEARTBEAT_KEY)
        value = {"at": iso(at), "mislukte_stappen": mislukt or [], "laatste_job_klaar": iso(at), "interval_s": 10}
        if row is None:
            s.add(ServiceState(key=HEARTBEAT_KEY, value=value))
        else:
            row.value = value
        s.commit()


def test_fixed_check_names_and_worst_check_wins(
    paired_client: Any, auth: Any, make_settings: Any, fake_hub: Any
) -> None:
    c, h = paired_client, auth("viewer")
    Worker(make_settings(), transport=fake_hub.transport).run_once()  # echte hartslag van een worker-ronde
    health = _health(c, h)
    checks = _checks(health)
    assert {"database", "worker", "jobs", "hub_link"} <= set(checks)
    assert all({"name", "status", "observed_at", "detail"} <= set(x) for x in health["checks"])
    assert all(x["observed_at"].endswith("Z") for x in health["checks"])
    assert checks["worker"]["status"] == "healthy" and checks["worker"]["detail"]["laatste_hartslag"]
    assert {"wachtrij", "bezig", "laatste_job_klaar"} <= set(checks["jobs"]["detail"])
    assert (health["status"], health["reason_code"]) == ("healthy", None)
    # een stille worker: degraded, en het totaal volgt de slechtste check
    _hartslag(c, at=utcnow() - timedelta(minutes=10))
    health = _health(c, h)
    assert (_checks(health)["worker"]["status"], health["status"], health["reason_code"]) == (
        "degraded",
        "degraded",
        "worker_stil",
    )
    # een mislukte stap is ook geen 'healthy'
    _hartslag(c, at=utcnow(), mislukt=["push"])
    assert _checks(_health(c, h))["worker"]["reason_code"] == "workerstap_mislukt"


def test_unknown_never_green_and_not_configured_is_no_check(paired_client: Any, auth: Any) -> None:
    c, h = paired_client, auth("viewer")
    _hartslag(c, at=utcnow())
    checks = _checks(_health(c, h))
    assert "bronnen" not in checks and "herstelregister" not in checks  # niets ingesteld → geen meting
    # een ingestelde bron zonder verse meting telt als unknown (meting_verouderd) en maakt het totaal unknown
    with c.app.state.db.sessions() as s:
        s.add(
            IntegrationSource(
                source_id="node_red",
                domain="automation",
                base_url="http://bron-node-red.test:1880",
                enabled=True,
                last_probe_at=utcnow() - timedelta(minutes=16),
                last_probe_status="healthy",
                updated_by="test",
            )
        )
        s.commit()
    health = _health(c, h)
    bronnen = _checks(health)["bronnen"]
    assert (bronnen["status"], bronnen["reason_code"]) == ("unknown", "meting_verouderd")
    assert health["status"] == "unknown" and health["reason_code"] == "meting_verouderd"
    # vers en gezond → healthy; vers en down → down (slechtste)
    with c.app.state.db.sessions() as s:
        row = s.get(IntegrationSource, "node_red")
        row.last_probe_at = utcnow()  # type: ignore[union-attr]
        s.commit()
    assert _health(c, h)["status"] == "healthy"
    with c.app.state.db.sessions() as s:
        row = s.get(IntegrationSource, "node_red")
        row.last_probe_status = "down"  # type: ignore[union-attr]
        s.commit()
    health = _health(c, h)
    assert (health["status"], health["reason_code"]) == ("down", "bron_down")


def test_recovery_register_counts_once_it_has_accounts(paired_client: Any, auth: Any) -> None:
    c = paired_client
    _hartslag(c, at=utcnow())
    r = c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "authentik", "username": "akadmin", "login_kind": "sso"},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 201
    health = _health(c, auth("viewer"))
    assert _checks(health)["herstelregister"]["status"] == "degraded" and health["status"] == "degraded"


def test_link_problems_in_hub_link(paired_client: Any, auth: Any, fake_hub: Any) -> None:
    c = paired_client
    _hartslag(c, at=utcnow())
    link = c.app.state.hublink

    def onbevestigd(st: Any) -> Any:
        st.confirmed_at = None
        return st

    c.app.state.hublink_store.update(onbevestigd)
    health = _health(c, auth("viewer"))
    assert (_checks(health)["hub_link"]["status"], health["reason_code"]) == ("degraded", "niet_bevestigd")
    assert link.state().linked


def test_discover_names_max_age(paired_client: Any, auth: Any) -> None:
    d = paired_client.get("/connector/v1/discover", headers=auth("viewer")).json()
    assert d["limits"]["max_age_s"] == {"source": 900, "health": 900}


def test_worker_writes_a_heartbeat_each_round(make_settings: Any, fake_hub: Any, clean_db: str) -> None:
    w = Worker(make_settings(), transport=fake_hub.transport)
    w.run_once()
    with w.db.sessions() as s:
        beat = s.get(ServiceState, HEARTBEAT_KEY)
        assert beat is not None and beat.value["at"].endswith("Z") and beat.value["mislukte_stappen"] == []
        eerste = beat.value["at"]
    w.run_once()
    with w.db.sessions() as s:
        assert s.get(ServiceState, HEARTBEAT_KEY).value["at"] >= eerste  # type: ignore[union-attr]
