"""B11 — de randen van het platform: worker (uitlezen, opruimen), connector-health, instellingen en de kluis.

Sim-getest met de nep-Node-RED; een echte Node-RED op de NAS: NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import func, select, update

from integrations.config import Settings, _modules
from integrations.domains.automation import inbox
from integrations.domains.automation.models import AutomationDelivery, AutomationEvent
from integrations.security.vault import Vault
from integrations.timeutil import utcnow
from integrations.worker import Worker
from tests import b11
from tests.b11 import A
from tests.conftest import idem, setup_node_red
from tests.fakes.node_red_fake import exec_flow, simple_flow

TAB = "tab0000000000001"


def checks(linked: Any, fake_hub: Any) -> dict[str, dict[str, Any]]:
    r = linked.get("/connector/v1/health", headers=fake_hub.service_auth())
    assert r.status_code == 200, r.text
    return {c["name"]: c for c in r.json()["checks"]}


# ------------------------------------------------------------------------------------------------- connector-health
def test_health_has_no_automation_check_until_node_red_is_configured(linked: Any, fake_hub: Any) -> None:
    assert "automatisering" not in checks(linked, fake_hub), "niet ingesteld is geen meting"


def test_health_follows_isolation_sync_and_blocked_flows(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, make_settings: Any
) -> None:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    # ingesteld maar nog niet gemeten: onbekend, nooit groen
    check = checks(linked, fake_hub)["automatisering"]
    assert check["status"] == "unknown" and check["detail"]["isolatie"] == "onbekend"
    # de worker leest uit en meet de isolatie
    worker = Worker(make_settings(node_red_sync_interval_s=60), transport=fake_hub.transport)
    worker.automation_step(100.0)
    assert worker.state.stats["node_red_syncs"] == 1 and worker.state.stats["node_red_sync_failed"] == 0
    check = checks(linked, fake_hub)["automatisering"]
    assert check["status"] == "healthy", check
    assert check["detail"]["isolatie"] == "gemeten_in_orde" and check["detail"]["synchronisatie_ok"] is True
    assert check["detail"]["flows"].get("geblokkeerd", 0) == 0 and check["reason_code"] is None
    # Node-RED valt weg: de synchronisatie mislukt en dat is zichtbaar
    node_red_fake.up = False
    worker.automation_step(200.0)
    assert worker.state.stats["node_red_sync_failed"] == 1
    check = checks(linked, fake_hub)["automatisering"]
    assert check["status"] == "degraded" and check["reason_code"] == "synchronisatie_mislukt"
    # terug, maar nu met een verboden node in een flow
    node_red_fake.up = True
    node_red_fake.deploy([*simple_flow(), *exec_flow()])
    worker.automation_step(300.0)
    check = checks(linked, fake_hub)["automatisering"]
    assert check["status"] == "degraded" and check["reason_code"] == "flow_geblokkeerd"
    assert check["detail"]["flows"]["geblokkeerd"] == 1
    assert node_red_fake.writes == [], "de worker schrijft nooit naar Node-RED"


def test_health_reports_an_isolation_deviation(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    setup_node_red(linked, fake_hub, auth, harden=False, flows=simple_flow())
    assert linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()["status"] == "afwijking"
    check = checks(linked, fake_hub)["automatisering"]
    assert check["status"] == "degraded" and check["reason_code"] == "isolatie_afwijking"
    assert check["detail"]["afwijkingen"]


def test_old_isolation_measurement_is_unknown_never_healthy(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """R-TECH-1 (ADR-0016 kop 2 en 8): een isolatiemeting ouder dan 15 minuten telt niet meer, ook als hij in orde
    was en de worker niet meer meet; de stand is dan onbekend, nooit gezond."""
    from integrations.domains.automation import snapshots as flow_snapshots
    from integrations.models import ServiceState
    from integrations.timeutil import iso

    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    assert linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()["status"] == "gemeten_in_orde"
    assert checks(linked, fake_hub)["automatisering"]["status"] == "healthy"

    def measured(ago: timedelta) -> None:
        with linked.app.state.db.sessions() as s:
            row = s.get(ServiceState, flow_snapshots.ISOLATION_KEY)
            assert row is not None
            row.value = {**row.value, "measured_at": iso(utcnow() - ago)}
            s.commit()

    measured(flow_snapshots.ISOLATION_MAX_AGE - timedelta(minutes=1))
    assert checks(linked, fake_hub)["automatisering"]["status"] == "healthy", "binnen 15 minuten: nog vers"
    measured(flow_snapshots.ISOLATION_MAX_AGE + timedelta(minutes=1))
    got = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["isolatie"]
    assert got["status"] == "onbekend" and got["reden"] == "meting_verouderd", got
    check = checks(linked, fake_hub)["automatisering"]
    assert check["status"] == "unknown" and check["reason_code"] == "meting_verouderd", check
    assert check["detail"]["isolatie"] == "onbekend"


def test_unreachable_node_red_does_not_clear_a_measured_deviation(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any
) -> None:
    """R-TECH-6: een eerder gemeten afwijking wordt niet 'onbekend' omdat Node-RED even niet antwoordt."""
    setup_node_red(linked, fake_hub, auth, harden=False, flows=simple_flow())
    assert linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()["status"] == "afwijking"
    node_red_fake.up = False
    report = linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()
    assert report["status"] == "afwijking" and report["verouderd"] is True, report
    assert report["afwijkingen"], "de eerder gemeten afwijkingen blijven zichtbaar"
    got = linked.get(f"{A}/isolation", headers=auth("viewer")).json()["isolatie"]
    assert got["status"] == "afwijking" and got["verouderd"] is True
    check = checks(linked, fake_hub)["automatisering"]
    assert check["status"] == "degraded" and check["reason_code"] == "isolatie_afwijking"


def test_failed_sync_is_measured_as_down_or_degraded_never_healthy(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-TECH-2 (B11: "een externe storing mag niet als succes worden gelogd"): elke synchronisatie is ook de
    meting van de bron node_red; een mislukte synchronisatie geeft 'down' (onbereikbaar of 5xx) of 'degraded'."""
    import httpx

    def source_health() -> dict[str, Any]:
        r = linked.get("/integrations/v1/sources/node_red", headers=auth("viewer"))
        assert r.status_code == 200, r.text
        health: dict[str, Any] = r.json()["runtime"]["health"]
        return health

    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    assert (source_health()["status"], source_health()["reason_code"]) == ("healthy", "synchronisatie_ok")

    node_red_fake.up = False  # ConnectError
    r = linked.post(f"{A}/snapshots", headers=idem(auth("admin")))
    assert r.status_code == 503 and r.json()["code"] == "node_red_unavailable", r.text
    assert (source_health()["status"], source_health()["reason_code"]) == ("down", "onbereikbaar")

    node_red_fake.up = True
    original = node_red_fake.handle

    def answer(status: int, body: bytes) -> Any:
        def handle(request: httpx.Request) -> httpx.Response:
            if request.method == "GET" and request.url.path == "/flows":
                return httpx.Response(status, content=body, headers={"content-type": "application/json"})
            return original(request)

        return handle

    monkeypatch.setattr(node_red_fake, "handle", answer(500, b'{"fout": "intern"}'))
    r = linked.post(f"{A}/snapshots", headers=idem(auth("admin")))
    assert r.status_code == 503, r.text
    assert (source_health()["status"], source_health()["reason_code"]) == ("down", "http_5xx")

    monkeypatch.setattr(node_red_fake, "handle", answer(200, b"geen json"))
    r = linked.post(f"{A}/snapshots", headers=idem(auth("admin")))
    assert r.status_code == 502 and r.json()["code"] == "node_red_fout", r.text
    assert (source_health()["status"], source_health()["reason_code"]) == ("degraded", "antwoord_ongeldig")

    monkeypatch.setattr(node_red_fake, "handle", original)
    b11.snapshot(linked, auth)
    assert source_health()["status"] == "healthy"


def test_health_reports_a_dead_letter(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    assert linked.post(f"{A}/isolation/check", headers=idem(auth("admin"))).json()["status"] == "gemeten_in_orde"
    _, token = b11.ready_flow(linked, auth, TAB, "notification.send", triggers=("energy.reading.recorded",))
    assert b11.post_event(linked, fake_hub, b11.envelope()).json()["afleveringen"] == 1
    assert checks(linked, fake_hub)["automatisering"]["status"] == "healthy"
    with linked.app.state.db.sessions() as s:
        s.execute(update(AutomationDelivery).values(attempts=inbox.MAX_ATTEMPTS - 1))
        s.commit()
    item = b11.claim(linked, token)["items"][0]
    assert b11.nack(linked, token, item["id"], "kapot").status_code == 200
    check = checks(linked, fake_hub)["automatisering"]
    assert (
        check["status"] == "degraded" and check["reason_code"] == "dead_letter" and check["detail"]["dead_letter"] == 1
    )


# ------------------------------------------------------------------------------------------------------------ worker
def test_worker_does_nothing_with_node_red_when_sync_is_off_or_not_configured(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, make_settings: Any
) -> None:
    worker = Worker(make_settings(node_red_sync_interval_s=60), transport=fake_hub.transport)
    worker.automation_step(100.0)
    assert node_red_fake.requests == [], "niet ingesteld: Node-RED wordt niet benaderd"
    assert worker.state.stats["node_red_syncs"] == 0 and worker.state.stats["node_red_sync_failed"] == 0
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    seen = len(node_red_fake.requests)
    off = Worker(make_settings(node_red_sync_interval_s=0), transport=fake_hub.transport)
    off.automation_step(100.0)
    assert len(node_red_fake.requests) == seen, "interval 0: uit"
    assert off.state.stats["node_red_syncs"] == 0


def test_worker_offers_own_events_to_flows(
    linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any, make_settings: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Events van deze dienst zelf (bv. een gemeten afwijking) bereiken een flow via dezelfde wachtrij."""
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    _, token = b11.ready_flow(linked, auth, TAB, "notification.send", triggers=("automation.isolation.degraded",))
    worker = Worker(make_settings(node_red_sync_interval_s=0), transport=fake_hub.transport)
    worker.automation_step(0.0)  # eerste ronde: beginpunt vastleggen, geen geschiedenis naspelen
    assert worker.state.stats["flow_events"] == 0
    node_red_fake.admin_auth = None  # de beveiliging van de editor valt weg
    node_red_fake.tokens.clear()
    linked.post(f"{A}/isolation/check", headers=idem(auth("admin")))
    own = b11.outbox(linked, "automation.isolation.degraded")
    assert len(own) == 1
    worker.automation_step(0.0)
    assert worker.state.stats["flow_events"] == 0, "een event van zojuist wacht nog even (volgorde van transacties)"
    later = utcnow() + inbox.OUTBOX_LAG + timedelta(seconds=1)
    monkeypatch.setattr("integrations.worker.utcnow", lambda: later)
    worker.automation_step(0.0)
    assert worker.state.stats["flow_events"] == 1
    worker.automation_step(0.0)  # een tweede ronde biedt hetzelfde event niet nog eens aan
    # de aflevering is opeisbaar vanaf het (verschoven) moment van aanbieden
    monkeypatch.setattr("integrations.domains.automation.flowapi.utcnow", lambda: later)
    items = b11.claim(linked, token)["items"]
    assert [i["event"]["event_id"] for i in items] == [own[0]["event_id"]]
    assert b11.claim(linked, token)["items"] == []


def test_purge_removes_only_old_finished_deliveries(linked: Any, fake_hub: Any, auth: Any, node_red_fake: Any) -> None:
    setup_node_red(linked, fake_hub, auth, flows=simple_flow())
    b11.snapshot(linked, auth)
    _, token = b11.ready_flow(linked, auth, TAB, "notification.send", triggers=("energy.reading.recorded",))
    for _ in range(3):
        assert b11.post_event(linked, fake_hub, b11.envelope()).json()["afleveringen"] == 1
    first = b11.claim(linked, token, limit=1)["items"][0]
    assert b11.ack(linked, token, first["id"]).status_code == 200
    old = utcnow() - inbox.RETENTION - timedelta(days=1)
    with linked.app.state.db.sessions() as s:
        # alles is "oud"; alleen de afgehandelde aflevering (en haar event) mag weg
        s.execute(update(AutomationEvent).values(received_at=old))
        s.execute(update(AutomationDelivery).where(AutomationDelivery.status == "verwerkt").values(finished_at=old))
        s.commit()
        result = inbox.purge(s, utcnow())
        s.commit()
        assert result["afleveringen"] == 1 and result["events"] == 1
        assert s.scalar(select(func.count()).select_from(AutomationDelivery)) == 2
        assert s.scalar(select(func.count()).select_from(AutomationEvent)) == 2
    assert len(b11.claim(linked, token)["items"]) == 1, "wat nog wacht blijft bestaan"


# ------------------------------------------------------------------------------------------------ instellingen en kluis
def test_allowed_modules_setting() -> None:
    assert _modules(None) == ("node-red",)
    assert _modules(" node-red-contrib-x , @scope/pakket,node-red,, node-red-contrib-x") == (
        "node-red",
        "node-red-contrib-x",
        "@scope/pakket",
    )
    for bad in ("../../etc", "Met Hoofdletter", "a b", "@scope/", "x" * 200):
        with pytest.raises(ValueError, match="HCH_NODE_RED_ALLOWED_MODULES"):
            _modules(bad)


def test_node_red_settings_from_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HCH_DATABASE_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/hch_bestaat_niet")
    for name in ("HCH_NODE_RED_SYNC_INTERVAL_S", "HCH_NODE_RED_DATA_DIR", "HCH_NODE_RED_ALLOWED_MODULES"):
        monkeypatch.delenv(name, raising=False)
    defaults = Settings.from_env()
    assert defaults.node_red_sync_interval_s == 60 and defaults.node_red_data_dir is None
    assert defaults.node_red_allowed_modules == ("node-red",)
    monkeypatch.setenv("HCH_NODE_RED_SYNC_INTERVAL_S", "0")
    monkeypatch.setenv("HCH_NODE_RED_DATA_DIR", str(tmp_path / "node-red"))
    monkeypatch.setenv("HCH_NODE_RED_ALLOWED_MODULES", "node-red-contrib-x")
    custom = Settings.from_env()
    assert custom.node_red_sync_interval_s == 0 and custom.node_red_data_dir == tmp_path / "node-red"
    assert custom.node_red_allowed_modules == ("node-red", "node-red-contrib-x")


def test_vault_seal_is_bound_to_its_context() -> None:
    vault = Vault(bytes(range(32)))
    aad = f"automation-snapshot:{uuid.uuid4()}".encode()
    nonce, ciphertext = vault.seal(aad, b"flows en credentials")
    assert b"flows" not in ciphertext and len(nonce) == 12
    assert vault.unseal(aad, nonce, ciphertext) == b"flows en credentials"
    assert vault.seal(aad, b"flows en credentials") != (nonce, ciphertext), "elke keer een nieuwe nonce"
    with pytest.raises(InvalidTag):
        vault.unseal(b"automation-snapshot:een-ander", nonce, ciphertext)
    with pytest.raises(InvalidTag):
        vault.unseal(aad, nonce, ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
    with pytest.raises(InvalidTag):
        Vault(bytes(32)).unseal(aad, nonce, ciphertext)
