"""Integratie (PostgreSQL, nep-Authentik, Hub-simulator): events volgens contract 1.3 §7 (C1.3-HCH-06, C1.3-HCH-08).

- ``sso.access.revoked``/``changed`` dragen ``issuer``, ``sub`` (de OIDC-``sub`` die de Hub-client krijgt, volgens de
  ``sub_mode`` van zijn provider) en ``preferred_username``; niet te bepalen → ``null`` + ``sub_onbekend`` (de Hub valt
  terug op de gebruikersnaam). Een verwijderde gebruiker houdt zijn ``sub`` uit de vorige momentopname.
- Probleem en herstel met hetzelfde onderwerp: ``sso.authentik_sync.failed`` → ``sso.authentik_sync.recovered``.
- ``payload.ernst`` met de vijf Peil-woorden; alle events passen in de envelope-regels van de Hub-inbox (eigen domein,
  vaste ``service.*``-lijst).

Sim-getest; NIET GEVALIDEERD tegen een echte Authentik (de ``sub``-afleiding komt uit de broncode van Authentik)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import text

from integrations import events
from tests.conftest import AUTHENTIK_URL, envelope_problems, idem
from tests.fakes.authentik_fake import DEFAULT_TOKEN, AuthentikFake

pytestmark = pytest.mark.integration

BASE = "/integrations/v1/sso"


def _klaar(c: Any, h: Any) -> None:
    r = c.put(
        "/integrations/v1/sources/authentik",
        json={"base_url": AUTHENTIK_URL, "enabled": True, "credential": DEFAULT_TOKEN},
        headers=idem(h),
    )
    assert r.status_code in (200, 201), r.text
    for group, role in (("hub-beheerders", "admin"), ("hub-operators", "operator"), ("hub-lezers", "viewer")):
        r = c.post(
            f"{BASE}/role-mappings",
            json={"app_id": "ai-server-manager", "authentik_group": group, "role": role},
            headers=idem(h),
        )
        assert r.status_code == 201


def _sync(c: Any, h: Any) -> dict[str, Any]:
    r = c.post(f"{BASE}/authentik/sync", headers=idem(h))
    assert r.status_code == 200, r.text
    return dict(r.json())


def _events(c: Any, soort: str | None = None) -> list[dict[str, Any]]:
    with c.app.state.db.sessions() as s:
        rijen = s.execute(text("SELECT seq FROM outbox_event ORDER BY seq")).all()
        from integrations.models import OutboxEvent

        out = [events.envelope(s.get(OutboxEvent, r[0])) for r in rijen]  # type: ignore[arg-type]
    return [e for e in out if soort is None or e["event_type"] == soort]


@pytest.mark.parametrize(
    ("sub_mode", "verwacht"),
    [
        ("hashed_user_id", lambda ak: ak.uid(ak.users["carla"]["pk"])),
        ("user_id", lambda ak: str(ak.users["carla"]["pk"])),
        ("user_uuid", lambda ak: ak.users["carla"]["uuid"]),
        ("user_username", lambda _ak: "carla"),
    ],
)
def test_access_events_carry_issuer_and_oidc_sub(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, sub_mode: str, verwacht: Any
) -> None:
    c, h = paired_client, auth("admin")
    authentik_fake.add_hub_app()
    authentik_fake.providers[-1]["sub_mode"] = sub_mode
    _klaar(c, h)
    assert _sync(c, h)["rights"]["status"] == "basislijn"
    authentik_fake.set_members("hub-lezers", ["kim"])  # carla verliest viewer in de Hub
    authentik_fake.set_members("hub-operators", ["bram", "carla"])  # … en krijgt operator
    _sync(c, h)
    revoked = _events(c, "sso.access.revoked")
    changed = _events(c, "sso.access.changed")
    assert len(revoked) == 1 and len(changed) == 1
    for ev in (revoked[0], changed[0]):
        p = ev["payload"]
        assert p["issuer"] == f"{authentik_fake.base}/application/o/hub/"  # uit de discovery van de Hub-client
        assert p["sub"] == verwacht(authentik_fake) and p["preferred_username"] == "carla"
        assert "sub_onbekend" not in p and ev["entity"] == {"type": "authentik_user", "id": "carla"}
        assert ev["classification"] == "sensitive" and envelope_problems(ev) == []


@pytest.mark.parametrize("sub_mode", ["user_email", "user_upn", "iets_nieuws"])
def test_unsupported_sub_mode_gives_null_and_reason(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake, sub_mode: str
) -> None:
    c, h = paired_client, auth("admin")
    authentik_fake.add_hub_app()
    authentik_fake.providers[-1]["sub_mode"] = sub_mode
    _klaar(c, h)
    _sync(c, h)
    authentik_fake.set_members("hub-lezers", ["kim"])
    _sync(c, h)
    p = _events(c, "sso.access.revoked")[0]["payload"]
    assert (p["issuer"], p["sub"], p["preferred_username"]) == (None, None, "carla")
    assert p["sub_onbekend"] == "sub_mode_niet_ondersteund"  # nooit gegokt (geen e-mail opgeslagen)


def test_deleted_user_keeps_the_sub_from_the_previous_snapshot(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake
) -> None:
    c, h = paired_client, auth("admin")
    authentik_fake.add_hub_app()
    _klaar(c, h)
    _sync(c, h)
    uid = authentik_fake.uid(authentik_fake.users["carla"]["pk"])
    del authentik_fake.users["carla"]
    for g in authentik_fake.groups.values():
        g["members"] = [m for m in g["members"] if m != "carla"]
    _sync(c, h)
    p = _events(c, "sso.access.revoked")[0]["payload"]
    assert p["change"] == "verwijderd" and p["sub"] == uid and p["preferred_username"] == "carla"


def test_sync_failure_and_recovery_share_the_subject(
    paired_client: Any, auth: Any, authentik_fake: AuthentikFake
) -> None:
    c, h = paired_client, auth("admin")
    _klaar(c, h)
    _sync(c, h)
    authentik_fake.up = False
    assert _sync(c, h)["status"] == "fout"
    _sync(c, h)  # nog steeds fout: geen tweede probleem-event
    authentik_fake.up = True
    assert _sync(c, h)["status"] == "ok"
    failed = _events(c, "sso.authentik_sync.failed")
    recovered = _events(c, "sso.authentik_sync.recovered")
    assert len(failed) == 1 and len(recovered) == 1
    assert failed[0]["entity"] == recovered[0]["entity"] == {"type": "integration_source", "id": "authentik"}
    assert events.event_role(failed[0]["event_type"]) == "probleem"
    assert events.event_role(recovered[0]["event_type"]) == "herstel"
    assert failed[0]["payload"]["ernst"] == "middel" and recovered[0]["payload"]["ernst"] == "info"


def test_all_emitted_events_fit_the_inbox_rules(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    """Na een volledige ronde (koppelen, bron, rechten, afwijkingen): elk event past in de regels van de Hub-inbox
    (1.3 §7: eigen domein, vaste service.*-lijst met entity = deze dienst, ernst uit de vijf woorden)."""
    c, h = paired_client, auth("admin")
    authentik_fake.add_hub_app()
    _klaar(c, h)
    _sync(c, h)
    for i in range(5):
        authentik_fake.add_event("login_failed", "bram", minutes_ago=5 - i)
    authentik_fake.set_members("hub-beheerders", ["anna", "kim"])
    _sync(c, h)
    alle = _events(c)
    assert {e["event_type"].split(".", 1)[0] for e in alle} <= {"sso", "network", "automation", "energy", "service"}
    assert [e for e in alle if envelope_problems(e)] == []
    afwijkingen = [e for e in alle if e["event_type"] == "sso.anomaly.detected"]
    assert afwijkingen and all(e["payload"]["ernst"] in events.ERNST for e in afwijkingen)
    assert all(e["payload"]["ernst"] == e["payload"]["severity"] for e in afwijkingen)  # overgangsrelease
    linked = [e for e in alle if e["event_type"] == "service.hub_link.linked"]
    assert linked and linked[0]["entity"] == {"type": "service", "id": "home-control-hub"}
    assert linked[0]["payload"]["via"] == "koppelcode"


def test_emit_refuses_events_outside_the_contract(paired_client: Any) -> None:
    tid = str(uuid.uuid4())
    with paired_client.app.state.db.sessions() as s:
        for et, entity_type, entity_id, payload in (
            ("media.item.failed", "x", "1", None),  # domein van een andere eigenaar
            ("service.iets.anders", "service", "home-control-hub", None),  # buiten de vaste service.*-lijst
            ("service.hub_link.linked", "hub_link", "hub", None),  # service-event over iets anders dan de dienst
            ("app.backup.failed", "app", "x", None),  # app alleen voor app.health.changed
            ("sso.twee_segmenten", "x", "1", None),
            ("sso.anomaly.detected", "sso_anomaly", "1", {"ernst": "ernstig"}),  # geen Peil-woord
        ):
            with pytest.raises(ValueError):
                events.emit(
                    s,
                    event_type=et,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    actor_type="system",
                    actor_id="test",
                    trace_id=tid,
                    payload=payload,
                )
        s.rollback()


def test_partial_read_is_not_yet_a_recovery(paired_client: Any, auth: Any, authentik_fake: AuthentikFake) -> None:
    """fout → onvolledig → ok: één probleem-event en pas bij 'ok' het herstel (half gelezen is nog geen herstel)."""
    c, h = paired_client, auth("admin")
    _klaar(c, h)
    _sync(c, h)
    authentik_fake.up = False
    assert _sync(c, h)["status"] == "fout"
    authentik_fake.up = True
    authentik_fake.forbidden.add("/api/v3/core/users/")
    assert _sync(c, h)["status"] == "onvolledig"
    assert _events(c, "sso.authentik_sync.recovered") == []
    authentik_fake.up = False
    assert _sync(c, h)["status"] == "fout"  # dezelfde storing loopt nog: geen tweede probleem-event
    authentik_fake.up = True
    authentik_fake.forbidden.discard("/api/v3/core/users/")
    assert _sync(c, h)["status"] == "ok"
    assert len(_events(c, "sso.authentik_sync.failed")) == 1
    assert len(_events(c, "sso.authentik_sync.recovered")) == 1
