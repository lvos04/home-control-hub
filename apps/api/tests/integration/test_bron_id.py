"""Bron-ID van uitgaande events (contract 1.3 §7; contractmelding van S-P2-140 in ai-server-manager).

De Hub dedupliceert op ``event_id`` én op (``source_app``, ``source_event_id``) en weigert dezelfde sleutel met andere
inhoud met ``409 bron_id_conflict``. Het outboxvolgnummer als bron-ID begint na het terugzetten van een back-up opnieuw;
daarom is de bron-ID de ``event_id``. Een 409 maakt het event zichtbaar ``dead_letter``, nooit stil "afgeleverd".
Sim-getest (de nep-Hub volgt hierin de echte inbox)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import text

from integrations import events
from integrations.models import OutboxEvent

pytestmark = pytest.mark.integration


def _emit(c: Any) -> uuid.UUID:
    with c.app.state.db.sessions() as s:
        ev = events.emit(
            s,
            event_type="automation.restore.proposed",
            entity_type="automation_restore",
            entity_id=str(uuid.uuid4()),
            actor_type="system",
            actor_id="test",
            trace_id=str(uuid.uuid4()),
            payload={"ernst": "info"},
        )
        s.commit()
        return ev.event_id


def _row(c: Any, event_id: uuid.UUID) -> OutboxEvent:
    with c.app.state.db.sessions() as s:
        row = s.query(OutboxEvent).filter_by(event_id=event_id).one()
        s.expunge(row)
        return row


def test_bron_id_blijft_uniek_als_het_volgnummer_na_herstel_opnieuw_begint(linked: Any) -> None:
    first = _row(linked, _emit(linked))
    with linked.app.state.db.sessions() as s:  # zoals een teruggezette back-up van vóór dit event
        s.execute(text("DELETE FROM outbox_event"))
        s.execute(text(f"ALTER TABLE outbox_event ALTER COLUMN seq RESTART WITH {int(first.seq)}"))
        s.commit()
    second = _row(linked, _emit(linked))
    assert second.seq == first.seq  # het volgnummer is hergebruikt …
    a, b = events.envelope(first), events.envelope(second)
    assert a["source_event_id"] == str(first.event_id) and b["source_event_id"] == str(second.event_id)
    assert a["source_event_id"] != b["source_event_id"]  # … de bron-ID niet


def test_409_van_de_hub_is_zichtbaar_dead_letter(linked: Any, fake_hub: Any, make_settings: Any) -> None:
    from integrations.worker import Worker

    worker = Worker(make_settings(), transport=fake_hub.transport)
    worker.push_step()  # eerst de events van het koppelen
    event_id = _emit(linked)
    sent = events.envelope(_row(linked, event_id))
    # de Hub kent deze bron-ID al met andere inhoud (bv. een ander event van vóór een herstel)
    fake_hub.inbox.append({**sent, "event_id": str(uuid.uuid4()), "payload": {"ernst": "hoog"}})
    worker.push_step()
    row = _row(linked, event_id)
    assert (row.delivery_status, row.last_error, row.delivered_at) == ("dead_letter", "bron_id_conflict", None)


def test_herlevering_van_hetzelfde_event_is_afgeleverd(linked: Any, fake_hub: Any, make_settings: Any) -> None:
    from integrations.worker import Worker

    worker = Worker(make_settings(), transport=fake_hub.transport)
    event_id = _emit(linked)
    fake_hub.inbox.append(events.envelope(_row(linked, event_id)))  # al ontvangen, antwoord verloren
    worker.push_step()
    row = _row(linked, event_id)
    assert (row.delivery_status, row.last_error) == ("delivered", None)
    assert sum(e["event_id"] == str(event_id) for e in fake_hub.inbox) == 1
