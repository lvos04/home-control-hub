"""B11-004 — vaste voorbeeld-events voor proefruns en tests.

De voorbeelden zijn **onveranderlijk**: de checksum hieronder hoort bij precies deze inhoud en wordt bij elk gebruik
en in CI gecontroleerd. Wie een voorbeeld wil aanpassen voegt een nieuw voorbeeld toe (nieuw ``id``) en werkt de
checksum bewust bij. Alle waarden zijn verzonnen en als voorbeeld gemarkeerd; er staat niets van een echte NAS in.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

_TS = "2026-01-01T12:00:00Z"
_ACTOR = {"type": "system", "id": "voorbeeld"}


def _sample(
    sample_id: str,
    title_nl: str,
    source_app: str,
    event_type: str,
    entity_type: str,
    entity_id: str,
    payload: dict[str, Any],
    nr: int,
) -> dict[str, Any]:
    return {
        "id": sample_id,
        "title_nl": title_nl,
        "envelope": {
            "schema_version": "1.0",
            "event_id": f"00000000-0000-4000-8000-{nr:012d}",
            "source_app": source_app,
            "source_event_id": f"voorbeeld:{sample_id}",
            "event_type": event_type,
            "entity": {"type": entity_type, "id": entity_id},
            "timestamp_utc": _TS,
            "trace_id": f"00000000-0000-4000-9000-{nr:012d}",
            "correlation_id": None,
            "actor": dict(_ACTOR),
            "classification": "internal",
            "payload": {**payload, "voorbeeld": True},
            "payload_ref": None,
        },
    }


SAMPLES: tuple[dict[str, Any], ...] = (
    _sample(
        "energie-meting",
        "Energiemeting vastgelegd",
        "home-control-hub",
        "energy.reading.recorded",
        "meter",
        "voorbeeld-meter-1",
        {"vermogen_w": 420, "eenheid": "W"},
        1,
    ),
    _sample(
        "netwerk-nieuw-apparaat",
        "Nieuw apparaat op het netwerk",
        "home-control-hub",
        "network.device.discovered",
        "device",
        "voorbeeld-apparaat-1",
        {"soort": "onbekend"},
        2,
    ),
    _sample(
        "backup-mislukt",
        "Back-up mislukt",
        "ai-server-manager",
        "backup.run.failed",
        "backup_run",
        "voorbeeld-run-1",
        {"ernst": "hoog", "stap": "controle"},
        3,
    ),
    _sample(
        "app-gezondheid",
        "Gezondheid van een app is gewijzigd",
        "mediaguard",
        "app.health.changed",
        "app",
        "mediaguard",
        {"status": "degraded", "vorige_status": "healthy"},
        4,
    ),
    _sample(
        "download-mislukt",
        "Download mislukt",
        "mediaguard",
        "media.download.failed",
        "download",
        "voorbeeld-download-1",
        {"ernst": "middel", "reden": "bron_onbereikbaar"},
        5,
    ),
    _sample(
        "toegang-ingetrokken",
        "Toegang ingetrokken (Authentik)",
        "home-control-hub",
        "sso.access.revoked",
        "authentik_user",
        "voorbeeld-gebruiker",
        {
            "issuer": "https://voorbeeld.invalid/application/o/hub/",
            "sub": "voorbeeld-sub",
            "preferred_username": "voorbeeld",
        },
        6,
    ),
)

#: sha256 over de canonieke JSON van ``SAMPLES`` (gesorteerde sleutels, zonder witruimte)
SAMPLES_SHA256 = "b32cf4648da4f83b8ecafcc783a5f476078bb799daaf6b1dfab971f54c5531f0"


class SamplesChanged(RuntimeError):
    """De voorbeelden wijken af van de vastgelegde checksum: niet gebruiken."""


def checksum() -> str:
    raw = json.dumps(list(SAMPLES), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def verified() -> dict[str, dict[str, Any]]:
    """De voorbeelden per id, als kopie (een aanroeper kan het origineel niet wijzigen)."""
    if checksum() != SAMPLES_SHA256:
        raise SamplesChanged
    return {s["id"]: copy.deepcopy(s) for s in SAMPLES}
