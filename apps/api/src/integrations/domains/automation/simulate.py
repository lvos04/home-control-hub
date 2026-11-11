"""B11-004 — proefrun (dry-run) van een flow met vaste voorbeeld-events.

Een proefrun biedt de flow een aantal **vaste voorbeeld-events** aan (``samples.py``, met een vastgepinde checksum) en
legt vast wat de flow ermee doet. Zolang de proefrun loopt:

- krijgt de flow via de flow-API **alleen** de events van de proefrun (echte events blijven wachten);
- wordt een actieverzoek **niet** aangevraagd: er komt geen rij, geen event naar de Hub en dus geen uitvoering; het
  runlog zegt alleen ``zou_worden_aangevraagd`` of ``zou_worden_geweigerd``;
- wordt een mislukte aflevering niet herhaald: de uitzondering staat in het runlog.

**Grens (eerlijk):** deze dienst schermt het pad via de flow-API af. Een node die zelf naar buiten gaat (``http
request``, ``mqtt out`` …) valt buiten wat deze dienst kan tegenhouden. Daarom meldt de proefrun die nodes als
``niet_afgeschermd`` en start hij alleen als de beheerder dat uitdrukkelijk bevestigt. Dat geen enkel echt apparaat
verandert is alleen aangetoond met de simulator in deze repo; een echte Node-RED is NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...errors import ApiError
from ...timeutil import iso
from . import inbox, policy, samples
from .models import AutomationDelivery, AutomationEvent, AutomationFlow, AutomationFlowRun, AutomationFlowVersion

MAX_SAMPLES = 20
RUN_TTL = timedelta(minutes=15)
MAX_RUNLOG = 500
UNSHIELDED_NL = (
    "Deze flow bevat nodes die zelf naar buiten kunnen gaan. Deze dienst kan die tijdens een proefrun niet "
    "tegenhouden; alleen actieverzoeken via de flow-API worden afgeschermd."
)


def sample_list() -> list[dict[str, Any]]:
    """De voorbeeld-events (alleen-lezen) met hun checksum; een gewijzigd voorbeeld is een fout, geen stil succes."""
    try:
        verified = samples.verified()
    except samples.SamplesChanged as exc:
        raise ApiError(
            503,
            "simulation_unavailable",
            "De voorbeeld-events zijn gewijzigd ten opzichte van de vastgelegde checksum; een proefrun kan niet.",
        ) from exc
    return [
        {"id": sample_id, "title_nl": sample["title_nl"], "envelope": sample["envelope"]}
        for sample_id, sample in verified.items()
    ]


def unshielded_types(session: Session, flow: AutomationFlow) -> list[str]:
    """Typen in de huidige versie van de flow die zelf naar buiten kunnen gaan."""
    if flow.current_version_id is None:
        return []
    version = session.get(AutomationFlowVersion, flow.current_version_id)
    if version is None:
        return []
    return sorted(set(version.node_types or []) & policy.OUTBOUND_TYPES)


def run_view(run: AutomationFlowRun, *, with_log: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        "id": str(run.id),
        "flow_id": str(run.flow_id),
        "mode": run.mode,
        "status": run.status,
        "started_at": iso(run.started_at),
        "finished_at": iso(run.finished_at),
        "expires_at": iso(run.expires_at),
        "error_code": run.error_code,
        "version_id": str(run.version_id) if run.version_id else None,
        "baseline_run_id": str(run.baseline_run_id) if run.baseline_run_id else None,
        "created_by": run.created_by,
        "sample_ids": list(run.sample_ids or []),
        "result": run.result or {},
        "uitvoering": "proefrun: via deze dienst wordt niets aangevraagd of gewijzigd",
    }
    if with_log:
        out["runlog"] = list(run.runlog or [])
    return out


def _log(run: AutomationFlowRun, entry: dict[str, Any]) -> None:
    run.runlog = [*list(run.runlog or []), entry][-MAX_RUNLOG:]


def start_run(
    session: Session,
    flow: AutomationFlow,
    *,
    sample_ids: list[str],
    baseline_run_id: uuid.UUID | None,
    confirm_unshielded: bool,
    created_by: str,
    trace_id: str,
    now: datetime,
) -> AutomationFlowRun:
    if flow.status == "geblokkeerd":
        raise ApiError(
            409,
            "flow_geblokkeerd",
            "Deze flow is geblokkeerd door het flowbeleid; een proefrun kan pas na het oplossen daarvan.",
            {"reden": flow.blocked_reason},
        )
    if flow.status == "verwijderd":
        raise ApiError(409, "flow_verwijderd", "Deze flow bestaat niet meer in Node-RED.")
    running = inbox.active_dry_run(session, flow.id, now)
    if running is not None:
        raise ApiError(
            409,
            "proefrun_loopt_al",
            "Voor deze flow loopt al een proefrun; wacht tot die klaar of verlopen is.",
            {"run_id": str(running.id), "expires_at": iso(running.expires_at)},
        )
    available = {s["id"]: s for s in sample_list()}
    wanted = list(dict.fromkeys(sample_ids)) or list(available)
    if len(wanted) > MAX_SAMPLES:
        raise ApiError(422, "te_veel_voorbeelden", f"Een proefrun heeft hooguit {MAX_SAMPLES} voorbeeld-events.")
    unknown = sorted(s for s in wanted if s not in available)
    if unknown:
        raise ApiError(
            422,
            "voorbeeld_onbekend",
            "Onbekend voorbeeld-event; zie GET /integrations/v1/automation/samples.",
            {"onbekend": unknown[:20]},
        )
    baseline: AutomationFlowRun | None = None
    if baseline_run_id is not None:
        baseline = session.get(AutomationFlowRun, baseline_run_id)
        if baseline is None or baseline.flow_id != flow.id or baseline.mode != "dry_run" or baseline.status != "klaar":
            raise ApiError(
                422,
                "vergelijking_ongeldig",
                "De run om mee te vergelijken moet een afgeronde proefrun van dezelfde flow zijn.",
            )
    unshielded = unshielded_types(session, flow)
    if unshielded and not confirm_unshielded:
        raise ApiError(
            409,
            "proefrun_niet_afgeschermd",
            UNSHIELDED_NL + " Bevestig uitdrukkelijk (bevestig_niet_afgeschermd) om toch te starten.",
            {"niet_afgeschermd": unshielded},
        )
    run = AutomationFlowRun(
        id=uuid.uuid4(),
        flow_id=flow.id,
        mode="dry_run",
        status="bezig",
        started_at=now,
        expires_at=now + RUN_TTL,
        version_id=flow.current_version_id,
        baseline_run_id=baseline.id if baseline is not None else None,
        created_by=created_by[:200],
        sample_ids=wanted,
        runlog=[],
        result={},
    )
    session.add(run)
    session.flush()
    _log(
        run,
        {
            "t": iso(now),
            "soort": "start",
            "voorbeelden": wanted,
            "flow_versie": flow.version,
            "niet_afgeschermd": unshielded,
            "niet_afgeschermd_bevestigd": bool(unshielded and confirm_unshielded),
            "toelichting_nl": UNSHIELDED_NL if unshielded else "Geen nodes gevonden die zelf naar buiten gaan.",
        },
    )
    offered = 0
    for sample_id in wanted:
        envelope = dict(available[sample_id]["envelope"])
        envelope["event_id"] = str(uuid.uuid5(run.id, sample_id))
        envelope["source_event_id"] = f"dryrun:{run.id}:{sample_id}"
        result = inbox.intake(
            session, envelope, received_by=f"proefrun:{run.id}", trace_id=trace_id, now=now, test_run=run
        )
        offered += result.deliveries
        if result.deliveries == 0:
            _log(
                run,
                {
                    "t": iso(now),
                    "soort": "niet_aangeboden",
                    "voorbeeld": sample_id,
                    "catalog_status": result.event.catalog_status,
                    "reden": result.skipped[:1] or result.event.catalog_detail,
                },
            )
    if offered == 0:
        _finish(session, run, now)
    return run


def _action_signature(entry: dict[str, Any]) -> str:
    return policy.canonical(
        {
            "action_id": entry.get("action_id"),
            "target": entry.get("target"),
            "uitkomst": entry.get("uitkomst"),
            "reden": entry.get("reden"),
        }
    ).decode("utf-8")


def _compare(run: AutomationFlowRun, baseline: AutomationFlowRun) -> dict[str, Any]:
    """Vergelijkt de actieverzoeken van deze proefrun met die van een eerdere (bv. van de vorige flowversie)."""
    now_actions = Counter(_action_signature(e) for e in run.runlog or [] if e.get("soort") == "actie")
    base_actions = Counter(_action_signature(e) for e in baseline.runlog or [] if e.get("soort") == "actie")
    only_now = sorted((now_actions - base_actions).elements())
    only_base = sorted((base_actions - now_actions).elements())
    return {
        "baseline_run_id": str(baseline.id),
        "baseline_version_id": str(baseline.version_id) if baseline.version_id else None,
        "zelfde_voorbeelden": sorted(run.sample_ids or []) == sorted(baseline.sample_ids or []),
        "gelijk": not only_now and not only_base,
        "alleen_nu": only_now[:50],
        "alleen_eerder": only_base[:50],
    }


def _finish(session: Session, run: AutomationFlowRun, now: datetime) -> None:
    rows = session.scalars(select(AutomationDelivery).where(AutomationDelivery.run_id == run.id)).all()
    by_status = Counter(d.status for d in rows)
    actions = [e for e in run.runlog or [] if e.get("soort") == "actie"]
    failed = by_status.get("dead_letter", 0)
    result: dict[str, Any] = {
        "afleveringen": {"verwerkt": by_status.get("verwerkt", 0), "mislukt": failed},
        "actieverzoeken": len(actions),
        "zou_worden_aangevraagd": sum(1 for e in actions if e.get("uitkomst") == "zou_worden_aangevraagd"),
        "zou_worden_geweigerd": sum(1 for e in actions if e.get("uitkomst") == "zou_worden_geweigerd"),
        "aangevraagd_bij_de_hub": 0,
        "echte_wijzigingen_via_deze_dienst": 0,
        "grens_nl": "Nodes die zelf naar buiten gaan vallen buiten deze meting (zie 'niet_afgeschermd' in het runlog).",
    }
    if run.baseline_run_id is not None:
        baseline = session.get(AutomationFlowRun, run.baseline_run_id)
        result["vergelijking"] = _compare(run, baseline) if baseline is not None else {"baseline": "niet_meer_bewaard"}
    run.result = result
    run.finished_at = now
    if failed:
        run.status = "mislukt"
        run.error_code = "aflevering_mislukt"
    else:
        run.status = "klaar"
    _log(run, {"t": iso(now), "soort": "einde", "status": run.status})


def settle(session: Session, delivery: AutomationDelivery, *, now: datetime) -> AutomationFlowRun | None:
    """Na een bevestiging (ack/nack) van een aflevering uit een proefrun: runlog bijwerken en zo nodig afronden."""
    if delivery.run_id is None:
        return None
    run = session.get(AutomationFlowRun, delivery.run_id, with_for_update=True)
    if run is None or run.status != "bezig":
        return run
    event = session.get(AutomationEvent, delivery.event_seq)
    _log(
        run,
        {
            "t": iso(now),
            "soort": "aflevering",
            "delivery_id": str(delivery.id),
            "event_type": event.event_type if event is not None else None,
            "voorbeeld": event.source_event_id.rsplit(":", 1)[-1] if event is not None else None,
            "uitkomst": "verwerkt" if delivery.status == "verwerkt" else "mislukt",
            "fout": delivery.last_error,
        },
    )
    session.flush()
    open_rows = session.scalars(
        select(AutomationDelivery.id).where(
            AutomationDelivery.run_id == run.id, AutomationDelivery.status.in_(("wachtend", "geclaimd"))
        )
    ).first()
    if open_rows is None:
        _finish(session, run, now)
    return run


def expire_runs(session: Session, now: datetime) -> int:
    """Een proefrun die niet binnen een kwartier is afgerond wordt gesloten; de flow krijgt weer echte events."""
    runs = session.scalars(
        select(AutomationFlowRun)
        .where(
            AutomationFlowRun.mode == "dry_run",
            AutomationFlowRun.status == "bezig",
            AutomationFlowRun.expires_at <= now,
        )
        .with_for_update(skip_locked=True)
    ).all()
    for run in runs:
        rows = session.scalars(
            select(AutomationDelivery).where(
                AutomationDelivery.run_id == run.id, AutomationDelivery.status.in_(("wachtend", "geclaimd"))
            )
        ).all()
        for d in rows:
            d.status = "dead_letter"
            d.lease_until = None
            d.finished_at = now
            d.last_error = "proefrun_verlopen"
        session.flush()
        _finish(session, run, now)
        run.status = "mislukt"
        run.error_code = "verlopen"
        _log(run, {"t": iso(now), "soort": "verlopen", "niet_verwerkt": len(rows)})
    return len(runs)
