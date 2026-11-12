"""B11-005 — flows terugzetten naar een momentopname ("undo"), inclusief het versleutelde credentials-bestand.

- **Voorstel** (``propose``): leest Node-RED uit (alleen lezen), vergelijkt de huidige flows met de momentopname en
  geeft een diff zonder waarden, een ``preview_hash`` en een ``resource_etag`` (de checksum van de huidige flows).
  Er verandert niets in Node-RED.
- **Toepassen** (``apply``): alleen met een door de Hub **ondertekend** ``ExecutionRequest`` (contract §8). Deze dienst
  controleert zelf opnieuw: vorm, handtekening tegen de gepinde policy-sleutel, geldigheidsduur, eenmalige nonce,
  eigen allowlist, parameterschema, risicoklasse ≥ R2, een menselijke goedkeuring die aan precies dit voorstel
  gebonden is (preview, ETag, actie, beleid), eenmalig gebruik van die goedkeuring en — via readback — dat Node-RED
  nog in de toestand van de preview staat. Pas daarna: momentopname van de huidige toestand (``voor_herstel``),
  ``POST /flows`` met de ``rev`` van de readback, readback van het resultaat en een momentopname ``na_herstel``.
  Vanaf de goedkeuring tot en met de momentopname ``voor_herstel``, en opnieuw bij het vastleggen van ``na_herstel``,
  houdt het herstel het slot op het flowregister vast (``snapshots.lock_register``, R-VEILIG-9): een synchronisatie
  die tegelijk loopt, wacht en schrijft daarna geen dubbele flowversie.
- **Nooit**: een herstel zonder ondertekend verzoek, een tweede uitvoering met dezelfde nonce of goedkeuring, een
  herstel naar flows die het flowbeleid nu zou blokkeren, of een geheim in log, event, audit of antwoord. De
  credentials gaan als het door Node-RED zelf versleutelde bestand heen en terug; deze dienst kan ze niet lezen.

Volgorde van weigeringen = die van de executor van de Hub. Tot en met de handtekening en de geldigheidsduur wordt er
niets vastgelegd (een vervalst verzoek kan geen nonce opmaken). Vanaf het gebruik van de nonce wordt elke weigering
vastgelegd en bij dezelfde ``Idempotency-Key`` identiek teruggegeven.

Echte Node-RED op de NAS: NIET GEVALIDEERD (echte NAS). De schrijfroute is gemeten tegen de vastgezette image in een
lokale container (``docs/b11/node-red-verificatie.json``) en getest met de in-repo-simulator (Sim-getest).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from ... import audit, events
from ...config import Settings
from ...errors import ApiError, forbidden, not_found
from ...security import execreq
from ...security.auth import Principal
from ...security.vault import Vault
from ...timeutil import iso
from . import nodered, policy, snapshots
from .models import AutomationExecutionNonce, AutomationRestore, AutomationSnapshot
from .nodered import SOURCE_ID, NodeRedError, client_from_source

ACTION_ID = "automation.flows.restore"
TITLE_NL = "Flows terugzetten naar een momentopname (inclusief versleutelde credentials)"
TASK_ID = "B11-005"
MIN_RISK_CLASS = "R2"
PROPOSAL_TTL = timedelta(minutes=15)
TARGET: dict[str, str] = {"type": "source", "id": SOURCE_ID}
#: een goedkeuring wordt onder een afgeleide sleutel in hetzelfde register bewaard als de nonce van het verzoek
_APPROVAL_NS = uuid.UUID("6f0f3f5e-7a55-5b0a-9d0b-0f1c2d3e4f50")
APPLY_STATUS = "vereist_execution_request"
APPLY_STATUS_NL = (
    "Toepassen kan alleen met een door de Hub ondertekend uitvoeringsverzoek met een menselijke goedkeuring (R2)."
)
UPSTREAM_UNKNOWN = ("onbereikbaar", "timeout", "http_5xx")
Result = tuple[int, Any, dict[str, str]]


def _bare(value: str) -> str:
    return value.removeprefix("sha256:")


def _prefixed(value: str) -> str:
    return "sha256:" + value


def parse_parameters(parameters: Any) -> uuid.UUID | None:
    """Precies ``{"snapshot_id": "<uuid>"}``; iets anders is ongeldig."""
    if not isinstance(parameters, dict) or set(parameters) != {"snapshot_id"}:
        return None
    raw = parameters["snapshot_id"]
    if not isinstance(raw, str) or not execreq.UUID_RE.fullmatch(raw):
        return None
    return uuid.UUID(raw)


def restore_view(row: AutomationRestore) -> dict[str, Any]:
    plan = row.plan or {}
    return {
        "proposal_id": str(row.id),
        "action_id": ACTION_ID,
        "task_id": TASK_ID,
        "target": dict(TARGET),
        "parameters": {"snapshot_id": str(row.target_snapshot_id)},
        "preview_hash": _prefixed(row.preview_hash),
        "resource_etag": _prefixed(row.base_checksum),
        "diff": plan.get("diff", {}),
        "blast_radius": plan.get("blast_radius", {}),
        "risk_claim": MIN_RISK_CLASS,
        "risk_class_min": MIN_RISK_CLASS,
        "rollback_recipe": plan.get("rollback_recipe", {}),
        "requires_backup": False,
        "warnings": plan.get("waarschuwingen", []),
        "credentials": plan.get("credentials", {}),
        "notes_nl": plan.get("notes_nl", []),
        "status": row.status,
        "apply_status": APPLY_STATUS,
        "apply_status_nl": APPLY_STATUS_NL,
        "created_at": iso(row.created_at),
        "created_by": row.requested_by,
        "expires_at": iso(row.expires_at),
        "applied_at": iso(row.applied_at) if row.applied_at else None,
        "pre_snapshot_id": str(row.pre_snapshot_id) if row.pre_snapshot_id else None,
        "post_snapshot_id": str(row.post_snapshot_id) if row.post_snapshot_id else None,
        "result": row.result or {},
    }


def _policy_problems(scan: policy.ScanResult) -> list[dict[str, Any]]:
    problems = [{"flow": t.label[:80], **f} for t in scan.tabs for f in t.findings]
    problems.extend(scan.global_findings)
    # eerst de oorzaken zelf; een tabblad dat alleen meegeblokkeerd is (bron_geblokkeerd) telt ook, maar daarna
    problems.sort(key=lambda f: f.get("code") == policy.SOURCE_BLOCKED)
    return problems[:20]


def _preview_hash(snapshot: AutomationSnapshot, base_checksum: str) -> str:
    return _bare(
        execreq.canonical_sha256(
            {
                "action_id": ACTION_ID,
                "target": TARGET,
                "parameters": {"snapshot_id": str(snapshot.id)},
                "base_checksum": base_checksum,
                "target_checksum": snapshot.checksum_sha256,
                "target_credentials_sha256": snapshot.credentials_sha256,
            }
        )
    )


# ----------------------------------------------------------------------------------------------------------- voorstel
def propose(
    session: Session,
    settings: Settings,
    vault: Vault,
    transport: httpx.BaseTransport | None,
    *,
    parameters: Any,
    principal: Principal,
    trace_id: str,
    now: datetime,
) -> dict[str, Any]:
    snapshot_id = parse_parameters(parameters)
    if snapshot_id is None:
        raise ApiError(
            422,
            "parameters_ongeldig",
            'De parameters van dit voorstel zijn precies {"snapshot_id": "<uuid van een momentopname>"}.',
        )
    snapshot = session.get(AutomationSnapshot, snapshot_id)
    if snapshot is None or snapshot.source_id != SOURCE_ID:
        raise not_found("Momentopname")
    try:
        document = snapshots.open_snapshot(vault, snapshot)
    except snapshots.SnapshotUnreadable as exc:
        raise ApiError(
            409,
            "momentopname_onleesbaar",
            "Deze momentopname is niet te ontsleutelen met de huidige kluissleutel; er is niets gewijzigd.",
            {"snapshot_id": str(snapshot.id)},
        ) from exc
    try:
        with client_from_source(session, settings, vault, transport) as client:
            current = client.get_flows()
            node_sets = client.get_nodes()
    except NodeRedError as exc:
        raise nodered.api_error(exc) from exc
    target_flows: list[dict[str, Any]] = document["flows"]
    scan = policy.scan(target_flows, policy.type_modules(node_sets), settings.node_red_allowed_modules)
    problems = _policy_problems(scan)
    if problems:
        raise ApiError(
            422,
            "momentopname_niet_toegestaan",
            "Deze momentopname bevat flows die het flowbeleid nu blokkeert; terugzetten zou ze opnieuw activeren.",
            {"bevindingen": problems},
        )
    base_checksum = policy.flows_checksum(current.flows)
    live = snapshots.read_credentials(settings.node_red_data_dir)
    credentials_differ = (
        snapshot.has_credentials and live.sha256 is not None and live.sha256 != snapshot.credentials_sha256
    )
    if base_checksum == snapshot.checksum_sha256 and not credentials_differ:
        raise ApiError(
            409,
            "niets_te_herstellen",
            "Node-RED staat al in de toestand van deze momentopname; er is niets te herstellen.",
            {"snapshot_id": str(snapshot.id), "checksum_sha256": base_checksum},
        )
    warnings: list[str] = []
    if not snapshot.has_credentials:
        warnings.append(
            "Deze momentopname bevat geen credentials-bestand (de datamap van Node-RED was niet gekoppeld). Nodes die "
            "door het herstel terugkomen, hebben daarna geen inloggegevens; bestaande nodes houden de hunne."
        )
    else:
        warnings.append(
            "Het credentials-bestand uit de momentopname vervangt alle huidige inloggegevens van nodes. Het is "
            "versleuteld met de credentialSecret van Node-RED; is die sindsdien gewijzigd, dan weigert Node-RED het "
            "herstel en verandert er niets."
        )
    diff = snapshots.diff_flows(current.flows, target_flows)
    plan: dict[str, Any] = {
        "diff": diff,
        "blast_radius": {
            "bron": SOURCE_ID,
            "flows_in_momentopname": snapshot.flow_count,
            "nodes_in_momentopname": snapshot.node_count,
            "gevolg_nl": "Alle flows in Node-RED worden vervangen door de momentopname en opnieuw gestart.",
        },
        "credentials": {
            "credentials_present": snapshot.has_credentials,
            "status": (snapshot.policy_summary or {}).get("credentials_status"),
            "wijzigt": bool(credentials_differ) if live.sha256 is not None else None,
        },
        "rollback_recipe": {
            "soort": "momentopname",
            "uitleg_nl": "Vlak voor het herstel legt deze dienst de huidige toestand vast als momentopname "
            "'voor_herstel'. Terugdraaien is een nieuw herstelvoorstel naar die momentopname.",
            "automatisch": False,
        },
        "waarschuwingen": warnings,
        "notes_nl": [
            "Het voorstel vervalt na 15 minuten of zodra de flows in Node-RED veranderen.",
            APPLY_STATUS_NL,
        ],
    }
    row = AutomationRestore(
        id=uuid.uuid4(),
        source_id=SOURCE_ID,
        target_snapshot_id=snapshot.id,
        base_rev=current.rev,
        base_checksum=base_checksum,
        target_checksum=snapshot.checksum_sha256,
        preview_hash=_preview_hash(snapshot, base_checksum),
        plan=plan,
        status="voorgesteld",
        requested_by=principal.audit_id[:200],
        created_at=now,
        expires_at=now + PROPOSAL_TTL,
        result={},
        trace_id=uuid.UUID(trace_id),
    )
    session.add(row)
    session.flush()
    audit.record(
        session,
        domain="automation",
        action="automation.restore.proposed",
        entity_type="automation_restore",
        entity_id=str(row.id),
        principal=principal,
        trace_id=trace_id,
        message_nl="Herstelvoorstel gemaakt voor de flows in Node-RED (er is niets gewijzigd).",
        details={"snapshot_id": str(snapshot.id), "aantallen": diff["aantallen"]},
    )
    events.emit(
        session,
        event_type="automation.restore.proposed",
        entity_type="automation_restore",
        entity_id=str(row.id),
        actor_type=principal.actor_type,
        actor_id=principal.audit_id,
        trace_id=trace_id,
        payload={"ernst": "info", "snapshot_id": str(snapshot.id), "aantallen": diff["aantallen"]},
    )
    return restore_view(row)


# ---------------------------------------------------------------------------------------------------------- toepassen
def _refusal_body(code: str, message: str, details: dict[str, Any] | None, trace_id: str) -> dict[str, Any]:
    return {"code": code, "message": message, "details": details or {}, "trace_id": trace_id}


def _refuse(
    status: int,
    code: str,
    message: str,
    trace_id: str,
    details: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> Result:
    return status, _refusal_body(code, message, details, trace_id), headers or {}


def _refuse_403(reason: str, message: str, trace_id: str, details: dict[str, Any] | None = None) -> Result:
    return _refuse(403, "forbidden", message, trace_id, {"reason": reason, **(details or {})})


def _from_refusal(exc: execreq.Refusal, trace_id: str) -> Result:
    return _refuse(exc.status, exc.code, exc.message, trace_id, dict(exc.details))


def _consume(session: Session, nonce: uuid.UUID, request_sha256: str, expires_at: datetime, now: datetime) -> bool:
    """Legt een nonce eenmalig vast. ``False`` als hij al gebruikt is (ook door een gelijktijdig verzoek)."""
    stmt = (
        insert(AutomationExecutionNonce)
        .values(
            nonce=nonce,
            action_id=ACTION_ID,
            request_sha256=request_sha256,
            used_at=now,
            expires_at=expires_at,
            outcome="aangenomen",
        )
        .on_conflict_do_nothing(index_elements=["nonce"])
        .returning(AutomationExecutionNonce.nonce)
    )
    return session.execute(stmt).first() is not None


def _set_outcome(session: Session, nonce: uuid.UUID, outcome: str) -> None:
    row = session.get(AutomationExecutionNonce, nonce)
    if row is not None:
        row.outcome = outcome[:20]


def _find_proposal(session: Session, snapshot_id: uuid.UUID, preview_hash: str) -> AutomationRestore | None:
    return session.scalars(
        select(AutomationRestore)
        .where(
            AutomationRestore.source_id == SOURCE_ID,
            AutomationRestore.target_snapshot_id == snapshot_id,
            AutomationRestore.preview_hash == preview_hash,
        )
        .order_by(AutomationRestore.created_at.desc())
        .limit(1)
        .with_for_update()
    ).first()


def _fail(
    session: Session,
    row: AutomationRestore,
    *,
    reason: str,
    trace_id: str,
    now: datetime,
    extra: dict[str, Any] | None = None,
) -> None:
    row.status = "mislukt"
    row.result = {"reden": reason, "at": iso(now), **(extra or {})}
    events.emit(
        session,
        event_type="automation.restore.failed",
        entity_type="automation_restore",
        entity_id=str(row.id),
        actor_type="system",
        actor_id=snapshots.SYSTEM_ACTOR,
        trace_id=trace_id,
        payload={"ernst": "hoog", "reden": reason, "snapshot_id": str(row.target_snapshot_id), **(extra or {})},
    )


def apply(
    session: Session,
    settings: Settings,
    vault: Vault,
    transport: httpx.BaseTransport | None,
    *,
    request: Any,
    keys: Sequence[Ed25519PublicKey],
    principal: Principal,
    trace_id: str,
    now: datetime,
) -> Result:
    """Voert een ondertekend herstelverzoek uit. Gooit :class:`ApiError` zolang er niets is vastgelegd; daarna komt elke
    uitkomst (ook een weigering) als resultaat terug, zodat ze met de nonce wordt bewaard."""
    # 1–3: vorm, handtekening, geldigheidsduur — niets vastgelegd
    if not keys:
        raise forbidden(
            "geen_gepinde_policy_sleutel",
            "Deze dienst heeft geen gepinde policy-sleutel van de Hub (niet gekoppeld); er is niets uitgevoerd.",
        )
    try:
        execreq.check_envelope(request, keys, now=now)
    except execreq.Refusal as exc:
        raise ApiError(exc.status, exc.code, exc.message, dict(exc.details)) from exc
    proposal = request["proposal"]
    # 4: eenmalige nonce van het verzoek
    request_nonce = uuid.UUID(request["nonce"])
    expires = execreq.parse_ts(request["expires_at"]) or now
    digest = execreq.request_sha256(request)
    if not _consume(session, request_nonce, digest, expires, now):
        raise ApiError(
            409,
            "nonce_al_gebruikt",
            "Dit uitvoeringsverzoek is al eerder aangeboden; er is niets (opnieuw) uitgevoerd.",
            {"nonce": str(request_nonce)},
        )

    def refused(result: Result, outcome: str = "geweigerd") -> Result:
        _set_outcome(session, request_nonce, outcome)
        return result

    # 5: eigen allowlist
    if proposal["action_id"] != ACTION_ID:
        return refused(
            _refuse_403(
                "actie_niet_toegestaan",
                "Deze actie staat niet op de eigen lijst van deze dienst; er is niets uitgevoerd.",
                trace_id,
                {"action_id": str(proposal["action_id"])[:80]},
            )
        )
    # 6: parameterschema en doel
    snapshot_id = parse_parameters(proposal["parameters"])
    if snapshot_id is None or dict(proposal["target"]) != TARGET:
        return refused(
            _refuse(
                422,
                "parameters_ongeldig",
                "Doel of parameters van het verzoek passen niet bij deze actie; er is niets uitgevoerd.",
                trace_id,
                {"verwacht": {"target": TARGET, "parameters": {"snapshot_id": "<uuid>"}}},
            )
        )
    # vanaf hier tot de commit vóór het schrijven: het slot op het flowregister (R-VEILIG-9), vóór de rij van het
    # voorstel en vóór de readback; zelfde volgorde als _finish_apply (eerst het slot, dan de rij)
    snapshots.lock_register(session)
    # 7: risicoklasse en goedkeuring, gebonden aan het eigen voorstel
    approval = request.get("approval")
    if not isinstance(approval, dict):
        try:
            execreq.check_approval(
                request, min_risk_class=MIN_RISK_CLASS, preview_hash="", requires_backup=False, now=now
            )
        except execreq.Refusal as exc:
            return refused(_from_refusal(exc, trace_id))
        return refused(_refuse_403("goedkeuring_ontbreekt", "Deze actie vraagt een menselijke goedkeuring.", trace_id))
    row = _find_proposal(session, snapshot_id, _bare(str(approval["preview_hash"])))
    if row is None:
        return refused(
            _refuse(
                409,
                "goedkeuring_past_niet",
                "Er is geen herstelvoorstel van deze dienst met deze preview; maak een nieuw voorstel.",
                trace_id,
                {"gewijzigd": ["preview_hash"]},
            )
        )
    if row.status in ("uitgevoerd", "mislukt"):
        return refused(
            _refuse(
                409,
                "voorstel_al_afgehandeld",
                "Dit herstelvoorstel is al afgehandeld; maak een nieuw voorstel.",
                trace_id,
                {"proposal_id": str(row.id), "status": row.status},
            )
        )
    if row.status == "verlopen" or row.expires_at <= now:
        row.status = "verlopen"
        return refused(
            _refuse(
                409,
                "voorstel_verlopen",
                "Dit herstelvoorstel is verlopen; maak een nieuw voorstel.",
                trace_id,
                {"proposal_id": str(row.id)},
            )
        )
    try:
        approval = execreq.check_approval(
            request,
            min_risk_class=MIN_RISK_CLASS,
            preview_hash=_prefixed(row.preview_hash),
            requires_backup=False,
            now=now,
        )
    except execreq.Refusal as exc:
        return refused(_from_refusal(exc, trace_id))
    if proposal["expected_version"] != _prefixed(row.base_checksum):
        return refused(
            _refuse(
                409,
                "goedkeuring_past_niet",
                "De versie in het verzoek hoort niet bij dit herstelvoorstel; maak een nieuw voorstel.",
                trace_id,
                {"gewijzigd": ["resource_etag"]},
            )
        )
    # 8: de goedkeuring is eenmalig
    approval_nonce = uuid.uuid5(_APPROVAL_NS, "approval:" + str(approval["one_time_nonce"]))
    approval_expires = execreq.parse_ts(approval["expires_at"]) or now
    if not _consume(session, approval_nonce, digest, approval_expires, now):
        return refused(
            _refuse(
                409,
                "goedkeuring_al_gebruikt",
                "Deze goedkeuring is al eerder gebruikt; er is niets (opnieuw) uitgevoerd.",
                trace_id,
            )
        )
    snapshot = session.get(AutomationSnapshot, snapshot_id)
    if snapshot is None:  # pragma: no cover - RESTRICT op de verwijzing maakt dit onmogelijk
        return refused(_refuse(409, "goedkeuring_past_niet", "De momentopname bestaat niet meer.", trace_id))
    try:
        document = snapshots.open_snapshot(vault, snapshot)
    except snapshots.SnapshotUnreadable:
        _fail(session, row, reason="momentopname_onleesbaar", trace_id=trace_id, now=now)
        return refused(
            _refuse(
                409,
                "momentopname_onleesbaar",
                "De momentopname is niet te ontsleutelen met de huidige kluissleutel; er is niets gewijzigd.",
                trace_id,
            )
        )
    target_flows: list[dict[str, Any]] = document["flows"]
    credentials = document.get("credentials") if isinstance(document.get("credentials"), dict) else None
    # 9: precondities via readback — een fout hier heeft nog niets gewijzigd: alles wordt teruggedraaid en het verzoek
    #    mag binnen zijn geldigheid opnieuw worden aangeboden
    try:
        client = client_from_source(session, settings, vault, transport)
    except NodeRedError as exc:
        raise nodered.api_error(exc) from exc
    with client:
        try:
            current = client.get_flows()
            node_sets = client.get_nodes()
            nr_settings = client.get_settings()
        except NodeRedError as exc:
            raise nodered.api_error(exc) from exc
        before_checksum = policy.flows_checksum(current.flows)
        if before_checksum != row.base_checksum:
            _fail(session, row, reason="doel_gewijzigd", trace_id=trace_id, now=now)
            return refused(
                _refuse(
                    409,
                    "doel_gewijzigd",
                    "De flows in Node-RED zijn gewijzigd sinds de preview; er is niets uitgevoerd. Maak een nieuw "
                    "voorstel.",
                    trace_id,
                    {"resource_etag": _prefixed(before_checksum), "verwacht": _prefixed(row.base_checksum)},
                )
            )
        modules = policy.type_modules(node_sets)
        problems = _policy_problems(policy.scan(target_flows, modules, settings.node_red_allowed_modules))
        if problems:
            _fail(session, row, reason="momentopname_niet_toegestaan", trace_id=trace_id, now=now)
            return refused(
                _refuse(
                    409,
                    "momentopname_niet_toegestaan",
                    "De momentopname bevat flows die het flowbeleid nu blokkeert; er is niets uitgevoerd.",
                    trace_id,
                    {"bevindingen": problems},
                )
            )
        # momentopname vóór de wijziging; samen met de nonce en de goedkeuring definitief vastgelegd vóór het schrijven
        version = str(nr_settings.get("version"))[:40] if nr_settings.get("version") else None
        pre = snapshots.create_snapshot(
            session,
            vault,
            flows=current.flows,
            rev=current.rev,
            credentials=snapshots.read_credentials(settings.node_red_data_dir),
            reason="voor_herstel",
            created_by=principal.audit_id,
            trace_id=trace_id,
            scan=policy.scan(current.flows, modules, settings.node_red_allowed_modules),
            node_red_version=version,
        )
        row.pre_snapshot_id = pre.id
        row.result = {"fase": "toepassen_gestart", "at": iso(now)}
        _set_outcome(session, request_nonce, "gestart")
        session.commit()

        # 10: schrijven en teruglezen
        write_error: NodeRedError | None = None
        try:
            client.post_flows(current.rev, target_flows, credentials)
        except NodeRedError as exc:
            write_error = exc
        after: nodered.FlowsDoc | None = None
        try:
            after = client.get_flows()
        except NodeRedError:
            after = None
    return _finish_apply(
        session,
        settings,
        vault,
        row=row,
        snapshot=snapshot,
        request_nonce=request_nonce,
        approval=dict(approval),
        principal=principal,
        before_checksum=before_checksum,
        after=after,
        write_error=write_error,
        node_sets=node_sets,
        nr_settings=nr_settings,
        credentials_sent=credentials is not None,
        trace_id=trace_id,
        now=now,
    )


def _finish_apply(
    session: Session,
    settings: Settings,
    vault: Vault,
    *,
    row: AutomationRestore,
    snapshot: AutomationSnapshot,
    request_nonce: uuid.UUID,
    approval: dict[str, Any],
    principal: Principal,
    before_checksum: str,
    after: nodered.FlowsDoc | None,
    write_error: NodeRedError | None,
    node_sets: list[dict[str, Any]],
    nr_settings: dict[str, Any],
    credentials_sent: bool,
    trace_id: str,
    now: datetime,
) -> Result:
    after_checksum = policy.flows_checksum(after.flows) if after is not None else None
    readback: dict[str, Any] = {
        "gelezen": after is not None,
        "checksum_sha256": after_checksum,
        "node_red_rev": after.rev if after is not None else None,
        "gelijk_aan_momentopname": after_checksum == row.target_checksum if after_checksum else None,
        "gelijk_aan_toestand_vooraf": after_checksum == before_checksum if after_checksum else None,
    }
    hashes = {
        "before_hash": _prefixed(before_checksum),
        "after_hash": _prefixed(after_checksum) if after_checksum else None,
    }
    if (
        after is not None
        and after_checksum == row.target_checksum
        and (write_error is None or write_error.reason in UPSTREAM_UNKNOWN)
    ):
        # het slot op het flowregister vóór latest_snapshot en de flows (R-VEILIG-9): een synchronisatie die tegelijk
        # loopt, schrijft dan niet dezelfde flowversie
        snapshots.lock_register(session)
        result = snapshots.record_state(
            session,
            settings,
            vault,
            doc_flows=after.flows,
            rev=after.rev,
            node_sets=node_sets,
            nr_settings=nr_settings,
            reason="na_herstel",
            actor=principal.audit_id,
            trace_id=trace_id,
            force_snapshot=True,
            now=now,
        )
        row.status = "uitgevoerd"
        row.applied_at = now
        row.post_snapshot_id = uuid.UUID(result.snapshot_id) if result.snapshot_id else None
        row.result = {
            **hashes,
            "readback": readback,
            "credentials_teruggezet": credentials_sent,
            "bevestigd_via": "readback" if write_error is not None else "antwoord_en_readback",
            "goedgekeurd_door": str(approval.get("approved_by"))[:200],
            "at": iso(now),
        }
        _set_outcome(session, request_nonce, "uitgevoerd")
        audit.record(
            session,
            domain="automation",
            action="automation.restore.applied",
            entity_type="automation_restore",
            entity_id=str(row.id),
            principal=principal,
            trace_id=trace_id,
            message_nl="Flows in Node-RED teruggezet naar een momentopname (ondertekend uitvoeringsverzoek).",
            details={
                "snapshot_id": str(snapshot.id),
                "pre_snapshot_id": str(row.pre_snapshot_id),
                "post_snapshot_id": str(row.post_snapshot_id),
                "goedgekeurd_door": str(approval.get("approved_by"))[:200],
                "approval_id": str(approval.get("approval_id")),
                **hashes,
            },
        )
        events.emit(
            session,
            event_type="automation.restore.applied",
            entity_type="automation_restore",
            entity_id=str(row.id),
            actor_type=principal.actor_type,
            actor_id=principal.audit_id,
            trace_id=trace_id,
            payload={
                "ernst": "info",
                "snapshot_id": str(snapshot.id),
                "pre_snapshot_id": str(row.pre_snapshot_id),
                "credentials_present": credentials_sent,
                **hashes,
            },
        )
        body = {
            "status": "uitgevoerd",
            "proposal_id": str(row.id),
            "action_id": ACTION_ID,
            "readback": readback,
            **hashes,
            "pre_snapshot_id": str(row.pre_snapshot_id),
            "post_snapshot_id": str(row.post_snapshot_id),
            "credentials_teruggezet": credentials_sent,
            "rollback_recipe": {"action_id": ACTION_ID, "parameters": {"snapshot_id": str(row.pre_snapshot_id)}},
            "validatie": "Echte Node-RED op de NAS: NIET GEVALIDEERD (echte NAS).",
            "trace_id": trace_id,
        }
        return 200, body, {}

    # niet (aantoonbaar) geslaagd: eerlijk melden wat er gemeten is
    unchanged = after_checksum is not None and after_checksum == before_checksum
    reason = write_error.reason if write_error is not None else "readback_wijkt_af"
    extra = {**hashes, "ongewijzigd": unchanged if after is not None else None}
    _fail(session, row, reason=reason, trace_id=trace_id, now=now, extra=extra)
    _set_outcome(session, request_nonce, "mislukt")
    audit.record(
        session,
        domain="automation",
        action="automation.restore.failed",
        entity_type="automation_restore",
        entity_id=str(row.id),
        principal=principal,
        trace_id=trace_id,
        message_nl="Herstel van de flows in Node-RED is niet gelukt.",
        details={"reden": reason, "snapshot_id": str(snapshot.id), **extra},
    )
    details = {"proposal_id": str(row.id), "readback": readback, **hashes, "pre_snapshot_id": str(row.pre_snapshot_id)}
    if write_error is not None and write_error.reason == "versie_conflict":
        return _refuse(
            409,
            "doel_gewijzigd",
            "Node-RED weigerde het herstel omdat de flows intussen gewijzigd zijn; er is niets uitgevoerd.",
            trace_id,
            details,
        )
    if write_error is not None and write_error.reason == "credentials_niet_te_ontsleutelen":
        return _refuse(
            409,
            "credentials_niet_te_ontsleutelen",
            "Node-RED kan het credentials-bestand uit de momentopname niet ontsleutelen (andere credentialSecret); "
            "het herstel is geweigerd.",
            trace_id,
            details,
        )
    if write_error is not None and unchanged and write_error.reason in UPSTREAM_UNKNOWN:
        return _refuse(
            503,
            "node_red_unavailable",
            "Node-RED was niet bereikbaar tijdens het herstel; de flows zijn ongewijzigd.",
            trace_id,
            {**details, **write_error.to_dict()},
            {"Retry-After": "30"},
        )
    if write_error is not None and after is not None and unchanged:
        return _refuse(
            502,
            "node_red_fout",
            "Node-RED weigerde het herstel; de flows zijn ongewijzigd.",
            trace_id,
            {**details, **write_error.to_dict()},
        )
    return _refuse(
        502,
        "herstel_niet_bevestigd",
        "Het herstel is niet bevestigd door de readback. Controleer de flows in Node-RED; de toestand van vóór het "
        "herstel staat in de momentopname 'voor_herstel'.",
        trace_id,
        details,
    )


def expire(session: Session, now: datetime) -> int:
    """Verlopen voorstellen krijgen de status ``verlopen``; opgeruimde nonces zijn ouder dan hun geldigheid + 1 dag."""
    rows = session.scalars(
        select(AutomationRestore).where(AutomationRestore.status == "voorgesteld", AutomationRestore.expires_at <= now)
    ).all()
    for row in rows:
        if (row.result or {}).get("fase") == "toepassen_gestart":
            row.status = "mislukt"
            row.result = {**row.result, "reden": "onderbroken", "uitkomst": "onbekend"}
        else:
            row.status = "verlopen"
    old = session.scalars(
        select(AutomationExecutionNonce).where(AutomationExecutionNonce.expires_at < now - timedelta(days=1))
    ).all()
    for nonce in old:
        session.delete(nonce)
    return len(rows)
