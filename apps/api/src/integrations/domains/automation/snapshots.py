"""B11-001/B11-005 — synchronisatie met Node-RED, versleutelde momentopnamen, flowversies en een diff zonder waarden.

- De synchronisatie leest ``/flows``, ``/nodes`` en ``/settings`` (alleen lezen), past het flowbeleid toe en legt bij
  elke wijziging **vóór verdere verwerking** een momentopname vast ("snapshot vóór edit" kan deze dienst niet afdwingen
  in de editor; daarom wordt elke gewijzigde toestand direct bewaard, zodat de vorige altijd terug te zetten is).
- Een momentopname is AES-256-GCM-versleuteld met de sleutel van de kluis en bevat de flows en — alleen als de
  datamap van Node-RED alleen-lezen is gekoppeld (``HCH_NODE_RED_DATA_DIR``) — het door Node-RED zelf versleutelde
  ``flows_cred.json``. ``GET /flows`` geeft nooit credentials terug (gemeten); zonder de koppeling is dat onderdeel
  eerlijk ``niet_gekoppeld``.
- De diff toont alleen **welke** nodes en velden verschillen, nooit de waarden (een function-node kan een geheim
  bevatten).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from cryptography.exceptions import InvalidTag
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ... import events
from ...config import Settings
from ...models import IntegrationSource, ServiceState
from ...security.vault import Vault
from ...timeutil import iso, utcnow
from . import policy
from .models import (
    AutomationFlow,
    AutomationFlowToken,
    AutomationFlowVersion,
    AutomationSnapshot,
)
from .nodered import (
    CONFIG_REASONS,
    SOURCE_ID,
    UNREACHABLE_REASONS,
    NodeRedClient,
    NodeRedError,
    client_from_source,
)

SYNC_KEY = "automation_sync"
ISOLATION_KEY = "automation_isolatie"
CRED_FILE = "flows_cred.json"
MAX_CRED_BYTES = 4 * 1024 * 1024
MAX_DIFF_ROWS = 200
ISOLATION_MAX_AGE = timedelta(minutes=15)
POLICY_REASONS = ("verboden_node", "module_niet_toegestaan", "onbekend_type")
SYSTEM_ACTOR = "home-control-hub"


def state_get(session: Session, key: str) -> dict[str, Any] | None:
    row = session.get(ServiceState, key)
    return dict(row.value) if row is not None else None


def state_put(session: Session, key: str, value: dict[str, Any]) -> None:
    row = session.get(ServiceState, key)
    if row is None:
        session.add(ServiceState(key=key, value=value))
    else:
        row.value = value


def source_row(session: Session) -> IntegrationSource | None:
    return session.get(IntegrationSource, SOURCE_ID)


def configured(session: Session) -> bool:
    row = source_row(session)
    return bool(row and row.base_url and row.enabled)


# ------------------------------------------------------------------------------------------------------- credentials
@dataclass(frozen=True)
class CredentialsBlob:
    status: str  # niet_gekoppeld | afwezig | meegenomen | onleesbaar
    blob: dict[str, Any] | None = None

    @property
    def sha256(self) -> str | None:
        return policy.sha256_hex(policy.canonical(self.blob)) if self.blob is not None else None


def read_credentials(data_dir: Path | None) -> CredentialsBlob:
    """Leest het door Node-RED versleutelde ``flows_cred.json`` uit de alleen-lezen gekoppelde datamap.

    Alleen de versleutelde vorm ``{"$": "<iv><base64>"}`` wordt aangenomen; een onversleuteld bestand (Node-RED zonder
    ``credentialSecret``) wordt bewust niet meegenomen: dat is een afwijking van het beveiligingsprofiel."""
    if data_dir is None:
        return CredentialsBlob("niet_gekoppeld")
    path = data_dir / CRED_FILE
    try:
        if not path.is_file():
            return CredentialsBlob("afwezig")
        if path.stat().st_size > MAX_CRED_BYTES:
            return CredentialsBlob("onleesbaar")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return CredentialsBlob("onleesbaar")
    if not (isinstance(data, dict) and set(data) == {"$"} and isinstance(data["$"], str) and data["$"]):
        return CredentialsBlob("onleesbaar")
    return CredentialsBlob("meegenomen", {"$": data["$"]})


# ----------------------------------------------------------------------------------------------------- momentopnamen
def _aad(snapshot_id: uuid.UUID) -> bytes:
    return f"automation-snapshot:{snapshot_id}".encode()


def latest_snapshot(session: Session) -> AutomationSnapshot | None:
    return session.scalars(
        select(AutomationSnapshot)
        .where(AutomationSnapshot.source_id == SOURCE_ID)
        .order_by(AutomationSnapshot.seq.desc())
        .limit(1)
    ).first()


def create_snapshot(
    session: Session,
    vault: Vault,
    *,
    flows: list[dict[str, Any]],
    rev: str | None,
    credentials: CredentialsBlob,
    reason: str,
    created_by: str,
    trace_id: str,
    scan: policy.ScanResult | None,
    node_red_version: str | None,
) -> AutomationSnapshot:
    snapshot_id = uuid.uuid4()
    document = {"flows": flows, "credentials": credentials.blob, "rev": rev}
    plaintext = policy.canonical(document)
    nonce, ciphertext = vault.seal(_aad(snapshot_id), plaintext)
    summary = scan.summary() if scan is not None else {}
    summary["credentials_status"] = credentials.status
    row = AutomationSnapshot(
        id=snapshot_id,
        source_id=SOURCE_ID,
        node_red_rev=rev,
        checksum_sha256=policy.flows_checksum(flows),
        reason=reason,
        nonce=nonce,
        ciphertext=ciphertext,
        size_bytes=len(plaintext),
        node_count=len(flows),
        flow_count=sum(1 for n in flows if n.get("type") == "tab"),
        policy_summary=summary,
        node_red_version=node_red_version,
        has_credentials=credentials.blob is not None,
        credentials_sha256=credentials.sha256,
        created_at=utcnow(),
        created_by=created_by[:200],
        trace_id=uuid.UUID(trace_id),
    )
    session.add(row)
    session.flush()
    return row


class SnapshotUnreadable(Exception):
    """De momentopname is niet te ontsleutelen (andere kluissleutel of beschadigd)."""


def open_snapshot(vault: Vault, row: AutomationSnapshot) -> dict[str, Any]:
    try:
        plaintext = vault.unseal(_aad(row.id), bytes(row.nonce), bytes(row.ciphertext))
    except InvalidTag as exc:
        raise SnapshotUnreadable from exc
    data = json.loads(plaintext)
    if not isinstance(data, dict) or not isinstance(data.get("flows"), list):
        raise SnapshotUnreadable
    if policy.flows_checksum(data["flows"]) != row.checksum_sha256:
        raise SnapshotUnreadable
    return data


def snapshot_view(row: AutomationSnapshot) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "seq": row.seq,
        "source_id": row.source_id,
        "reason": row.reason,
        "checksum_sha256": row.checksum_sha256,
        "node_red_rev": row.node_red_rev,
        "node_red_version": row.node_red_version,
        "size_bytes": row.size_bytes,
        "node_count": row.node_count,
        "flow_count": row.flow_count,
        "credentials_present": row.has_credentials,
        "credentials_status": (row.policy_summary or {}).get("credentials_status"),
        "policy_summary": {k: v for k, v in (row.policy_summary or {}).items() if k != "credentials_status"},
        "versleuteld": "AES-256-GCM (sleutel van de kluis)",
        "created_at": iso(row.created_at),
        "created_by": row.created_by,
    }


# ---------------------------------------------------------------------------------------------------------------- diff
def _brief(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(node.get("id"))[:64],
        "type": str(node.get("type"))[:80],
        "z": str(node.get("z"))[:64] if node.get("z") else None,
    }


def diff_flows(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    """Verschil per node: toegevoegd, verwijderd, gewijzigd (alleen veldnamen). Nooit waarden."""
    a = {str(n.get("id")): n for n in before}
    b = {str(n.get("id")): n for n in after}
    added = [_brief(b[i]) for i in sorted(set(b) - set(a))]
    removed = [_brief(a[i]) for i in sorted(set(a) - set(b))]
    changed = []
    for i in sorted(set(a) & set(b)):
        if a[i] == b[i]:
            continue
        fields = sorted(k for k in set(a[i]) | set(b[i]) if a[i].get(k) != b[i].get(k))
        changed.append({**_brief(b[i]), "velden": [str(f)[:60] for f in fields][:40]})
    total = len(added) + len(removed) + len(changed)
    return {
        "toegevoegd": added[:MAX_DIFF_ROWS],
        "verwijderd": removed[:MAX_DIFF_ROWS],
        "gewijzigd": changed[:MAX_DIFF_ROWS],
        "aantallen": {
            "toegevoegd": len(added),
            "verwijderd": len(removed),
            "gewijzigd": len(changed),
            "ongewijzigd": len(set(a) & set(b)) - len(changed),
        },
        "afgekapt": any(len(x) > MAX_DIFF_ROWS for x in (added, removed, changed)),
        "gelijk": total == 0,
        "waarden_getoond": False,
    }


# ------------------------------------------------------------------------------------------------------ synchronisatie
@dataclass
class SyncResult:
    ok: bool
    changed: bool = False
    snapshot_id: str | None = None
    rev: str | None = None
    checksum: str | None = None
    flows: int = 0
    blocked: list[str] = field(default_factory=list)
    error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "gewijzigd": self.changed,
            "snapshot_id": self.snapshot_id,
            "rev": self.rev,
            "checksum_sha256": self.checksum,
            "flows": self.flows,
            "geblokkeerd": self.blocked,
            "fout": self.error,
        }


def _emit(session: Session, event_type: str, flow: AutomationFlow, trace_id: str, payload: dict[str, Any]) -> None:
    events.emit(
        session,
        event_type=event_type,
        entity_type="flow",
        entity_id=str(flow.id),
        actor_type="system",
        actor_id=SYSTEM_ACTOR,
        trace_id=trace_id,
        payload=payload,
    )


def apply_scan(
    session: Session,
    scan: policy.ScanResult,
    *,
    snapshot: AutomationSnapshot | None,
    actor: str,
    trace_id: str,
    now: datetime,
) -> list[str]:
    """Werkt het flowregister bij met de uitkomst van de scan. Geeft de bron-id's van geblokkeerde flows terug."""
    existing = {
        f.source_flow_id: f
        for f in session.scalars(select(AutomationFlow).where(AutomationFlow.source_id == SOURCE_ID))
    }
    blocked: list[str] = []
    seen: set[str] = set()
    for tab in scan.tabs:
        seen.add(tab.tab_id)
        flow = existing.get(tab.tab_id)
        if flow is None:
            flow = AutomationFlow(
                id=uuid.uuid4(),
                source_id=SOURCE_ID,
                source_flow_id=tab.tab_id[:120],
                label=tab.label,
                owner="",
                status="uitgeschakeld" if tab.disabled else "actief",
                version=0,
                disabled_in_node_red=tab.disabled,
            )
            session.add(flow)
            session.flush()
        flow.label = tab.label
        flow.disabled_in_node_red = tab.disabled
        flow.last_seen_at = now
        current = session.get(AutomationFlowVersion, flow.current_version_id) if flow.current_version_id else None
        if current is None or current.checksum_sha256 != tab.checksum:
            flow.version = (flow.version or 0) + 1
            version = AutomationFlowVersion(
                id=uuid.uuid4(),
                flow_id=flow.id,
                seq=flow.version,
                checksum_sha256=tab.checksum,
                node_types=tab.node_types,
                created_at=now,
                created_by=actor[:200],
                snapshot_id=snapshot.id if snapshot is not None else None,
                node_count=tab.node_count,
                policy_status="geblokkeerd" if tab.blocked else "in_orde",
                findings=tab.findings,
            )
            session.add(version)
            session.flush()
            flow.current_version_id = version.id
        if tab.blocked:
            blocked.append(tab.tab_id)
            if flow.status != "geblokkeerd" or flow.blocked_reason != tab.blocked_reason:
                was_blocked = flow.status == "geblokkeerd"
                flow.status = "geblokkeerd"
                flow.blocked_reason = tab.blocked_reason
                flow.blocked_at = flow.blocked_at if was_blocked and flow.blocked_at else now
                if not was_blocked:
                    _emit(
                        session,
                        "flow.policy.blocked",
                        flow,
                        trace_id,
                        {
                            "ernst": "hoog",
                            "reden": tab.blocked_reason,
                            "label": flow.label,
                            "bevindingen": tab.findings[:10],
                            "gevolg_nl": "Deze flow krijgt geen events en mag geen acties aanvragen.",
                        },
                    )
        elif flow.status == "geblokkeerd" and flow.blocked_reason in POLICY_REASONS:
            # het beleid is weer in orde: de flow blijft gepauzeerd tot een beheerder hem bewust hervat
            flow.status = "gepauzeerd"
            flow.blocked_reason = None
            flow.blocked_at = None
            _emit(
                session,
                "flow.policy.resolved",
                flow,
                trace_id,
                {"ernst": "info", "label": flow.label, "vervolg_nl": "De flow staat gepauzeerd; hervat hem zelf."},
            )
        elif flow.status in ("actief", "uitgeschakeld", "onbekend", "verwijderd"):
            flow.status = "uitgeschakeld" if tab.disabled else "actief"
    for source_flow_id, flow in existing.items():
        if source_flow_id not in seen and flow.status != "verwijderd":
            flow.status = "verwijderd"
            flow.blocked_reason = None
            flow.blocked_at = None
            revoke_tokens(session, flow.id, "flow_verwijderd", now)
    return blocked


def revoke_tokens(session: Session, flow_id: uuid.UUID, reason: str, now: datetime) -> int:
    rows = session.scalars(
        select(AutomationFlowToken).where(
            AutomationFlowToken.flow_id == flow_id, AutomationFlowToken.status == "actief"
        )
    ).all()
    for token in rows:
        token.status = "ingetrokken"
        token.revoked_at = now
        token.revoked_reason = reason[:80]
    return len(rows)


def sync(
    session: Session,
    settings: Settings,
    vault: Vault,
    transport: httpx.BaseTransport | None,
    *,
    reason: str = "gepland",
    actor: str = "worker",
    trace_id: str | None = None,
    force_snapshot: bool = False,
) -> SyncResult:
    """Leest Node-RED uit, legt een momentopname vast als er iets veranderd is en werkt het flowregister bij.

    Schrijft nooit naar Node-RED. Een fout wordt vastgelegd in de synchronisatietoestand en teruggegeven; de aanroeper
    committeert."""
    tid = trace_id or str(uuid.uuid4())
    now = utcnow()
    try:
        with client_from_source(session, settings, vault, transport) as client:
            doc = client.get_flows()
            node_sets = client.get_nodes()
            nr_settings = client.get_settings()
    except NodeRedError as exc:
        previous = state_get(session, SYNC_KEY) or {}
        state_put(
            session,
            SYNC_KEY,
            {**previous, "laatste_poging": iso(now), "fout": exc.to_dict(), "ok": False},
        )
        if exc.reason not in CONFIG_REASONS:
            # een ingestelde bron die niet (goed) antwoordt is een meting: 'down' of 'degraded', nooit de oude stand
            status = "down" if exc.reason in UNREACHABLE_REASONS else "degraded"
            _record_probe(session, now, status, exc.reason, {"http_status": exc.http_status, "path": exc.path})
        return SyncResult(ok=False, error=exc.to_dict())
    _record_probe(
        session, now, "healthy", "synchronisatie_ok", {"node_red_version": nr_settings.get("version"), "pad": "/flows"}
    )
    return record_state(
        session,
        settings,
        vault,
        doc_flows=doc.flows,
        rev=doc.rev,
        node_sets=node_sets,
        nr_settings=nr_settings,
        reason=reason,
        actor=actor,
        trace_id=tid,
        force_snapshot=force_snapshot,
        now=now,
    )


def _record_probe(session: Session, now: datetime, status: str, reason: str, detail: dict[str, Any]) -> None:
    """Elke synchronisatie is ook de gezondheidsmeting van de bron (er is geen apart liveness-pad nodig)."""
    row = source_row(session)
    if row is None:
        return
    row.last_probe_at = now
    row.last_probe_status = status
    row.last_probe_reason = reason
    row.last_probe_detail = {k: v for k, v in detail.items() if v is not None}


def record_state(
    session: Session,
    settings: Settings,
    vault: Vault,
    *,
    doc_flows: list[dict[str, Any]],
    rev: str | None,
    node_sets: list[dict[str, Any]],
    nr_settings: dict[str, Any],
    reason: str,
    actor: str,
    trace_id: str,
    force_snapshot: bool,
    now: datetime,
) -> SyncResult:
    modules = policy.type_modules(node_sets)
    result = policy.scan(doc_flows, modules, settings.node_red_allowed_modules)
    checksum = policy.flows_checksum(doc_flows)
    credentials = read_credentials(settings.node_red_data_dir)
    version = str(nr_settings.get("version"))[:40] if nr_settings.get("version") else None
    last = latest_snapshot(session)
    changed = last is None or last.checksum_sha256 != checksum or last.credentials_sha256 != credentials.sha256
    snapshot: AutomationSnapshot | None = None
    if changed or force_snapshot:
        snapshot = create_snapshot(
            session,
            vault,
            flows=doc_flows,
            rev=rev,
            credentials=credentials,
            reason=reason,
            created_by=actor,
            trace_id=trace_id,
            scan=result,
            node_red_version=version,
        )
    blocked = apply_scan(session, result, snapshot=snapshot or last, actor=actor, trace_id=trace_id, now=now)
    state_put(
        session,
        SYNC_KEY,
        {
            "ok": True,
            "laatste_poging": iso(now),
            "laatste_ok": iso(now),
            "rev": rev,
            "checksum_sha256": checksum,
            "node_red_version": version,
            "flows": len(result.tabs),
            "geblokkeerd": len(blocked),
            "credentials_status": credentials.status,
            "fout": None,
        },
    )
    return SyncResult(
        ok=True,
        changed=bool(changed),
        snapshot_id=str(snapshot.id) if snapshot is not None else None,
        rev=rev,
        checksum=checksum,
        flows=len(result.tabs),
        blocked=blocked,
    )


# --------------------------------------------------------------------------------------------------- isolatietoestand
def run_isolation_check(
    session: Session,
    settings: Settings,
    vault: Vault,
    transport: httpx.BaseTransport | None,
    *,
    trace_id: str | None = None,
) -> dict[str, Any]:
    """Meet de isolatie en legt de uitkomst vast. Een verandering naar of van ``afwijking`` geeft een event."""
    tid = trace_id or str(uuid.uuid4())
    try:
        client: NodeRedClient = client_from_source(session, settings, vault, transport)
    except NodeRedError as exc:
        report: dict[str, Any] = {
            "status": "onbekend",
            "measured_at": iso(utcnow()),
            "node_red_version": None,
            "checks": [],
            "afwijkingen": [],
            "niet_meetbaar": list(policy.NOT_MEASURABLE),
            "fout": exc.to_dict(),
            "validatie": "Niet gemeten: Node-RED is niet (volledig) ingesteld.",
        }
    else:
        with client:
            report = policy.check_isolation(client, settings.node_red_allowed_modules)
    previous = state_get(session, ISOLATION_KEY) or {}
    was_bad = previous.get("status") == "afwijking"
    is_bad = report["status"] == "afwijking"
    if is_bad and not was_bad:
        events.emit(
            session,
            event_type="automation.isolation.degraded",
            entity_type="source",
            entity_id=SOURCE_ID,
            actor_type="system",
            actor_id=SYSTEM_ACTOR,
            trace_id=tid,
            payload={"ernst": "hoog", "afwijkingen": report["afwijkingen"]},
        )
    elif was_bad and report["status"] == "gemeten_in_orde":
        events.emit(
            session,
            event_type="automation.isolation.recovered",
            entity_type="source",
            entity_id=SOURCE_ID,
            actor_type="system",
            actor_id=SYSTEM_ACTOR,
            trace_id=tid,
            payload={"ernst": "info"},
        )
    if report["status"] == "onbekend" and was_bad:
        # een onbereikbare Node-RED maakt een eerder gemeten afwijking niet goed: die blijft staan tot er opnieuw
        # in orde gemeten is
        report = {**report, "status": "afwijking", "afwijkingen": previous.get("afwijkingen", []), "verouderd": True}
    state_put(session, ISOLATION_KEY, report)
    return report


def isolation_state(session: Session, now: datetime | None = None) -> dict[str, Any]:
    """De laatst gemeten isolatie; ouder dan 15 minuten telt als ``onbekend`` (een afwijking blijft een afwijking)."""
    report = state_get(session, ISOLATION_KEY)
    if report is None:
        return {
            "status": "onbekend",
            "measured_at": None,
            "checks": [],
            "afwijkingen": [],
            "niet_meetbaar": list(policy.NOT_MEASURABLE),
            "fout": None,
            "reden": "nog_niet_gemeten",
        }
    measured = report.get("measured_at")
    try:
        at = datetime.fromisoformat(str(measured).replace("Z", "+00:00")) if measured else None
    except ValueError:
        at = None
    stale = at is None or (now or utcnow()) - at > ISOLATION_MAX_AGE
    if stale and report.get("status") == "gemeten_in_orde":
        return {**report, "status": "onbekend", "reden": "meting_verouderd"}
    return {**report, "verouderd": bool(stale) or bool(report.get("verouderd"))}


def count_flows(session: Session) -> dict[str, int]:
    rows = session.execute(
        select(AutomationFlow.status, func.count())
        .where(AutomationFlow.source_id == SOURCE_ID)
        .group_by(AutomationFlow.status)
    ).all()
    return {str(status): int(n) for status, n in rows}
