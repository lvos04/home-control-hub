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
- **Blokkeren bij mislukken** (vorm A, besluit van de gebruiker 2026-11-12, R-VEILIG-8): loopt de synchronisatie vast
  nadat Node-RED antwoordde (een uitzondering bij het lezen, in de scan, het flowregister of de opslag), dan zet een
  aparte transactie elke flow van de bron op ``geblokkeerd`` met reden ``synchronisatie_mislukt`` en de stand op
  ``ok: false``. Nooit de oude stand; na een geslaagde synchronisatie blijven die flows gepauzeerd tot een beheerder
  of operator ze hervat. Een :class:`NodeRedError` (onbereikbaar, te groot antwoord, 5xx, ongeldige JSON) valt hier
  niet onder: dan blijft de stand van de flows staan en is alleen de synchronisatie ``ok: false``.
- **Eén slot op het flowregister** (R-VEILIG-9): de synchronisatie, het blokkeren bij mislukken en het herstel in
  ``restore.py`` nemen eerst :func:`lock_register`, vóór ze :func:`latest_snapshot` en het flowregister lezen. Zo
  schrijven een herstel en de worker nooit tegelijk dezelfde flowversie (zonder slot gaf dat een uniekheidsfout en
  legde het blokkeren bij mislukken alle flows stil), en blokkeert het blokkeren bij mislukken altijd de nieuwste
  stand. Wat het slot per plek doet staat bij :func:`lock_register`.
- **Proefrun bij blokkeren:** raakt een flow geblokkeerd (flowbeleid in :func:`apply_scan`, of blokkeren bij
  mislukken in :func:`block_every_flow`), dan wordt zijn lopende proefrun direct afgesloten
  (``simulate.close_for_block``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
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
#: reden van een flow die geblokkeerd is omdat de synchronisatie vastliep (vorm A, R-VEILIG-8)
SYNC_FAILED = "synchronisatie_mislukt"
#: redenen van het flowbeleid en van een vastgelopen synchronisatie: is de oorzaak weg, dan wordt de flow gepauzeerd
#: (nooit vanzelf weer actief)
POLICY_REASONS = (*policy.BLOCK_REASONS, SYNC_FAILED)
SYSTEM_ACTOR = "home-control-hub"
#: vaste sleutel van het transactieslot op het flowregister (``pg_advisory_xact_lock``, R-VEILIG-9); afgeleid van een
#: vaste tekst, zodat geen ander slot in deze database dezelfde sleutel heeft
REGISTER_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"home-control-hub:automation:flowregister").digest()[:8], "big", signed=True
)

log = logging.getLogger("integrations.automation")


def lock_register(session: Session) -> None:
    """Neemt het slot op het flowregister voor de rest van de transactie (R-VEILIG-9).

    Wie het neemt en waarom (de tests staan in ``tests/integration/test_b11_005_herstel.py``):

    - de synchronisatie, vóór het uitlezen van Node-RED, zodat het register Node-RED in commitvolgorde volgt;
    - ``restore._finish_apply``, vóór :func:`record_state`: samen met het slot in de synchronisatie schrijven een
      herstel en de worker zo nooit tegelijk dezelfde flowversie. Test:
      ``test_a_restore_and_the_worker_at_the_same_time_block_nothing``;
    - het blokkeren bij mislukken (:func:`_block_after_failure`): na de rollback van de synchronisatie kan een herstel
      het slot nemen; het blokkeren wacht dan op diens commit en blokkeert de nieuwe stand, in plaats van een oude
      stand te lezen en een flow open te laten. Test:
      ``test_blocking_after_a_failed_sync_waits_for_a_restore_that_holds_the_register_lock``;
    - ``restore.apply``, vóór de goedkeuring en de readback, tot en met de commit van de momentopname
      ``voor_herstel``. Apply schrijft daar zelf nog geen flowversie; het slot houdt een synchronisatie en een
      handmatige momentopname tegen tot die commit, zodat die Node-RED pas daarna uitlezen. Test:
      ``test_while_a_restore_holds_the_register_lock_the_worker_and_a_snapshot_wait``.

    Een tweede houder wacht tot de eerste gecommit of teruggedraaid is. Daarna leest hij altijd de nieuwe stand:
    eerst gaat wat nog openstaat naar de database (``flush``), daarna vervalt wat de sessie nog in het geheugen had
    (``expire_all``; de sessies hebben ``expire_on_commit=False``). Het slot vervalt vanzelf bij commit of
    rollback."""
    session.flush()
    session.execute(select(func.pg_advisory_xact_lock(REGISTER_LOCK_KEY)))
    session.expire_all()


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
    ``credentialSecret``) wordt bewust niet meegenomen: dat is een afwijking van het beveiligingsprofiel.

    Node-RED schrijft zelf in die datamap; daarom wordt het bestand nooit via een symbolische koppeling gevolgd
    (``O_NOFOLLOW`` ten opzichte van de geopende map), moet het een gewoon bestand zijn (``fstat``; een FIFO blokkeert
    door ``O_NONBLOCK`` niet) en wordt er hooguit ``MAX_CRED_BYTES`` + 1 byte gelezen. Anders: ``onleesbaar``."""
    if data_dir is None:
        return CredentialsBlob("niet_gekoppeld")
    dir_fd: int | None = None
    fd: int | None = None
    try:
        try:
            dir_fd = os.open(data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            fd = os.open(CRED_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
            return CredentialsBlob("afwezig")
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CRED_BYTES:
            return CredentialsBlob("onleesbaar")
        chunks: list[bytes] = []
        size = 0
        while size <= MAX_CRED_BYTES:
            chunk = os.read(fd, min(65536, MAX_CRED_BYTES + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_CRED_BYTES:
            return CredentialsBlob("onleesbaar")
        data = json.loads(b"".join(chunks).decode("utf-8"))
    except (OSError, ValueError):
        return CredentialsBlob("onleesbaar")  # o.a. een symbolische koppeling (ELOOP) of een onleesbare map
    finally:
        for open_fd in (fd, dir_fd):
            if open_fd is not None:
                os.close(open_fd)
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
        flow_count=sum(1 for n in flows if isinstance(n, dict) and n.get("type") == "tab"),
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
    # een element dat geen object is, telt niet als node; de flowscan blokkeert zo'n configuratie (vorm_ongeldig)
    a = {str(n.get("id")): n for n in before if isinstance(n, dict)}
    b = {str(n.get("id")): n for n in after if isinstance(n, dict)}
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


def _close_dry_runs(session: Session, flow: AutomationFlow, now: datetime) -> None:
    """Een geblokkeerde flow heeft geen proefrun meer: een proefrun die nog loopt wordt direct afgesloten
    (``simulate.close_for_block``; R-TECH-1 en R-VEILIG-2 van S-P2-300). Pas hier geladen, omdat ``simulate`` via
    ``inbox`` deze module nodig heeft."""
    from . import simulate

    simulate.close_for_block(session, flow, now=now)


def apply_scan(
    session: Session,
    scan: policy.ScanResult,
    *,
    snapshot: AutomationSnapshot | None,
    actor: str,
    trace_id: str,
    now: datetime,
) -> list[str]:
    """Werkt het flowregister bij met de uitkomst van de scan. Een proefrun van een geblokkeerde flow wordt afgesloten
    (:func:`_close_dry_runs`). Geeft de bron-id's van geblokkeerde flows terug."""
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
            _close_dry_runs(session, flow, now)
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


def block_every_flow(session: Session, *, trace_id: str, now: datetime) -> list[str]:
    """Zet elke flow van de bron die nog bestaat op ``geblokkeerd`` met reden :data:`SYNC_FAILED` (een verwijderde flow
    blijft verwijderd: hij heeft geen token meer en krijgt niets). Per flow die nog niet geblokkeerd was gaat een event
    ``flow.policy.blocked`` naar de Hub. Een proefrun die nog loopt wordt afgesloten (:func:`_close_dry_runs`). Geeft
    de bron-id's van de geblokkeerde flows terug."""
    reason = SYNC_FAILED
    blocked: list[str] = []
    rows = session.scalars(
        select(AutomationFlow)
        .where(AutomationFlow.source_id == SOURCE_ID, AutomationFlow.status != "verwijderd")
        .order_by(AutomationFlow.source_flow_id)
    ).all()
    for flow in rows:
        blocked.append(flow.source_flow_id)
        was_blocked = flow.status == "geblokkeerd"
        if was_blocked and flow.blocked_reason == reason:
            _close_dry_runs(session, flow, now)
            continue
        flow.status = "geblokkeerd"
        flow.blocked_reason = reason
        flow.blocked_at = flow.blocked_at if was_blocked and flow.blocked_at else now
        if not was_blocked:
            _emit(
                session,
                "flow.policy.blocked",
                flow,
                trace_id,
                {
                    "ernst": "hoog",
                    "reden": reason,
                    "label": flow.label,
                    "bevindingen": [],
                    "gevolg_nl": "De synchronisatie met Node-RED is vastgelopen: deze flow krijgt geen events en mag "
                    "geen acties aanvragen tot een synchronisatie weer slaagt en een beheerder hem hervat.",
                },
            )
        _close_dry_runs(session, flow, now)
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

    Schrijft nooit naar Node-RED. Een :class:`NodeRedError` wordt vastgelegd in de synchronisatietoestand en
    teruggegeven; de aanroeper committeert. Elke andere uitzondering (bij het lezen, bijvoorbeeld een RecursionError
    uit ``json.loads``, of in de scan, het flowregister of de opslag) wordt teruggedraaid en daarna blokkeert een
    aparte, hier gecommitte transactie alle flows (:func:`_block_after_failure`).

    Neemt eerst het slot op het flowregister (:func:`lock_register`, R-VEILIG-9), vóór het uitlezen van Node-RED: een
    herstel dat tegelijk loopt, wacht of wordt afgewacht."""
    tid = trace_id or str(uuid.uuid4())
    lock_register(session)
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
    except Exception as exc:  # o.a. RecursionError uit NodeRedClient._json: dicht, nooit de oude stand
        return _block_after_failure(session, exc, trace_id=tid, now=now)
    try:
        _record_probe(
            session,
            now,
            "healthy",
            "synchronisatie_ok",
            {"node_red_version": nr_settings.get("version"), "pad": "/flows"},
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
    except Exception as exc:  # scan, flowregister of opslag: dicht, nooit de oude stand
        return _block_after_failure(session, exc, trace_id=tid, now=now)


def _block_after_failure(session: Session, exc: Exception, *, trace_id: str, now: datetime) -> SyncResult:
    """Vorm A ("blokkeren bij mislukken", besluit van de gebruiker 2026-11-12, R-VEILIG-8). Het half gedane werk wordt
    teruggedraaid (ook een afgebroken databasetransactie); daarna zet een **aparte** transactie elke flow van de bron
    op ``geblokkeerd`` (:data:`SYNC_FAILED`), de synchronisatie op ``ok: false`` en de meting van de bron op
    ``degraded``, en commit die meteen: de blokkade blijft ook staan als de aanroeper daarna iets terugdraait. Alleen
    de soort uitzondering wordt bewaard en gelogd, nooit de tekst (die kan inhoud van de configuratie bevatten). Lukt
    ook dat niet, dan gaat de uitzondering door (de worker meldt de stap dan als mislukt). De rollback geeft ook het slot
    op het flowregister vrij; de aparte transactie neemt het opnieuw (R-VEILIG-9). Heeft een herstel het slot in dat
    venster genomen, dan wacht het blokkeren op diens commit en blokkeert het de stand van daarna (zie
    :func:`lock_register`)."""
    session.rollback()
    kind = type(exc).__name__[:80]
    error: dict[str, Any] = {"reason": SYNC_FAILED, "http_status": None, "path": None, "uitzondering": kind}
    try:
        lock_register(session)
        blocked = block_every_flow(session, trace_id=trace_id, now=now)
        previous = state_get(session, SYNC_KEY) or {}
        state_put(
            session,
            SYNC_KEY,
            {**previous, "ok": False, "laatste_poging": iso(now), "geblokkeerd": len(blocked), "fout": error},
        )
        _record_probe(session, now, "degraded", SYNC_FAILED, {"uitzondering": kind})
        session.commit()
    except Exception:
        session.rollback()
        raise
    log.warning("synchronisatie met Node-RED vastgelopen (%s): %d flows geblokkeerd", kind, len(blocked))
    return SyncResult(ok=False, blocked=blocked, error=error)


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
