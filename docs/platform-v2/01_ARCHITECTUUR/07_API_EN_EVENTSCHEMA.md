# Technische contracten (voorstellen, niet huidige API-claims)

## Hub event envelope
```json
{"schema_version":"1.0","event_id":"<uuid>","source_app":"mediaguard","source_event_id":"<source-id>","event_type":"media.download.failed","timestamp_utc":"2026-11-09T04:00:00Z","trace_id":"<uuid>","entity":{"type":"media_item","id":"<safe-id>"},"classification":"internal","payload":{"error_code":"no_articles","confidence":0.82}}
```
De source verbindt zijn originele ID; alleen geschoonde strings en beperkte velden. Sources zonder native events via polling met cursor; minimaal één idempotency check.

## Actievoorstel (Hub → Policy → Executor)
```json
{"idempotency_key":"<uuid>","action_id":"app.restart","target":{"host_id":"nas-primary","app_id":"uptime-kuma"},"parameters":{"grace_seconds":30},"reason":"service unresponsive","actor":"operator-123","expected_version":"<digest>","risk_claim":"R1","evidence_ids":["evt-123"],"expires_in_seconds":300}
```
**Policy server (niet de AI)** bepaalt uiteindelijke risicoklasse. Verwijdering, credential export, routerwijziging, ZFS vernietiging en permissions wijziging vereisen per diff menselijke toestemming. Het systeem mag geen `shell.exec` tool aanbieden aan AI.

## Approval record
`approval_id`, `request_id`, `preview_hash`, `resource_etag`, `risk_class`, `approved_by`, `approved_at`, `expires_at`, `one_time_nonce`, `backup_checkpoint_id`, `action_scope`. Gaat één van de gebonden eigenschappen veranderen, dan vervalt de goedkeuring.

## Connector contracts
- `discover()` → capabilities + schema_version, source_version, permissions, timestamp.
- `read_health()` → status `healthy/degraded/down/unknown`, timestamp, reason_code.
- `read_items(cursor)` → owned data only, pagination, read scopes.
- `propose(action)` → preview; `apply(approved_request)` → exact target readback; `rollback(checkpoint)` waar door eigenaar ondersteund.
- `get_evidence(id)` → beperkte redacted records zonder secrets.

## Compatibiliteitsregels
1. MediaGuard is bibliotheekeigenaar, MSO leest/adviseert en zoekt via eigen allowed route; Prowlarr native sync blijft bij eigenaar.
2. my_house is eigenaar van fysieke commands en readback; de Hub overschrijft geen safety invariant.
3. TrueNAS API per versie; geen stringly-typed command injection en geen deprecated REST aannames.
4. Auth/SSO alleen werkelijk aangeboden app-interface, bij ontbreken houden we native login.
5. De Hub behoudt privacy van Immich metadata; bron ACL wordt ook in zoekindex afgedwongen.
