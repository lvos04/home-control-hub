# Beheer, updates, CI/CD en rollback

## App lifecycle
`discovered → inventory → risk-evaluated → backed-up → staged → tested → approved → deployed → observed → accepted` of `rolled_back`. Versies gepind op digest of semver; nooit blind `latest` deployen. Voor custom/private GHCR packages controleer image-pull met autorisatie, geen geheimen in compose.

## Releasebeheer
- Test op PR: lint, typecheck, unit, DB-schema-migratie, contracttest, security scan, 360/390/768/1440 UI, E2E met mocks.
- Test bij release: echte image-start, health, init op lege data, migratie op kopie van oudere DB, terugzetproef, shutdown terwijl jobs lopen, restart van status.
- Eerst canary met nietkritieke module; kritieke subsystemen alleen na terugvalplan en goedgekeurde change window.
- CI cache, testvouchers en release lock. Maak reproducerbare builds en SBOM; repositories privé waar nodig.

## Monitoring
Actuele uptime, response, background job lag, dead letters, pool degraded, disks SMART, GPU queue stall, backup age, credential expiry, API credits en security alerts. Eén inbox met dedupe/correlation/snooze en readback, geen pushstorm. Onbereikbare bron is expliciet `unknown`, nooit `healthy` op stale cache.

## Incident & herstel
Runbooks per: service offline, database migration failed, quota/disk full, bad deployment, Tailscale/Cloudflare lockout, Jellyfin client compatibility issue, Gree device unknown, MSO provider outage. Iedere runbook bevat observeren → isoleren → mitigeren → rollback → bewijs verzamelen → oorzaak vastleggen.
