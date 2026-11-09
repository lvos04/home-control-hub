# Storage, resources, backup en restore

## Datasetvoorstel (geen echte poolnaam invullen)
`/mnt/<POOL>/apps/home-control-hub`, `/mnt/<POOL>/apps/home-control-hub-db`, `/mnt/<POOL>/apps/observability`, `/mnt/<POOL>/apps/workflow`, `/mnt/<POOL>/apps/security`, `/mnt/<POOL>/apps/search-index`, `/mnt/<POOL>/apps/jellyfin-fork`. Bestaande MediaGuard/MSO/my_house/Immich/Jellyfin-datasets niet verplaatsen tenzij migratie met back-up, dry-run en hersteltest is geautoriseerd.

## Workloadbeleid
- A310: media-encode/transcode als eerste, af te bakenen per job; UHD 770 alternatieve decode/transcode waar ondersteund. Codec/driver/ffmpeg-capabilities op echte TrueNAS controleren.
- CPU/RAM: reserve voor TrueNAS/ZFS ARC; resource limits per container, queue jobs (AV1/backups/AI indexing), platform laat RAM aan OS en ARC; geen hardcoded 100%-CPU-usage.
- Laat media en download-workloads op hun bestaande paden; gebruik voor transcodes en tijdelijke AI-indexering aparte beperkte scratch met vrijeruimtedrempel.

## Back-uplagen
1. Applicatie-eigen database-export met toepasselijke consistency guarantee (Postgres `pg_dump` of app-native, SQLite consistent backup). Geen simpele live bestandskopie van DB.
2. ZFS-snapshot van configuratie/appdata datasets, periodiek en vóór elke migratie.
3. Bestaande OneDrive-offsite kopie: controleer of nieuwe datasets, secrets (versleuteld), app exports, audit en recovery keys meegenomen worden. Foto's en appdatabases bestaan al, maar verificatiestatus is onbekend.
4. Implementeer hersteltest naar tijdelijke aparte dataset/container zonder productie te overschrijven; plan elk kwartaal en na grote schema-updates.
5. Beheer retentie en back-updatagroei per soort data; mediafiles apart beleid, duplicatie niet verplicht als opslag ontbreekt, maar risico expliciet accepteren.

## Gate voor risicovolle acties
- Preflight toont laatst geslaagde externe back-up, laatste restore-test, leeftijd van herstelpunt, ZFS pool health, vrije ruimte en benodigde snapshotruimte.
- AI mag nooit 'back-up geslaagd' markeren op alleen een exitcode; checksum, decodeerbaarheid of DB consistency moet waarneembaar zijn.
- Bij niet herstelbare data faalt deployment of blijft in read-only modus.
