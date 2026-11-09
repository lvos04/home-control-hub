# Programma-fasering en harde doorgangsgates

## Fase P0 — Inspecteren en herstellen
**Doel:** documenteer bestaande productie, gebruik, datasetindeling, actuele image-tags, NAS-versie, hardware rendernodes, auth, bestaande OneDrive kopie en afhankelijke apps. Maak eerste ZFS-snapshots plus geslaagde restore-test van foto en een appdatabase.
**Opgeleverd:** inventaris, opslagplattegrond, data-eigenaarschap, source/version register, RPO/RTO-doelen en testbackup.
**No-go:** onduidelijke datamap, onherstelbare belangrijke data of storage in degraded state.

## Fase P1 — Ogen en toegang
**Doel:** installeer Beszel, Uptime Kuma en Gotify; maak onafhankelijke app-heartbeats en kritieke meldingen. Zet basis Hub read-only aan; Authentik OIDC zodra loginroute voorbereid is.
**Opgeleverd:** appcatalogus, NAS CPU/RAM/GPU/disk, uptime, alert bij app offline, secure mobile access.
**No-go:** GUI toont oude data als gezond, management staat op publiek internet, eigen agents op mini-pc.

## Fase P2 — Veilig automatiseren
**Doel:** risk policy, acties met diff/TTL, limited executor, dry-run, staged updates, Node-RED integration.
**Opgeleverd:** goedgekeurde R1-restart, audit, rollback en blokkade van R3 zonder toestemming.
**No-go:** AI kan rechtstreeks shell/sudo, policy overruled door model, DB backup onbekend.

## Fase P3 — Eigen apps koppelen
**Doel:** MediaGuard v1.2.2, MSO 1.5.0/1.6 kandidaat en my_house v0.1.0 live API contracten; actual hardware/live accounts testen. Integratie met Hub.
**Opgeleverd:** één incident en downloadketen, één smart-home paneel, energy provenance; bestaande eigen app DB behouden.
**No-go:** wijzigingen aan Prowlarr/SABnzbd vanuit twee eigenaren, boiler schakelen, ongeteste Gree aansturing.

## Fase P4 — Universele mediaplatform
**Doel:** Jellyfin plugin/adapter eerst, daarna minimaal onderhouden fork, streaming matrix, A310 scheduling, scene search, live-tv/DVR, offline apps waar haalbaar.
**Opgeleverd:** echte playbacktests, TV/client compat, intacte watch history, MediaGuard request links.
**No-go:** upstream clients breken, HDR/DV verlies, media mutatie buiten MediaGuard, Jellyfin direct verwijderen.

## Fase P5 — Netwerk, persoonlijke AI, kosten en uitbreiding
**Doel:** AdGuard pilot, NetAlertX discovery, zoekindex, spraak (opt-in), energie- en kostenanalyse, nieuwe appcatalogus en uitbreidbare connectors.
**Opgeleverd:** veilige DNS fallback, per-bron indexrechten, opt-in lokale STT/TTS, geen overage.
**No-go:** router lockout, AI leaks via RAG, automatische credentials naar internet.

## Fase P6 — Oplevering en beheer
Regressies, releasegates, herstelproef, mobiele E2E, 72h soak, update/rollback, documentatie, metrics vergelijking en alleen dan productieacceptatie.

## Gate matrix
| Voorwaarde | Verplichting voor volgende fase |
|---|---|
| NAS versie/pool bekend | Altijd |
| OneDrive foto en DB restore getest | Voor mutaties aan bestaande data en upgrades |
| ZFS snapshots en pre-change database-export | Voor schema- en infrastructuurwijzigingen |
| Risk policy + privileged executor tested | Voor autonome writes |
| MediaGuard/MSO API contract live verified | Voor downloadgerelateerde acties |
| my_house fysieke apparaten gevalideerd | Voor climate actuation |
| Jellyfin client/GPU testmatrix geslaagd | Voor universele mediaserver cutover |
| DNS rollback route getest | Voor routerwijzigingen |
| 0 paid API overage en monitor | Voor AI in productie |
