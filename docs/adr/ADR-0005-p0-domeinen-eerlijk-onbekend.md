# ADR-0005 — P0-domeinen B10/B11/B14: datamodel en inventaris, de rest eerlijk onbekend

Status: aanvaard · Datum: 2026-11-09 · Fase: P0

## Context
In P0 zijn NetAlertX, AdGuard Home, Node-RED, Authentik en de energiebronnen niet geïnstalleerd of niet gemeten;
NAS-gegevens D01–D18 zijn onbekend. Het contract verbiedt gesimuleerd succes en voorbeeldwaarden als echte waarden.

## Besluit
- Per domein een **inventaris** (`catalog.py`) van verwachte bronnen en capabilities, gekoppeld aan Excel-taak-ID's.
  Wat een externe app kan (API, OIDC, health-pad) staat op `te_verifieren`; geen enkele app staat op "ondersteunt OIDC".
- **Datamodel** voor B10/B11/B14 als schema met invarianten in de database, zonder data.
- Data-endpoints die nog niet gebouwd zijn geven `501 capability_unavailable` (nooit een lege lijst, want die zou
  "geen apparaten"/"geen verbruik" suggereren). Bronnen zonder configuratie hebben health `unknown`.
- De energie-dekkingsmatrix toont de verwachte meterrollen uit D14 met status `onbekend`; de boiler-socket is altijd
  alleen-lezen. Node-RED: de exec-node staat op de verbodslijst (typenaam te verifiëren tegen de Node-RED-docs).
- Liveness-probe alleen voor Authentik (`/-/health/live/`, pad te verifiëren); voor andere bronnen 501.

## Gevolgen
- In de Excel staan alleen de F0-taken op *Bezig*; latere taken blijven *Niet gestart* (alleen schemavoorbereiding).
