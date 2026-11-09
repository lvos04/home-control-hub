# ADR-0004 — Alles-in-één image en installatie als standaard Custom App

Status: aanvaard · Datum: 2026-11-09 · Fase: P0

## Context
Contract 1.1: installatie uitsluitend als standaard TrueNAS Custom App (image + tag, poort, opslag), één image per
repo met ingebouwde PostgreSQL via unix-socket, geen geheimen in het formulier, root alleen voor `/appdata`, daarna
568. Het werkende voorbeeld is `media-source-optimizer/deploy/allinone`.

## Besluit
- `deploy/allinone/Dockerfile`: PostgreSQL 16-binaries uit de officiële image (16.15) en Python 3.12.16-slim, beide op
  exacte versie **én** sha256-digest; runtime-afhankelijkheden uit `requirements.lock` (exact gepind). Geen
  setuid-bestanden in de image. De sandbox-CA wordt nooit in de image gezet: alleen een optionele BuildKit-secret.
- `supervisor.py` (onder dumb-init): rechten van `/appdata` en alleen de eigen submappen naar 568, daarna alles als
  568; first-start-init van `/appdata/secrets` (0600, nooit overschrijven); `initdb` met `--auth-host=reject` en
  `listen_addresses=''`; `pg_dump` vóór openstaande migraties (nieuwste 3); duidelijke NL-fouten; herstart met backoff.
- Healthcheck = `GET /readyz` (database, migraties, geheimen). Niet gekoppeld zijn is géén healthcheck-fout: de dienst
  werkt en toont dat eerlijk.
- `deploy/dev/compose.yaml` bestaat alleen voor ontwikkeling/CI; `deploy/truenas/CUSTOM_APP.md` beschrijft de velden
  van het standaard formulier; het manifest heeft `install.method: custom_app` en geen `compose`-veld.

## Gevolgen
- `no-new-privileges` en capabilities zijn in het standaard formulier (voor zover bekend) niet volledig in te stellen;
  de image heeft daarom zelf geen setuid-bestanden en vraagt geen extra capabilities. Te verifiëren op echte TrueNAS.
- Terugdraaien met alleen een tag-wissel is na een schemawijziging niet veilig; de releasenotes melden dat per versie.
