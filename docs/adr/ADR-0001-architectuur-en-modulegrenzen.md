# ADR-0001 — Architectuur en modulegrenzen

Status: aanvaard · Datum: 2026-11-09 · Fase: P0

## Context
`home-control-hub` bundelt vier integratiedomeinen (B10 netwerk/privacy, B11 Node-RED, B13 Authentik/SSO, B14
energie/resources). De gebruiker koos vast voor Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL 16; alle
schermen staan in de Hub; deze dienst heeft alleen een kleine statuspagina (contract §1, §10).

## Besluit
- Eén pakket `integrations` (`apps/api/src/integrations`) met een gedeelde kern (config, db, foutformaat, auth,
  enrollment, idempotency, audit, outbox, connector, statuspagina) en per domein een eigen module
  `domains/<domein>/{models,catalog,router}.py` met tabellen met domeinprefix (`network_`, `automation_`, `sso_`,
  `energy_`). Een domein muteert nooit tabellen van een ander domein.
- Synchrone SQLAlchemy (psycopg 3) en synchrone FastAPI-handlers: eenvoudiger, ruim voldoende voor de verwachte last.
- Invarianten die veiligheid raken staan als CHECK-constraints in de database (bv. malware alleen met bewijs, meters
  altijd alleen-lezen, noodaccount nooit SSO-only), zodat ook toekomstige code ze niet kan omzeilen.
- Api-prefix `/integrations/v1`, connectorcontract `/connector/v1` (contract §5/§6), poort 30420 (contract §2).
- Één alles-in-één image (ADR-0004). Worker en API zijn aparte processen; ze delen alleen de database.

## Gevolgen
- Domeinen kunnen later apart groeien (adapters per bron) zonder de kern te raken.
- Alembic-migraties dekken alle domeinen; een drifttest bewaakt dat modellen en migraties gelijk blijven.
