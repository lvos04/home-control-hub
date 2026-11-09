# Testrapport P0 — home-control-hub 0.1.0 (2026-11-09)

Omgeving: Linux-bouwomgeving (4 CPU, gedeeld), Python 3.12.3 (venv), PostgreSQL 16 + pgvector op 127.0.0.1:5432
(databases `hch_test_api`, `hch_test_migrations`, `hch_test_e2e`), Docker met buildx. Geen echte NAS, Hub, Authentik,
NetAlertX, AdGuard Home, Node-RED of HomeWizard-meters: die worden gesimuleerd of zijn niet gebouwd.

| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check . && mypy` | geen bevindingen (51 bronbestanden, mypy ok) |
| `ruff check tests/e2e deploy/allinone && ruff format --check tests/e2e deploy/allinone` | geen bevindingen |
| `cd apps/api && pytest -q` (unit + integratie, PostgreSQL) | **133 geslaagd** (88 unit, 45 integratie) |
| `pytest -q tests/e2e -p no:cacheprovider` (API + worker als echte processen, Hub-simulator in eigen proces) | **6 geslaagd** |
| `python -m integrations migrate` → `migrate --down base` → `migrate` | op/neer/op zonder fouten; drifttest: geen verschil |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| `docker buildx build -f deploy/allinone/Dockerfile -t home-control-hub:dev .` | gebouwd (± 436 MB) |
| `deploy/allinone/smoke-test.sh home-control-hub:dev` | **17 geslaagd, 0 mislukt** |

## Wat de rooktest van de image controleert
Start als root op een root-map → healthcheck *healthy*; `/healthz`, `/readyz`; statuspagina *niet gekoppeld*; 401
zonder token; geen proces als root behalve dumb-init/bewaker; PostgreSQL, API en worker als 568; geen TCP-poort voor
PostgreSQL; geheimen 0600/568; ontkoppelcode in de log; geen setuid-bestanden; herstart met behoud van geheimen; harde
kill en herstart; start als 568; duidelijke NL-fout bij verkeerde rechten.

## Validatieniveau
- Sim-getest: B13-001 (inclusief *Authenticator offline → noodtoegang blijft testbaar*), koppelen, fail-closed (EX16-deel).
- Unit-getest: datamodellen/inventaris B10/B11/B14.
- **NIET GEVALIDEERD (echte NAS/account/hardware):** installatie via het TrueNAS-formulier, echte Hub-koppeling,
  echte Authentik, echte noodlogin, alle externe bronnen. (De back-up vóór upgrade is sinds de review wel getest met
  een testrevisie en echte `pg_dump`; zie hieronder.)

## Onafhankelijke review P0 (2026-11-09)

Opnieuw gedraaid zoals de CI het doet, daarna gerepareerd en opnieuw gedraaid (zie ADR-0006). Eindstand:

| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check . && mypy` | geen bevindingen (52 bronbestanden, mypy ok) |
| `ruff check tests/e2e deploy/allinone && ruff format --check tests/e2e deploy/allinone` | geen bevindingen |
| `cd apps/api && pytest -q` (unit + integratie, PostgreSQL) | **218 geslaagd** (92 unit, 126 integratie, waarvan 81 in `test_review_p0.py`) |
| `pytest -q tests/e2e -p no:cacheprovider` | **7 geslaagd** (3× achter elkaar gedraaid, niet wisselvallig) |
| `python -m integrations migrate` → `migrate --down base` → `migrate` (database `hch_ci_mig`) | op/neer/op zonder fouten |
| `python -m integrations openapi --out …` + `git diff --exit-code docs/openapi/` | geen drift |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| `actionlint .github/workflows/*.yml` (actionlint-py 1.7.12, zonder shellcheck) | geen bevindingen |
| `nice -n 10 docker buildx build --load --network host --secret id=ca_bundle,… -f deploy/allinone/Dockerfile -t home-control-hub:review .` | gebouwd (± 436 MB) |
| `deploy/allinone/smoke-test.sh home-control-hub:review` | **23 geslaagd, 0 mislukt** |

### Gevonden en gerepareerd
- **Back-up vóór migratie was niet fail-closed:** mislukte `pg_dump` → migratie ging toch door. Nu: geen migratie,
  app stopt met melding (`test_migration_refused_when_backup_fails`, `test_backup_before_migration_with_real_pg_dump`;
  de stap was eerder helemaal niet getest).
- **Geen grens op de verzoekgrootte:** FastAPI las grote bodies vóór de auth. Nu 413 boven 1 MiB, ook chunked
  (integratie, dienst-E2E en rooktest).
- **Herstelkit openen:** scrypt-parameters tot ruim 2 GiB geheugen per verzoek en een 500 bij een ongeldige nonce of
  `n`. Nu begrensd, nette 422.
- **Statuspagina** (zonder login) toonde aantal beheeraccounts en aandachtspunten van het herstelregister; nu alleen
  het totaalniveau.
- **Ongebruikte instellingen** `HCH_TRUSTED_PROXIES`/`HCH_EMERGENCY_ADMIN_MAX_DAYS` verwijderd.
- **Tests konden stil wegvallen:** zonder PostgreSQL werden integratie/E2E overgeslagen; in CI falen ze nu hard.
- **EVIDENCE.json:** taken zonder enige test stonden op *Unit-getest*; nu eerlijk *Niet getest: alleen datamodel*.
  B13-002 ontbrak en is toegevoegd (Niet gestart).

### Extra afgedekt
Route-sweep uit de OpenAPI-export (elke route 401 zonder/ongeldig token, 403 voor rol `kind`, Idempotency-Key op
elke mutatie), JWT-randgevallen (ontbrekende claims, `iat`/`nbf` in de toekomst, lege/onbereikbare JWKS, rol
`service` niet claimbaar), B13-003 (geen header-SSO), eenmalig enrollment-token na ontkoppelen/herstart en nooit in
de log, B10-002 in het datamodel. Rooktest nu met `--cap-drop ALL` + alleen CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID
en `no-new-privileges`, plus databasegegevens behouden na herstart en harde kill en een werkende `pg_dump`.

### Nog steeds NIET GEVALIDEERD
Installatie via het echte TrueNAS-formulier (en of TrueNAS de vijf capabilities toestaat), echte Hub, echte
Authentik, echte noodlogin in de Hub, alle externe bronnen; CI is niet op GitHub gedraaid (alleen lokaal).
