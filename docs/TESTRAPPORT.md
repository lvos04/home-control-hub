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
  echte Authentik, echte noodlogin, alle externe bronnen. Niet getest: de back-up vóór upgrade (er is nog maar één
  migratie, dus die stap wordt nog nooit geraakt).
