# home-control-hub

Integratiedienst van **TrueNAS Home Platform V2**: B10 netwerk/privacy, B11 Node-RED, B13 Authentik/SSO (met
beheerherstel B13-001) en B14 energie/resources. Een zelfstandige API-dienst met alleen een kleine Nederlandse
statuspagina; alle schermen staan in de Hub (`ai-server-manager`).

**Status (fase P0):** kern volgens de platformcontracten 1.1 + B13-001 (accountrecovery en admin-toegang) gebouwd en
met simulators getest. B10/B11/B14 hebben in P0 alleen datamodel en inventaris; hun data-endpoints geven eerlijk
`501 capability_unavailable`. **Niets is op een echte NAS gevalideerd** (zie `docs/platform-v2/EVIDENCE.json`).

## Installeren

Uitsluitend als **standaard TrueNAS Custom App** (image + tag, poort `30420`, opslag `/appdata`) — geen YAML, geen
compose, geen terminal. Normaal installeert het platform deze app via de TrueNAS-API. Zie
[`deploy/truenas/CUSTOM_APP.md`](deploy/truenas/CUSTOM_APP.md) en het manifest
[`deploy/manifest/home-control-hub.manifest.yaml`](deploy/manifest/home-control-hub.manifest.yaml).

## Wat erin zit

| Onderdeel | Waar |
|---|---|
| API (`/integrations/v1`), connectorcontract (`/connector/v1`), `/healthz`, `/readyz`, statuspagina `GET /` | `apps/api/src/integrations/` |
| Auth: Hub-JWT (EdDSA) via JWKS-cache, fail-closed; service-token uit de enrollment | `security/auth.py`, `security/jwks.py` |
| Koppelen met de Hub: eenmalig token (worker) of koppelcode op de statuspagina | `enrollment.py`, `status_page.py` |
| B13-001: herstelregister, noodtoegang LAN/VPN, zelftest met Authentik offline, versleutelde herstelkit | `domains/sso/` |
| B10/B11/B14: datamodellen met database-invarianten en inventaris (alles *te verifiëren*) | `domains/network`, `automation`, `energy` |
| Migraties (Alembic) | `apps/api/alembic/` |
| Alles-in-één image (PostgreSQL 16 via unix-socket + API + worker, procesbewaker, root → 568) | `deploy/allinone/` |
| OpenAPI | `docs/openapi/home-control-hub.openapi.json` |
| Besluiten | `docs/adr/` |
| Noodprocedure (gebruikers) | `docs/runbooks/NOODTOEGANG.md` |

## Ontwikkelen

```sh
python3.12 -m venv .venv && .venv/bin/pip install -e 'apps/api[dev]'
make lint test e2e          # ruff, mypy, unit + integratie (PostgreSQL), dienst-E2E met simulator
make image smoke            # alles-in-één image bouwen en rooktest (start, healthcheck, herstart, kill, rechten)
make openapi                # OpenAPI opnieuw exporteren (CI faalt bij drift)
```

Integratietests gebruiken een lokale PostgreSQL 16 (`HCH_TEST_ADMIN_URL`, standaard `postgres@127.0.0.1:5432`) met
databases `hch_test_*`. `deploy/dev/compose.yaml` is alleen voor ontwikkeling — **geen** installatiemethode.

Geen licentie toegevoegd (keuze van de eigenaar).
