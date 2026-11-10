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

## P1 — B13-002…005 (2026-11-09, Ubuntu 26.04-bouwmachine)

Omgeving: eigen Ubuntu 26.04-machine (22 CPU, 14,5 GiB RAM, gedeeld), Python 3.12.16 (venv), PostgreSQL 16.15 op
127.0.0.1:5432 (databases `hch_test_*`, `hch_ci_mig`), Docker Engine met buildx (image-builds via
`flock …/docker-build.lock nice -n 10`). Geen echte NAS, Hub, Authentik of domeinnaam (D17): de Hub en Authentik
zijn simulators (`tests/e2e/sim_hub.py`, `apps/api/tests/fakes/authentik_fake.py`).

### Nulmeting (vóór enige wijziging, commit 63e9ea6)

| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check .` / `ruff check tests/e2e deploy/allinone` (+ format) | geen bevindingen |
| `cd apps/api && mypy` | geen bevindingen (50 bronbestanden) |
| `cd apps/api && pytest -q` | **217 geslaagd, 1 mislukt**: `test_backup_before_migration_with_real_pg_dump` — *omgeving*: Debians pg_wrapper kiest voor `pg_dump -h` de nieuwste client (18), voor `pg_restore --list` die van het standaardcluster (16), dat het archiefformaat 1.16 niet leest. Met PostgreSQL-16-binaries vooraan in PATH: geslaagd. |
| `python -m integrations migrate` → `--down base` → `migrate` (hch_ci_mig) | op/neer/op zonder fouten |
| OpenAPI-export + `git diff --exit-code docs/openapi/` | geen drift |
| `pytest -q tests/e2e -p no:cacheprovider` | 7 geslaagd |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| `docker buildx build … -t home-control-hub:nulmeting .` | gebouwd |
| `deploy/allinone/smoke-test.sh home-control-hub:nulmeting` | **mislukt** (afgebroken na "geheimen 0600 en eigenaar 568") — *echte fout in de rooktest*: die las bestanden van uid 568 (0600, map 0700) vanaf de host; dat kan alleen als root (de oude sandbox) en ook niet op een GitHub-runner. Na reparatie (commit b27cd88): 24 geslaagd, 0 mislukt op dezelfde image. |

### Na P1 (commit 0f38e1d; JWKS-reparatie b81d2e5: 305 unit+integratie, E2E 8 geslaagd 4×)

| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check . && mypy` | geen bevindingen (61 bronbestanden) |
| `ruff check tests/e2e deploy/allinone tools && ruff format --check tests/e2e deploy/allinone tools` | geen bevindingen |
| `cd apps/api && pytest -q` | **303 geslaagd** (134 unit, 169 integratie; waarvan 57 nieuw voor B13 P1), ± 32 s |
| `migrate` → `--down base` → `migrate` → `--down 0001` → `migrate` (hch_ci_mig) | 0001 ⇄ 0002 zonder fouten |
| OpenAPI-export + `git diff --exit-code docs/openapi/` | geen drift |
| `pytest -q tests/e2e -p no:cacheprovider` (API + worker + Hub-simulator + Authentik-simulator als echte processen) | **8 geslaagd**, 3× achter elkaar |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| `actionlint .github/workflows/*.yml`, `shellcheck deploy/allinone/*.sh` | geen bevindingen |
| `python tools/authentik_schema_check.py --schemas <map>` en zonder `--schemas` (download van GitHub) | alle 11 release-lijnen 2024.10–2026.8 ok; sha256 gelijk aan `compat.SCHEMA_SHA256` |
| `docker buildx build … -t home-control-hub:p1 .` | gebouwd |
| `deploy/allinone/smoke-test.sh home-control-hub:p1` | **24 geslaagd, 0 mislukt** |
| Upgradetest (handmatig, named volume): P0-image (revisie 0001) → P1-image op dezelfde data | back-up `voor-upgrade-0001-*.dump` (0600, map 0700) gemaakt, migratie 0001→0002, markeerrij behouden, `/readyz` ready |
| Terugzettest: P0-image op de gemigreerde database | weigert te starten zonder iets te wijzigen (verbeterde melding zit in P1: `migrate` code 4 "database nieuwer dan deze image") |

### GitHub Actions (echte CI-runs op GitHub, branch `ccr-c133d7a0-kuz1cv`)
| Run | Uitkomst |
|---|---|
| 42595905753, 42599009643 (P0) | **mislukt** in de job `image`: rooktest "geheimen 0600 en eigenaar 568" (`stat: Permission denied`, niet-root runner) — dezelfde fout als in de nulmeting |
| 42613295750 (P1, commit be89e22) | **mislukt** in de dienst-E2E: JWKS-gat (TTL 2 s + vaste ophaalbegrenzing 30 s) → 401; gerepareerd in b81d2e5 |
| 42613907117 (commit b81d2e5) | **geslaagd**: job `python` (ruff, mypy, pytest, migraties, OpenAPI-drift, E2E, pip-audit) en job `image` (bouwen + rooktest) |

### Wat B13 P1 aantoont (Sim-getest)
- Er wordt nooit naar Authentik geschreven (nep-Authentik registreert elke niet-GET; overal leeg).
- Voorstel met diff/preview_hash/resource_etag; drift → 409; `risk_claim` genegeerd; toepassen eerlijk 501.
- Eén Hub-JWT per wijziging (replay → 401), retry met dezelfde Idempotency-Key toegestaan.
- Afwijkingen bereiken de Hub-inbox als `sso.anomaly.detected` (E2E via de worker).
- Herstelcheck vindt verlies van 2FA, gewijzigde groepsleden en een ontbrekende provider.

### Nog steeds NIET GEVALIDEERD
Echte Authentik (catalogusapp), domeinnaam/HTTPS (D17), de OIDC-login in de Hub, uitvoeren van voorstellen (P2),
echte testlogins per app, echte database-back-up/-restore van Authentik, installatie via het TrueNAS-formulier.

## Onafhankelijke review P1 (2026-11-09, Ubuntu 26.04-bouwmachine)

Reviewer/QA na de bouwers van B13-002…005. Eerst alle CI-stappen opnieuw gedraaid in een **verse venv**
(`/usr/bin/python3.12 -m venv`, `pip install -r apps/api/requirements.lock` en `-e 'apps/api[dev]'`, zoals
`.github/workflows/ci.yml`), daarna gerepareerd wat niet klopte. Validatieniveau ongewijzigd: **Sim-getest**; niets
op een echte NAS of met een echte Authentik.

### Nulmeting review (HEAD 9b6ec5d, vóór wijzigingen)
| Commando | Uitkomst |
|---|---|
| `ruff check/format --check` (apps/api, tests/e2e, deploy/allinone, tools), `mypy` | geen bevindingen (61 bronbestanden) |
| `cd apps/api && pytest -q` (HCH_TEST_ADMIN_URL=postgres@127.0.0.1:5432) | **305 geslaagd** |
| `migrate` → `--down base` → `migrate` → `--down 0001` → `migrate` (database hch_qa_mig) | geslaagd |
| OpenAPI-export + `git diff --exit-code docs/openapi/` | geen drift |
| `pytest -q tests/e2e -p no:cacheprovider` | **8 geslaagd** |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| `actionlint .github/workflows/*.yml`, `shellcheck deploy/allinone/*.sh` | geen bevindingen |
| `flock …/docker-build.lock nice -n 10 docker buildx build --load -f deploy/allinone/Dockerfile -t home-control-hub:qa-p1-base .` | gebouwd |
| `deploy/allinone/smoke-test.sh home-control-hub:qa-p1-base` | **24 geslaagd, 0 mislukt** |
| `gh run list` (GitHub Actions) | 42613907117 en 42614500432 (HEAD 9b6ec5d) **geslaagd** |

Alle stappen groen — maar de review vond inhoudelijke fouten die de tests niet zagen.

### Gevonden en gerepareerd (ADR-0009)
1. **Eventtypen met vier segmenten** (`sso.authentik.sync.failed`, `sso.authentik.upgrade_gate.evaluated`,
   `sso.authentik.restore_check.completed`): de inbox van de echte Hub (`ai-server-manager`, patroon
   `<domein>.<object>.<gebeurtenis>`) weigert die met 422 → na 10 pogingen dead-letter en connector `degraded`.
   De simulators accepteerden alles. Hernoemd; `events.emit` dwingt het Hub-patroon af; beide Hub-simulators
   valideren nu de envelope als de echte Hub. Ook: `entity_id` > 120 tekens (Authentik-gebruikersnaam tot 150) gaf
   een databasefout → afgekapt; payload > 16 KiB → ingekort met `_ingekort`.
2. **Least privilege `ok` zonder grond**: elk niet-superuser-token heette `ok`, terwijl rolrechten via
   `/core/users/me/` niet te zien zijn. Nu `te_ruim` / `onbekend` / `deels_gecontroleerd`; systeemrechten
   (`system_permissions`) worden gecontroleerd. Schemacontrole opnieuw gedraaid (download van GitHub): alle 11
   release-lijnen 2024.10.5–2026.8.5 ok, sha256 gelijk.
3. **Rechtenkaart `ok` op oude gegevens**: na uitval of een ingetrokken token bleef `/sso/rights` `ok`. Nu
   `verouderd` als de laatste volledige lezing ouder is dan max(15 min, 3 × sync-interval).
4. **Hub-client-controle te mild**: uitgeschakelde of `negate`-bindingen telden als beperking; ontbrekende gekoppelde
   groepen gaven `ok`.
5. **Events-gat stil**: meer dan 500 nieuwe events per soort → watermerk schuift door, oudere events ontbreken; nu
   een blijvende afwijking `events_onvolledig`.
6. **B11-004 ontbrak in EVIDENCE.json**: toegevoegd als *Niet gestart*.

### Extra afgedekt (nieuwe tests)
- `apps/api/tests/integration/test_review_p1.py` (7 tests): Authentik-token nooit in logs (DEBUG + tracebacks),
  API-antwoorden/headers, enige tabel buiten de versleutelde vault, outbox of idempotency-opslag — ook als de
  nep-Authentik het token in foutantwoorden terugkaatst (500/403), bij time-out, uitval en via de worker; met twee
  bewuste mutaties gecontroleerd dat de test een lek vangt. Geen wijziging zonder door de Hub ondertekend verzoek
  (andere sleutel, HS256, `alg: none`, verkeerde aud/iss → 401, database byte-gelijk). `apply`/`rollback` met een
  ExecutionRequest-achtige body → 501, niets gewijzigd. Rechtenkaart `verouderd`. Events-gat. Header-SSO op de
  P1-routes en bron bij elke "ondersteund". Elk P1-eventtype komt door de Hub-validatie, niets dead-letter.
- Unit: `test_token_privileges_never_claims_full_least_privilege` (8 gevallen),
  `test_check_hub_client_access_is_never_ok_on_weak_bindings`, `test_every_event_type_follows_contract_7`,
  `test_event_payload_and_ids_fit_the_hub_limits`.
- E2E: `test_05c_hub_accepted_every_event`, `test_08_no_tokens_in_process_logs` (echte proceslogs van API en worker).
- Bronvermeldingen in de SSO-dekkingsmatrix nagelezen in de zusterrepo's (media-guard-ultimate@8cd3175,
  media-source-optimizer@4558ee4, my_house@210614b, ai-server-manager@40850dc): bestanden bestaan, geen OIDC/OAuth.

### Eindstand review
| Commando | Uitkomst |
|---|---|
| `ruff check/format --check` (alle mappen), `mypy` | geen bevindingen (61 bronbestanden) |
| `cd apps/api && pytest -q` | **323 geslaagd** (± 40 s) |
| `pytest -q tests/e2e -p no:cacheprovider` | **10 geslaagd** |
| OpenAPI-export + `git diff --exit-code docs/openapi/` | alleen de bijgewerkte omschrijving van `/sso/rights` (gecommit), daarna geen drift |
| `python tools/authentik_schema_check.py --out docs/b13/authentik-api-verificatie.json` (download) | 11/11 release-lijnen ok |
| `flock … docker buildx build … -t home-control-hub:qa-p1b .` + `deploy/allinone/smoke-test.sh home-control-hub:qa-p1b` | gebouwd; **24 geslaagd, 0 mislukt** (lege /appdata, healthy, herstart en harde kill zonder dataverlies, start als 568, nette fout bij verkeerde rechten) |
| GitHub Actions ci run 42617780925 (commit c3d021f) | **geslaagd**: job `python` (ruff, mypy, pytest, migraties, OpenAPI-drift, E2E, pip-audit) en job `image` (bouwen + rooktest); alleen waarschuwingen dat de gepinde acties nog Node.js 20 gebruiken |
| Upgradetest (named volume): image van vóór de review (9b6ec5d) → gerepareerde image | healthy, markeerrij behouden, `vault.key` ongewijzigd, revisie 0002, `/readyz` ready, geen fout in de log |

### Nog steeds NIET GEVALIDEERD
Echte Authentik (catalogusapp) en de rolrechten van het serviceaccount, domeinnaam/HTTPS (D17), de OIDC-login in de
Hub, uitvoeren van voorstellen (P2), echte testlogins per app, echte back-up/restore van Authentik, installatie via
het TrueNAS-formulier, ontvangst van de events door de echte Hub (alleen de validatieregels zijn overgenomen).

## Contract 1.2 (2026-11-09, Ubuntu 26.04-bouwmachine)

Uitgevoerd: `CONTRACT_1.2_CONFORMITEIT.md` §0 (A2, A4–A7) en §2 (HC1–HC10); keuzes in ADR-0010. Python 3.12.16
(venv), PostgreSQL 16 op 127.0.0.1:5432 (`PATH=/usr/lib/postgresql/16/bin:$PATH`), Docker + buildx. Geen echte NAS,
Hub, Authentik of accounts: de Hub is `tests/e2e/sim_hub.py` (§3.3 exact; ook de nep-Hub van de integratietests).

### Nulmeting (HEAD 02204c5, vóór wijzigingen)
| Commando | Uitkomst |
|---|---|
| `cd apps/api && pytest -q` | 323 geslaagd |

### Eindstand
| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check . && mypy` | geen bevindingen (62 bronbestanden) |
| `ruff check tests/e2e deploy/allinone tools && ruff format --check tests/e2e deploy/allinone tools` | geen bevindingen |
| `cd apps/api && pytest -q tests/unit` | **261 geslaagd** (o.a. testvectoren §4.5, exact enroll-verzoek, §4.7-reasons en volgorde, sleutelrotatie, contractkopie byte-gelijk, EVIDENCE §11) |
| `cd apps/api && pytest -q tests/integration` (PostgreSQL) | **223 geslaagd** |
| `pytest -q tests/e2e -p no:cacheprovider` (API + worker als echte processen, Hub-simulator, kapotte proxy-env) | **14 geslaagd** |
| `python -m integrations migrate` → `--down 0002` → `--down base` → `migrate` (database `hch_ci_mig`) | op/neer/op zonder fouten (revisie 0003) |
| `python -m integrations openapi --out …` + `git diff --exit-code docs/openapi/` | geen drift |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| `flock …/docker-build.lock nice -n 10 docker buildx build --load -f deploy/allinone/Dockerfile -t home-control-hub:dev .` | gebouwd |
| `deploy/allinone/smoke-test.sh home-control-hub:dev` (zonder `--security-opt`/`--cap-drop`) | **29 geslaagd, 0 mislukt** |
| `jl-manifest validate deploy/manifest/home-control-hub.manifest.yaml` (validator van appstore-en-fork, alleen gelezen/uitgevoerd) | geldig, 0 fouten, 1 verwachte waarschuwing (`digest_pending_release`) |

| `HCH_REAL_HUB_PYTHON=<venv met hub> pytest -q tests/interop -p no:cacheprovider` — **echte Hub-API** van ai-server-manager (`git archive` van `b4c7a0e`, eigen venv en database) | **1 geslaagd** (volledige levenscyclus, zie hieronder) |

GitHub Actions: run `42658212431` (commit `a872e7f`, jobs `python` en `image`): **geslaagd**; run `42659058663`
(commit `3e70db9`, met base_url-controle, interop-lint en dit bewijs): **geslaagd**. De run daarvoor
(`42657826250`, commit `8c10d1f`) faalde op `ruff format --check` van één testbestand; gerepareerd in `91625f6`.

Interop met de echte Hub (lokaal, niet in CI): verkeerde `HUB_KEY_FINGERPRINT` → niets opgeslagen; koppelen met
token + vingerafdruk en bevestigen met `services/self`; gepinde `kid`'s gelijk aan de JWKS van de Hub; gebruikers-JWT
van de Hub geaccepteerd en `jti`-hergebruik geweigerd; het echte service-token inkomend geweigerd; lege
`key-rotations`; rotatie op verzoek van de beheerder; dienst-JWT van de Hub leest `hub-link` en ontkoppelt (herhaling
401 `not_linked`); opnieuw koppelen met een nieuw token (zelfde `service_id`); intrekken → 401 `revoked`.

Controle van de rooktest zelf: met een extra `docker exec -d … sleep 60` (root, met capabilities) in een draaiende
container meldt de procescontrole precies dat proces (`uid=['0','0','0','0'] capeff=00000000a80425fb nnp=0`).

### Negatieve scenario's (Sim-getest)
- Verlopen enrollment-token en een al gebruikt token (andere sleutel) → 401 `invalid_enrollment` → definitief,
  nooit opnieuw; toegestane herhaling na een verloren antwoord → `enrollment_replayed` en het ongebruikte token
  ingetrokken (`test_enrollment_and_worker.py`).
- Verkeerde of vervalste sleutelset-vingerafdruk, ontbrekende/ongeldige antwoordvelden, aliassen → niets opgeslagen;
  422/404/413 definitief; 429 wacht op `Retry-After`; 5xx/3xx backoff ≥ 5 s, redirect nooit gevolgd, stoppen na 60 min.
- JWT met niet-gepinde `kid` → 401 `unknown_key` (+ achtergrondpoll), gepinde `kid` met een gewisselde sleutel →
  401 `invalid_token`, een sleutel die alleen via de HTTP-JWKS bekend is → `unknown_key` (`test_security.py`);
  ondertekende rotatie met een niet-gepinde of verkeerd-doel-sleutel, gat in volgnummers of vervalste inhoud →
  geweigerd, gestopt, health `degraded`.
- `jti`-replay op mutaties (gebruikers- én dienst-JWT) → 401 `token_replayed`; `jti` ontbreekt → `jti_missing`;
  replaycache weg → 503.
- Inkomend `Bearer svc_…` (ook het echte eigen token) → 401 `service_token_not_accepted`.
- > 1 MiB → 413 vóór auth, ook chunked (integratie, E2E, rooktest).
- Koppelen via de statuspagina na de eerste koppeling (ook na ontkoppelen of intrekking) → geweigerd zonder verzoek
  naar de Hub; 5 pogingen per 15 min per bron-IP (X-Forwarded-For telt niet), 20 voor de dienst.
- Intrekken: alleen na 401 op `services/self`; 5xx/429/netwerk nooit.

### Nog steeds NIET GEVALIDEERD
Koppelen met de echte Hub op een echte NAS; het TrueNAS-formulier (o.a. of het tagveld `versie@sha256:…` accepteert);
het bron-IP dat de container achter de Docker-portpublicatie van TrueNAS ziet (rate-limit per bron-IP); echte
Authentik.

## Statuspagina in Peil — HC11 (2026-11-09, Ubuntu 26.04-bouwmachine)

Uitgevoerd: `CONTRACT_1.2_CONFORMITEIT.md` §2 HC11 + ONTWERPTAAL §13.2/§14 (O-14); keuzes, ontwerpstap en
ontwerpreview in ADR-0011. Sjabloon: Peil 1.1.0, versie-gepinde kopie van `lvos04/ai-server-manager@172ee87`.
Geen echte NAS, Hub of telefoon: de Hub is `tests/e2e/sim_hub.py`; de browser is Chromium (Playwright).

| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check . && mypy` | geen bevindingen (63 bronbestanden) |
| `ruff check tests/e2e tests/interop tests/ui deploy/allinone tools && ruff format --check …` | geen bevindingen |
| `cd apps/api && PATH=/usr/lib/postgresql/16/bin:$PATH pytest -q` (unit + integratie, PostgreSQL) | **544 geslaagd** (was 484; nieuw: 45 unit in `test_statuspagina_peil.py`, 15 integratie in `test_statuspagina_http.py`) |
| `pytest -q tests/e2e -p no:cacheprovider` | **14 geslaagd** |
| `python3 tools/peil_kopie.py controleer` en `vergelijk --bron ../ai-server-manager --online` | in orde (geen drift; bron op de gepinde commit en op de bronbranch gelijk) |
| `python tests/ui/genereer_toestanden.py` (echte app + Hub-simulator) | 9 toestanden: niet gekoppeld (200), koppelen mislukt (400), ongeldige invoer (422), te veel pogingen (429), gekoppeld (303 → 200), ingetrokken, ontkoppeld, niet gereed, onleesbaar (200) |
| `cd tests/ui && SCHERMAFDRUKKEN=1 npx playwright test` (Playwright 1.65, axe-core 4.14, Chromium) | **18 geslaagd** (9 toestanden × licht/donker, elk op 320/360/390/768/1024/1440 px); 30 afdrukken |
| negatieve controle UI-tests (gemanipuleerde kopie van de toestanden: groene totaalpil, overloop, veld zonder label) | alle drie gevangen (`pil-gezond`, horizontale overloop, axe `label`) |
| `flock …/docker-build.lock nice -n 10 docker buildx build --load -f deploy/allinone/Dockerfile -t home-control-hub:dev .` | gebouwd; de build controleert de sha256 van het sjabloon |
| controle in de image met een gewijzigde kopie (`integrations.peil.lees`) | geweigerd: "Peil-sjabloon wijkt af van de herkomstkop" (exit 1) |
| `deploy/allinone/smoke-test.sh home-control-hub:dev` | **30 geslaagd, 0 mislukt** (nieuw: Peil-sjabloon met "Niet gekoppeld" en vingerafdrukveld; eerste signaal niet groen) |
| `actionlint .github/workflows/*.yml` | geen bevindingen |

GitHub Actions: run `42664729776` (commit `b3b9bed`): **geslaagd** — job `python` (543 geslaagd + 1 overgeslagen: de
lokale vergelijking met `../ai-server-manager` bestaat in CI niet; Peil-drift online in orde; E2E 14 geslaagd), job
`statuspagina-ui` (18 geslaagd; afdrukken als artefact `statuspagina-peil`) en job `image` (rooktest 30 geslaagd).

### Wat de tests aantonen (Sim-getest)
- Precies één koppeltoestand per pagina; het formulier alleen zolang de dienst nog nooit gekoppeld is, met verplicht
  vingerafdrukveld; nergens ontkoppelen of een ontkoppelcode.
- Eerste signaal nooit groen als de dienst niet gereed is (ook in een invariantentest over alle combinaties van
  koppeltoestand, database, schema en fout); "Gekoppeld" is een neutrale pil.
- Een mislukte poging: passende HTTP-status, vaste melding, code en de trace-ID van het verzoek (gelijk aan
  `X-Trace-Id`, in de log en in de auditregel), veldfout met `aria-invalid` en een skiplink naar het veld; ingevulde
  waarden worden nooit teruggetoond.
- Geen JavaScript, geen event-attributen, CSP `default-src 'none'` zonder overtredingen of externe verzoeken; axe-core
  (WCAG 2.0/2.1/2.2 A+AA + best practices) 0 overtredingen; geen overloop op 320 px; doelen ≥ 44 px; tekst ≥ 14 px;
  focusring ≥ 3 px en in beeld; stippelranden bij forced colors.

### Nog steeds NIET GEVALIDEERD
De pagina op een echte NAS achter de Docker-portpublicatie van TrueNAS; koppelen met de echte Hub via deze pagina;
echte schermlezer (NVDA/TalkBack) en echte telefoon in fel licht; de ontwerpreview is een zelfreview van de bouwer,
geen onafhankelijke review door de ontwerpagent.

## Onafhankelijke ontwerpreview van de statuspagina (2026-11-09, Ubuntu 26.04-bouwmachine)

Uitgevoerd door de ontwerpagent (contract §13; ADR-0012). Bevindingen en reparaties staan in
`docs/ontwerp/PEIL_REVIEW.md`. Het Peil-sjabloon is ongewijzigd: kopie 1.1.0 van `lvos04/ai-server-manager@172ee87`.
Er waren geen echte NAS, Hub, telefoon of schermlezer: de Hub is `tests/e2e/sim_hub.py` en de browser is Chromium
(Playwright 1.65, axe-core 4.14).

| Commando | Uitkomst |
|---|---|
| `python tests/ui/ontwerpreview.py` vóór de reparaties (draaiende API + worker per toestand, Hub-simulator via uvicorn, eigen database `hch_review_<n>`) | 140 metingen (14 toestanden × 320/360/390/768/1440 × licht/donker): axe 0, tekst ≥ 8,34:1, randen ≥ 4,86:1, iconen ≥ 5,71:1, focus ≥ 7,79:1, overloop 0, doelen 0; **10 metingen met een overtreding**: in alle 10 metingen van `gekoppeld-met-bronnen` stond de Authentik-meting van 3 dagen oud als Gezond |
| idem, met de tekstafstandcontrole (WCAG 1.4.12) erbij | **1 overtreding**: `onleesbaar` 9 px overloop op 320 px (woord "(HUB_ENROLLMENT_TOKEN)." in de melding) |
| `python tests/ui/ontwerpreview.py` na de reparaties (`make ontwerpreview`) | **140 metingen, 0 overtredingen**; laagste waarde licht/donker: tekst 8,34/9,32, rand 4,86/5,69, icoon 5,71/7,58, focus 7,79/8,04; tekstafstand op 320 px in elke toestand 0 px overloop; best-practice 0; geen CSP- of paginafouten |
| `cd apps/api && ruff check . && ruff format --check . && mypy` | geen bevindingen (63 bronbestanden) |
| `ruff check tests/e2e tests/interop tests/ui deploy/allinone tools && ruff format --check …` | geen bevindingen |
| `cd apps/api && PATH=/usr/lib/postgresql/16/bin:$PATH pytest -q -p no:cacheprovider` | **552 geslaagd** (was 544; 8 nieuwe unit-tests in `test_statuspagina_peil.py`) |
| `pytest -q tests/e2e -p no:cacheprovider` | **14 geslaagd** |
| `make schermafdrukken` (genereer_toestanden + `SCHERMAFDRUKKEN=1 npx playwright test`) | **18 geslaagd**; 30 afdrukken opnieuw gemaakt en met pngquant verkleind |
| `python3 tools/peil_kopie.py controleer` en `vergelijk --bron ../ai-server-manager` | in orde (sjabloon niet gewijzigd) |
| `python -m integrations openapi` en vergelijken met `docs/openapi/` | geen drift |
| `actionlint .github/workflows/*.yml` | geen bevindingen |
| `flock …/docker-build.lock nice -n 10 docker buildx build --load -f deploy/allinone/Dockerfile -t home-control-hub:dev .` | gebouwd |
| `deploy/allinone/smoke-test.sh home-control-hub:dev` | **30 geslaagd, 0 mislukt** |

GitHub Actions, run `42671473510` (commit `603f8a1`):
- Pogingen 1 en 2: job `python` **geslaagd** en job `statuspagina-ui` **geslaagd**. Die laatste bevat de nieuwe stap
  "Ontwerpreview tegen de draaiende dienst" (ruim 3 minuten, 0 overtredingen). **Correctie (review contract 1.2,
  ADR-0013):** in CI beoordeelde die stap **0 metingen**. Door het relatieve `--uit`-pad schreef de browser zijn
  resultaten naar `tests/ui/tests/ui/review-uit`, terwijl de beoordeling `tests/ui/review-uit` las. "0 overtredingen"
  was in CI dus niets waard. De 140 metingen hierboven zijn lokaal gedaan (absoluut standaardpad).
- In beide pogingen maakte GitHub de job `image` niet aan, en poging 3 startte niet ("workflow file issue").
- Op dat moment meldde githubstatus.com een **major outage van GitHub Actions** ("Incident with Actions", 18:23 UTC).
  Ook andere repos van het programma hadden toen runs zonder jobs.
- Het image en de rooktest zijn daarom lokaal gedraaid (zie hierboven).

GitHub Actions, run `42673722426` (commit `b62abeb`, dezelfde code): **geslaagd**, met de jobs `python`,
`statuspagina-ui` (UI-tests en de ontwerpreview tegen de draaiende dienst) en `image` (rooktest). **Correctie
(ADR-0013):** ook in deze run beoordeelde de ontwerpreview-stap 0 metingen (log: "0 metingen; … overtredingen: 0");
de UI-tests (18) en de rooktest waren wel echt.

### Wat de review aantoont (Sim-getest)
- In geen enkele toestand, breedte of thema is onbekend of verouderd groen. Een meting ouder dan 15 minuten telt als
  Onbekend, met "laatst bekend <tijd>".
- Elke pil heeft het vaste Peil-woord bij zijn icoon. De precieze koppeltoestand staat in de reden.
- WCAG 2.2 AA:
  - axe 0;
  - tekst haalt zelfs AAA;
  - randen, iconen en de focusring halen ≥ 3:1;
  - 44 px-doelen;
  - geen overloop op 320 px, ook niet met de tekstafstand van 1.4.12;
  - de focus is zichtbaar en niet bedekt.
- De browser kan echt koppelen via het formulier, met CSRF-cookie, Origin en 303. Mislukte pogingen geven de juiste
  HTTP-status, code en trace-ID.

### Nog steeds NIET GEVALIDEERD
- Een echte schermlezer (NVDA/TalkBack) en een echte telefoon in fel licht.
- De pagina op een echte NAS achter de portpublicatie van TrueNAS.
- Koppelen met de echte Hub via deze pagina.
- De sjabloonpunten S-1…S-8 vragen een nieuwe Peil-versie in ai-server-manager.

## Onafhankelijke review contract 1.2 — QA (2026-11-09, Ubuntu 26.04-bouwmachine)

Een onafhankelijke reviewer heeft na de bouwrondes HC1–HC11 en A1–A7 alles opnieuw gedraaid zoals de CI het doet.
Daarnaast is de code gelezen tegen contract 1.2 §1–§13. Bevindingen en besluiten staan in ADR-0013. Er waren geen echte
NAS, Hub-installatie, Authentik of accounts. De Hub is `tests/e2e/sim_hub.py`; de interop-test draait lokaal tegen de
echte Hub-API (venv uit ai-server-manager `b4c7a0e`).

### Nulmeting (HEAD `182aea3`, vóór wijzigingen)
| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check . && mypy`; ruff op `tests/e2e tests/interop tests/ui deploy/allinone tools` | geen bevindingen (63 bronbestanden) |
| `actionlint .github/workflows/*.yml`, `shellcheck deploy/allinone/smoke-test.sh` | geen bevindingen |
| `cd apps/api && PATH=/usr/lib/postgresql/16/bin:$PATH pytest -q -p no:cacheprovider` | 552 geslaagd |
| `pytest -q tests/e2e -p no:cacheprovider` | 14 geslaagd |
| `python -m integrations migrate` → `--down base` → `migrate` (database `hch_qa_mig`) | op/neer/op zonder fouten (0003) |
| OpenAPI-export + `git diff --exit-code docs/openapi` | geen drift |
| `tools/peil_kopie.py controleer` + `vergelijk --bron ../ai-server-manager` | in orde |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| sha256 van `PLATFORM_CONTRACTEN.md` en `CONTRACT_1.2_CONFORMITEIT.md` tegen ai-server-manager | byte-gelijk |
| `jl-manifest validate deploy/manifest/home-control-hub.manifest.yaml` (validator van appstore-en-fork `ce80d40`) | GELDIG, 0 fouten, 1 verwachte waarschuwing (`digest_pending_release`) |
| `flock …/docker-build.lock nice -n 10 docker buildx build --load …` + `smoke-test.sh` | gebouwd; 30 geslaagd, 0 mislukt |
| `genereer_toestanden.py` + `npx playwright test` | 18 geslaagd |
| `python tests/ui/ontwerpreview.py --uit tests/ui/review-uit` (het CI-commando) | **"0 metingen; overtredingen: 0", exit 0**: de review mat niets en slaagde toch (zie hieronder) |

### Gevonden en gerepareerd (ADR-0013)
Bij elke reparatie hoort een test die op de vorige code faalt. Dat is gecontroleerd door de oude bronbestanden
tijdelijk terug te zetten.

| # | Bevinding | Reparatie (commit) | Test |
|---|---|---|---|
| 1 | Onleesbaar `hub-link.json` + mislukt env-token (of ongeldige `HUB_URL`) → bestand stil vervangen door `nooit_gekoppeld` → koppelformulier terug (open bij fout) | origineel bewaard als `hub-link.json.onleesbaar-<tijd>`, status blijft onbekend tot een geslaagde koppeling; `/readyz` meldt `koppelstatus_onleesbaar` (`6f3aad0`) | `test_hublink_unit.py::test_write_over_unreadable_file_keeps_it_and_stays_fail_closed`, `::test_unreadable_file_without_write_is_untouched`, `test_contract_1_2_link.py::test_unreadable_link_file_stays_fail_closed_after_a_failed_env_token` |
| 2 | Bronmeting van > 15 min nog `healthy` in `GET /integrations/v1/sources`, connector-items en `GET /connector/v1/health` | `sources.PROBE_MAX_AGE`: `unknown`/`meting_verouderd` (`b7bbe80`) | `test_platform_core.py::test_stale_probe_is_never_shown_as_healthy` |
| 3 | JWT met `aud: ["home-control-hub", "zoeken-en-persoonlijke-ai"]` geaccepteerd | `strict_aud` + controle op exact de string (`87f1d06`) | `test_security.py::test_invalid_claims` (2 nieuwe gevallen) |
| 4 | `127.1`, `2130706433`, `0x7f000001`, `0`, `010.0.0.1` en `localhost.` omzeilden de adresregels van §3.2 | alleen `a.b.c.d`, punt achteraan telt niet (`32740ab`) | `test_catalog_and_contracts.py::test_hub_url_rejected` (8 nieuwe gevallen) |
| 5 | Healthcheck-exec bij start als 568: `NoNewPrivs 0` | altijd `PR_SET_NO_NEW_PRIVS` (`727f70a`) | rooktest "als 568: healthcheck-exec zet ook no-new-privileges" (oude code: `568 0…0 0`, nieuwe: `568 0…0 1`) |
| 6 | EVIDENCE.json verwees naar 7 tests die niet meer bestaan, plus een sjabloonrest `{T}` (EX16, B13-002) | verwijzingen vervangen | `test_contract_docs.py::test_evidence_references_existing_tests` |
| 7 | Ontwerpreview in CI: relatief `--uit` → browser schreef naar `tests/ui/tests/ui/review-uit`, beoordeling las `tests/ui/review-uit` → 0 metingen, toch geslaagd (ook CI-run 42674398952) | absoluut pad; review faalt bij 0 of te weinig metingen (`6755c78`); claims in dit rapport, ADR-0012, PEIL_REVIEW en EX16 gecorrigeerd | `beoordeel()` op een lege map → 1 overtreding; CI-commando lokaal → 140 metingen |
| 8 | CI-acties op Node 20 | huidige majors op SHA, gecontroleerd met `git ls-remote` (`9641e33`) | actionlint; CI-run hieronder |

### Eindstand
| Commando | Uitkomst |
|---|---|
| `cd apps/api && ruff check . && ruff format --check . && mypy` + ruff op de overige mappen | geen bevindingen |
| `cd apps/api && PATH=/usr/lib/postgresql/16/bin:$PATH pytest -q -p no:cacheprovider` | **568 geslaagd** (16 nieuw) |
| `pytest -q tests/e2e -p no:cacheprovider` | **14 geslaagd** |
| `HCH_REAL_HUB_PYTHON=<venv met hub uit ai-server-manager b4c7a0e> pytest -q tests/interop` | **1 geslaagd** (lokaal, niet in CI) |
| OpenAPI-export + diff | geen drift |
| `docker buildx build …` + `deploy/allinone/smoke-test.sh home-control-hub:qa` | **31 geslaagd, 0 mislukt** (nieuw: healthcheck als 568) |
| `genereer_toestanden.py` + `SCHERMAFDRUKKEN=1 npx playwright test` | **18 geslaagd**. De afdrukken zijn niet opnieuw ingecheckt: de 5 vaste toestanden zien er hetzelfde uit. |
| `python tests/ui/ontwerpreview.py --uit tests/ui/review-uit` (CI-commando, na de reparatie) | **140 metingen, 0 overtredingen**; laagste tekst 8,34, rand 4,86, icoon 5,71, focus 7,79 |
| `actionlint .github/workflows/*.yml`, `shellcheck deploy/allinone/smoke-test.sh` | geen bevindingen |

GitHub Actions:
- Run `42677974905` (commit `87f1d06`, de nieuwe actieversies): **geslaagd**, met de jobs `python`, `statuspagina-ui`
  en `image`.
- Run `42678823148` (commit `089858f`): **geslaagd**.
  - Job `python`: 567 geslaagd en 1 overgeslagen. De overgeslagen test is de lokale Peil-vergelijking, want in CI is
    er geen checkout van ai-server-manager; daar vergelijkt CI online. E2E: 14 geslaagd.
  - Job `statuspagina-ui`: UI-tests 18 geslaagd. De ontwerpreview meet nu ook in CI echt: **140 metingen, 0
    overtredingen**.
  - Job `image`: rooktest 31 geslaagd.

### Nog steeds NIET GEVALIDEERD
- Alles op een echte NAS:
  - het Custom App-formulier (tag met `@sha256`);
  - het bron-IP achter de Docker-NAT, dat de rate-limit bepaalt;
  - koppelen met de echte Hub op de NAS;
  - de statuspagina via `http://<NAS-adres>:30420`.
- Echte Authentik-accounts (B13-002…005).
- Een echte schermlezer en een echte telefoon.

## Contract 1.3 en Peil 1.1.1 (2026-11-10, Ubuntu 26.04-bouwmachine)

Conformiteitsronde C1.3-HCH-01…14 (ADR-0014). Python 3.12.16 (venv), PostgreSQL 16 op 127.0.0.1:5432 (client 16 via
`PATH=/usr/lib/postgresql/16/bin:$PATH`), Node 22, Playwright 1.65 (Chromium), Docker + buildx. Alles tegen de
Hub-simulator (`tests/e2e/sim_hub.py`, nu volgens 1.3) en de nep-Authentik; geen echte Hub, NAS of Authentik.

### Nulmeting (HEAD 9d886ad, vóór wijzigingen)

| Commando | Uitkomst |
|---|---|
| `cd apps/api && PATH=/usr/lib/postgresql/16/bin:$PATH pytest -q -x -p no:cacheprovider` | 568 geslaagd |

### Eindstand

| Commando | Uitkomst |
|---|---|
| `make lint` (ruff check + format, mypy) en ruff over `tests/e2e tests/interop tests/ui deploy/allinone tools` | geen bevindingen; mypy: 63 bronbestanden ok |
| `cd apps/api && PATH=/usr/lib/postgresql/16/bin:$PATH nice -n 10 pytest -q -p no:cacheprovider` | **720 geslaagd** (unit + integratie) |
| `pytest -q tests/e2e -p no:cacheprovider` (API + worker als processen, Hub-simulator 1.3 met de envelope-regels van §7) | **14 geslaagd**, 0 geweigerde events |
| `python -m integrations migrate` → `--down base` → `migrate` (nieuwe migratie 0004) | op/neer/op zonder fouten |
| `python3 tools/contract_kopie.py controleer` en `vergelijk --bron ../ai-server-manager` en `vergelijk --online` | in orde (kopieën = ai-server-manager@0a7143b) |
| `python3 tools/peil_kopie.py bijwerken … --commit 0a7143b…` en `vergelijk --bron ../ai-server-manager` | Peil 1.1.1, in orde |
| `tools/authentik_schema_check.py` (officiële schema's van alle release-lijnen, nieuw: `uid`/`uuid` van gebruikers) | 2024.10.5 t/m 2026.8.5: alle ok |
| `jl-manifest validate --strict deploy/manifest/home-control-hub.manifest.yaml` (1.3-validator van appstore-en-fork, lokaal) | GELDIG, 0 fouten; `digest_pending_release` geaccepteerd |
| `pip-audit -r apps/api/requirements.lock` | geen bekende kwetsbaarheden |
| `python tests/ui/genereer_toestanden.py` + `npx playwright test` (12 toestanden × licht/donker × 320–1440) | **24 geslaagd**: axe 0, geen overloop, CSP, meldingsrol, Referrer-Policy |
| `python tests/ui/ontwerpreview.py` (draaiende dienst, 14 toestanden × 320/360/390/768/1024/1440 × licht/donker) | **168 metingen, 0 overtredingen**; tekst ≥ 8,34:1, randen ≥ 4,86:1, iconen ≥ 5,41:1, focus ≥ 7,79:1 |
| idem, browsertest `tests/ui/herkomst.mjs` (echt formulier, echte dienst) | negatief 5 gevallen, 0 fouten; positief 1 geval (303), 0 fouten |
| `flock …/docker-build.lock nice -n 10 docker buildx build --load -f deploy/allinone/Dockerfile -t home-control-hub:dev .` | gebouwd |
| `deploy/allinone/smoke-test.sh home-control-hub:dev` | **34 geslaagd, 0 mislukt** (nieuw: CapPrm/CapAmb/CapBnd, healthcheck apart, Referrer-Policy, Origin null → 403) |

Tijdens het werk gevonden en hersteld (in deze ronde): de testhulp van de ontwerpreview schreef `hub-link.json` met
0644. Sinds 1.3 §3.5 is dat onleesbaar (fail-closed) — de review ving dat terecht op. En de review las de reden van een
rij uit de 1.1.0-opbouw; in 1.1.1 staat die in `.sub > span`.

### Negatieve scenario's (Sim-getest)

- Formulier-POST met `Origin: null`, zonder `Origin`, met een vreemde `Origin`, ander schema of andere poort,
  `Sec-Fetch-Site: same-site`/`cross-site`, `Host` een publieke domeinnaam of `127.1`, zonder cookie → 403, niets naar
  de Hub, niets gewijzigd, telt niet als poging (HTTP-tests én Chromium tegen de echte dienst).
- Zes POST's op een al gekoppelde dienst → 5 × 409 `al_gekoppeld`, dan 429; lopende poging → 409 `koppelen_bezig`;
  onleesbaar koppelbestand → 409 `koppelstatus_onleesbaar` (bestand blijft onaangeroerd); te lange invoer → 422
  zonder afkappen.
- Onleesbare body zonder aanmelding → 401 (was 422); schemafout zonder aanmelding → 401; geen `Idempotency-Key` zonder
  aanmelding → 401; daarna pas 400/403/422. Een POST met een ongeldige body verbruikt toch de `jti`.
- Hub-hostnaam die naar loopback, link-local, `0.0.0.0`/`::` of een IPv4-mapped loopback wijst → geen verbinding, ook
  niet als hij eerder naar een LAN-adres wees (rebinding).
- Hub roteerde vóór de koppeling met intrekking van de oude sleutel → de dienst begint bij `rotation_sequence` 1 en
  weigert niets (met 1.2-gedrag zou dat een geweigerde rotatie zijn geweest).
- Koppelbestand met een andere major, zonder `schema_version`/`state` of met rechten 0644/0660 → onleesbaar.
- Events buiten het eigen domein, buiten de vaste `service.*`-lijst, `app.*` anders dan `app.health.changed`, of met
  een ernst buiten de vijf woorden → geweigerd vóór verzending.
- `100.64.0.0/10` zonder toestemming → 422 bij registreren en geen toegang bij beoordelen.

### Nog steeds NIET GEVALIDEERD

Een echte Hub (die `rotation_sequence`, de inbox-regels en `sso.access.*` met `issuer`/`sub` nog moet bouwen, C1.3-ASM),
een echte Authentik (de `sub`-afleiding komt uit de broncode van Authentik 2026.8.5), een echte browser op het LAN
tegen de dienst op een echte NAS (Host-header, bron-IP achter de portpublicatie), een echte schermlezer en telefoon, en
installatie als standaard Custom App op een echte TrueNAS.

### GitHub Actions (contract 1.3)

| Run | Commit | Uitkomst |
|---|---|---|
| 42782260548 | e415866 (alle codewijzigingen tot dan) | python en image geslaagd; **statuspagina-ui mislukt**: de ontwerpreview schreef `hub-link.json` met 0644 (sinds 1.3 onleesbaar) en las de reden uit de 1.1.0-opbouw; hersteld in edc8722 |
| 42783332605 | edc8722 | **geslaagd**: python, statuspagina-ui (Playwright, ontwerpreview 320–1440 + browsertest herkomst), image (bouwen + rooktest) |
| 42784902419 | 33148a8 | **geslaagd**: python, statuspagina-ui, image |

## Onafhankelijke review contract 1.3 — QA (2026-11-10, Ubuntu 26.04-bouwmachine)

Onafhankelijke controle na de bouwronde (ADR-0015). Alles **Sim-getest** of lokaal tegen de echte Hub-code; niets op
een echte NAS, met een echte Authentik of met echte accounts.

### Nulmeting (HEAD `40fb53f`, vóór wijzigingen)

| Commando | Uitkomst |
|---|---|
| `ruff check`/`ruff format --check` (apps/api, tests, deploy, tools) en `mypy` | in orde; mypy 63 bestanden zonder fouten |
| `cd apps/api && PATH=/usr/lib/postgresql/16/bin:$PATH pytest -q -p no:cacheprovider` | 720 passed (lokaal, met de checkouts naast deze repo) |
| GitHub-run 42785941983 (40fb53f), stap unit en integratie | **708 passed, 12 skipped**: manifestvalidator en Peil-referentierenderer draaiden niet in CI |
| `pytest -q tests/e2e -p no:cacheprovider` | 14 passed |
| `python -m integrations migrate` → `--down base` → `migrate` (eigen database) | op/neer/op zonder fouten, revisie 0004 |
| OpenAPI-export + `git diff --exit-code docs/openapi/` | geen drift |
| `tools/contract_kopie.py controleer`/`vergelijk --bron`/`--online`; `tools/peil_kopie.py` idem | in orde (byte-gelijk aan ai-server-manager `0a7143b`; bron ongewijzigd tot `5e21775`) |
| `actionlint .github/workflows/*.yml`; `pip-audit -r apps/api/requirements.lock` | in orde; geen bekende kwetsbaarheden |
| `genereer_toestanden.py` + `npx playwright test` | 24 passed |
| `ontwerpreview.py` (draaiende dienst + browsertest herkomst) | 168 metingen, 0 overtredingen; herkomst negatief 5/0 fouten, positief 1/0 fouten |
| image bouwen (flock, nice) + `smoke-test.sh` | 34 geslaagd, 0 mislukt |
| `jl-manifest validate --strict` (appstore-en-fork `cca4403`, eigen venv) | GELDIG, 0 fouten (alleen het geaccepteerde `digest_pending_release`) |
| interop tegen de echte Hub (ai-server-manager `5e21775`, eigen venv) | 1 passed |

### Gevonden en gerepareerd (ADR-0015)

1. CI sloeg 12 tests stil over (validator en Peil-referentie). Nu verplicht op vaste commits.
2. Connector-check `bronnen`: bij een verouderde meting kreeg de check `observed_at` = nu. Een verse `down` stond
   onder de reden `meting_verouderd`. Nu: de tijd van de meting en de juiste oorzaak.
3. `hub-link.json` krijgt expliciet 0600 (`fchmod`), tegen geërfde ACL's die het bestand onleesbaar zouden maken.
4. Juiste logregel bij het apart zetten van een onleesbaar bestand.
5. Manifestnotitie noemt migratie 0004.
6. Interoptest uitgebreid met de 1.3-punten van de echte Hub.

### Eindstand

| Commando | Uitkomst |
|---|---|
| lint + `mypy` | in orde |
| `pytest -q` met `HCH_PEIL_REFERENTIE(_VERPLICHT)` en `HCH_JL_MANIFEST`/`HCH_MANIFEST_VALIDATOR_VERPLICHT` (zoals CI) | **723 passed, 0 skipped** |
| dezelfde tests met een ontbrekende referentie/validator en de verplicht-vlag | 11 failed (zoals bedoeld: nooit stil overgeslagen) |
| nieuwe test zonder de `fchmod` | faalt (zoals bedoeld); met de wijziging groen |
| `pytest -q tests/e2e` | 14 passed |
| interop tegen de echte Hub (`HCH_REAL_HUB_PYTHON=…`, alleen lokaal) | 1 passed, met `schema_version` 1.3, `rotation_sequence` en `service.hub_link.linked` afgeleverd in de inbox |
| image opnieuw bouwen + `smoke-test.sh` | 34 geslaagd, 0 mislukt |
| GitHub-run 42788378621 (eddcf17) | **geslaagd**: python (720 passed, 1 skipped: de lokale Peil-vergelijking, CI vergelijkt online), statuspagina-ui, image |

### Nog steeds NIET GEVALIDEERD

Een echte NAS (Custom App-formulier, Host-header en bron-IP achter de portpublicatie, ZFS-ACL's van de dataset op
`hub-link.json`), een echte Authentik (`issuer`/`sub` in `sso.access.*`), een echte browser op het LAN, een echte
schermlezer en telefoon.
