# Platformcontracten — TrueNAS Home Platform V2 (bouwcontract voor alle repos)

Versie: `contracts 1.1` (1.1: installatie uitsluitend als standaard TrueNAS Custom App, alles-in-één image per repo, executor als aparte Custom App, derden via TrueNAS-catalogus) · Peildatum 2026-11-09 · Eigenaar: `lvos04/ai-server-manager` (bron van waarheid).
Elke repo heeft een kopie in `docs/platform-v2/PLATFORM_CONTRACTEN.md`; bij verschil wint deze repo.
Dit document maakt de pakketvoorstellen (`01_ARCHITECTUUR/02`, `03`, `07`) concreet zodat alle repos samenwerken.
Het zegt **niets** over de echte NAS: alle NAS-gegevens (D01–D18) zijn onbekend tot de gebruiker ze in de
onboarding-wizard invult of de wizard ze via de TrueNAS-API meet.

## 1. Vaste keuzes (van de gebruiker)

- Nieuwe repos: **Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL 16**, frontend **Next.js/React PWA** (alleen in
  `ai-server-manager`; alle schermen van alle nieuwe diensten staan in die ene Hub-UI). Andere nieuwe diensten zijn
  zelfstandige API-diensten met alleen een kleine eigen statuspagina (`GET /` → eenvoudige HTML, NL).
- Installatie **zonder terminal en zonder YAML**: alles wordt geïnstalleerd als **standaard TrueNAS Custom App**
  (het gewone formulier: image + tag, poorten, opslag, omgevingsvariabelen) — nooit via *Install via YAML*,
  `custom_compose_config` of docker compose. Eerste installatie: de gebruiker maakt in de TrueNAS-web-UI precies **twee**
  Custom Apps: `ai-server-manager` (de Hub, alles-in-één) en `ai-server-manager-executor`. Daarna installeert het platform
  alles via de TrueNAS-API vanuit de platform-UI. Apps van derden die meerdere containers nodig hebben (Authentik, Immich,
  …) via de **officiële TrueNAS-catalogusapp** waar die bestaat (versie vastgezet); anders een standaard Custom App met
  één gepinde image. `docker compose` mag alleen voor ontwikkeling, CI en de integrale E2E-testomgeving.
- **Eén alles-in-één image per repo** (zoals MSO `deploy/allinone`): eigen ingebouwde PostgreSQL 16 (alleen unix-socket,
  geen netwerkpoort), API, worker en — alleen bij de Hub — de web-UI, onder een kleine procesbewaker; één datamap
  `/appdata`, één poort, healthcheck, start als root alleen om `/appdata` aan 568:568 te geven en draait daarna alles als
  568. Geen wachtwoorden of geheimen in het formulier; geheimen maakt de app zelf bij eerste start in `/appdata/secrets`.
- Geen `latest`-tags. Elke image op exacte versie, base-images bovendien op `@sha256:`-digest.
- Geen shell/root voor AI, geen `sh -c`/`sudo`-endpoint, geen Docker-socket in een container, boiler nooit schakelen,
  geen betaalde API-overage (Claude alleen binnen inbegrepen credits, harde stop op 0 overage).
- Lokale modellen (Ollama-LLM, faster-whisper STT, Piper TTS, lokaal embeddingmodel) zijn **optionele apps, standaard uit**.
- UI-taal Nederlands. Elke kaart: waarde + eenheid + bron + **laatst bijgewerkt**. Onbekend is `unknown`, nooit groen.
- Jellyfin-fork: technische identiteit/API blijft "Jellyfin" (clientcompatibiliteit); alleen de zichtbare naam is
  "Jelly Leon". GPL-licentie en upstream-credits blijven staan.

## 2. Apps, images en poorten

Elke eigen app is één standaard Custom App met één image en één datamap `/appdata` (hostpad of ixVolume, door de gebruiker
of — na onboarding — door de Hub gekozen via de datasetkiezer). Apps zitten **niet** in een gedeeld Docker-netwerk: ze
bereiken elkaar via `http://<NAS-adres>:<hostpoort>` uit het dienstenregister van de Hub. Het NAS-adres komt uit de wizard
(D03) of wordt door de wizard gemeten en door de gebruiker bevestigd; nooit aangenomen.

| Repo | Custom App-naam | Image (GHCR, exacte versie) | Containerpoort | Hostpoort (voorstel, wijzigbaar) |
|---|---|---|---|---|
| ai-server-manager | `ai-server-manager` (Hub: web-UI + API + worker + AI-runner + PostgreSQL) | `ghcr.io/lvos04/ai-server-manager` | 30400 | 30400 |
| ai-server-manager | `ai-server-manager-executor` (enige met TrueNAS-schrijfkey) | `ghcr.io/lvos04/ai-server-manager-executor` | 30410 | 30410 |
| home-control-hub | `home-control-hub` (integraties B10/B11/B13/B14) | `ghcr.io/lvos04/home-control-hub` | 30420 | 30420 |
| appstore-en-fork | `appstore-en-fork` | `ghcr.io/lvos04/appstore-en-fork` | 30430 | 30430 |
| jelly-leon-platform | `jelly-leon-platform` (lifecycle) | `ghcr.io/lvos04/jelly-leon-platform` | 30440 | 30440 |
| zoeken-en-persoonlijke-ai | `zoeken-en-persoonlijke-ai` (PostgreSQL + pgvector ingebouwd) | `ghcr.io/lvos04/zoeken-en-persoonlijke-ai` | 30450 | 30450 |
| jelly-leon(+web) | `jelly-leon` (server incl. web-client) | `ghcr.io/lvos04/jelly-leon` | 8096 | 30460 |
| optioneel (standaard uit) | `stt` (faster-whisper), `tts` (Piper), `ollama` | gepinde upstream images | per image | voorstel bij installatie |

Hostpoorten zijn voorstellen: vóór installatie controleert de Hub via de TrueNAS-API op conflicten met bestaande apps.
Binnen de alles-in-één image houdt elke app intern dezelfde modulegrenzen (api, worker, …) als aparte processen; in
ontwikkeling/CI mogen die als losse processen of compose-diensten draaien.

**Eerste installatie (handmatig, 2 formulieren)**, beschreven in `jelly-leon-platform/install/truenas/INSTALLATIE.md`:
1. Custom App `ai-server-manager`: image + tag, poort 30400, opslag `/appdata`. Bij eerste start toont de app een
   eenmalige **setupcode** in de app-logs (TrueNAS-web-UI → Apps → app → Logs); de wizard vraagt die vóór het eerste
   admin-account.
2. Custom App `ai-server-manager-executor`: image + tag, poort 30410, eigen opslag `/appdata`. Koppelen gebeurt via de
   web-UI (§3); de TrueNAS-schrijfkey voert de gebruiker alleen op de koppelpagina van de executor in.
Daarna installeert de Hub (via executor) de overige eigen apps (`appstore-en-fork`, `jelly-leon-platform`, …) als
standaard Custom App.

**Installatie via de API** (executor, `app.install`): TrueNAS `app.create` voor een standaard Custom App met de
formulierwaarden (image, ports, storage, env, resources, gpu) — in TrueNAS 24.10+ is dat de catalogus-app `ix-app`
met `values`; methodenaam en waardenschema per versie ontdekken en tegen de officiële docs controleren — of `app.create`
met `catalog_app`/`train`/`version` voor een catalogusapp. **Nooit** `custom_compose_config`.

## 3. Geheimen en koppelen

- Nooit geheimen in het Custom App-formulier, in Git of in logs. Elke app maakt bij eerste start ontbrekende geheimen
  aan in `/appdata/secrets/` (0600, eigenaar 568, nooit overschrijven): eigen DB-wachtwoord/socket, `vault.key`
  (AES-256-GCM voor opgeslagen credentials), eigen Ed25519-identiteit. De Hub maakt daarnaast `policy-signing.ed25519`,
  `jwt-signing.ed25519` en de eenmalige setupcode (alleen in de logs).
- **Eigen apps aanmelden bij de Hub (enrollment):** bij installatie via de API geeft de Hub alleen niet-geheime env mee:
  `HUB_URL` en een **eenmalig enrollment-token** (vervalt na 60 min of na eerste gebruik). Bij eerste start roept de app
  `POST {HUB_URL}/api/v1/services/enroll` aan, krijgt een eigen service-token + de Hub-JWKS en de publieke
  policy-sleutel. Het token in de app-configuratie is daarna waardeloos. Handmatig geïnstalleerde apps koppelen via een
  koppelcode uit de Hub-UI, ingevoerd op de statuspagina van de app.
- **Executor koppelen:** de Hub-wizard toont een eenmalige koppelcode (30 min). De gebruiker opent de statuspagina van
  de executor (`http://<NAS>:30410`), vult daar de koppelcode én de TrueNAS-API-key met schrijfrechten in. De executor
  wisselt met de Hub publieke sleutels uit (Hub-policy-sleutel ↔ executor-identiteit), versleutelt de key in zijn eigen
  vault en toont alleen nog de laatste 4 tekens. De Hub ziet de schrijfkey nooit. Ontkoppelen/roteren via dezelfde pagina.
- Credentials van andere apps (MediaGuard-`X-Api-Key`, my_house-token, TrueNAS-read-only-key, …) voert de gebruiker in de
  Hub-UI in; opslag versleuteld, alleen vault-referentie (`vault://<scope>/<naam>`) in tabellen. UI toont nooit de waarde
  terug (alleen laatste 4 tekens + datum). Logs en evidence worden geredigeerd.

## 4. Authenticatie en rollen

- **Gebruikers** loggen in op de Hub (lokaal account, argon2id; optioneel OIDC via Authentik zodra B13 actief is).
  Rollen: `admin`, `operator`, `viewer`, `kind` (kinderprofiel). Sessiecookie (HttpOnly, SameSite=Strict, Secure achter
  HTTPS) + CSRF-token voor muterende webcalls.
- **Gebruikerscontext naar diensten**: de Hub-API geeft kortlevende JWT's (EdDSA, `iss=hub`, `aud=<dienst>`, `sub`, `roles`,
  `exp ≤ 120 s`). JWKS: `GET {HUB_URL}/api/v1/auth/jwks`. Diensten met ACL (search-ai, jelly-leon-plugin)
  dwingen rol/ACL zelf af op basis van deze JWT.
- **Dienst-naar-dienst**: `Authorization: Bearer <service-token>` (per app eigen token uit de enrollment); de Hub
  houdt het register en kan roteren zonder herinstallatie.
- Diensten zonder geldige auth → 401 `{code:"unauthorized"}`; nooit "open access" bij verlopen/ingetrokken credentials
  (EX16): connector wordt `unknown` + incident.

## 5. Gemeenschappelijke API-regels

- Prefix per dienst: Hub `/api/v1/…`; overige diensten hun eigen prefix (bv. `/integrations/v1`, `/catalog/v1`,
  `/lifecycle/v1`, `/search/v1`, `/voice/v1`, `/media/v1`) **plus** het connectorcontract (§6).
- JSON, UUID's, tijden ISO-8601 UTC (`…Z`), paginering met `cursor`/`limit` (max 200), `ETag` op muteerbare objecten.
- Fout: HTTP-status + body `{"code": "<snake_case>", "message": "<NL tekst>", "details": {…}, "trace_id": "<uuid>"}`.
- Mutaties: header `Idempotency-Key` (UUID) verplicht; herhaling met zelfde key → zelfde resultaat, géén tweede uitvoering.
- `GET /healthz` (proces leeft) en `GET /readyz` (afhankelijkheden ok) op elke dienst, zonder auth, zonder geheimen.
- OpenAPI: elke dienst exporteert `docs/openapi/<dienst>.openapi.json`; CI faalt bij drift.
- Tijdlimieten: uitgaande calls standaard 5 s connect / 15 s read, retry met exponentiële backoff + jitter, max 3.

## 6. Connectorcontract (elke dienst én elke adapter voor bestaande apps)

| Endpoint | Doel |
|---|---|
| `GET /connector/v1/discover` | `{app_id, source_version, schema_version:"1.0", capabilities:[read,propose,apply,rollback,stream], permissions:[…], limits:{…}, timestamp_utc}` |
| `GET /connector/v1/health` | `{status: healthy|degraded|down|unknown, observed_at, reason_code, checks:[{name,status,observed_at,detail}]}` |
| `GET /connector/v1/items?type=&cursor=&limit=` | alleen eigen data, gepagineerd, scopes gerespecteerd |
| `POST /connector/v1/propose` | voorstel → `{proposal_id, preview_hash, resource_etag, diff, blast_radius, risk_claim, rollback_recipe, requires_backup}` |
| `POST /connector/v1/apply` | alleen met door de Hub **ondertekend** `ExecutionRequest` (§8); resultaat met `readback` + before/after-hash |
| `POST /connector/v1/rollback` | alleen als eigenaar het ondersteunt; anders `501 {code:"capability_unavailable"}` |
| `GET /connector/v1/evidence/{id}` | geredigeerd bewijs, nooit geheimen |
| `GET /connector/v1/events?cursor=` | outbox voor polling (§7) |

Ontbrekende functie → `capability_unavailable`/`unknown`, **nooit gesimuleerd succes**. Bestaande apps (MediaGuard, MSO,
my_house) krijgen in de Hub een adapter die hun **bestaande** routes gebruikt; nieuwe routes in die apps alleen als hun
delta-matrix ze als ontbrekend markeert.

## 7. Event-envelope

```json
{"schema_version":"1.0","event_id":"<uuid>","source_app":"mediaguard","source_event_id":"<bron-id>",
 "event_type":"media.download.failed","entity":{"type":"media_item","id":"<safe-id>"},
 "timestamp_utc":"2026-11-09T04:00:00Z","trace_id":"<uuid>","correlation_id":"<uuid|null>",
 "actor":{"type":"system|user|ai|flow","id":"<id>"},"classification":"public|internal|sensitive",
 "payload":{…geschoond…},"payload_ref":null}
```
- Push: `POST {HUB_URL}/api/v1/events/inbox` (service-token). Dedupe op `event_id` én `(source_app, source_event_id)`.
- Bron houdt een outbox (retry met backoff, dead-letter na 10 pogingen, zichtbaar in Hub). Zonder native events: Hub pollt
  `/connector/v1/events` of bestaande routes met cursor/ETag/watermark. Geen exact-once-aanname.
- `event_type`-namen: `<domein>.<object>.<gebeurtenis>` (bv. `app.health.changed`, `backup.run.failed`,
  `incident.opened`, `action.executed`, `energy.reading.recorded`, `network.device.discovered`, `flow.action.requested`).

## 8. Risicobeleid, voorstel, goedkeuring en executor

**Stroom:** (AI, gebruiker, Node-RED-flow of spraak) → `ActionProposal` → **policy-engine in de Hub** (deterministisch,
policybestanden `ai-server-manager/policy/*.yaml` ingebakken in de Hub- én executor-image, read-only, hash `policy_hash`
vastgelegd; de AI-runner draait als aparte gebruiker zonder toegang tot signing keys of vault) → bij R0/R1
automatisch (allowlist, cooldown, anti-flap), bij R2/R3 **menselijke goedkeuring per gebonden diff** → de Hub ondertekent
`ExecutionRequest` (Ed25519) → de executor-app of de eigenaar-connector voert uit → readback → audit.

`ActionProposal`:
```json
{"idempotency_key":"<uuid>","action_id":"app.restart","target":{"host_id":"nas-primary","app_id":"uptime-kuma"},
 "parameters":{"grace_seconds":30},"reason":"service unresponsive","actor":{"type":"ai","id":"hub-ai"},
 "expected_version":"<digest|etag>","risk_claim":"R1","evidence_ids":["evt-123"],"expires_in_seconds":300}
```
- `risk_claim` van AI/flow wordt **genegeerd** voor de beslissing; de policy bepaalt `risk_class` (EX18). Onbekende
  `action_id` → geweigerd. Er bestaat **geen** `shell.exec`, `sudo`, `docker.*`-socket of vrije-tekstcommando.
- Blokkades (altijd, ook met goedkeuring): pool `DEGRADED`/onbekend of backup-gate rood → geen opslag-/massamedia-mutaties
  (EX11/EX12); boiler-schakelen (elke route; EX27); auto-delete van torrents/downloads/media/foto's/datasets; wijzigen van
  policy/rollen/privileges door AI; betaalde acties.

`Approval` (gebonden): `approval_id, request_id, preview_hash, resource_etag, policy_hash, risk_class, approved_by,
approved_at, expires_at (≤ 15 min), one_time_nonce, backup_checkpoint_id, action_scope`. Wijzigt één gebonden veld
(bv. app-digest na preview, EX19) → goedkeuring vervalt, nieuwe diff nodig. Nonce eenmalig → replay geweigerd (EX20).

`ExecutionRequest` = `{proposal, approval|null, policy_decision{risk_class, rule_ids, policy_hash}, issued_at, expires_at,
nonce}` + `signature` (Ed25519 over canonieke JSON, sleutels gesorteerd, UTF-8, geen spaties).
**Executor** controleert zelf opnieuw: handtekening, vervaltijd, nonce (eigen SQLite), `action_id` in eigen allowlist,
parameterschema + harde grenzen, policy-hash gelijk aan eigen read-only kopie, risicoklasse ≥ eigen herberekening,
precondities via readback (ETag/digest). Daarna uitvoering via TrueNAS JSON-RPC, before/after-hash, readback,
afwijking → stop + incident. Executor-allowlist v1:

| action_id | klasse (min.) | TrueNAS-API (versie-afhankelijk via `core.get_methods`) |
|---|---|---|
| `app.restart` / `app.stop` / `app.start` | R1 (niet-kritiek) / R2 (kritiek, netwerk, DNS, auth) | `app.redeploy` / `app.stop` / `app.start` |
| `app.install` | R2 | `app.create` als standaard Custom App (`ix-app`-waarden) of catalogusapp — nooit custom compose |
| `app.update` | R2 | `app.update` (nieuwe gepinde image-tag/waarden) of `app.upgrade` (catalogusapp, vaste versie) |
| `app.rollback` | R2 (R3 bij DB-restore) | vorige waarden/versie (`app.rollback` waar ondersteund) + snapshot-restore via eigenaar |
| `app.uninstall` | R2 (container-only; data blijft) | `app.delete` met `remove_ix_volumes=false` |
| `app.uninstall_data` | R3 (aparte bevestiging, nooit door AI aangeboden) | — standaard **niet** aangeboden |
| `zfs.snapshot.create` | R1 | `pool.snapshot.create` / `zfs.snapshot.create` |
| `zfs.snapshot.clone_to_sandbox` | R1 (alleen naar sandbox-dataset) | `pool.snapshot.clone` / `zfs.snapshot.clone` |
| `notification.send` | R0 | via Gotify-adapter (geen TrueNAS) |

TrueNAS-API: JSON-RPC 2.0 over WebSocket `wss://<NAS>/api/current` (versie-endpoint `/api/v25.10.x` waar beschikbaar),
`auth.login_with_api_key`. Methodenamen en -schema's per versie ontdekken (`core.get_methods`, `system.version`); geen
oude REST-API. Hub-api gebruikt een **read-only** key (aparte TrueNAS-gebruiker met alleen-lezen-rol); alleen de executor
heeft een key met schrijfrechten, en die key voert de gebruiker in de wizard in.

## 9. Manifeststandaard (B08-001, eigenaar `appstore-en-fork`)

`manifest_version: "1"` YAML met o.a.: `app_id`, `name`, `owner_repo`, `category`, `description_nl`,
`version`, `install: {method: custom_app | catalog_app}`, bij `custom_app`: `image: {repository, tag, digest}` (één
image; tag ≠ `latest`; digest verplicht voor upstream-images; voor eigen GHCR-images vult de release-CI de digest) +
`custom_app: {ports, storage, env, resources, gpu, run_as}` (het formulier van de standaard Custom App), bij `catalog_app`:
`catalog: {train, app, version}` + `values`; een `compose`-veld is **verboden**,
`parameters` (getypt, met `source: wizard|dataset_picker|secret|generated|default`, nooit voorbeeldwaarden als echte waarde),
`storage: [{name, mount, kind: config|data|media|scratch, required_dataset_role}]`, `network: {ports, host_network:false,
joins_platform_network}`, `privileges: {privileged:false, cap_add:[], devices:[], gpu:none|intel_render}` + `privilege_reason`,
`healthcheck`, `backup: {db_export, snapshot_datasets, rpo, rto}`, `dependencies`, `sso: oidc|native|none`,
`risk: {install, update, uninstall}`, `upgrade: {migrations, tag_only_rollback_safe: bool}`, `decisions_required: [D01…]`,
`docs: [I-/A-doc]`, `validation_status`. Weigeren vóór uitvoering (EX47): compose/YAML-installatie, `privileged`, Docker-socket, hostpad
`/`, `/mnt` zonder dataset, `/etc`, `/var/run`, `/root`, host network zonder reden, `latest`, ontbrekende digest.

## 10. Repo-indeling nieuwe Python-diensten

```
apps/api/            pyproject.toml, src/<pakket>/…, alembic/, tests/{unit,integration}
apps/web/            (alleen ai-server-manager) Next.js PWA + Playwright (360/390/768/1440)
apps/executor/       (alleen ai-server-manager; eigen image)
policy/              (alleen ai-server-manager) policy YAML + hash
deploy/allinone/     Dockerfile (alles-in-één), supervisor, healthcheck, first-start-init (zie MSO als voorbeeld)
deploy/truenas/      CUSTOM_APP.md: exacte velden van het standaard Custom App-formulier (NL), geen YAML
deploy/dev/          compose.yaml alleen voor ontwikkeling/CI (expliciet géén installatiemethode)
deploy/manifest/     <app_id>.manifest.yaml (manifeststandaard §9, install.method custom_app)
.env.example         alle variabelen gedocumenteerd, géén echte waarden (voor ontwikkeling; de Custom App heeft geen
                     verplichte variabelen)
docs/openapi/        geëxporteerde OpenAPI
docs/adr/            ADR-0001… (keuzes en waarom)
docs/platform-v2/    pakketdocs + DELTA_MATRIX.md (bestaande repos) + EVIDENCE.json
tests/e2e/           dienst-E2E met simulators
.github/workflows/   ci.yml (ruff, mypy, pytest + postgres-service, alembic up/down, openapi-drift, pip-audit,
                     alles-in-één image bouwen en starten met healthcheck), release.yml (tag → GHCR push, SBOM,
                     digest in release/digests.json)
Makefile, VERSION (start 0.1.0), CHANGELOG.md, geen licentie toevoegen zonder vraag aan de gebruiker
```
Container: start als root alleen voor eigenaarschap van `/appdata`, daarna alle processen als 568:568,
`no-new-privileges`, geen extra capabilities, geen Docker-socket, healthcheck; resource-limieten worden in het
formulier/de API-waarden gezet.

## 11. Bewijs en Excel (EVIDENCE.json)

Elke repo houdt `docs/platform-v2/EVIDENCE.json` bij — een lijst met objecten:
```json
{"id":"B01-003","status":"Bezig","validatie":"Sim-getest","bewijs":"commit <sha>; tests/e2e/test_install.py::test_privileged_manifest_rejected",
 "blokkade":"","opmerking":"","repo":"ai-server-manager","bijgewerkt":"2026-11-09"}
```
- `id` = exacte ID uit de Excel (`B01-003`, `I23-23-05`, `APP-07`, `EX17`, `D04`).
- `status` ∈ Excel-lijst: Werkpakketten/Fasen `Niet gestart|Bezig|Gereed|Geblokkeerd|N.v.t.`; Testmatrix
  `Niet gestart|Bezig|Geslaagd|Mislukt|Geblokkeerd|N.v.t.`; Besluiten `Open|Ingevuld|Getest|Geblokkeerd|N.v.t.`.
- **Regel (gekozen door gebruiker):** code + CI + simulator-E2E geslaagd ⇒ `status: Bezig` (of `Geblokkeerd` als echte
  NAS/hardware/account nodig is), `validatie: Sim-getest`/`Unit-getest`/`NIET GEVALIDEERD (echte NAS)`/
  `NIET GEVALIDEERD (hardware)`/`NIET GEVALIDEERD (account)`/`NIET GEVALIDEERD (Mac/Xcode)`. `Gereed`/`Geslaagd` alleen na
  echte acceptatie op de NAS — dat kan in deze bouwomgeving niet en wordt dus **nooit** gezet.
- Testmatrix (EX01–EX50): simulator-resultaat in `validatie` ("Sim-geslaagd"/"Sim-mislukt"); `status` blijft
  `Bezig` of `Geblokkeerd` tot een echte run.
- `ai-server-manager/tools/excel/update_excel.py` voegt alle EVIDENCE.json samen in
  `docs/platform-v2/08_EXCEL/TrueNAS_V2_Uitvoering_en_Afvinken.xlsx` (kolom **Validatie** toegevoegd).

## 12. Commit- en pushregels

Branch `ccr-c133d7a0-kuz1cv` in elke repo; geen PR's; geen force-push; kleine logische commits per fase/onderdeel,
NL-commitberichten, afgesloten met:
```
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_017JdKNGFT8sA1ouPbVkuzpR
```
`ai-factory` wordt niet aangeraakt. Bestaande integriteit, rollback en monitoring in MediaGuard/MSO/my_house nooit
dubbel bouwen, vervangen of uitschakelen.
