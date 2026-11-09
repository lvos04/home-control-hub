# Platformcontracten — TrueNAS Home Platform V2 (bouwcontract voor alle repos)

Versie: `contracts 1.0` · Peildatum 2026-11-09 · Eigenaar: `lvos04/ai-server-manager` (bron van waarheid).
Elke repo heeft een kopie in `docs/platform-v2/PLATFORM_CONTRACTEN.md`; bij verschil wint deze repo.
Dit document maakt de pakketvoorstellen (`01_ARCHITECTUUR/02`, `03`, `07`) concreet zodat alle repos samenwerken.
Het zegt **niets** over de echte NAS: alle NAS-gegevens (D01–D18) zijn onbekend tot de gebruiker ze in de
onboarding-wizard invult of de wizard ze via de TrueNAS-API meet.

## 1. Vaste keuzes (van de gebruiker)

- Nieuwe repos: **Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL 16**, frontend **Next.js/React PWA** (alleen in
  `ai-server-manager`; alle schermen van alle nieuwe diensten staan in die ene Hub-UI). Andere nieuwe diensten zijn
  zelfstandige API-diensten met alleen een kleine eigen statuspagina (`GET /` → eenvoudige HTML, NL).
- Installatie **zonder terminal**: eerste installatie via TrueNAS-web-UI (Apps → Discover Apps → ⋮ → *Install via YAML*,
  of Custom App), daarna alles via de platform-UI. Geen `install.sh`-stappen voor de gebruiker.
- Geen `latest`-tags. Elke image op exacte versie, base-images bovendien op `@sha256:`-digest.
- Geen shell/root voor AI, geen `sh -c`/`sudo`-endpoint, geen Docker-socket in een container, boiler nooit schakelen,
  geen betaalde API-overage (Claude alleen binnen inbegrepen credits, harde stop op 0 overage).
- Lokale modellen (Ollama-LLM, faster-whisper STT, Piper TTS, lokaal embeddingmodel) zijn **optionele apps, standaard uit**.
- UI-taal Nederlands. Elke kaart: waarde + eenheid + bron + **laatst bijgewerkt**. Onbekend is `unknown`, nooit groen.
- Jellyfin-fork: technische identiteit/API blijft "Jellyfin" (clientcompatibiliteit); alleen de zichtbare naam is
  "Jelly Leon". GPL-licentie en upstream-credits blijven staan.

## 2. Diensten, namen en poorten

Gedeeld Docker-netwerk: **`jl-platform`** (aangemaakt door de bootstrap-app; latere apps sluiten aan met
`networks: { jl-platform: { external: true } }`). Diensten vinden elkaar op hun DNS-alias in dat netwerk.
Bestaande zelfstandige apps (MediaGuard, MSO, my_house, Jellyfin, Immich, arr-apps) worden bereikt via de URL die de
gebruiker in de wizard opgeeft of die de wizard uit de TrueNAS-app-inventaris haalt — nooit een aangenomen IP.

| Repo | Dienst (DNS-alias) | Containerpoort | Image (GHCR) |
|---|---|---|---|
| ai-server-manager | `hub-web` (Next.js PWA, proxyt `/api/*` naar hub-api) | 3000 | `ghcr.io/lvos04/ai-server-manager-web` |
| ai-server-manager | `hub-api` (FastAPI) | 8000 | `ghcr.io/lvos04/ai-server-manager-api` |
| ai-server-manager | `hub-worker` (zelfde image, `command: worker`) | – | idem api |
| ai-server-manager | `hub-ai` (AI-agent-runner, zelfde image, `command: ai-runner`, géén signing key) | – | idem api |
| ai-server-manager | `hub-executor` (smalle executor, enige met schrijf-API-key TrueNAS) | 8010 | `ghcr.io/lvos04/ai-server-manager-executor` |
| ai-server-manager | `platform-db` (PostgreSQL 16; aparte database + rol per kerndienst) | 5432 | `postgres:16.x-alpine@sha256:…` |
| home-control-hub | `integrations` (B10/B11/B13/B14) | 8100 | `ghcr.io/lvos04/home-control-hub` |
| appstore-en-fork | `appstore` (catalogus, manifeststandaard, import, forkbeheer) | 8200 | `ghcr.io/lvos04/appstore-en-fork` |
| jelly-leon-platform | `platform-lifecycle` (install/update/rollback/remove/move) | 8300 | `ghcr.io/lvos04/jelly-leon-platform` |
| zoeken-en-persoonlijke-ai | `search-ai` (B07/B15) | 8400 | `ghcr.io/lvos04/zoeken-en-persoonlijke-ai` |
| zoeken-en-persoonlijke-ai | `stt` (faster-whisper, optioneel) / `tts` (Piper, optioneel) | 8410 / 8420 | gepinde upstream images |
| jelly-leon(+web) | `jelly-leon` (server incl. web-client) | 8096 | `ghcr.io/lvos04/jelly-leon` |

Hostpoort (enige standaard naar buiten): `hub-web` → voorstel **30400/TCP**; de bootstrap-YAML noemt dit als voorstel
dat de gebruiker in het TrueNAS-formulier kan wijzigen. Andere diensten publiceren standaard géén hostpoort.

**Bootstrap-app** (`jelly-leon-platform/install/truenas/bootstrap.yaml`): `platform-init` (one-shot, maakt geheimen),
`platform-db`, `hub-api`, `hub-worker`, `hub-ai`, `hub-web`, `hub-executor`, `appstore`, `platform-lifecycle`.
Opslag in de bootstrap: **benoemde Docker-volumes** (geen hostpaden, dus geen poolnaam nodig). Na onboarding (D02 ingevuld
en getest) biedt de UI een verhuizing naar gekozen datasets aan (R2, met back-up en hersteltest).

## 3. Geheimen

- Nooit geheimen in compose/YAML/Git. `platform-init` (one-shot, image van hub-api, `command: init-secrets`) maakt bij
  eerste start ontbrekende bestanden aan in het volume `jl-secrets` (mode 0600, eigenaar 568:568) en wijzigt bestaande nooit:
  `platform-db.password`, `db-<dienst>.password`, `service-token-<dienst>`, `policy-signing.ed25519` (privé; alleen hub-api),
  `policy-signing.pub` (publiek; executor + diensten), `hub-vault.key`, `executor-vault.key` (alleen executor),
  `jwt-signing.ed25519`, `bootstrap-code` (eenmalige setupcode).
- Containers lezen via `*_FILE`-omgevingsvariabelen. Executor krijgt alléén `executor-vault.key`, `policy-signing.pub`,
  en eigen DB (SQLite in eigen volume `executor-data`). `hub-ai` krijgt alléén `service-token-hub-ai`.
- De **bootstrap-code** staat in de app-logs (TrueNAS-web-UI → Apps → app → Logs) en wordt door de wizard gevraagd vóór
  het eerste admin-account. Geen terminal nodig.
- Credentials van externe apps (TrueNAS-API-keys, MediaGuard-`X-Api-Key`, my_house-token, …) voert de gebruiker in de UI in;
  opslag versleuteld (AES-256-GCM, key uit vault-keyfile), alleen vault-referentie (`vault://<scope>/<naam>`) in tabellen.
  UI toont nooit de waarde terug (alleen laatste 4 tekens + datum). Logs en evidence worden geredigeerd.

## 4. Authenticatie en rollen

- **Gebruikers** loggen in op de Hub (lokaal account, argon2id; optioneel OIDC via Authentik zodra B13 actief is).
  Rollen: `admin`, `operator`, `viewer`, `kind` (kinderprofiel). Sessiecookie (HttpOnly, SameSite=Strict, Secure achter
  HTTPS) + CSRF-token voor muterende webcalls.
- **Gebruikerscontext naar diensten**: hub-api geeft kortlevende JWT's (EdDSA, `iss=hub`, `aud=<dienst>`, `sub`, `roles`,
  `exp ≤ 120 s`). JWKS: `GET http://hub-api:8000/api/v1/auth/jwks`. Diensten met ACL (search-ai, jelly-leon-plugin)
  dwingen rol/ACL zelf af op basis van deze JWT.
- **Dienst-naar-dienst**: `Authorization: Bearer <service-token>` (per dienst eigen token uit `jl-secrets`); hub-api
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
- Push: `POST http://hub-api:8000/api/v1/events/inbox` (service-token). Dedupe op `event_id` én `(source_app, source_event_id)`.
- Bron houdt een outbox (retry met backoff, dead-letter na 10 pogingen, zichtbaar in Hub). Zonder native events: Hub pollt
  `/connector/v1/events` of bestaande routes met cursor/ETag/watermark. Geen exact-once-aanname.
- `event_type`-namen: `<domein>.<object>.<gebeurtenis>` (bv. `app.health.changed`, `backup.run.failed`,
  `incident.opened`, `action.executed`, `energy.reading.recorded`, `network.device.discovered`, `flow.action.requested`).

## 8. Risicobeleid, voorstel, goedkeuring en executor

**Stroom:** (AI, gebruiker, Node-RED-flow of spraak) → `ActionProposal` → **policy-engine in hub-api** (deterministisch,
policybestanden read-only gemount uit `ai-server-manager/policy/*.yaml`, hash `policy_hash` vastgelegd) → bij R0/R1
automatisch (allowlist, cooldown, anti-flap), bij R2/R3 **menselijke goedkeuring per gebonden diff** → hub-api ondertekent
`ExecutionRequest` (Ed25519) → `hub-executor` of de eigenaar-connector voert uit → readback → audit.

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
| `app.install` | R2 | `app.create` (custom compose uit gevalideerd manifest) |
| `app.update` | R2 | `app.update` (nieuwe gepinde compose) |
| `app.rollback` | R2 (R3 bij DB-restore) | vorige compose + snapshot-restore via eigenaar |
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
`version`, `images: [{name, repository, tag, digest}]` (tag ≠ `latest`, digest verplicht voor upstream-images; voor eigen
GHCR-images vult de release-CI de digest), `compose` (TrueNAS custom-compose-sjabloon met `${…}`-parameters),
`parameters` (getypt, met `source: wizard|dataset_picker|secret|generated|default`, nooit voorbeeldwaarden als echte waarde),
`storage: [{name, mount, kind: config|data|media|scratch, required_dataset_role}]`, `network: {ports, host_network:false,
joins_platform_network}`, `privileges: {privileged:false, cap_add:[], devices:[], gpu:none|intel_render}` + `privilege_reason`,
`healthcheck`, `backup: {db_export, snapshot_datasets, rpo, rto}`, `dependencies`, `sso: oidc|native|none`,
`risk: {install, update, uninstall}`, `upgrade: {migrations, tag_only_rollback_safe: bool}`, `decisions_required: [D01…]`,
`docs: [I-/A-doc]`, `validation_status`. Weigeren vóór uitvoering (EX47): `privileged`, Docker-socket, hostpad
`/`, `/mnt` zonder dataset, `/etc`, `/var/run`, `/root`, host network zonder reden, `latest`, ontbrekende digest.

## 10. Repo-indeling nieuwe Python-diensten

```
apps/api/            pyproject.toml, src/<pakket>/…, alembic/, tests/{unit,integration}
apps/web/            (alleen ai-server-manager) Next.js PWA + Playwright (360/390/768/1440)
apps/executor/       (alleen ai-server-manager)
policy/              (alleen ai-server-manager) policy YAML + hash
deploy/truenas/      compose.yaml (TrueNAS custom app), README_INSTALLATIE.md
deploy/manifest/     <app_id>.manifest.yaml (manifeststandaard §9)
.env.example         alle variabelen gedocumenteerd, géén echte waarden
docs/openapi/        geëxporteerde OpenAPI
docs/adr/            ADR-0001… (keuzes en waarom)
docs/platform-v2/    pakketdocs + DELTA_MATRIX.md (bestaande repos) + EVIDENCE.json
tests/e2e/           dienst-E2E met simulators
.github/workflows/   ci.yml (ruff, mypy, pytest + postgres-service, alembic up/down, openapi-drift, pip-audit,
                     docker build, Playwright waar UI), release.yml (tag → GHCR push, SBOM, digest in release/digests.json)
Makefile, VERSION (start 0.1.0), CHANGELOG.md, LICENSE-keuze laten aan gebruiker (geen licentie toevoegen zonder vraag)
```
Container: niet-root (UID/GID 568:568, zoals TrueNAS-apps), read-only rootfs waar mogelijk, `cap_drop: [ALL]`,
`no-new-privileges`, resource-limits in compose, healthcheck.

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
