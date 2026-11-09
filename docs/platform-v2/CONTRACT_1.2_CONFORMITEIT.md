# Conformiteit met contract 1.2 — wat elke repo moet veranderen

Peildatum 2026-11-09 · Bij: `PLATFORM_CONTRACTEN.md` (`contracts 1.2`) · Motivering: `docs/adr/ADR-0011-contract-1-2.md`.
Gemaakt door de contracteigenaar door de code en ADR's van alle repos te **lezen** (stand van de branch
`ccr-c133d7a0-kuz1cv` op de peildatum). Niets hiervan is al gebouwd tenzij er "conform" staat; niets is op een echte NAS
getest. Paden zijn relatief aan de repo. Bouwers werken per repo; kruisafhankelijkheden staan onder "Volgorde".

**Onafhankelijke review (2026-11-09, ADR-0012):** elke genoemde bestandsnaam is in de repo teruggevonden; de lijst is
bijgewerkt naar wat bouwers ná het vaststellen van 1.2 al gecommit hadden. Gecontroleerde stand per repo:
home-control-hub `ccc55e5`, appstore-en-fork `2895404`, jelly-leon-platform `0a13cc8`, zoeken-en-persoonlijke-ai
`5ca8c57`, media-guard-ultimate `8cd3175`, media-source-optimizer `4558ee4`, my_house `210614b`, jelly-leon
`d4bc20d6a`, jelly-leon-web `2795f3365`, jelly-leon-clients `f585a08`. Wat daarna gecommit is, staat hier niet in.

## 0. Voor alle repos

- **A1** Kopie van `PLATFORM_CONTRACTEN.md` 1.2 in `docs/platform-v2/` (volgende stap van de orkestratie, niet per repo
  zelf aanpassen).
- **A2** Commits eindigen met de attributieregel(s) van de lopende sessie; geen `Claude-Session:`-link meer (§12).
- **A3** Vóór publiek maken (besluit 3): scan van de volledige historie op geheimen en privégegevens; bevindingen eerst
  aan de gebruiker. Bekende kandidaten staan per repo hieronder (o.a. echte LAN-adressen in testrapporten).
- **A4** `EVIDENCE.json`: `validatie` mag meerdere lijstwaarden met `"; "` bevatten (§11); nooit `Gereed`/`Geslaagd`.
  Toelichting hoort in `opmerking`, niet in `validatie`. In de review stond nog vrije tekst in `validatie` bij
  home-control-hub (o.a. B13-002, B13-003, B10-001…006), my_house (B06-001…008) en zoeken-en-persoonlijke-ai (o.a.
  B07-002…006, B15-002/005/006, I14-14-03); ai-server-manager (D01–D18) is in de review gerepareerd en heeft nu een
  test (`apps/api/tests/unit/test_evidence_contract.py`) die §11 bewaakt — een vergelijkbare test per repo wordt
  aanbevolen (jelly-leon-clients heeft er al een).
- **A5** Elke nieuwe dienst (home-control-hub, appstore-en-fork, jelly-leon-platform, zoeken-en-persoonlijke-ai,
  executor) krijgt een unit-test met de **testvectoren uit §4.5** (thumbprint + sleutelset-vingerafdruk
  `MEGG-8GFG-2E4Y-K2RQ` en `CYRC-JS8C-14AN-JR17`) en een test dat het enroll-verzoek exact de velden van §3.3 bevat
  (geen extra velden). Hub-simulatoren volgen §3.3 exact, inclusief `401 invalid_enrollment`, `422 validation_error`,
  `429` met `Retry-After` en `enrollment_replayed`.
- **A6** Rooktests van alles-in-één images draaien **zonder** `--security-opt no-new-privileges` en **zonder**
  `--cap-drop` (zoals het TrueNAS-formulier) en controleren voor **elk** proces, ook PID 1, `Uid 568`, `CapEff 0` en
  `NoNewPrivs 1` (§2.2). In de review aangetroffen: `dumb-init` blijft als root PID 1 in home-control-hub,
  appstore-en-fork, jelly-leon-platform, zoeken-en-persoonlijke-ai en MSO (`ENTRYPOINT ["/usr/local/bin/dumb-init",
  "--"]`), `tini` in MediaGuard (`deploy/aio/Dockerfile`); de Hub (bewaker is PID 1 en wisselt zelf) en jelly-leon
  (`exec setpriv`) niet. Oplossing: bewaker als PID 1 die zombies opruimt (zoals `ai-server-manager`
  `deploy/allinone/supervisor.py`), of de init pas na de wissel starten. Alleen de Hub, appstore-en-fork en jelly-leon
  controleren nu `CapEff`.
- **A7** Gemeenschappelijk voor de vier nieuwe diensten (home-control-hub, appstore-en-fork, jelly-leon-platform,
  zoeken-en-persoonlijke-ai) en de executor, naast de punten per repo:
  - `app_id` blijft de vaste constante uit §2 (zo gebouwd: `APP_ID` in het pakket-`__init__`); niet afleiden uit de
    TrueNAS-appnaam.
  - Enroll-verzoek: `public_key_jwk` alleen `{kty, crv, x, kid}` met `kid` = RFC 7638-thumbprint; **geen** `use`/`alg`
    (de Hub weigert ze in 1.2 met 422).
  - `hub-link.json`: `state` zonder `bezig`; lopende poging in `pending` naast de bestaande koppeling; `previous_pins`;
    `last_error` als `{code, at}`; elk proces leest het bestand opnieuw bij een wijziging (§3.5, §3.6).
  - Herstart: `pending` met koppelcode → `koppelen_onderbroken`; definitief mislukt → hash in
    `used_enrollment_token_sha256`, bestaande koppeling ongemoeid (§3.6).
  - Hub-aanroepen volgen nooit een redirect; Hub-adres op de statuspagina met dezelfde regels als `HUB_URL` (§3.2).
  - 401 van de Hub → eerst `GET /api/v1/services/self`; pas bij opnieuw 401 `ingetrokken` (§3.8).
  - Rotatie: nieuw token bevestigen met `services/self`; `Hub-Token-Rotation: required` ook na een onderbroken rotatie
    (§3.8).
  - Inkomende 401's met de vaste `reason` uit de tabel in §4.7 en de controlevolgorde daar.
  - Sleutelrotatie (§4.5): statements per doel, `sequence` zonder gaten; onbekende `kid` → direct 401, poll op de
    achtergrond. Zolang de Hub `{"items":[]}` geeft, is alleen het pollen en het verwerken van een lege lijst nodig.

## Volgorde (kruisafhankelijkheden)

1. **Hub eerst** (`ai-server-manager`, §1 hieronder: H1–H6): enroll-schema 1.2, `services/self`, dienst-JWT met
   `token_use`, vingerafdruk. Daarna kunnen de diensten tegen de echte Hub testen.
2. **Diensten** (home-control-hub, appstore-en-fork, jelly-leon-platform, zoeken-en-persoonlijke-ai): client, opslag,
   inkomende auth, statuspagina. Tot de Hub H1–H4 levert, testen ze tegen hun simulator die al 1.2 volgt.
3. **Validator eerst** (`appstore-en-fork` M1–M6, met de overgangsregel `deprecated_field` die oude manifesten nog
   accepteert); pas daarna de manifesten in de andere repos aanpassen — de huidige validator eist
   `joins_platform_network` en `custom_app.ports` nog.
4. Bestaande apps (P3) en Jellyfin-repos (12.x-upgradefase vóór P4) volgen hun eigen fase.

---

## 1. ai-server-manager (Hub + executor; contracteigenaar)

**Conform:** 1 MiB-grens vóór auth, ook chunked (`apps/api/src/hub/app.py`, ADR-0010); `jti` in gebruikers-JWT's
(`apps/api/src/hub/keys.py`); AI-runner 569 met zelfcontrole (`deploy/allinone/supervisor.py`, ADR-0005);
`PR_SET_NO_NEW_PRIVS` in Hub en executor (`deploy/allinone/supervisor.py`, `deploy/executor/entrypoint.py`) en rooktest
(`deploy/smoke.sh`: geen root, AI-runner 569, `NoNewPrivs 1`; de controle op `CapEff 0` ontbrak en is in de review
toegevoegd); rate-limit op enroll per bron-IP in de database (`apps/api/src/hub/routers/services.py`: na 10 mislukte
pogingen 429, zoals §3.3); inlog-rate-limit per (gebruikersnaam, bron-IP) (`routers/auth.py`, zoals §4.1 vraagt);
alleen hashes van tokens; D10 = Ingevuld (`docs/platform-v2/EVIDENCE.json`); referentie-implementatie van de
thumbprint en sleutelset-vingerafdruk met de contracttestvectoren (`apps/api/src/hub/keys.py`).

| # | Wijziging | Bestanden |
|---|---|---|
| H1 | `EnrollIn`: `public_key_jwk` en `version` verplicht (`version` nu `default=""`); `app_id` TrueNAS-patroon `^[a-z]([-a-z0-9]*[a-z0-9])?$` (1–40) i.p.v. `APP_ID_PATTERN`; `enrollment_token` met patroon `^enr_[A-Za-z0-9_-]{43}$`; `pairing_code` na normalisatie precies 12 Crockford-tekens, anders 422; JWK: `use`/`alg`/andere velden → 422 (nu stil weggelaten in `_jwk`), `kid` indien aanwezig = RFC 7638-thumbprint (anders 422), bewaren als `{kty, crv, x, kid=thumbprint}`. Antwoord aanvullen met `schema_version:"1.2"`, `keyset_fingerprint`, `key_rotation_url`, `enrollment_replayed`. | `apps/api/src/hub/routers/services.py`, `apps/api/tests/integration/test_enrollment.py`, `docs/openapi/hub-api.openapi.json` |
| H2 | Toegestane herhaling (§3.6): grant bewaart `used_with_key_thumbprint`; token krijgt `grant_id`; herhaling alleen bij zelfde thumbprint, niet verlopen, token nooit gebruikt → oud token intrekken, nieuw uitgeven. Nieuw `GET /api/v1/services/self`. | `apps/api/src/hub/models.py`, nieuwe migratie `apps/api/alembic/versions/0002_*.py`, `routers/services.py`, tests |
| H3 | Rotatie (§3.8): `POST /services/{id}/rotate` (admin) → `202`, geen token, zet `rotation_requested_at`, nu mét verplichte `Idempotency-Key` (geeft geen geheim meer terug); header `Hub-Token-Rotation: required` op dienst-aanroepen zolang de aanvraag openstaat **en** als een dienst een ouder token gebruikt terwijl het nieuwste nooit gebruikt is; oude tokens geldig tot 10 min na het eerste gebruik van het nieuwe, max. 24 uur (nu vast 10 min vanaf de rotatie in `_rotate`); herhaalde `self/rotate` trekt ongebruikte nieuwe tokens in; token > 180 dagen alleen een melding in de Hub-UI (geen automatische rotatie, R2). ADR-0006 bijwerken (enroll-herhaling). | `routers/services.py`, `apps/api/src/hub/deps.py`, `models.py`, migratie, `docs/adr/ADR-0006-idempotency-en-geheimen.md` |
| H4 | JWT's: `token_use:"user"` in gebruikers-JWT's; nieuwe `issue_hub_service_jwt(audience, service_id)` (`sub:"hub"`, `roles:["service"]`, `token_use:"hub_service"`, `jti`, ≤ 120 s) voor elke Hub → dienst-aanroep (nieuwe JWT per mutatie); de vingerafdruk zelf bestaat al als referentie-implementatie (`jwk_thumbprint`, `keyset_fingerprint`, `normalize_fingerprint`, `KeyRing.keyset_fingerprint()` met de testvectoren in `apps/api/tests/unit/test_keyset_fingerprint.py`), maar zit nog niet in het enroll-antwoord. `GET /api/v1/auth/key-rotations` (zonder authenticatie) → `{"items":[]}` tot rotatie gebouwd is. Hub-sleutel `kid` blijft `sha256(raw)[:16]` (geen eis in 1.2). | `apps/api/src/hub/keys.py`, `apps/api/src/hub/routers/auth.py`, `apps/api/tests/unit/` |
| H5 | Hub-UI scherm "Diensten": enrollment-token en koppelcode maken met **vingerafdruk + kopieerknop**, publieke sleutelset (`jwks` + `policy_public_key`) kopieerbaar voor bestaande apps (§2.3 regel 3), register (laatste 4, gebruikt, ingetrokken), ontkoppelen (`POST /connector/v1/hub-link/unlink` bij de dienst, daarna revoke), opnieuw koppelen (nieuw token; vanaf P2 via executor `app.update`), rotatie aanvragen. Bij installatie via de API altijd `HUB_URL`, `HUB_ENROLLMENT_TOKEN`, `HUB_KEY_FINGERPRINT` meegeven. Na ontwerpstap (§13). | `apps/web/src/app/…` (nieuw), `apps/web/e2e/*.spec.ts`, worker/lifecycle-aanroep in P2 |
| H6 | Noodlogin (§4.1): vlag `break_glass` + TOTP (RFC 6238) op gebruikers, login alleen vanaf privé-bereiken (echte bron-IP), sessie ≤ 60 min, incident `auth.break_glass.used`, rotatieplicht, herbevestiging 90 dagen, `POST /api/v1/auth/break-glass/selftest` (toont ook het bron-IP zoals de Hub het ziet); "OIDC verplicht" geblokkeerd zonder werkend noodaccount; beleid van home-control-hub alleen als verscherping cachen. Excel B01-006, B13-001 (afhankelijkheid). | `apps/api/src/hub/models.py`, migratie, `routers/auth.py`, `apps/api/src/hub/security.py`, `apps/web/src/app/…`, tests |
| H7 | Executor-koppelen (P2, §3.9): enroll met koppelcode (30 min) + vingerafdruk op de executorpagina, pinning van de policy-sleutel, schrijfkey live verifiëren tegen het bij de eerste koppeling vastgelegde NAS-adres + TLS-certificaatvingerafdruk; ontkoppelen/roteren alleen na zo'n live geverifieerde schrijfkey. Executor-koppelcode 30 min: nu bestaat alleen `pairing_code_ttl_seconds` (60 min) voor diensten. | `apps/executor/src/executor/app.py`, nieuw `apps/executor/src/executor/hublink.py`, `apps/executor/tests/` |
| H8 | Manifesten volgens §9: `joins_platform_network` en `custom_app.ports` weg; header "platformcontract 1.2". | `deploy/manifest/ai-server-manager.manifest.yaml`, `deploy/manifest/ai-server-manager-executor.manifest.yaml` |
| H9 | Custom App-instructies: tag als `<versie>@sha256:<digest>` uit `release/digests.json` (met terugval op alleen de versie, NIET GEVALIDEERD of het formulier `@` accepteert); publieke image, registry-login alleen als fallback. | `deploy/truenas/CUSTOM_APP.md`, `README.md` |
| H10 | Lifecycle-hulp in de Hub (P2): vóór elke `app.update` de volledige vorige `values` (tag+digest) als terugzetrecept bewaren; `app.rollback` van een Custom App = `app.update` met die waarden; digest-readback na installatie/update (`app.image.query`). | executor/worker (P2), samen met `jelly-leon-platform` B08-003/004 |
| H11 | Hub-adapters bestaande apps (P3, §2.3): MediaGuard `X-Api-Key` (viewer), my_house viewer-token via `POST /api/v1/pairing/redeem`, MSO machine-sleutel (zodra MSO die heeft), Jellyfin alleen openbare routes + niet-admin-gebruiker; foutformaten van bestaande routes vertalen. | nieuwe adaptermodules in `apps/api/src/hub/` (P3) |
| H12 | Web-UI omzetten naar de ontwerptaal (§13) zodra `docs/platform-v2/ONTWERPTAAL.md` + `design/ontwerptaal/` er zijn (Tailwind 4 + shadcn/ui + lucide in `apps/web/package.json`; `src/app/globals.css` naar tokens). | `apps/web/**` |
| H13 | Open punt voor een volgende contractversie: scopes per dienst op `GET /connector/v1/items` (nu leest elke ingeschreven dienst alle besluiten; ADR-0010). | `apps/api/src/hub/routers/` (connector) |
| H14 | Register (P2): `app_id` (vast, §2) apart van de werkelijke TrueNAS-appnaam (gemeten via `app.query` op image-repository, door de gebruiker bevestigd); bij een afwijkende appnaam die naam gebruiken voor `app.update`/hostpoort. | `apps/api/src/hub/models.py` (`Service`), migratie, Hub-UI "Diensten" |

---

## 2. home-control-hub

**Conform:** 1 MiB-grens vóór auth, ook chunked (`apps/api/src/integrations/bodylimit.py`, ADR-0006); `jti`-replaycache
voor mutaties met fail-closed (`apps/api/src/integrations/security/replay.py`, ADR-0008); koppelen via de statuspagina
alleen als niet gekoppeld, CSRF + Origin; `HUB_ENROLLMENT_TOKEN` wordt gelezen; JWT-controles iss/aud/exp/120 s.

| # | Wijziging | Bestanden |
|---|---|---|
| HC1 | Enroll-verzoek exact §3.3: `enrollment_token` \| `pairing_code` i.p.v. `kind` + `secret`; `api_prefix`/`connector_prefix` weg (de Hub leest `discover`); `public_key_jwk` zonder `use`/`alg` (nu `self.identity_jwk` uit `security/secrets.py` `public_jwk`, `kid` is al de RFC 7638-thumbprint). Antwoord: alle verplichte velden controleren (o.a. `jwks`, `policy_public_key`, `keyset_fingerprint`, `app_id`); vingerafdruk zelf berekenen en vergelijken met `HUB_KEY_FINGERPRINT`/formulier; daarna `GET /api/v1/services/self`. 401/422 definitief, 429 `Retry-After`, 5xx backoff tot 15 min, stoppen na 60 min. | `apps/api/src/integrations/enrollment.py`, `apps/api/src/integrations/hubclient.py`, `apps/api/tests/integration/test_enrollment_and_worker.py`, `tests/e2e/sim_hub.py` |
| HC2 | Opslag naar `/appdata/secrets/hub-link.json` (§3.5) i.p.v. `ServiceState` + vault (`vault://hub/service-token`); eenmalige overzetting; witte lijst voor publieke status; `pending` + herhaling na herstart (§3.6). | `enrollment.py`, `apps/api/src/integrations/security/secrets.py`, `apps/api/src/integrations/models.py`, migratie |
| HC3 | Inkomend: `Bearer <service-token>` niet meer accepteren (`service_token_not_accepted`); dienst-JWT (`token_use:"hub_service"`, `sub:"hub"`, `roles:["service"]`, `service_id` = eigen) → principal `service:hub`; `token_use` verplicht; `jti` op **elke** JWT verplicht (nu alleen bij mutaties). `reason`-waarden naar de vaste Engelse lijst van §4.7 (nu o.a. `niet_gekoppeld`, `token_hergebruikt`, `jwks_niet_beschikbaar`). | `apps/api/src/integrations/security/auth.py`, `security/replay.py`, tests |
| HC4 | Pinning: vertrouwensset = pins uit `hub-link.json`; de via HTTP opgehaalde JWKS voegt niets toe; onbekende `kid` → 401 `unknown_key`; rotatie via `/api/v1/auth/key-rotations` (§4.5). | `apps/api/src/integrations/security/jwks.py`, `worker.py` |
| HC5 | Statuspagina: formulier alleen als `first_linked_at` leeg; veld Hub-vingerafdruk; **lokale ontkoppelcode verwijderen** (`new_unpair_code`, formulier `/ontkoppelen`, logregel); throttle per bron-IP 5/15 min + 20/15 min per dienst (nu 10/10 min voor de hele dienst). | `apps/api/src/integrations/status_page.py`, `apps/api/src/integrations/app.py` |
| HC6 | Ontkoppelroute naar `GET /connector/v1/hub-link` + `POST /connector/v1/hub-link/unlink` (dienst-JWT of admin) i.p.v. `POST /integrations/v1/enrollment/unpair`; env-token met nieuwe hash koppelt opnieuw, ook als al gekoppeld (§3.8); 401 van de Hub → `ingetrokken`; `Hub-Token-Rotation` → `self/rotate`. | `app.py`, `connector.py`, `enrollment.py`, `worker.py`, `docs/openapi/home-control-hub.openapi.json` |
| HC7 | `PR_SET_NO_NEW_PRIVS` na `os.setuid` in de bewaker; geen root-PID 1 meer (`dumb-init`, A6); rooktest zonder `--security-opt`/`--cap-drop` en met `CapEff`/`NoNewPrivs` per proces (A6). | `deploy/allinone/supervisor.py`, `deploy/allinone/smoke-test.sh` |
| HC8 | Config: alias `ENROLLMENT_TOKEN` uitfaseren (waarschuwing), `HUB_KEY_FINGERPRINT` toevoegen. | `apps/api/src/integrations/config.py`, `.env.example`, `deploy/truenas/CUSTOM_APP.md` |
| HC9 | Manifest §9: `joins_platform_network`, `custom_app.ports` weg. CUSTOM_APP.md: tag met digest, registry-fallback. | `deploy/manifest/home-control-hub.manifest.yaml`, `deploy/truenas/CUSTOM_APP.md` |
| HC10 | B13-001: noodlogin zit in de Hub (H6); deze dienst blijft register en adviseur; `sso.recovery.readiness_changed` blijft de bron voor de Hub-cache. ADR-0002/0008 bijwerken naar 1.2 (open punten gesloten). | `docs/adr/ADR-0002-authenticatie-en-koppelen.md`, `docs/adr/ADR-0008-jwt-replay-en-contract-1-2.md` |
| HC11 | Statuspagina-CSS uit de tokens van de ontwerptaal (§13; framework-vrij). | `status_page.py` |

---

## 3. appstore-en-fork

**Conform:** 1 MiB-grens (`apps/api/src/appstore/app.py`); statuspagina-throttle 5/15 min per bron-IP
(`apps/api/src/appstore/api/status_page.py`); 4xx-tokens nooit opnieuw; `PR_SET_NO_NEW_PRIVS` in de image
(`deploy/allinone/supervisor.py`); `HUB_ENROLLMENT_TOKEN`.

| # | Wijziging | Bestanden |
|---|---|---|
| AS1 | Enroll-verzoek: veld `capabilities` weg; `public_key_jwk` zonder `use`/`alg` en met `kid` = RFC 7638-thumbprint (nu `manifest/provenance.py` `public_jwk` met `kid` = `key_id` en `use`/`alg`); antwoord volledig controleren + vingerafdruk + `services/self`; aliassen `policy_public_jwk` weg; backoff/429 volgens §3.3 (nu ook 400/403/409/410 als definitief: mag, het zijn geen 1.2-codes). | `apps/api/src/appstore/hublink.py`, `apps/api/tests/fakehub.py`, `apps/api/tests/integration/test_service_basics.py`, `tests/e2e/test_service_e2e.py` |
| AS2 | Opslag naar `/appdata/secrets/hub-link.json` i.p.v. tabel `HubLink` (versleuteld token); eenmalige overzetting; herhaling na herstart. | `hublink.py`, `apps/api/src/appstore/models.py`, `apps/api/src/appstore/secrets_store.py`, nieuwe alembic-migratie |
| AS3 | Inkomend: service-token niet meer accepteren; dienst-JWT → principal service (nu "telt als operator"); `token_use` verplicht; **`jti` verplicht + persistente replaycache** (ontbreekt nu volledig); `reason`-lijst §4.7 (nu o.a. `hub_not_linked`, `jwks_unavailable`). | `apps/api/src/appstore/auth.py`, models + migratie (`jti`-tabel), tests |
| AS4 | Pinning (§4.5): JWKS uit `HubLink.jwks`/HTTP voegt geen sleutels meer toe. | `auth.py` |
| AS5 | Statuspagina: formulier alleen als nooit gekoppeld (nu ook na `revoked`); vingerafdrukveld; extra cap 20/15 min per dienst. | `api/status_page.py` |
| AS6 | `GET /catalog/v1/hub-link` → `GET /connector/v1/hub-link` + `POST /connector/v1/hub-link/unlink`; env-token met nieuwe hash koppelt opnieuw; `Hub-Token-Rotation`. | `api/catalog.py`, `api/connector.py`, `docs/openapi/*.json` |
| M1 | **Validator §9:** `network.joins_platform_network` uit het verplichte schema; aanwezig `false` → `deprecated_field` (waarschuwing), `true` → bestaande fout `platform_network_not_supported` (`rules.py` r. ~892, blijft); `--strict` → fout. | `schemas/manifest-v1.schema.json` **en** de kopie `apps/api/src/appstore/manifest/manifest-v1.schema.json` (moeten gelijk blijven), `apps/api/src/appstore/manifest/model.py` (`Network`), `manifest/rules.py` (r. ~892) |
| M2 | `custom_app.ports` uit het schema (nu in `required` van `CustomApp`); vertaling uit `network.ports`; legacy gelijk → `deprecated_field`, anders `ports_inconsistent`; `custom_app.portal.port` tegen `network.ports` controleren (nu tegen `custom_app.ports`, `rules.py` r. ~811). | schema's, `model.py` (`CustomApp`), `rules.py` (r. ~686, ~811), `manifest/translate.py` |
| M3 | GPU: nieuw `ParamType` `gpu` (`none\|intel_render`); `custom_app.gpu` mag `{param: …}`; regel `custom_app.gpu ≠ none` ⇒ `privileges.gpu = intel_render` (vervangt `gpu_inconsistent` r. ~791); `intel_render` vereist `privilege_reason` + D08 in `decisions_required`; ontbrekende parameterwaarde → `none`; vertaling `use_all_gpus` alleen bij gemeten render-node (D08). | schema's, `model.py`, `rules.py`, `translate.py`, `apps/api/src/appstore/catalog/service.py` (r. ~331) |
| M4 | Nieuwe meldingscode `deprecated_field` in de tabel; `jl-manifest validate --strict` faalt erop. | `apps/api/src/appstore/manifest/findings.py`, `docs/MANIFESTSTANDAARD.md` |
| M5 | Vertaling naar het formulier: `image.tag` als `<tag>@<digest>` (§2.2) met digest-readbackstap in de preview; `version_unavailable` als blokkade bij verdwenen catalogusversie (samen met jelly-leon-platform). | `manifest/translate.py`, `manifest/truenas.py`, `docs/TRUENAS_APP_VALUES.md`, `docs/adr/ADR-0004-truenas-vertaling.md` |
| M6 | Fixtures en docs bijwerken; eigen manifest conform. | `apps/api/tests/fixtures/manifests/*.manifest.yaml` (o.a. `valid-custom-upstream`, `valid-catalog`, `ex47-privileged-hostmount`), `docs/adr/ADR-0002-manifeststandaard-v1.md`, `deploy/manifest/appstore-en-fork.manifest.yaml` |
| AS7 | Statuspagina-CSS uit de ontwerptaaltokens (§13). | `api/status_page.py` |
| AS8 | Geen root-PID 1 meer (`dumb-init` in `deploy/allinone/Dockerfile`, A6); de image-E2E controleert `CapEff` al, maar dan ook voor PID 1 en zonder uitzondering voor de init. | `deploy/allinone/Dockerfile`, `deploy/allinone/supervisor.py`, `tests/e2e/test_allinone_image.py` |

---

## 4. jelly-leon-platform

**Conform:** enroll-verzoek met exact de velden van §3.3 en `kid` = RFC 7638-thumbprint, zonder `use`/`alg`, plus een
even strenge Hub-simulator (`8c83aa6`, ADR-0004 herzien; na het vaststellen van 1.2 gebouwd); 1 MiB-grens vóór auth,
ook chunked (`apps/api/src/lifecycle/limits.py`, `d5fda8a`); JWT alleen met sleutels van een **geslaagde** koppeling
(ADR-0009); adres van mislukte poging niet bewaard;
`PR_SET_NO_NEW_PRIVS` in de image; TrueNAS-feiten (ix-app 1.4.8, `clear_caps`, `app.rollback`, catalogustreinen) al
vastgelegd in `docs/platform-v2/TRUENAS_APP_API.md`; ontkoppelen alleen met admin.

| # | Wijziging | Bestanden |
|---|---|---|
| JP1 | ~~Enroll-verzoek: `kind`, `capabilities`, `schema_version` weg~~ (gedaan in `8c83aa6`). Nog: antwoord zonder aliassen (`token`, `id` worden in `parse_response` nog gelezen); volledige controle + vingerafdruk + `services/self`; herhaling na herstart. | `apps/api/src/lifecycle/enrollment.py`, `e2e/simulators/hub/hub_sim.py`, `apps/api/tests/integration/test_enrollment_worker.py` |
| JP2 | Opslag naar `/appdata/secrets/hub-link.json` i.p.v. tabel `hub_link` (versleuteld token, `jwks_fetched_at`); overzetting. | `apps/api/src/lifecycle/hublink.py`, `apps/api/src/lifecycle/secrets_store.py`, `apps/api/src/lifecycle/models.py`, migratie in `apps/api/src/lifecycle/migrations/versions/` |
| JP3 | Inkomend: service-token niet meer accepteren; dienst-JWT; `token_use`; **`jti` verplicht + persistente replaycache** (ontbreekt); pins i.p.v. JWKS-cache met TTL (de leeftijdsregel van ADR-0009 punt 3 vervalt voor gepinde sleutels). | `apps/api/src/lifecycle/auth.py`, tests |
| JP4 | ~~1 MiB-grens vóór auth~~ — **conform** sinds `d5fda8a` (`limits.py` `BodySizeLimitMiddleware`, `details.max_bytes`). | — |
| JP5 | Statuspagina: vingerafdrukveld; formulier alleen als nooit gekoppeld. De throttle is nu 5/15 min voor de hele app-instantie: binnen de maxima van §3.7 (conform), maar één bron kan zo alle pogingen opmaken; per-bron-IP-telling naast een dienstbrede grens ≤ 20 wordt aanbevolen. | `apps/api/src/lifecycle/statuspage.py` |
| JP6 | `/lifecycle/v1/hub-link` + `/hub-link/unlink` → `/connector/v1/hub-link` (+ `/unlink`, ook met dienst-JWT); env-token met nieuwe hash koppelt opnieuw. | `apps/api/src/lifecycle/api_lifecycle.py`, `api_connector.py`, `docs/openapi/jelly-leon-platform.openapi.json` |
| JP7 | B08-003/004 (P2): terugzetten Custom App = `app.update` met bewaarde vorige waarden; `app.rollback` alleen catalogusapps; digest in het tagveld + readback; blokkade `version_unavailable`; TrueNAS-simulator: `app.rollback` weigert image-tagwijziging van ix-app, catalogus met één versie per app. | lifecycle-planner (P2), `e2e/simulators/truenas/…` |
| JP8 | `INSTALLATIE.md`: route A (publiek) wordt de standaard, route B (registry-login) alleen fallback; tag met digest; executor-koppelen met vingerafdruk (§3.9); `HUB_KEY_FINGERPRINT`. | `install/truenas/INSTALLATIE.md`, `deploy/truenas/CUSTOM_APP.md` |
| JP9 | Manifest §9 (eigen manifest en alle later te maken I-manifesten): geen `joins_platform_network`, geen `custom_app.ports`, GPU als parameter. | `deploy/manifest/jelly-leon-platform.manifest.yaml`, toekomstige `deploy/manifest/*` |
| JP10 | Integrale E2E (P6): Hub-simulator en echte Hub met dezelfde 1.2-conformiteitstests; ADR-0004/0005/0009 bijwerken. | `e2e/`, `docs/adr/` |
| JP11 | Statuspagina-CSS uit de ontwerptaaltokens (§13). | `statuspage.py` |
| JP12 | Geen root-PID 1 meer (`dumb-init`, A6); de image-E2E slaat PID 1 nu bewust over en kijkt niet naar `CapEff`. | `deploy/allinone/Dockerfile`, `deploy/allinone/supervisor.py`, `tests/e2e/test_allinone_image.py` |

---

## 5. zoeken-en-persoonlijke-ai

**Conform:** enroll-verzoek gelijk aan de Hub (ADR-0002); statuspagina met CSRF + Origin; JWT-controles; uitgaande calls
zonder proxy-omgeving.

| # | Wijziging | Bestanden |
|---|---|---|
| ZA1 | Antwoord volledig controleren (verplichte velden §3.3) + vingerafdruk + `services/self`; herhaling na herstart. | `apps/api/src/search_ai/enrollment.py`, `tests/e2e/sim_hub.py`, `apps/api/tests/integration/test_platform_core.py` |
| ZA2 | Opslag naar `/appdata/secrets/hub-link.json` i.p.v. vault in de database; overzetting. | `enrollment.py`, `apps/api/src/search_ai/security/` |
| ZA3 | Inkomend: service-token niet meer accepteren; dienst-JWT; `token_use`; **`jti` verplicht + persistente replaycache** (nu alleen meegegeven als `token_id`); pins i.p.v. JWKS-cache; `reason`-lijst §4.7. | `apps/api/src/search_ai/security/auth.py`, `security/jwks.py`, tests |
| ZA4 | Body-grens: chunked verzoeken niet met `411` weigeren maar tellen en > 1 MiB → `413` (§5); `details` als `{"max_bytes": 1048576}` (nu `{"max": …}`). | `apps/api/src/search_ai/app.py` (middleware `trace_and_headers`) |
| ZA5 | Statuspagina: **lokale ontkoppelcode verwijderen** (`new_unpair_code`, `/ontkoppelen`); vingerafdrukveld; throttle per bron-IP 5/15 min + 20/15 min per dienst. | `apps/api/src/search_ai/status_page.py` |
| ZA6 | `POST /search/v1/enrollment/unpair` → `/connector/v1/hub-link` + `/unlink`; env-token met nieuwe hash koppelt opnieuw; `Hub-Token-Rotation`. | `apps/api/src/search_ai/app.py`, connector-router, `docs/openapi/zoeken-en-persoonlijke-ai.openapi.json` |
| ZA7 | ~~`PR_SET_NO_NEW_PRIVS` na `os.setuid`; rooktest zonder `--security-opt`~~ — **conform** sinds `72d3714` (supervisor zet `no_new_privs`, rooktest start zoals het formulier); CI groen (GitHub-run 42623359900). Nog: geen root-PID 1 (`dumb-init`) en `CapEff 0` per proces in de rooktest (A6; nu alleen `Uid` en `NoNewPrivs`). | `deploy/allinone/Dockerfile`, `deploy/allinone/supervisor.py`, `deploy/allinone/smoke-test.sh` |
| ZA8 | Manifest §9 + CUSTOM_APP.md (tag met digest, registry-fallback, `HUB_KEY_FINGERPRINT`); `.env.example`. | `deploy/manifest/zoeken-en-persoonlijke-ai.manifest.yaml`, `deploy/truenas/CUSTOM_APP.md`, `.env.example` |
| ZA9 | Statuspagina-CSS uit de ontwerptaaltokens (§13). | `status_page.py` |

---

## 6. media-guard-ultimate (MediaGuard, bestaande app; P3)

**Conform (blijft zo):** poorten 30080 + 38989/38990/37878/37879, SQLite-WAL, mounts `/config` `/work` `/data`, eigen
UI en foutformaat, alles-in-één Custom App; ADR-0013 punt 1–5 wordt door contract 1.2 §2.3 bevestigd.

| # | Wijziging | Bestanden |
|---|---|---|
| MG1 | Geen enrollment-client bouwen; Hub leest via bestaande routes met `X-Api-Key` (viewer); scopes op sleutels (P3-02) vóór operator-rechten. | `docs/adr/ADR-0013-platform-v2-p0-interpretaties.md` (status → aangenomen, verwijzing 1.2 §2.3) |
| MG2 | Nieuwe routes `/connector/v1/*` (alleen-lezen; `propose`/`apply`/`rollback` → `501 capability_unavailable`), `/healthz`, `/readyz`: contractfoutformaat + 1 MiB-grens **alleen** op die routes; webproxy zet ze door. | `apps/core/mediaguard/` (nieuwe connectormodule), `apps/web/server.mjs`, `docs/openapi/mediaguard.openapi.json` |
| MG3 | `PR_SET_NO_NEW_PRIVS` na `os.setuid` in de alles-in-één-start; geen root-PID 1 (`tini` in `deploy/aio/Dockerfile`, A6); rooktest controleert per proces `NoNewPrivs 1`, `CapEff 0`. | `apps/core/mediaguard/aio.py` (r. ~415), `scripts/aio-smoke.py` |
| MG4 | Manifest volgens 1.2 §9 (P3-07): `network.ports` met de vijf poorten, geen `joins_platform_network`/`custom_app.ports`, `privileges.gpu: intel_render` + reden + D08 met `custom_app.gpu: {param: gpu}`, `MG_HOST` met `source: wizard` (D03), tag met digest. | nieuw `deploy/manifest/mediaguard.manifest.yaml` |
| MG5 | Installatiedocs: Custom App met tag `<versie>-aio@sha256:…` en publieke image; `deploy/truenas/compose.yaml` en "Install via YAML" expliciet markeren als **ontwikkeling/CI, geen installatiemethode**. | `README.md`, `docs/INSTALL_TRUENAS.md`, `deploy/truenas/compose.yaml` (kop) |
| MG6 | Uiterlijk volgens de ontwerptaal (§13) na ontwerpstap; functies, routes, gebruikersreizen en Android-API ongewijzigd. | `apps/web/**` |
| MG7 | Vóór publiek maken (A3): testrapporten bevatten een echt LAN-adres en een gebruikersnaam — aan de gebruiker voorleggen. | `docs/reports/2026-11-04-cowork-testrapport*.md` |

---

## 7. media-source-optimizer (MSO, bestaande app; P3)

**Conform (blijft zo):** poort 38081, alles-in-één image met ingebouwde PostgreSQL en één `/appdata`, eigen UI,
foutformaat `{detail, code, correlation_id}` op bestaande routes, change-set-mechanisme.

| # | Wijziging | Bestanden |
|---|---|---|
| MS1 | **Geen enrollment in v1** (wijzigt ADR-0002 "Auth (P3-06)": daar stond Hub-JWT via JWKS uit enrollment). P3-06 wordt: **machine-sleutel met scopes** (`read`; later `changes:approve`), aangemaakt in de MSO-UI, ingevoerd in de Hub-UI; geen menselijk account in de Hub. De eigen Ed25519-identiteit (ADR-0004 punt 3) is pas nodig als MSO ooit ondertekende verzoeken verifieert of pusht. | `docs/adr/ADR-0002-hub-koppeling-via-bestaande-routes.md`, `docs/adr/ADR-0004-interpretaties-tweede-lezing.md`, `docs/platform-v2/DELTA_MATRIX.md` (P3-06/P3-07) |
| MS2 | Dunne connectorlaag `/connector/v1/*` (P3-07) met contractfoutformaat, `Idempotency-Key`, `expected_preview_hash` en 1 MiB-grens alleen op die routes; auth met de machine-sleutel; `propose` → `501`. | `apps/core/mso/` (connectormodule), migratie `0608` (`connector_idempotency`, `preview_hash`) |
| MS3 | `PR_SET_NO_NEW_PRIVS` na `os.setuid`; geen root-PID 1 (`dumb-init` in `deploy/allinone/Dockerfile`, A6); rooktest uitbreiden. | `deploy/allinone/supervisor.py` (r. ~57), `docs/test-evidence/allinone-report.md` |
| MS4 | Custom App-instructie: tag met digest; stap "0. image openbaar maken" wordt een onderhoudsnotitie (na besluit 3 is de image publiek), registry-login alleen fallback. `docs/TRUENAS_INSTALL.md` (compose/YAML met `sed` op voorbeeldpaden) markeren als ontwikkeling, geen installatiemethode. | `docs/TRUENAS_CUSTOM_APP.md`, `docs/TRUENAS_INSTALL.md` |
| MS5 | Manifest volgens 1.2 §9 (nieuw). | nieuw `deploy/manifest/media-source-optimizer.manifest.yaml` |
| MS6 | Uiterlijk volgens de ontwerptaal (§13); functies en routes gelijk. | web-UI van MSO |
| MS7 | Vóór publiek maken (A3): voorbeeldadressen en paden in installatiedocs controleren. | `docs/TRUENAS_INSTALL.md` |

---

## 8. my_house (bestaande app; P3)

**Conform (blijft zo):** eigen PWA + Android, foutformaat `{"detail":{"code","message"}}` op bestaande routes,
koppelcode-mechanisme, veiligheidsbeleid (boiler alleen lezen); ADR-0006 punt 1 (leesadapter in de Hub) wordt door
contract 1.2 §2.3 **bevestigd**; `api_clients.kind` is voor v1 niet nodig (viewer kan niets bedienen, rol niet
achteraf te verhogen).

| # | Wijziging | Bestanden |
|---|---|---|
| MH1 | **Alles-in-één Custom App-image** (ADR-0004): `deploy/allinone/Dockerfile` (base op digest), `supervisor.py`, healthcheck, first-start-init, `PR_SET_NO_NEW_PRIVS`; Custom App `smart-home`, image `ghcr.io/lvos04/my_house`, container 8080 → host 8088. | nieuw `deploy/allinone/*`, `deploy/truenas/CUSTOM_APP.md`, `deploy/manifest/my_house.manifest.yaml`, `.env.example` |
| MH2 | **Herstelprocedures zonder terminal**: updaten/terugdraaien via het formulier (tag met digest), wachtwoord vergeten, oude hoofdsleutel uploaden/sleutelwissel via de UI (nu `shc-api rekey`), verhuizen; nieuwere schema's → NL-herstelpagina (EX15). | `apps/api/**`, `apps/web/**`, `docs/onderhoud.md` (CLI alleen nog als noodprocedure) |
| MH3 | `infra/scripts/install.sh`, `infra/compose/`, `infra/scripts/render_truenas.py` en "Install via YAML" markeren als ontwikkeling/CI (naar `deploy/dev/`); `docs/installatie-truenas.md` vervangen door de Custom App-weg (bevat nu terminalcommando's met voorbeeldpaden en -adressen). | `infra/`, `docs/installatie-truenas.md`, `README.md` |
| MH4 | Bewaakt schrijfpad `POST /connector/v1/propose`/`apply` met ondertekend `ExecutionRequest`; **policy-sleutel pinnen zonder enrollment**: de beheerder plakt de publieke Hub-sleutelset (`jwks` + `policy_public_key`) in de my_house-beheer-UI, my_house toont de berekende sleutelset-vingerafdruk (§4.5) ter vergelijking met de Hub-UI en pint daarna de policy-sleutel; zonder pin → `501 capability_unavailable`. Contractfoutformaat en 1 MiB-grens alleen op nieuwe routes. | `apps/api/**` (connectormodule), ADR-0002 punt 3 bijwerken |
| MH5 | Uiterlijk volgens de ontwerptaal (§13); functies, routes, QR-koppeling en Android-gedrag gelijk. | `apps/web/**` |
| MH6 | Opruimen: het in Git opgenomen bouwartefact in de repo-root verwijderen. | `shellcheck_py-0.11.0.1-py2.py3-none-manylinux1_x86_64.manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_5_x86_64.whl` |
| MH7 | Release 0.2.0 mag opnieuw (besluit 5) — eigen stap, niet in de contractronde. | `VERSION`, release-workflow |

---

## 9. jelly-leon (server-fork)

**Conform:** identiteit "Jellyfin", zichtbare naam "Jelly Leon", GPL (ADR-0003/0004); alles-in-één entrypoint met
`setpriv --no-new-privs --inh-caps=-all --bounding-set=-all` (`deploy/allinone/entrypoint.sh`).

| # | Wijziging | Bestanden |
|---|---|---|
| JL1 | **Upgradefase vóór P4** (besluit 2, niet in de contractronde): naar de nieuwste stabiele Jellyfin 12.x (.NET 10; upstream-tags op de peildatum `v12.0`…`v12.4`, exacte versie dan opnieuw vaststellen); patches en plugins opnieuw toepassen; CI naar .NET 10 (CI is sinds `d71439da0` groen op het 9.0.x-kanaal uit `global.json`, ADR-0010; GitHub-run 42622088484). Plan: `docs/adr/ADR-0011-upgrade-12x-voor-p4.md` (in jelly-leon). | `global.json`, `.github/workflows/*`, `docs/platform-v2/FORK_STRATEGIE.md`, `docs/platform-v2/PATCHES.md`, `docs/adr/ADR-0005-versieschema.md`, `docs/adr/ADR-0006-upstream-sync.md` |
| JL2 | Manifest §9: `joins_platform_network`, `custom_app.ports` weg; GPU als `{param: gpu}` met `privileges.gpu: intel_render` + reden + D08. | `deploy/manifest/jelly-leon.manifest.yaml` |
| JL3 | Custom App-instructie: tag met digest, publieke image, registry-fallback; een eventuele stock-Jellyfin (D07 meet dat) blijft op eigen poort. | `deploy/truenas/*` |
| JL4 | Hub-adapter (v1): alleen openbare routes + niet-admin-gebruiker; de B03-plugin (P4) verifieert Hub-JWT's pas als er een pinmechanisme is (plugin-configuratie in het Jellyfin-dashboard, vingerafdruk §4.5) — ontwerp in P4, tot dan geen Hub-JWT accepteren. | P4-ontwerp, ADR in deze repo |
| JL5 | `JL_SYNC_PUSH_TOKEN` blijft open (besluit 4): geen token in repo of workflow; zonder het geheim levert de sync alleen een git-bundle als artefact (zo gebouwd) — niets wijzigen tot het besluit valt. | `.github/workflows/upstream-sync.yml` |
| JL6 | Ontwerptaal §13 is **niet** van toepassing. | — |

## 10. jelly-leon-web (web-fork)

| # | Wijziging | Bestanden |
|---|---|---|
| JW1 | Upgradefase vóór P4 samen met de server naar dezelfde 12.x (besluit 2); smoketest fork/stock opnieuw. | fork-branch, `docs/platform-v2/*`, CI |
| JW2 | Zichtbare naam "Jelly Leon" blijft de enige merkwijziging; ontwerptaal §13 is **niet** van toepassing. | — |
| JW3 | Opnieuw proberen wat in de oude sandbox geblokkeerd was (`npm ci` met het classList.js-archief) en EVIDENCE.json bijwerken naar wat nu echt lukt. | `docs/platform-v2/EVIDENCE.json` |

## 11. jelly-leon-clients

| # | Wijziging | Bestanden |
|---|---|---|
| JC1 | **Eigen applicationId** (besluit 1) als geregistreerde patch: android `applicationId` (staat nu niet in `defaultConfig`, dus impliciet `namespace`); androidtv `applicationId` + `app_id` + `app_search_suggest_authority` + `app_search_suggest_intent_data` (alle nu uit `namespace` afgeleid, r. 18 en 59–61/76–78) en de sharedpref-namen in `res/xml/backup_content.xml`/`backup_rules.xml`; `namespace` blijft. Uitwerking staat al in `docs/adr/ADR-0004-branding-en-applicationid.md`; de exacte ID's worden bij de patch vastgelegd; nooit `org.jellyfin.*`. | `android/app/build.gradle.kts`, `androidtv/app/build.gradle.kts`, `docs/platform-v2/PATCHES.md`, `docs/platform-v2/FORK_STRATEGIE.md` (open vraag sluiten), `docs/adr/` |
| JC2 | iOS/tvOS: eigen bundle-id als patch voor Swiftfin 1.6.1 — **NIET GEVALIDEERD (Mac/Xcode)**. | `swiftfin/XcodeConfig/Shared.xcconfig`, `docs/platform-v2/PATCHES.md` |
| JC3 | Android-clients op compatibiliteit met de 12.x-server controleren (na JL1); Swiftfin 1.6.1 tegen 12.x herbeoordelen. | `jelly-leon/docs/platform-v2/CLIENT_COMPAT_MATRIX.md` (alleen lezen vanuit deze repo), `docs/adr/ADR-0009-swiftfin-servercompatibiliteit.md` |
| JC4 | ~~Android/Android TV-builds opnieuw proberen~~ — gedaan in `5ee6d91` (android en androidtv lokaal gebouwd, androidtv 15/15 tests; desktop in container); proxy-teksten in `BOUWVERIFICATIE_P0.md` staan er alleen nog als geschiedenis. Op een apparaat: NIET GEVALIDEERD (hardware). | — |
| JC5 | Ontwerptaal §13 is **niet** van toepassing. | — |
