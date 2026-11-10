# Conformiteit met contract 1.3 — wat elke repo moet veranderen

Peildatum 2026-11-10 · Bij: `PLATFORM_CONTRACTEN.md` (`contracts 1.3`, zelfde map) · Motivering:
`ai-server-manager:docs/adr/ADR-0027-contract-1-3.md` · Invoer: `ai-server-manager:docs/platform-v2/CONTRACT_1.3_KANDIDATEN.md`.

Gemaakt door de contracteigenaar door de code, ADR's en EVIDENCE van alle repos te **lezen** (grep en bestandsinhoud,
geen uitvoering in andere repos). Niets hiervan is al gebouwd tenzij er "conform" staat; niets is op een echte NAS,
met echte accounts of op echte hardware getest. Paden zijn relatief aan de repo. Bouwers werken per repo;
kruisafhankelijkheden staan onder "Volgorde". Wat contract 1.2 vroeg en nog open is, staat in
`CONTRACT_1.2_CONFORMITEIT.md` (historie, blijft geldig waar 1.3 het niet vervangt).

**Gelezen stand per repo** (branch `ccr-c133d7a0-kuz1cv`): ai-server-manager `22152dc`, home-control-hub `9d886ad`,
appstore-en-fork `fc682e5`, jelly-leon-platform `1d862f9`, zoeken-en-persoonlijke-ai `0d2cf0b`, media-guard-ultimate
`3998bea`, media-source-optimizer `f2bb49a`, my_house `a97d6f7`, jelly-leon `371b98379`, jelly-leon-web `5ced8a246`,
jelly-leon-clients `3da4548`. Wat daarna gecommit is, staat hier niet in.

**Onafhankelijke review (2026-11-10, ADR-0028):** steekproef per repo opnieuw tegen de code gelegd. Gecorrigeerd:
C1.3-JLP-02 en C1.3-JLP-03 (de gemeten stand klopte niet); aangevuld: de correcties RV1–RV13 van het contract (o.a.
C1.3-ASM-04, -12, -18, -19, -21, C1.3-HCH-02, C1.3-ASF-03, C1.3-MGU-02, -04, C1.3-MSO-04, C1.3-MH-02, C1.3-JL-05…07), het
ontbrekende repowerk Δ-HUB-2 bij ai-server-manager en het nieuwe punt C1.3-MH-07. jelly-leon is daarna verder gegaan
(P4-0 op 12.4, `55fd3eeeb`); de punten van hoofdstuk 9 zijn daarop nagelopen en blijven gelden.

**Lezen van de tabellen:**
- **ID** = `C1.3-<REPO>-<nn>`; dezelfde ID mag als regel in `EVIDENCE.json` (contract §11).
- **Contract** = paragraaf van `PLATFORM_CONTRACTEN.md` 1.3 en de groep uit de inventaris (A01–A36).
- **Moment** = **NU** (conformiteitsronde van 1.3) of de fase waarin het hoort: **P2** (executor, lifecycle,
  policy-engine), **P3** (bestaande apps), **P4-0** (upgrade- en overnamefase vóór P4), **P4** (B03-plugin), **P5**
  (optionele model-apps). "na BG-xx" = pas na dat besluit van de gebruiker (contract §1.2).
- Groepen (c) uit de inventaris staan per repo onder **Repowerk** (geen contractzaak); groepen (e) gaan naar Peil 1.1.1
  (§12 hieronder) en worden in de repos alleen via een nieuwe Peil-versie overgenomen.

## 0. Voor alle repos (ALG)

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-ALG-01 | **Byte-gelijke kopie** van `PLATFORM_CONTRACTEN.md` 1.3 en van dit document in `docs/platform-v2/`, met een **drifttest** (sha256 van beide tegen een vaste bron-commit). Nooit lokaal aanpassen. Gemeten: kopie 1.2 in home-control-hub, appstore-en-fork, jelly-leon-platform, zoeken-en-persoonlijke-ai, jelly-leon, jelly-leon-web en jelly-leon-clients; **nog 1.1** in media-guard-ultimate, media-source-optimizer en my_house. Drifttest aanwezig in home-control-hub, appstore-en-fork, jelly-leon, jelly-leon-web en jelly-leon-clients; **ontbreekt** in jelly-leon-platform, zoeken-en-persoonlijke-ai, media-guard-ultimate, media-source-optimizer en my_house. `CONTRACT_1.2_CONFORMITEIT.md` mag als historie blijven staan. | kop, §10 (A35) | `docs/platform-v2/PLATFORM_CONTRACTEN.md`, `docs/platform-v2/CONTRACT_1.3_CONFORMITEIT.md`, de drifttest per repo (hieronder) | NU (stap van de orkestratie, daarna de pin per repo) |
| C1.3-ALG-02 | **EVIDENCE §11 (1.3):** nieuwe waarden `Intel-iGPU-getest (ontwikkelmachine)` en `Niet getest` (alleen bij `Niet gestart`); geen lege `validatie`; Testmatrix-ID's (`EX..`, `JLT-..`) met `Sim-geslaagd`/`Sim-mislukt`; elke `NIET GEVALIDEERD (…)` uit `blokkade` ook in `validatie`; regels voor statuspagina's, reviews en contractpunten met ID `C1.3-…`/`REVIEW-…` mogen. Een EVIDENCE-test per repo die dit bewaakt (ontbreekt in media-guard-ultimate, media-source-optimizer en my_house). | §11 (A33) | `docs/platform-v2/EVIDENCE.json` + de EVIDENCE-test per repo | NU |
| C1.3-ALG-03 | **Licentie:** `LICENSE` GPL-3.0 in elke eigen repo; forks houden hun upstream-licentie. Gemeten: GPL-3.0 aanwezig in ai-server-manager, home-control-hub, appstore-en-fork, jelly-leon-platform, zoeken-en-persoonlijke-ai, media-guard-ultimate, media-source-optimizer en my_house; jelly-leon en jelly-leon-web GPL-2.0; jelly-leon-clients per subtree — **conform**. De nieuwe publieke MediaGuard-repo krijgt GPL-3.0. | §1.1 besluit 8 (A01) | `LICENSE` | NU (conform; nieuwe MediaGuard-repo bij de overstap) |
| C1.3-ALG-04 | **Images:** healthcheck in exec-vorm die eerst naar 568 + no_new_privs wisselt, met controlevlag; bij start als root bounding set leeg; rooktest controleert `CapPrm`/`CapAmb` 0, `CapBnd` 0 (root-start) en de healthcheck apart. Per repo hieronder. | §2.2 (A08) | `deploy/*/healthcheck.*`, bewaker/entrypoint, rooktest | NU (nieuwe diensten), P3 (bestaande apps) |
| C1.3-ALG-05 | **Peil-verbeterpunten** (inventaris E01–E16): alleen via Peil 1.1.1 overnemen (nieuwe kopie van het sjabloon/de tokens), nooit lokaal omzeilen. Tot dan geldt de contracttekst (bv. 409 `koppelen_bezig`, `koppelstatus_onleesbaar` zonder formulier). | §13 | statuspagina's, aliaslagen | na Peil 1.1.1 |

### Gemeenschappelijk voor de vijf eigen diensten

Voor home-control-hub, appstore-en-fork, jelly-leon-platform, zoeken-en-persoonlijke-ai en de executor gelden naast de
punten per repo deze regels; per repo staat alleen wat daar **nog niet** conform is (gemeten):

- **Adressen (§3.2, A11):** alleen canonieke IPv4 (`a.b.c.d`), IPv6 tussen `[]`, punt aan het eind van een naam negeren,
  verboden bereiken ook na DNS-resolutie per verbinding; `base_url` alleen sturen als hij geldig is, anders `null`.
- **Koppelbestand (§3.5, A12):** onleesbaar = fail-closed (`koppelstatus_onleesbaar`, geen formulier, origineel bewaren
  bij vervangen, `unreadable_replaced_at`, vervangen bij de eerste schrijfactie van een poging met een nieuw env-token,
  vóór het verzoek; `/readyz` blijft 200); de vaste aanvullende `last_error`-codes met hun HTTP-uitkomst (RV6); extra
  velden mogen; lezers accepteren elke `1.x`; een dienst schrijft `schema_version: "1.3"`.
- **Statuspagina (§3.7, A13–A15):** `Referrer-Policy: same-origin`; exacte `Origin`, `null` → 403; `Sec-Fetch-Site`;
  `Host`-beperking (403 `host_niet_toegestaan`); elke POST telt als poging, ook bij een al gekoppelde dienst (409
  `al_gekoppeld`, RV7); 409 `koppelen_bezig`; meldingen alleen bij
  een echte poging; invoer niet afkappen; één logregel per poging; "Gereed" = `/readyz` + gekoppeld + bevestigd;
  browsertest met de negatieve gevallen.
- **JWT (§4.2–§4.7, A16):** `aud` als lijst → 401 `invalid_token`; reasons uit de tabel van §4.7 (geen header / ander
  schema / lege waarde / foute handtekening met gepinde `kid` → `invalid_token`; geen `kid` → `unknown_key`); elke
  POST/PUT/PATCH/DELETE verbruikt de `jti`; authenticatie vóór rol, `Idempotency-Key` en bodyvalidatie (RV9).
- **Sleutels (§3.3, §4.5, A17):** vingerafdruk over alle policy-sleutels gesorteerd (testvector `HN69-2PHK-XV2D-X85W`
  naast `MEGG-8GFG-2E4Y-K2RQ` en `CYRC-JS8C-14AN-JR17`); `rotation_sequence` uit het enroll-antwoord overnemen (ontbreekt
  → 0); `schema_version` `"1.3"` accepteren (gemeten: alle diensten controleren alleen major 1 — conform).
- **API (§5, A20–A21):** foutcatalogus; statische test op `Idempotency-Key` met uitzonderingslijst (de formulier-POST's
  van de statuspagina staan erin met de reden van §5, RV10).
- **Connector (§6, A22–A23):** health = slechtste check; vaste checknamen `database`, `worker`, `jobs`, `hub_link`;
  `observed_at` overal; `limits.max_age_s` in `discover`; verouderd = `unknown` met `meting_verouderd`.
- **Events (§7, A24–A25):** eigen domein(en); werkwoorden; de vaste `service.*`-namen (één release beide mag); grenzen
  van de inbox vóór verzending controleren; `payload.ernst` optioneel met de vijf woorden. Niet gekoppeld = niet pushen
  en geen pogingen tellen (RV12): gemeten **conform** in home-control-hub (`worker.py` r. ~81), appstore-en-fork
  (`worker.py` r. ~115), zoeken-en-persoonlijke-ai (`worker.py` r. ~212) en jelly-leon-platform (`worker.py` r. ~114;
  `outbox.py` stopt bij 401 zonder poging te tellen).
- **Manifest (§9, A11/A30/A32):** geen `HUB_*` in parameters of `custom_app.env`; `healthcheck.monitor`; kop
  "platformcontract 1.3". Pas na C1.3-ASF-08 (validator).

## Volgorde (kruisafhankelijkheden)

1. **Contractkopieën** (C1.3-ALG-01) door de orkestratie, zodat elke repo tegen 1.3 test.
2. **Hub eerst** (`ai-server-manager`): enroll-antwoord met `rotation_sequence`/`"1.3"` en het nieuwe intrekmoment
   (C1.3-ASM-02), vingerafdruk-referentie (C1.3-ASM-03), scopes en momentopname op de inventaris (C1.3-ASM-07/08), inbox
   met domeinen, werkwoorden en ernst (C1.3-ASM-09). De diensten testen tot dan tegen hun simulator, die 1.3 volgt.
3. **Validator eerst** (`appstore-en-fork` C1.3-ASF-08), met een overgang die oude manifesten nog als waarschuwing
   accepteert; daarna de manifesten in de andere repos (jelly-leon-platform C1.3-JLP-09 en de eigen manifesten).
4. **Diensten** (home-control-hub, appstore-en-fork, jelly-leon-platform, zoeken-en-persoonlijke-ai, executor) parallel:
   statuspagina, koppelbestand, JWT, sleutels, events, connector.
5. Bestaande apps (P3), de upgrade- en overnamefase P4-0 (Δ-MG-DUAL/Δ-MG-AUTH zijn exitcriterium), de B03-plugin (P4)
   en de optionele model-apps (P5) volgen hun eigen fase. Gereserveerde MediaGuard-acties pas na BG-05 en P3-02.

---

## 1. ai-server-manager (Hub + executor; contracteigenaar)

**Conform (gemeten):** contract 1.3 zelf, deze lijst en ADR-0027; de inventaris met traceerbaarheidstest
(`apps/api/tests/unit/test_contract_13_kandidaten.py`) en de contracttest
(`apps/api/tests/unit/test_contract_13.py`: kop, wijzigingslog per groep, geen relatieve links, alle repos in deze lijst,
testvectoren); `core.subscribe` voor `reporting.realtime` (A29, ADR-0021 §5); Hub-herkenning `custom_compose` (A09,
ADR-0021); SSO met groep → rol in de Hub, https-issuer, PKCE en de regel voor het terugkeerpad (A27, ADR-0023,
ADR-0026 punt 2); heartbeat- en log-sinkroutes (A19, ADR-0021 §3, ADR-0022 §4; `monitoring/heartbeat.py`,
`routers/logs.py`, `logsink.py`); statische `Idempotency-Key`-test (A20, `apps/api/tests/unit/test_idempotency_routes.py`);
`Idempotent-Replay` en de codes van de foutcatalogus (A21, `apps/api/src/hub/deps.py`, `errors.py`); inbox-grenzen en
`source_mismatch` (A24, `events/envelope.py`, `routers/events.py`); OIDC-`client_secret` handmatig in de vault (A10 b,
`oidc/service.py`); executor-statuspagina `same-origin` + exacte `Origin` (A13 deels, ADR-0026); ontwerpreview op
320–1440 met axe `wcag22aa` (A34, `apps/web/review/peil-review.spec.ts`, ADR-0025); EVIDENCE-test en Excel-overzicht volgens §11 1.3 (A33, C1.3-ASM-15, sinds de review).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-ASM-01 | **Healthcheck** van Hub en executor: exec-vorm, als eerste handeling bounding set leeg (root) + `setgroups/setgid/setuid(568)` + `PR_SET_NO_NEW_PRIVS`, daarna pas controleren; controlevlag die `Uid`, `CapEff`, `CapPrm`, `NoNewPrivs` meldt. Gemeten: beide healthchecks draaien nu als root zonder wissel. **Bewaker en executor-entrypoint** legen de bounding set nog niet: toevoegen vóór de wissel. Rooktest: `CapPrm`/`CapAmb` 0, `CapBnd` 0 bij root-start, healthcheck apart. | §2.2 (A08) | `deploy/allinone/healthcheck.py`, `deploy/executor/healthcheck.py`, `deploy/allinone/supervisor.py`, `deploy/executor/entrypoint.py`, `deploy/allinone/Dockerfile` (r. ~98), `deploy/executor/Dockerfile` (r. ~42), `deploy/smoke.sh` | NU |
| C1.3-ASM-02 | **Enroll (Hub):** `base_url` tolerant — een string die niet aan de regels voldoet → `null` + waarschuwing in de Hub-UI, nooit 422 (nu `Field(pattern=BASE_URL)`, r. ~81); antwoord met `rotation_sequence` (nu 0, er is nog geen sleutelrotatie) en `schema_version: "1.3"` (`ENROLL_SCHEMA_VERSION`, r. ~49); bij een nieuwe enrollment van een bestaande registratie de oude tokens pas intrekken bij het eerste gebruik van het nieuwe (`services/self`), en het nieuwe intrekken als het 60 min ongebruikt blijft. OpenAPI bijwerken. | §3.3, §3.6 (A11, A17) | `apps/api/src/hub/routers/services.py`, `apps/api/src/hub/models.py` + migratie, `apps/api/tests/integration/test_enrollment.py`, `docs/openapi/hub-api.openapi.json` | NU |
| C1.3-ASM-03 | **Vingerafdruk-referentie** over alle policy-sleutels (lijst, gesorteerd); testvector `HN69-2PHK-XV2D-X85W` in de unit-test van de implementatie (de contracttest rekent hem nu onafhankelijk na). Ook de executor (pinnen en vergelijken). | §4.5 (A17) | `apps/api/src/hub/keys.py` (`keyset_fingerprint`), `apps/api/tests/unit/test_keyset_fingerprint.py`, `apps/executor/src/executor/hublink.py`, `apps/executor/tests/test_hublink.py` | NU |
| C1.3-ASM-04 | **Executor als dienst:** `rotation_sequence` lezen; adresregels (IP-vorm); koppelbestand onleesbaar fail-closed + vaste codes; `Sec-Fetch-Site`, `Host`-beperking, exacte `Origin` met het schema van het verzoek (nu worden `http://` én `https://` + Host geaccepteerd, `app.py` r. ~397), elke POST een poging, 409 `koppelen_bezig`, invoer niet afkappen, logregel per poging, "Gereed"; JWT-regels (`aud`, reasons, `jti` per POST, auth vóór body); browsertest met de negatieve gevallen in de web-E2E. De executor stuurt geen events (n.v.t. voor `service.*` tot hij dat doet). | §3.2, §3.5, §3.7, §3.9, §4 (A11–A17) | `apps/executor/src/executor/hublink.py`, `app.py`, `statuspagina.py`, `statuspagina.html`, `replay.py`, `apps/executor/tests/test_statuspagina.py`, `test_hublink.py`, `test_mutaties.py`, `apps/web/e2e/90-afsluiting.spec.ts` | NU |
| C1.3-ASM-05 | **Noodlogin:** `100.64.0.0/10` standaard niet privé; beheerinstelling om het toe te staan (audit + waarschuwing, geen `action_id`); de zelftest toont het; UI. | §4.1 (A07) | `apps/api/src/hub/breakglass.py`, `apps/api/src/hub/routers/breakglass.py`, `models.py` + migratie, `apps/web/src/app/instellingen/noodaccount/NoodaccountScreen.tsx`, tests | NU |
| C1.3-ASM-06 | **401 alleen voor authenticatie:** `invalid_totp` bij `break-glass/confirm` → 422 (nu 401, `routers/breakglass.py` r. ~193); de UI onderscheidt op status, niet op code. | §5 (A21) | `apps/api/src/hub/routers/breakglass.py`, `apps/web/src/app/instellingen/noodaccount/NoodaccountScreen.tsx`, tests, OpenAPI | NU |
| C1.3-ASM-07 | **Scopes dienst → Hub:** vaste scope per dienst in het register (`inventaris.lezen` voor appstore-en-fork en jelly-leon-platform op `GET /api/v1/apps(/{id})`, nu alleen `Viewer`); `besluiten.lezen` standaard aan niemand; `GET /connector/v1/items` (nu `ViewerOrService`) zonder scope 403 `scope_ontbreekt`, `backup.self` alleen voor gebruikers; scopes zichtbaar in de Hub-UI. Route catalogusbeschikbaarheid (`catalogus.lezen`) in P2. | §4.4 (A18) | `apps/api/src/hub/deps.py`, `apps/api/src/hub/routers/catalog.py`, `apps/api/src/hub/routers/events.py` (connector items), `models.py` (`Service`) + migratie, `apps/web/src/app/instellingen/diensten/DienstenScreen.tsx`, tests | NU (catalogusbeschikbaarheid P2) |
| C1.3-ASM-08 | **Paginering over een momentopname** voor `GET /api/v1/apps`: `snapshot_id` of `observed_at` van de meting + totaal per pagina; 409 `snapshot_changed` als de momentopname weg is (nu een offset over de laatste meting). | §5 (A21) | `apps/api/src/hub/routers/catalog.py`, `apps/api/src/hub/catalog/`, tests, OpenAPI | NU |
| C1.3-ASM-09 | **Inbox en incidenten:** domeinen per eigenaar (buiten het eigen domein alleen informatie); werkwoorden voor probleem en herstel, `entity` als stabiel onderwerp; `app.health.changed` met `unknown` nooit herstel; ernst met vijf woorden en de vaste afbeelding, `severity` na één overgangsrelease weg (nu `ernst` of `severity`, `incidents/rules.py` r. ~103); UI toont de bronwaarde. | §7 (A24, A25) | `apps/api/src/hub/events/envelope.py`, `apps/api/src/hub/routers/events.py`, `apps/api/src/hub/incidents/rules.py`, `incidents/view.py`, `apps/web/src/app/problemen/…`, tests | NU |
| C1.3-ASM-10 | **`sso.access.*`:** koppelen op `(issuer, sub)`, alleen zonder `sub` op `preferred_username` (nu alleen gebruikersnaam); ook `sso.access.changed` verwerken (alleen sessies intrekken, nooit rechten geven). | §7 (A26) | `apps/api/src/hub/oidc/service.py` (r. ~153), tests | NU |
| C1.3-ASM-11 | **Connector-health:** de Hub rekent het totaal als slechtste check en een check zonder verse meting als `unknown`; "200 maar geen jobs" na één overgangsrelease alleen aan `worker`/`jobs` (nu ook `job`, `queue`, `wachtrij`, `taken`); de eigen `GET /connector/v1/health` met de vaste namen. | §6 (A22) | `apps/api/src/hub/monitoring/sources.py` (r. ~34 `JOB_CHECKS`), `monitoring/health.py`, `apps/api/src/hub/routers/events.py` (eigen health), tests | NU |
| C1.3-ASM-12 | **Versheid:** eigen `discover` met `limits.max_age_s`; de Hub neemt `max_age_s` van een bron over (nooit soepeler); de instelbare `inventory_ttl_seconds` maakt een meting nooit verser dan haar bron; een verouderde meting krijgt `reason_code: meting_verouderd` (nu alleen een vlag `verouderd`, o.a. `monitoring/timeseries.py`). | §6.2 (A23) | `apps/api/src/hub/routers/events.py` (discover, r. ~108), `monitoring/sources.py`, `config.py`, tests | NU |
| C1.3-ASM-13 | **Log-sink en heartbeat** nalopen tegen §6.1: ingekorte opslag van `bericht` zichtbaar markeren; antwoordvelden zoals beschreven. | §6.1 (A19) | `apps/api/src/hub/logsink.py`, `routers/logs.py`, `monitoring/heartbeat.py`, tests | NU |
| C1.3-ASM-14 | **Idempotency-uitzonderingen:** bron in de lijst wordt "contract 1.3 §5" (nu "contract_issue voor 1.3"); de executor-routes in een gelijke statische test. | §5 (A20) | `apps/api/tests/unit/test_idempotency_routes.py`, `apps/executor/tests/test_mutaties.py` | NU |
| C1.3-ASM-15 | **EVIDENCE en Excel — conform sinds de review (ADR-0028):** `test_evidence_contract.py` kent `Intel-iGPU-getest (ontwikkelmachine)` en `Niet getest` (alleen bij `Niet gestart`), weigert een lege `validatie`, eist dat elke `NIET GEVALIDEERD (…)` uit `blokkade` ook in `validatie` staat en controleert de vorm van `C1.x-…`- en `REVIEW-…`-ID's; `update_excel.py` zet zulke regels niet in een blad maar in het overzicht `contractpunten_en_reviews` van de uitvoer (geen "geen rij gevonden" meer); de rijen B01-001 en I23-23-08 zijn consistent gemaakt. Nieuwe regels: `REVIEW-ai-server-manager-contract-1.3` en `C1.3-ASM-15` | §11 (A33) | `apps/api/tests/unit/test_evidence_contract.py`, `tools/excel/update_excel.py`, `tools/excel/tests/`, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-ASM-16 | **Hub-UI Diensten:** de NL-melding van `last_error` van de dienst tonen, geen codes hardcoden; `koppelstatus_onleesbaar` als storing; waarschuwing bij een genegeerde `base_url`; scopes per dienst tonen. Catalogus: `adopted` als "Geïmporteerd". Na ontwerpstap (§13). | §3.5, §9 (A12, A31) | `apps/web/src/app/instellingen/diensten/DienstenScreen.tsx`, `apps/web/src/app/apps/…`, `apps/web/e2e/*.spec.ts` | NU |
| C1.3-ASM-17 | **Eigen manifesten:** geen `HUB_*`; `healthcheck.monitor`; kop "platformcontract 1.3". | §9 (A11, A32) | `deploy/manifest/ai-server-manager.manifest.yaml`, `deploy/manifest/ai-server-manager-executor.manifest.yaml` | NU (na C1.3-ASF-08) |
| C1.3-ASM-18 | **Catalogusgeheimen** (Authentik e.d.): de Hub genereert ze, vault `vault://app/<app_id>/<parameter>`, de executor geeft ze alleen in `values` mee; nooit in diff, audit, log of evidence. Eigen ADR voor de overdracht van het OIDC-`client_secret`. De vertaling zet bij `app.install`/`app.update` de `HUB_*`-env alleen als de Hub koppelt, en bij my_house alleen `HUB_URL` (RV5). | §3.1 (A10) | `apps/api/src/hub/` (vault, installatieplan), `apps/executor/` (`app.install`) | P2 |
| C1.3-ASM-19 | **Policy-engine:** de tabel "acties via de eigenaar-connector" (`sso.oidc.hub.register`, `sso.sessions.revoke`), back-upbevestiging in de `Approval` (`backup_checkpoint_id` van een geverifieerde B12-back-up, niet ouder dan het RPO), en `post_install_checks` als gate. MediaGuard-acties pas na BG-05 en P3-02 (Δ-HUB-1). Geen `app.update` van MediaGuard zonder upgradebewijs van die release (§2.3 regel 7b, RV2); hoe de Hub het bewijs ziet: ADR in P3. | §8, §9 (A28, A30, A05) | `policy/*.yaml`, `apps/api/src/hub/` (policy, approvals) | P2 (MediaGuard: na BG-05, vóór golf 3) |
| C1.3-ASM-20 | **Monitorplan (B09):** per app uit register + `healthcheck.monitor`; de beheerder bevestigt in Uptime Kuma ("handmatig bevestigd"). | §9 (A32) | `apps/api/src/hub/monitoring/`, Hub-UI | P2 |
| C1.3-ASM-21 | **Hub-adapters bestaande apps** (H11 uit 1.2, aangevuld): MediaGuard per server (`servers[]`, terugval op de velden op het hoogste niveau); Emby alleen-lezen client (alleen `GET`) voor D07 en de overname; Jelly Leon met eigen niet-admin-gebruiker via `MediaBrowser Token` (Δ-HUB-JL) en de stap "Hub-sleutelset kopiëren" voor de plugin, met een `service_id` uit het register (RV4); B12-dekking van het Emby-exportarchief (Δ-HUB-3). MediaGuard-adapter met de veldenwitte lijst op `/api/v1/mediaserver/status` (nooit `sessions`, `hold.reason`, `actions`, `tests`, `last`; RV3). | §2.3 regels 2, 8, 9 (A03, A04) | nieuwe adaptermodules in `apps/api/src/hub/`, B12 | P3 (MediaGuard, Emby-archief), P4-0 (Emby/D07), P4 (Jelly Leon-plugin) |
| C1.3-ASM-22 | **Optionele model-apps:** manifesten (via appstore-en-fork) zonder GPU als standaard; geen tweede producent; `mt` pas na BG-06/BG-18. | §1, §2 (A06) | manifesten, Hub-UI | P5 (na BG-06/BG-18) |
| C1.3-ASM-23 | **Werkopdrachten en stand:** `OVERDRACHT/STATUS.md` besluit 1 met de concrete ID's en hun bron (**conform**, bij het vaststellen van 1.3 gedaan); de algemene KWALITEIT-tekst in de workflowscripts niet meer opleggen aan jelly-leon-web en jelly-leon-clients (inventaris B03); werkopdrachten noemen contract 1.3 en deze lijst. | §1.1 (A02), §10 | `docs/platform-v2/OVERDRACHT/STATUS.md`, `docs/platform-v2/OVERDRACHT/workflows/` | NU |

**Repowerk (geen contract; inventaris C01–C05, C07, C08, C11):** sorteren op status in `GET /api/v1/apps`, filter op
app in `GET /api/v1/incidents`, poolstatus naast `pool.gezond`, lijst van open koppelcodes/tokens zonder geheim (C01,
NU); readback aan de hoofdimage in `catalog/discovery.py` (r. ~170) en de MediaGuard-imagenaam
`ghcr.io/lvos04/mediaguard-core` in de fake TrueNAS en `tests/unit/test_catalogus.py` (C02, NU); keuzes die binnen het
contract passen opnieuw bekijken bij P2 (C03); interop-test voor `POST /api/v1/services/{id}/unlink` (C04, P2);
ADR-nummer pas kiezen na `git pull --rebase` (C05, werkwijze); bouwplan B03 "H-ITEMDETAILS" en `UG-WEB-<n>` (C07, NU);
I01 stap 3 zonder shellopdrachten (`app.gpu_choices` + bewijsrecord D08, C08, NU); vervolgpunten Peil-review Hub-UI
(C11); Δ-HUB-2 uit B03 hoofdstuk 18 (inventaris C12): de eventtypes van B03 §10.10 in de B09-incidenten en de
mediakaart, en de Hub-kaarten van F1–F6 met ontwerpstap en ontwerpreview (P4).

---

## 2. home-control-hub

**Conform (gemeten):** healthcheck wisselt naar 568 met no_new_privs en legt de bounding set (`deploy/allinone/healthcheck.py`,
A08); bewaker legt de bounding set; IP-vormen en `aud` als lijst (ADR-0013 punt 3–4, A11/A16); onleesbaar koppelbestand
fail-closed met `unreadable_replaced_at` en de extra velden `token_rotation_requested_at`/`key_rotation_blocked_sequence`
(ADR-0010 punt 4, ADR-0013 punt 1, A12); vingerafdruk over alle thumbprints gesorteerd (`security/hubkeys.py`, A17);
"Gereed" tegenover `/readyz` (A15); de vaste `service.*`-namen (A24); back-upcheckpoint alleen bevestigd met een
dienst-JWT van de Hub (`domains/sso/backup.py`, `authentik_router.py`, A28); drifttest en EVIDENCE-test
(`apps/api/tests/unit/test_contract_docs.py`).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-HCH-01 | **Herkomst statuspagina:** `Referrer-Policy: no-referrer` → `same-origin` (r. ~76); `Origin: null` niet meer accepteren, exacte `Origin`; `Sec-Fetch-Site` toevoegen; `Host`-beperking; browsertest met `Origin: null`, vreemde `Origin`, `same-site`, `cross-site`, niet-toegestane `Host`, geen cookie. | §3.7 (A13, A14) | `apps/api/src/integrations/status_page.py`, `tests/ui/statuspagina.spec.ts`, `apps/api/tests/integration/test_contract_1_2_link.py` | NU |
| C1.3-HCH-02 | **Koppelformulier nalopen:** elke POST telt als poging (ook ongeldige invoer, lopende poging, onleesbaar bestand en al gekoppeld; nu telt `al_gekoppeld` niet mee, `status_page.py` r. ~745); 409 `koppelen_bezig`; meldingen alleen bij een echte poging; invoer niet afkappen (nu `hub_adres[:500]` en `koppelcode[:64]` vóór de controle, r. ~750); één logregel met trace-ID. | §3.7 (A14) | `apps/api/src/integrations/status_page.py`, tests | NU |
| C1.3-HCH-03 | **Reasons:** de code volgt de tabel van §4.7 al (gemeten in `security/auth.py`: geen header, ander schema of lege waarde → `invalid_token`; geen gepinde `kid` → `unknown_key`; `strict_aud`); per geval een test toevoegen waar die ontbreekt (ook gepinde `kid` met foute handtekening en een onleesbare body zonder auth → 401). | §4.7 (A16) | `apps/api/tests/unit/` of `apps/api/tests/integration/test_contract_1_2_link.py` | NU (tests nalopen) |
| C1.3-HCH-04 | **`rotation_sequence`** uit het enroll-antwoord in `pins.rotation_sequence`; `key-rotations?after=` vanaf die waarde; `schema_version` van het bestand `"1.3"`. | §3.3, §3.5, §4.5 (A17) | `apps/api/src/integrations/enrollment.py`, `hublink_store.py` (r. ~127), `worker.py`, `tests/e2e/sim_hub.py` | NU |
| C1.3-HCH-05 | **`last_error`-codes:** de vaste aanvullingen van §3.5 gebruiken waar de dienst nu een eigen code heeft (o.a. `hub_incompatibel`, `token_ongeldig`, `vingerafdruk_ongeldig`, `hub_adres_ongeldig`, `overzetten_onvolledig`, `koppelstatus_onleesbaar`); bij `vingerafdruk_ongeldig`/`hub_adres_ongeldig` de Hub niet aanspreken en het token niet afhandelen. | §3.5 (A12) | `apps/api/src/integrations/enrollment.py`, `hublink_store.py`, tests | NU |
| C1.3-HCH-06 | **`sso.access.revoked`/`changed`:** `payload` met `issuer`, `sub` (OIDC-`sub` van de Hub-client; `sub_mode` nagaan in de Authentik-broncode) en `preferred_username` (nu alleen de gebruikersnaam in `entity.id`). | §7 (A26) | `apps/api/src/integrations/domains/sso/authaudit.py`, tests | NU |
| C1.3-HCH-07 | **Connector-health en versheid:** totaal = slechtste check, vaste namen; `limits.max_age_s` in `discover` (nu `PROBE_MAX_AGE` 15 min intern, `sources.py` r. ~47). | §6, §6.2 (A22, A23) | `apps/api/src/integrations/connector.py`, `health.py`, `sources.py`, tests | NU |
| C1.3-HCH-08 | **Events nalopen:** domeinen `sso`, `energy`, `network`, `automation`, `flow`; werkwoorden; `entity` als stabiel onderwerp; `ernst` optioneel. | §7 (A24, A25) | `apps/api/src/integrations/events.py`, `domains/*` | NU |
| C1.3-HCH-09 | **Statische `Idempotency-Key`-test** met uitzonderingslijst (ontbreekt). | §5 (A20) | nieuw `apps/api/tests/unit/test_idempotency_routes.py` | NU |
| C1.3-HCH-10 | **Privé-bereiken** in het noodloginbeleid en het register: `100.64.0.0/10` standaard niet privé; de cache van de Hub mag alleen verscherpen. | §4.1 (A07) | `apps/api/src/integrations/domains/sso/recovery.py`, tests | NU |
| C1.3-HCH-11 | **Groep → rol** alleen als advies tonen (de Hub beheert de koppeling); nalopen. | §4.1 (A27) | `apps/api/src/integrations/domains/sso/mapping.py`, `oidc_hub.py` | NU (nalopen) |
| C1.3-HCH-12 | **Healthcheck-controlevlag** en de aparte controle in de rooktest (`CapPrm`, `CapBnd`). | §2.2 (A08) | `deploy/allinone/healthcheck.py`, `deploy/allinone/smoke-test.sh` | NU |
| C1.3-HCH-13 | **Manifest:** geen `HUB_*`, `healthcheck.monitor`, kop 1.3. | §9 (A11, A32) | `deploy/manifest/home-control-hub.manifest.yaml` | NU (na C1.3-ASF-08) |
| C1.3-HCH-14 | **Kopie 1.3 + drifttest-pin** en EVIDENCE-regels 1.3. | kop, §11 (A35, A33) | `apps/api/tests/unit/test_contract_docs.py`, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-HCH-15 | **Authentik-upgradegate:** catalogusbeschikbaarheid via scope `catalogus.lezen` (nu "catalogusversie onbekend"); `apply` van `sso.oidc.hub.register` en `sso.sessions.revoke` alleen met een ondertekend `ExecutionRequest`; het `client_secret` nooit via Hub-connector, items of events. | §4.4, §8, §3.1 (A18, A28, A10) | `apps/api/src/integrations/domains/sso/backup.py`, `authentik_router.py`, `proposals.py`, `oidc_hub.py` | P2 |

**Repowerk:** geen.

---

## 3. appstore-en-fork

**Conform (gemeten):** `Referrer-Policy: same-origin` en `Origin: null` geweigerd (`api/status_page.py` r. ~72, A13
deels); bewaker legt de bounding set (A08 deels); vingerafdruk over alle thumbprints gesorteerd (`hubkeys.py`, A17);
adoptiemanifest als eigen documentsoort (`schemas/adoption-manifest-v1.schema.json`, ADR-0010, A31); drifttest en
EVIDENCE-test (`apps/api/tests/unit/test_evidence_contract.py`).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-ASF-01 | **Healthcheck** naar 568 + no_new_privs (+ bounding set) als eerste handeling, exec-vorm, controlevlag (gemeten: draait nu als root zonder wissel); image-E2E controleert de healthcheck apart en `CapBnd`. | §2.2 (A08) | `deploy/allinone/healthcheck.py`, `deploy/allinone/Dockerfile` (r. ~75), `tests/e2e/test_allinone_image.py` | NU |
| C1.3-ASF-02 | **Herkomst:** `Sec-Fetch-Site` en `Host`-beperking toevoegen; negatieve browsertests. | §3.7 (A13, A14) | `apps/api/src/appstore/api/status_page.py`, `tests/ui/statuspagina.spec.ts`, `tests/ui/statuspagina.live.ts` | NU |
| C1.3-ASF-03 | **Koppelformulier en "Gereed"** nalopen (pogingen — nu telt `al_gekoppeld` niet mee, `api/status_page.py` r. ~694 —, 409, meldingen, invoer, logregel; Gereed = readyz + gekoppeld + bevestigd). | §3.7 (A14, A15) | `apps/api/src/appstore/api/status_page.py` | NU |
| C1.3-ASF-04 | **Koppelbestand:** onleesbaar fail-closed, vaste codes, extra velden, `schema_version` `"1.3"`. | §3.5 (A12) | `apps/api/src/appstore/hublink.py`, `hublink_store.py` (r. ~105), tests | NU |
| C1.3-ASF-05 | **JWT:** `aud` string, reasons, `jti` per POST, auth vóór body. | §4 (A16) | `apps/api/src/appstore/auth.py`, tests | NU |
| C1.3-ASF-06 | **Sleutels en adres:** `rotation_sequence` overnemen; testvector `HN69-2PHK-XV2D-X85W`; IP-vorm en `base_url` alleen als geldig. | §3.2, §3.3, §4.5 (A11, A17) | `apps/api/src/appstore/hublink.py`, `hubkeys.py`, `config.py`, `apps/api/tests/unit/test_hubkeys.py`, `apps/api/tests/fakehub.py` | NU |
| C1.3-ASF-07 | **Events:** `service.enrollment.completed` → `service.hub_link.linked` (payload `{via}`); domein `catalog`; werkwoorden; `ernst` optioneel. | §7 (A24, A25) | `apps/api/src/appstore/hublink.py`, `events.py`, `worker.py` | NU |
| C1.3-ASF-08 | **Validator en schema (eerst, vóór de manifesten elders):** `install.reason` (+ `install_reason_ontbreekt`); `reserved_env` voor `HUB_*`; `source: generated` + `secret: true`; `accepted_findings` met vaste lijst en `--strict`-regels; `backup.db_export: stopped_snapshot`; documentsoort `kind: checklist` met eigen schema; `post_install_checks`; `container_port: same_as_host`; `healthcheck.monitor`; nieuwe meldingscodes in de tabel; fixtures. Beide schemakopieën gelijk houden. | §9 (A09, A10, A11, A30, A32) | `schemas/manifest-v1.schema.json`, `apps/api/src/appstore/manifest/manifest-v1.schema.json`, nieuw `schemas/checklist-v1.schema.json`, `apps/api/src/appstore/manifest/model.py`, `rules.py`, `findings.py`, `translate.py`, `validator.py`, `docs/MANIFESTSTANDAARD.md`, `apps/api/tests/fixtures/manifests/` | NU |
| C1.3-ASF-09 | **Inventaris-import:** scope `inventaris.lezen` (403 `scope_ontbreekt` → eerlijk `capability_unavailable`); paginering met `snapshot_id`/`observed_at` en 409 `snapshot_changed`; `max_age` volgens de Hub (nu vast 15 min, `hubinventory.MAX_AGE`). | §4.4, §5, §6.2 (A18, A21, A23) | `apps/api/src/appstore/catalog/hubinventory.py`, tests | NU (na C1.3-ASM-07/08) |
| C1.3-ASF-10 | **Connector-health en versheid:** vaste checknamen, totaal = slechtste, `limits.max_age_s`. | §6 (A22, A23) | `apps/api/src/appstore/api/connector.py`, `api/health.py` | NU |
| C1.3-ASF-11 | **Statische `Idempotency-Key`-test** (ontbreekt). | §5 (A20) | nieuw `apps/api/tests/unit/test_idempotency_routes.py` | NU |
| C1.3-ASF-12 | **Emby als adoptie-item** (`owner.soort: derde`, status volgens §9); herkenning alleen op exacte catalogusappnaam of image-repository. | §2.3, §9 (A03, A31) | `apps/api/src/appstore/bestaande_apps/`, `apps/api/src/appstore/catalog/adoption_manifest.py`, `docs/BESTAANDE_APPS.md` | NU |
| C1.3-ASF-13 | **Eigen manifest** (geen `HUB_*`, `healthcheck.monitor`, kop 1.3), **kopie 1.3 + drifttest-pin**, EVIDENCE-regels 1.3. | §9, kop, §11 (A11, A32, A35, A33) | `deploy/manifest/appstore-en-fork.manifest.yaml`, `apps/api/tests/unit/test_evidence_contract.py`, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-ASF-14 | **Catalogusapps met geheime values** in de vertaling: alleen een verwijzing naar de vault, nooit een waarde (samen met C1.3-ASM-18). | §3.1, §9 (A10) | `apps/api/src/appstore/manifest/translate.py` | P2 |

**Repowerk (inventaris C06):** een 429 van de Hub-inventaris volgt `Retry-After` (nu de eigen backoff) — NU;
herkenning zonder labels/namespace (voorstel: Excel-tekst B08-002 bijwerken); Snapotter/Teeltboek/Uren alleen
handmatig koppelen.

---

## 4. jelly-leon-platform

**Conform (gemeten):** `Referrer-Policy: same-origin` op de statuspagina en `Origin: null` geweigerd (`statuspage.py`
r. ~393, A13 deels); healthcheck wisselt naar 568 met no_new_privs (`deploy/allinone/healthcheck.py`, A08 deels);
`schema_version` major-controle (`enrollment.py` r. ~134); `TRUENAS_APP_API.md` met de bronnen van §2.2.

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-JLP-01 | **Herkomst:** `Sec-Fetch-Site` en `Host`-beperking; negatieve gevallen in de browsertest. | §3.7 (A13, A14) | `apps/api/src/lifecycle/statuspage.py`, `tests/ui/live/live.mjs`, `tests/ui/controle.mjs` | NU |
| C1.3-JLP-02 | **Koppelformulier:** de teller zelf is conform (5 per bron-IP en 20 voor de dienst per 15 min, `PairingLimiter`, `statuspage.py` r. ~150); nog: elke POST een poging — nu worden al gekoppeld, onleesbaar en een lopende poging vóór de teller geweigerd (r. ~430–436); 409 `koppelen_bezig` (conform); meldingen; invoer; logregel; "Gereed". | §3.7 (A14, A15) | `apps/api/src/lifecycle/statuspage.py`, tests | NU |
| C1.3-JLP-03 | **Koppelbestand:** onleesbaar is al fail-closed (geen formulier, 409), maar met de code `hub_link_onleesbaar` → `koppelstatus_onleesbaar`; het origineel heet nu `hub-link.json.beschadigd-<tijd>` → `.onleesbaar-<UTC-tijd>`, `unreadable_replaced_at` ontbreekt, en vervangen gebeurt pas na een geslaagde koppeling → bij de eerste schrijfactie van de poging (RV6; `hublink.py` r. ~319–330); vaste codes; extra velden; `schema_version` `"1.3"`. | §3.5 (A12) | `apps/api/src/lifecycle/hublink.py`, `enrollment.py`, tests | NU |
| C1.3-JLP-04 | **JWT:** `aud` string, reasons, `jti` per POST, auth vóór body. | §4 (A16) | `apps/api/src/lifecycle/auth.py`, `replay.py`, tests | NU |
| C1.3-JLP-05 | **Sleutels en adres:** `rotation_sequence`; vingerafdruk over alle policy-sleutels + testvector; IP-vorm en `base_url`. | §3.2, §3.3, §4.5 (A11, A17) | `apps/api/src/lifecycle/enrollment.py`, `keys.py`, `keyrotation.py`, `config.py`, `e2e/simulators/hub/hub_sim.py` | NU |
| C1.3-JLP-06 | **Bounding set** in de bewaker vóór de wissel; healthcheck-controlevlag; image-E2E controleert `CapBnd`, `CapPrm` en de healthcheck apart. | §2.2 (A08) | `deploy/allinone/supervisor.py`, `deploy/allinone/healthcheck.py`, `tests/e2e/test_allinone_image.py` | NU |
| C1.3-JLP-07 | **Events:** `service.enrollment.completed` → `service.hub_link.linked`; `service.token.rotated` en `service.key_rotation.*` waar van toepassing; domein `lifecycle` voor eigen events. | §7 (A24) | `apps/api/src/lifecycle/worker.py`, `outbox.py` | NU |
| C1.3-JLP-08 | **Connector-health en versheid:** vaste checknamen, totaal = slechtste, `limits.max_age_s`. | §6 (A22, A23) | `apps/api/src/lifecycle/api_connector.py`, `health.py` | NU |
| C1.3-JLP-09 | **I-manifesten volgens §9 1.3** (na C1.3-ASF-08): `validatie-uitzonderingen.yaml` vervangen door `accepted_findings` per manifest; Authentik-geheimen `source: generated` + `secret: true`; `post_install_checks` (o.a. Gotify-standaardaccount, eerste start van Beszel, setup van Uptime Kuma en Authentik, niet-schrijfbare `/tmp` van de Beszel-agent als 568); `container_port: same_as_host` voor de Authentik-catalogusapp; `install.reason`; `healthcheck.monitor`; checklist-documenten (`kind: checklist`) voor I01 en I02. | §9, §3.1 (A30, A10, A09, A32) | `install/manifests/*.manifest.yaml`, `install/manifests/validatie-uitzonderingen.yaml` (vervalt), nieuw `install/manifests/i01.checklist.yaml` en `i02.checklist.yaml`, `deploy/manifest/jelly-leon-platform.manifest.yaml` | NU (na C1.3-ASF-08) |
| C1.3-JLP-10 | **Begrippen** *standaard Custom App* (`ix-app`, `custom_app: false`) en *compose-app* (`custom_app: true`) in de TrueNAS-bron; derden-apps met één container als Custom App tenzij `install.reason`. | §2, §9 (A09) | `docs/platform-v2/TRUENAS_APP_API.md`, `install/truenas/INSTALLATIE.md` | NU |
| C1.3-JLP-11 | **INSTALLATIE.md:** koppelen via de statuspagina alleen via het IP-adres of een lokale naam (`Host`-beperking); env-enrollment aanbevolen. | §3.7 (A14) | `install/truenas/INSTALLATIE.md` | NU |
| C1.3-JLP-12 | **Statische `Idempotency-Key`-test** (ontbreekt). | §5 (A20) | nieuw `apps/api/tests/unit/test_idempotency_routes.py` | NU |
| C1.3-JLP-13 | **Kopie 1.3 + drifttest** (ontbreekt) en EVIDENCE-regels 1.3. | kop, §11 (A35, A33) | nieuw `tests/repo/test_contract_kopie.py`, `tests/repo/test_repo_rules.py`, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-JLP-14 | **Lifecycle-plannen** lezen inventaris (`inventaris.lezen`) en catalogusbeschikbaarheid (`catalogus.lezen`); `version_unavailable` op basis van de gemeten beschikbaarheid. | §4.4, §2.2 (A18) | lifecycle-planner (B08-003/004) | P2 |

**Repowerk:** I01 stap 3 doet hier al `app.gpu_choices` + bewijsrecord D08 (inventaris C08; de bron in ai-server-manager
volgt, C1.3-ASM repowerk). De driftregel van de Peil-kopie (faalt nu bij elke nieuwe versie) gaat mee met Peil 1.1.1
(E08).

---

## 5. zoeken-en-persoonlijke-ai

**Conform (gemeten):** healthcheck wisselt naar 568 met no_new_privs (`deploy/allinone/healthcheck.py`, A08 deels);
`Sec-Fetch-Site` gecontroleerd (`status_page.py` r. ~680); onleesbare body zonder auth geeft 401 (ADR-0012, A16 deels);
`schema_version` major-controle (`enrollment.py` r. ~118); "Gereed" tegenover `/readyz` (A15); één embeddingproducent
(A06); EVIDENCE-test
(`apps/api/tests/unit/test_evidence_contract.py`).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-ZPA-01 | **Herkomst:** `Referrer-Policy: no-referrer` → `same-origin` (r. ~277); `Origin: null` niet meer accepteren (r. ~672), exacte `Origin`; `Host`-beperking; negatieve browsertests. | §3.7 (A13, A14) | `apps/api/src/search_ai/status_page.py`, `tests/ui/statuspagina.mjs`, `tests/ui/echte_dienst.mjs` | NU |
| C1.3-ZPA-02 | **Koppelformulier:** geen melding uit alleen `?melding=` (melding hoort bij een echte poging, ADR-0015 Q-01); invoer nooit eerst afkappen (Q-02, nalopen); één logregel met trace-ID (Q-06); elke POST een poging; 409 `koppelen_bezig`. | §3.7 (A14, A21) | `apps/api/src/search_ai/status_page.py`, `ratelimit.py`, tests | NU |
| C1.3-ZPA-03 | **Vingerafdruk over alle policy-sleutels** (nu "de laatst gepinde telt", `security/pins.py` r. ~144–149); testvector `HN69-2PHK-XV2D-X85W`. | §4.5 (A17) | `apps/api/src/search_ai/security/pins.py`, `apps/api/tests/unit/test_pins.py` | NU |
| C1.3-ZPA-04 | **`rotation_sequence`** uit het enroll-antwoord (ADR-0011); `schema_version` van het bestand `"1.3"`. | §3.3, §3.5 (A17) | `apps/api/src/search_ai/enrollment.py`, `hublink.py`, `tests/e2e/sim_hub.py` | NU |
| C1.3-ZPA-05 | **Events:** `service.hub_link.paired` → `service.hub_link.linked`; `service.hub_key.rotation_rejected` → `service.key_rotation.rejected`; `service.token.rotated` en `service.key_rotation.applied` toevoegen waar van toepassing; domeinen `search`, `voice`. | §7 (A24) | `apps/api/src/search_ai/worker.py`, `connector.py`, `status_page.py`, `events.py` | NU |
| C1.3-ZPA-06 | **Koppelbestand:** onleesbaar fail-closed, vaste codes, extra velden. | §3.5 (A12) | `apps/api/src/search_ai/hublink.py`, tests | NU |
| C1.3-ZPA-07 | **JWT:** `aud` string, reasons, `jti` per POST. | §4 (A16) | `apps/api/src/search_ai/security/auth.py`, tests | NU |
| C1.3-ZPA-08 | **Adres:** IP-vorm, `base_url` alleen als geldig. | §3.2, §3.3 (A11) | `apps/api/src/search_ai/enrollment.py`, `hubclient.py`, `config.py` | NU |
| C1.3-ZPA-09 | **Bounding set** in de bewaker; healthcheck-controlevlag; rooktest met `CapPrm`/`CapBnd` en de healthcheck apart. | §2.2 (A08) | `deploy/allinone/supervisor.py`, `deploy/allinone/healthcheck.py`, `deploy/allinone/smoke-test.sh` | NU |
| C1.3-ZPA-10 | **Connector-health en versheid:** vaste checknamen, totaal = slechtste, `limits.max_age_s`. | §6 (A22, A23) | `apps/api/src/search_ai/connector.py`, `health.py` | NU |
| C1.3-ZPA-11 | **Statische `Idempotency-Key`-test** (ontbreekt). | §5 (A20) | nieuw `apps/api/tests/unit/test_idempotency_routes.py` | NU |
| C1.3-ZPA-12 | **Kopie 1.3 + drifttest** (ontbreekt); EVIDENCE-regels 1.3 (ZA9 en de statuspagina als `C1.x-…`/`REVIEW-…`-regels). | kop, §11 (A35, A33) | nieuw `apps/api/tests/unit/test_contract_kopie.py`, `apps/api/tests/unit/test_evidence_contract.py`, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-ZPA-13 | **Eigen manifest** (geen `HUB_*`, `healthcheck.monitor`, kop 1.3). | §9 (A11, A32) | `deploy/manifest/zoeken-en-persoonlijke-ai.manifest.yaml` | NU (na C1.3-ASF-08) |
| C1.3-ZPA-14 | **Eén producent:** zoeken blijft de enige embeddingproducent; `transcript_ref.origin: machine_translation` (Δ-ZK-1) en canonieke itemtekst met `text_sha256` (Δ-ZK-2). | §1 (A06), inventaris C12 | `apps/api/src/search_ai/search/` | P5 (na BG-06) |

**Repowerk:** geen.

---

## 6. media-guard-ultimate (MediaGuard, bestaande app; P3 en P4-0)

**Conform (gemeten):** "Terug naar de Hub" uit de instelling `system.hub_url` (`apps/core/mediaguard/hub_url.py`, A36);
GPL-3.0-`LICENSE`; de repo-overgang zelf (nieuwe publieke repo met schone historie, archief privé; gemeten in de
review, zie C1.3-MGU-02). De punten hieronder gelden in de nieuwe publieke repo.

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-MGU-01 | **Kopie 1.3** (nu nog 1.1) + nieuwe drifttest; EVIDENCE-test (ontbreekt) volgens §11 1.3. | kop, §11 (A35, A33) | `docs/platform-v2/PLATFORM_CONTRACTEN.md`, `docs/platform-v2/CONTRACT_1.3_CONFORMITEIT.md`, nieuwe test onder `apps/core/tests/` of `scripts/`, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-MGU-02 | **Repo-overgang — repo gemeten uitgevoerd (review, GitHub-API 2026-11-10):** `lvos04/media-guard-ultimate` is een nieuwe publieke repo met één startcommit (schone historie, GPL-3.0) en `media-guard-ultimate-archief` is privé. Nog open: het GHCR-pakket `mediaguard-core` aan de nieuwe repo koppelen en de zichtbaarheid per pakket controleren (de review kon pakketten niet lezen). Tot het pakket gekoppeld is: geen nieuwe release | §1.1 besluit 3, §2.3 (A01) | repo, GHCR | na het GHCR-besluit (stap van de gebruiker; repo-deel gedaan) |
| C1.3-MGU-03 | **HARDE EIS — upgradebewijs per release:** CI-gate die de vorige release start, een gevulde database maakt (fixture met voortgang), upgradet en controleert dat er niets verloren is; zonder groen bewijs geen release en geen update op de NAS. Geldt ook voor de eerste release uit de nieuwe repo. UI-rondes wijzigen geen datamodel. | §2.3 regel 7, §12 (A03) | `.github/workflows/` (release), nieuw upgradetestscript onder `scripts/`, migraties | NU (gate vóór de eerste release uit de nieuwe repo) |
| C1.3-MGU-04 | **Meerdere mediaservers (Δ-MG-DUAL, Δ-MG-AUTH):** elke ingestelde server volgen; kijkpauze bij elke server; afspeeltest en NL-ondertitels per server; Emby `X-Emby-Token`, Jelly Leon 12.x `Authorization: MediaBrowser Token=…`; Emby-koppeling nooit onderbreken; de bestaande Emby-aanroepen (bibliotheek bijwerken `POST /Library/Media/Updated` en `/Library/Refresh`, afspeeltest, sessies; `mediaserver/clients.py`, `service.py`) blijven, zonder nieuwe schrijfroute naar Emby (§2.3 regel 3, RV1); `servers[]` **erbij** in `GET /api/v1/mediaserver/status`, bestaande velden blijven (eerste server). | §2.3 regel 2 (A03) | `apps/core/mediaguard/mediaserver/api.py`, `clients.py`, `service.py`, `subtitles.py`, instellingen, tests | P4-0 (exitcriterium) |
| C1.3-MGU-05 | **Sleutelscopes (P3-02)** en gescopete routes voor de gereserveerde acties (eigenaar-connector met ondertekend `ExecutionRequest`); tot BG-05 geen van deze acties via de Hub of Jelly Leon. Rol `viewer` voor de sleutel van Jelly Leon (BG-04) bestaat al; `GET /api/v1/auth/me` geeft de rol. | §2.3 regels 2–3, §8 (A05, A28) | `apps/core/mediaguard/` (auth, sleutels), OpenAPI | P3 (scopes), na BG-05 (acties) |
| C1.3-MGU-06 | **Nieuwe routes** (`/connector/v1/*` alleen-lezen, `/healthz`, `/readyz`): foutcatalogus, health-regels, `observed_at`/`max_age`, events in domein `media` met werkwoorden en `ernst`. | §5, §6, §7 (A21–A25) | `apps/core/mediaguard/` (connectormodule), `docs/openapi/` | P3 |
| C1.3-MGU-07 | **Healthcheck** in exec-vorm met wissel naar 568 + no_new_privs (nu `healthcheck.sh`), bounding set, rooktest. | §2.2 (A08) | `deploy/aio/healthcheck.sh`, `deploy/aio/Dockerfile` (r. ~55), `apps/core/mediaguard/aio.py`, `scripts/aio-smoke.py` | P3 |
| C1.3-MGU-08 | **Terugkeerpad na inloggen** volgens §4.1; `system.hub_url` valideren volgens §3.2 (ongeldig → geen link). | §4.1, §2.3 regel 5 (A27, A36, A11) | `apps/web/` (login), `apps/core/mediaguard/hub_url.py` | P3 (terugkeerpad), NU (adresvalidatie nalopen) |
| C1.3-MGU-09 | **Manifest** (nieuw, P3-07): `backup.db_export: stopped_snapshot` of `accepted_findings` voor SQLite; `healthcheck.monitor`; geen `HUB_*`. | §9 (A30, A32) | nieuw `deploy/manifest/mediaguard.manifest.yaml` | P3 |

**Repowerk (inventaris C09, C12):** Android-app en servertekst ook en-US (besluit van de gebruiker); één kleurregel
voor "Wat kwam erbij / Waar ging de ruimte heen"; Overzicht periodiek verversen; SysteemStatusPaneel met rijen per
onderdeel; Δ-MG-1…8 en Δ-MG-DV volgens B03 hoofdstuk 18. Woord "Niet beschikbaar" voor "indexers vinden niets": Peil
1.1.1 (E13).

---

## 7. media-source-optimizer (MSO, bestaande app; P3)

**Conform (gemeten):** "Terug naar de Hub" uit `systeem.hub_url` (`apps/core/mso/settings_registry.py`, A36);
GPL-3.0-`LICENSE`; alles-in-één image met healthcheck in Python (`deploy/allinone/healthcheck.py`).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-MSO-01 | **Kopie 1.3** (nu nog 1.1) + nieuwe drifttest; EVIDENCE-test (ontbreekt) volgens §11 1.3. | kop, §11 (A35, A33) | `docs/platform-v2/PLATFORM_CONTRACTEN.md`, `docs/platform-v2/CONTRACT_1.3_CONFORMITEIT.md`, nieuwe test, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-MSO-02 | **`systeem.hub_url`** valideren volgens §3.2 (ongeldig of leeg → geen link). | §2.3 regel 5 (A36, A11) | `apps/core/mso/settings_registry.py`, web | NU (nalopen) |
| C1.3-MSO-03 | **Healthcheck** naar 568 + no_new_privs als eerste handeling; bewaker legt de bounding set; rooktest. | §2.2 (A08) | `deploy/allinone/healthcheck.py`, `deploy/allinone/supervisor.py`, `docs/test-evidence/allinone-report.md` | P3 |
| C1.3-MSO-04 | **Connectorlaag (P3-07)** volgens 1.3: foutcatalogus, `Idempotency-Key` met uitzonderingslijst, health-regels, `max_age`, change sets als acties via de eigenaar-connector. Let op: `docs/platform-v2/DELTA_MATRIX.md` (P3-06) noemt nog enrollment/koppelcode en JWKS; dat vervalt (§2.3 regel 2: machine-sleutel met scopes, geen enrollment; 1.2-punt MS1 staat nog open). | §5, §6, §8 (A20–A23, A28) | `apps/core/mso/` (connectormodule) | P3 |
| C1.3-MSO-05 | **Terugkeerpad na inloggen** volgens §4.1. | §4.1 (A27) | web-UI van MSO (login) | P3 |
| C1.3-MSO-06 | **Manifest** (nieuw): `healthcheck.monitor`, back-up, geen `HUB_*`. | §9 (A30, A32) | nieuw `deploy/manifest/media-source-optimizer.manifest.yaml` | P3 |

**Repowerk (inventaris C10):** SysteemStatusPaneel bovenaan het Overzicht, bron en tijd per KPI-tegel, Peil-woorden
in de core, fase 2d (inline styles en `mg.css` weg), mock voor de doel-trendlijn, toetsenbordtests, echte toestellen.
Zekerheid als woord met vaste drempels: Peil 1.1.1 (E11).

---

## 8. my_house (bestaande app; P3)

**Conform (gemeten):** "Terug naar de Hub" uit de optionele `HUB_URL` zonder enrollment (`apps/web/src/hub.ts`,
ADR-0008, A36); GPL-3.0-`LICENSE`.

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-MH-01 | **Kopie 1.3** (nu nog 1.1) + nieuwe drifttest; EVIDENCE-test (ontbreekt) volgens §11 1.3. | kop, §11 (A35, A33) | `docs/platform-v2/PLATFORM_CONTRACTEN.md`, `docs/platform-v2/CONTRACT_1.3_CONFORMITEIT.md`, nieuwe test onder `apps/api/tests/`, `docs/platform-v2/EVIDENCE.json` | NU |
| C1.3-MH-02 | **`HUB_URL`** valideren volgens §3.2 (ongeldig of leeg → geen link); nooit uit `Referer` of de URL afleiden; geen manifestparameter (bij installatie via de Hub zet de vertaling hem, §3.2, RV5). | §2.3 regel 5 (A36, A11) | `apps/web/src/hub.ts` (+ waar de waarde aan de web-app wordt doorgegeven) | NU (nalopen) |
| C1.3-MH-03 | **Alles-in-één image** (MH1 uit 1.2) met healthcheck volgens §2.2 (exec-vorm, wissel, bounding set) en rooktest. | §2.2 (A08) | nieuw `deploy/allinone/*` | P3 |
| C1.3-MH-04 | **Bewaakt schrijfpad** `propose`/`apply` als eigenaar-connector met ondertekend `ExecutionRequest`, back-upbevestiging waar nodig; de geplakte sleutelset met de vingerafdruk over alle policy-sleutels (testvector `HN69-2PHK-XV2D-X85W`). | §2.3 regel 3, §4.5, §8 (A17, A28) | `apps/api/**` (connectormodule) | P3 |
| C1.3-MH-05 | **Nieuwe routes** volgens §5/§6 (foutcatalogus, health, `max_age`) en het terugkeerpad na inloggen (§4.1). | §5, §6, §4.1 (A21–A23, A27) | `apps/api/**`, `apps/web/**` | P3 |
| C1.3-MH-06 | **Manifest** (nieuw): `healthcheck.monitor`, back-up, geen `HUB_*`. | §9 (A30, A32) | nieuw `deploy/manifest/my_house.manifest.yaml` | P3 |
| C1.3-MH-07 | **Delta-matrix bijwerken:** "enrollment via `HUB_URL`" (§6, laatste alinea) en "optioneel push naar `POST {HUB_URL}/api/v1/events/inbox` na enrollment" (B06-006) schrappen: een bestaande app krijgt in v1 geen enrollment en `HUB_URL` start er nooit een (§2.3 regels 2 en 5); de Hub pollt de outbox. | §2.3 regels 2, 5 (A36) | `docs/platform-v2/DELTA_MATRIX.md` | NU (tekst) |

**Repowerk (inventaris C09):** tabelweergave bij "Laatste 24 uur" (akkoord van de gebruiker nodig). Woord "Verzonden",
ondernavigatie op 320 px, rand-token en `-soft`-contrast: Peil 1.1.1 (E13, E14, E16).

---

## 9. jelly-leon (server-fork)

**Conform (gemeten):** healthcheck via `setpriv` als 568 met no_new_privs en geleegde bounding set
(`deploy/allinone/entrypoint.sh`, `deploy/allinone/healthcheck.sh` met `setpriv`, ADR-0014, A08); GPL-2.0 (upstream); drifttest
(`tools/jelly-leon/contract_drift.py`) en EVIDENCE-test (`tools/jelly-leon/tests/test_evidence_contract.py`);
`100.64.0.0/10` telt in de B03-ontwerpen al als niet privé (A07).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-JL-01 | **Kopie 1.3 + drifttest-pin** (nieuwe bron-commit en sha256). | kop (A35) | `tools/jelly-leon/contract_drift.py`, `docs/platform-v2/PLATFORM_CONTRACTEN.md`, `docs/platform-v2/CONTRACT_1.3_CONFORMITEIT.md` | NU |
| C1.3-JL-02 | **EVIDENCE:** `Intel-iGPU-getest (ontwikkelmachine)` uit de opmerking naar `validatie` (ADR-0026 in deze repo); de 1.3-regels in de test. | §11 (A33) | `docs/platform-v2/EVIDENCE.json`, `tools/jelly-leon/tests/test_evidence_contract.py` | NU |
| C1.3-JL-03 | **Healthcheck-controlevlag** en aparte controle in de rooktest nalopen. | §2.2 (A08) | `deploy/allinone/Dockerfile` (r. ~91), `deploy/allinone/healthcheck.sh`, rooktest | NU (nalopen) |
| C1.3-JL-04 | **Manifest** (geen `HUB_*`, `healthcheck.monitor` op `/health`, kop 1.3). | §9 (A11, A32) | `deploy/manifest/jelly-leon.manifest.yaml` | NU (na C1.3-ASF-08) |
| C1.3-JL-05 | **Overname uit Emby (B03-015):** alleen `GET` met een API-sleutel; vóór/na-rapport per gebruiker; akkoord op elk verschil; Emby blijft ongewijzigd; geen rechtstreekse schrijfactie in een database. Hetzelfde rapport en akkoord bij elke upgrade die `jellyfin.db` migreert (10.11 → 12.x en latere updates met upstream-migraties; JLT-60/61), terugzetten = vorige image én snapshot (§2.3 regel 7a, RV2). | §2.3 regels 2, 3, 7 (A03) | overnametool (B03-015) | P4-0 (golf 0 al tegen stock 12.4 + Emby-container) |
| C1.3-JL-06 | **B03-plugin, Hub-koppeling (JL4):** pin via het dashboard met de vingerafdruk over alle policy-sleutels, plus de meegekopieerde `service_id` voor de controle van dienst-JWT's (§4.3, RV4); §4.2–§4.7 (`aud` string, reasons, persistente `jti`, `kind` wint); zonder pin 401 `not_linked`; events alleen via poll; alleen aantallen en ondoorzichtige ID's naar de Hub; `propose`/`apply`/`rollback` 501. | §2.3 regel 9, §4 (A04, A16, A17) | B03-017 (plugin) | P4 |
| C1.3-JL-07 | **1 MiB per route** (`RequestSizeLimit` + `Content-Length`) en de `IStartupFilter`-spike; foutcatalogus incl. 423 `item_in_playback`; health-regels, `max_age`, events in domein `media` met werkwoorden en `ernst`. De eventnamen van B03 §10.10 nalopen tegen de werkwoorden van §7: bv. `media.subtitle.rejected` telt dan als probleem en `media.quality_finding.detected` als informatie (zonder bijpassend probleem bij `.resolved`); hernoemen of bewust zo laten, met ADR. | §5, §6, §7 (A04, A21–A25) | B03-017, B03 §10.10 | P4 |
| C1.3-JL-08 | **MediaGuard-viewerclient** (rolcontrole, routes- en veldenwitte lijst, nooit ruwe antwoorden bewaren); acties alleen als deeplink `handmatig_in_mediaguard`. | §2.3 regels 2–3 (A05) | B03-009 | P4 (na BG-04; acties na BG-05) |
| C1.3-JL-09 | **Model-apps:** geen torch, transformers of ctranslate2 in de image; vertaling via de app `mt`; adresregels voor model-apps. | §1, §2 (A06) | `deploy/allinone/Dockerfile`, B03 F3 | P5 (na BG-06/BG-18) |

**Repowerk:** geen.

---

## 10. jelly-leon-web (web-fork)

**Conform (gemeten):** drifttest (`tools/jelly-leon-web/contract_drift.py`); GPL-2.0 (upstream); §10 geldt niet voor de
webclient (geen eigen image of Custom App, ADR-0008/ADR-0010 in deze repo; contract §10 laatste zin).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-JLW-01 | **Kopie 1.3 + drifttest-pin**. | kop (A35) | `tools/jelly-leon-web/contract_drift.py`, `docs/platform-v2/PLATFORM_CONTRACTEN.md`, `docs/platform-v2/CONTRACT_1.3_CONFORMITEIT.md` | NU |
| C1.3-JLW-02 | **EVIDENCE-consistentie:** elke `NIET GEVALIDEERD (…)` uit `blokkade` ook in `validatie`; geen lege `validatie`; controle in de bestaande tests. | §11 (A33) | `docs/platform-v2/EVIDENCE.json`, `tools/jelly-leon-web/check_fork_consistency.py`, `tools/jelly-leon-web/tests/` | NU |

**Repowerk (inventaris C07):** de Node-image op digest in `baseline.json` is een repo-keuze; de haaknamen volgen de
bouwplantekst "H-ITEMDETAILS" zodra ai-server-manager die aanpast.

---

## 11. jelly-leon-clients

**Conform (gemeten):** android `applicationId = "org.jellyfin.mobile.jellyleon"` (`android/app/build.gradle.kts` r. ~35),
androidtv `org.jellyfin.androidtv.jellyleon` (`androidtv/app/build.gradle.kts` r. ~19); Swiftfin-bundle-id
`org.jellyfin.swiftfin.jellyleon` in `swiftfin/XcodeConfig/Shared.xcconfig` (r. ~11) **én** `project.pbxproj`
(r. ~1192); CI-controle op botsende ID's (ADR-0004/ADR-0010 in deze repo); drifttest
(`tools/clients/tests/test_contract_kopie.py`) en EVIDENCE-test (`tools/clients/tests/test_evidence.py`).

| ID | Wijziging | Contract | Bestanden | Moment |
|---|---|---|---|---|
| C1.3-JLC-01 | **Kopie 1.3 + drifttest-pin**. | kop (A35) | `tools/clients/tests/test_contract_kopie.py`, `docs/platform-v2/PLATFORM_CONTRACTEN.md`, `docs/platform-v2/CONTRACT_1.3_CONFORMITEIT.md` | NU |
| C1.3-JLC-02 | **ID-regel van §1.1 besluit 1** in de CI nalopen: niet alleen de ID, ook accounttype, authority, permissie, `app_search_suggest_*` en sharedpref-namen ≠ die van de officiële app; Swiftfin: CI leest de effectieve build-instelling (NIET GEVALIDEERD (Mac/Xcode)). De ID's zelf wachten op bevestiging van de gebruiker (§1.2); niet verspreiden en geen Apple-registratie vóór die bevestiging. | §1.1 besluit 1, §2.3 regel 6 (A02) | `tools/clients/`, `.github/workflows/`, `docs/platform-v2/PATCHES.md` | NU (nalopen); verspreiden na bevestiging |
| C1.3-JLC-03 | **EVIDENCE-regels 1.3** in de test. | §11 (A33) | `tools/clients/tests/test_evidence.py`, `docs/platform-v2/EVIDENCE.json` | NU |

**Repowerk:** geen.

---

## 12. Peil 1.1.1 (ontwerp-agent; geen repo-werk in deze ronde)

De inventarisgroepen E01–E16 gaan naar de ontwerp-agent (`ai-server-manager:docs/platform-v2/ONTWERPTAAL.md` en
`design/ontwerptaal/`): sjabloonblok voor een onleesbare koppelstatus (E01, past bij §3.5) en voor "Koppelen bezig"
(E02, past bij de 409 van §3.7), extra tonen en iconen (E03, E04), de rol van de melding (E05), codes en lange woorden
(E06), de renderer in één doorgang (E07), de drift- en pinregel van de kopieën (E08), novalidate/verplicht/skiplink
(E09), de totaalstatus (E10), zekerheid als woord (E11), reflow met het lettertype van de CI-runner (E12, past bij §13),
woorden (E13), aliaslaag en tokens (E14), de verouderd-regel (E15) en de ondernavigatie op 320 px (E16). De repos nemen
ze pas over via de nieuwe Peil-versie (C1.3-ALG-05).
