# Platformcontracten — TrueNAS Home Platform V2 (bouwcontract voor alle repos)

Versie: `contracts 1.2` · Peildatum 2026-11-09 · Eigenaar: `lvos04/ai-server-manager` (bron van waarheid).
Elke repo heeft een kopie in `docs/platform-v2/PLATFORM_CONTRACTEN.md`; bij verschil wint deze repo.
Wat elke repo moet veranderen om aan 1.2 te voldoen: [`CONTRACT_1.2_CONFORMITEIT.md`](CONTRACT_1.2_CONFORMITEIT.md).
Keuzes en motivering: [`docs/adr/ADR-0011-contract-1-2.md`](../adr/ADR-0011-contract-1-2.md); correcties uit de
onafhankelijke review: [`docs/adr/ADR-0012-review-contract-1-2.md`](../adr/ADR-0012-review-contract-1-2.md).
Dit document maakt de pakketvoorstellen (`01_ARCHITECTUUR/02`, `03`, `07`, `08`) concreet zodat alle repos samenwerken.
Het zegt **niets** over de echte NAS: alle NAS-gegevens (D01–D18) zijn onbekend tot de gebruiker ze in de
onboarding-wizard invult of de wizard ze via de TrueNAS-API meet. Voorbeeldwaarden (IP-adressen, poolnamen zoals in
oude installatiedocs, versies) zijn nooit echte waarden.

## Wijzigingslog 1.1 → 1.2 (2026-11-09)

1. **Bestaande apps** (MediaGuard, MSO, my_house, Jellyfin/Jelly Leon) houden eigen poorten, database, UI en
   foutformaat op bestaande routes; het contractformaat geldt alleen op hun nieuwe routes; geen enrollment in v1; de
   Hub-adapter leeft in de Hub en gebruikt hun bestaande routes met een gescopete sleutel (§2.3). Hun **uiterlijk**
   volgt wel de platform-ontwerptaal (§13).
2. **Enrollment exact vastgelegd** (§3.3–§3.8): verzoek, antwoord, foutcodes, tokenformaten, 60 min, eenmaligheid,
   herhaling na herstart halverwege, opslag in `/appdata/secrets/hub-link.json` (0600, 568), rotatie en intrekking,
   env `HUB_URL` + `HUB_ENROLLMENT_TOKEN` (+ optioneel `HUB_KEY_FINGERPRINT`).
3. **Hub → dienst** authenticeert met een kortlevende, door de Hub ondertekende **dienst-JWT**
   (`token_use: "hub_service"`), niet meer met het service-token van de dienst (§4.3). Dienst → Hub blijft
   `Bearer <service-token>`.
4. **Sleutelpinning**: Hub-sleutels worden bij enrollment gepind (kid + publieke sleutel + RFC 7638-thumbprint) en
   met een menselijk controleerbare **sleutelset-vingerafdruk** geverifieerd; een via HTTP opgehaalde JWKS voegt nooit
   vertrouwen toe; nieuwe Hub-sleutels alleen via een met een gepinde sleutel ondertekende rotatie of opnieuw koppelen
   (§4.5). `jti` verplicht + replaycache tot `exp` (§4.6). Verzoeken > 1 MiB → `413 payload_too_large`, ook chunked,
   vóór auth (§5).
5. **Koppelen via de statuspagina** alleen zolang de dienst nog **nooit** gekoppeld is, met vingerafdruk en
   rate-limit per bron-IP; daarna alleen via de Hub (§3.7).
6. **Custom App-realiteit** (§2.2, §8, §10): het standaardformulier (ix-app 1.4.8) laat `no-new-privileges` en
   `cap_drop` weg → images zetten zelf `PR_SET_NO_NEW_PRIVS`; digest in het tagveld als `versie@sha256:…`;
   `app.rollback` werkt niet voor image-tags van Custom Apps; catalogustreinen houden alleen de nieuwste versie.
7. **Manifest §9**: `joins_platform_network` vervalt; poorten alleen in `network.ports`; GPU als optionele
   parameter (`gpu: none|intel_render`).
8. **Hub** (§4.1, §8): AI-runner als eigen uid 569; noodlogin (break-glass) in de Hub; D10 = Ingevuld.
9. **Besluiten van de gebruiker** (§1.1): Jellyfin-fork vóór P4 naar de nieuwste stabiele 12.x; eigen
   applicationId/bundle-id; repos en images publiek (na scan); releases `v0.1.0` na groene CI; §12 attributie van de
   lopende sessie, geen vaste sessielink.
10. **Nieuw §13 Ontwerptaal** (Tailwind 4 + shadcn/ui + lucide), met ontwerpstap vooraf en ontwerpreview achteraf.
11. §11: `validatie` mag meerdere waarden uit de vaste lijst bevatten, gescheiden door `"; "`.
12. §7: `event_type` heeft precies drie segmenten (zoals de Hub-inbox afdwingt); de voorbeelden met twee segmenten
    (`incident.opened`, `action.executed`) zijn gecorrigeerd.

### Correcties uit de onafhankelijke review (2026-11-09, blijft `contracts 1.2`; ADR-0012)

Het contract was nog nergens gekopieerd of gebouwd; deze correcties horen daarom bij 1.2 zelf.
R1. `app_id` is de **vaste** naam uit §2 (constante in de image), niet de door de gebruiker gekozen TrueNAS-appnaam; de
    Hub houdt die naam apart bij (§3.3).
R2. Koppelstatus: `bezig` is geen `state` meer maar een apart veld `pending`; een lopende poging laat een bestaande
    koppeling ongemoeid. Herstart met een koppelcode, mislukte pogingen en `previous_pins` zijn nu vastgelegd (§3.5, §3.6).
R3. Enroll-verzoek: `kid` (indien aanwezig) moet de RFC 7638-thumbprint zijn; `use`/`alg` en andere JWK-velden → 422;
    koppelcode moet na normalisatie 12 Crockford-tekens zijn (anders 422); rate-limit zonder ±1-onduidelijkheid; Hub-adres
    van de statuspagina volgt dezelfde regels als `HUB_URL`; redirects worden nooit gevolgd (§3.2, §3.3).
R4. Rotatie service-token: het oude token vervalt pas 10 min **na het eerste gebruik** van het nieuwe (hooguit 24 uur);
    de Hub vraagt opnieuw rotatie als een dienst een ouder token gebruikt terwijl het nieuwste ongebruikt is (herstel na
    een crash). Rotatie na 180 dagen is alleen een melding: geheimen roteren is R2 (03_RISICO_AUTONOMIE) (§3.8).
R5. Een 401 van de Hub leidt pas tot `ingetrokken` als ook `GET /api/v1/services/self` 401 geeft; een herhaalde
    `unlink` na ontkoppelen (401 `not_linked`) telt voor de Hub als geslaagd (§3.8).
R6. Sleutelrotatie: `key-rotations` zonder authenticatie (de handtekening is het bewijs); één statement wijzigt precies
    één doel; de Hub ondertekent pas met een nieuwe sleutel als elke actieve dienst de rotatie heeft (§4.5). Vaste
    `reason` per controle (§4.3, §4.7).
R7. Koppelen, ontkoppelen, intrekken, token- en sleutelrotatie en het noodaccount zijn **geen** `action_id`'s: de AI kan
    ze niet voorstellen of uitvoeren (§8).
R8. Uitspraken over TrueNAS zijn bronwaarnemingen met zekerheid uit `TRUENAS_APP_API.md`, geen feiten over de NAS van de
    gebruiker; ook de `ix-app`-versie zelf kan uit de catalogus verdwijnen (§2.2). Bron-IP voor de noodlogin achter
    Docker-NAT is NIET GEVALIDEERD; de zelftest toont het gemeten adres (§4.1).
R9. Besluit 1: ook `app_search_suggest_intent_data` en de back-upregels (sharedpref-namen) volgen de eigen ID (§2.3).
R10. Externe kopieën van `/appdata/secrets` alleen versleuteld (04_GEGEVENS_EN_STORAGE punt 3) (§3.5).
R11. "Alles als 568" geldt ook voor PID 1: een init die als root blijft draaien voldoet niet; de rooktest kijkt naar
     elk proces (§2.2, §10; waar dat nu nog zo is: `CONTRACT_1.2_CONFORMITEIT.md` A6).
R12. Executor: "live geverifieerde schrijfkey" betekent tegen het bij de eerste koppeling vastgelegde NAS-adres en
     TLS-certificaat; een zelf opgegeven ander adres telt niet als bewijs (§3.9).

## 1. Vaste keuzes (van de gebruiker)

- Nieuwe repos: **Python 3.12 + FastAPI + SQLAlchemy 2 + Alembic + PostgreSQL 16**, frontend **Next.js/React PWA** (alleen in
  `ai-server-manager`; alle schermen van alle nieuwe diensten staan in die ene Hub-UI). Andere nieuwe diensten zijn
  zelfstandige API-diensten met alleen een kleine eigen statuspagina (`GET /` → eenvoudige HTML, NL).
- Installatie **zonder terminal en zonder YAML**: alles wordt geïnstalleerd als **standaard TrueNAS Custom App**
  (het gewone formulier: image + tag, poorten, opslag, omgevingsvariabelen) — nooit via *Install via YAML*,
  `custom_compose_config` of docker compose. Eerste installatie: de gebruiker maakt in de TrueNAS-web-UI precies **twee**
  Custom Apps: `ai-server-manager` (de Hub, alles-in-één) en `ai-server-manager-executor`. Daarna installeert het platform
  alles via de TrueNAS-API vanuit de platform-UI. Apps van derden die meerdere containers nodig hebben (Authentik, Immich,
  …) via de **officiële TrueNAS-catalogusapp** waar die bestaat (versie vastgezet, zie §2.2 over verdwijnende versies);
  anders een standaard Custom App met één gepinde image. `docker compose` mag alleen voor ontwikkeling, CI en de
  integrale E2E-testomgeving.
- **Eén alles-in-één image per repo** (zoals MSO `deploy/allinone`): eigen ingebouwde PostgreSQL 16 (alleen unix-socket,
  geen netwerkpoort), API, worker en — alleen bij de Hub — de web-UI, onder een kleine procesbewaker; één datamap
  `/appdata`, één poort, healthcheck, start als root alleen om `/appdata` aan 568:568 te geven en draait daarna alles als
  568 (uitzondering: de AI-runner van de Hub als 569, §8). Geen wachtwoorden of geheimen in het formulier; geheimen maakt
  de app zelf bij eerste start in `/appdata/secrets`. Bestaande apps: §2.3.
- Geen `latest`-tags. Elke image op exacte versie, base-images bovendien op `@sha256:`-digest.
- Geen shell/root voor AI, geen `sh -c`/`sudo`-endpoint, geen Docker-socket in een container, boiler nooit schakelen,
  geen betaalde API-overage (Claude alleen binnen inbegrepen credits, harde stop op 0 overage).
- Lokale modellen (Ollama-LLM, faster-whisper STT, Piper TTS, lokaal embeddingmodel) zijn **optionele apps, standaard uit**.
- UI-taal Nederlands. Elke kaart: waarde + eenheid + bron + **laatst bijgewerkt**. Onbekend is `unknown`, nooit groen.
  Uiterlijk volgens de platform-ontwerptaal (§13).
- Jellyfin-fork: technische identiteit/API blijft "Jellyfin" (clientcompatibiliteit); alleen de zichtbare naam is
  "Jelly Leon". GPL-licentie en upstream-credits blijven staan.

### 1.1 Besluiten van de gebruiker (2026-11-09, vast)

| # | Besluit | Gevolg in dit contract |
|---|---|---|
| 1 | Android: **eigen applicationId**, naast de officiële app installeerbaar (android `applicationId`; androidtv daarnaast `app_id` en `app_search_suggest_authority`). iOS/tvOS: eigen bundle-id. | §2.3, conformiteit `jelly-leon-clients`. Nooit `org.jellyfin.*` als ID van de fork. Alle daarvan afgeleide waarden volgen mee (androidtv ook `app_search_suggest_intent_data` en de sharedpref-namen in `backup_content.xml`/`backup_rules.xml`; `jelly-leon-clients` ADR-0004). iOS/tvOS: NIET GEVALIDEERD (Mac/Xcode). |
| 2 | Swiftfin 1.6.1 blijft. De **server gaat vóór P4 naar de nieuwste stabiele Jellyfin 12.x (.NET 10)** (jelly-leon + jelly-leon-web), zodat B03 direct op 12.x wordt gebouwd. | Aparte upgradefase vóór P4; **niet** in de ronde van contract 1.2. Identiteit "Jellyfin", zichtbare naam "Jelly Leon", GPL blijven. Op de peildatum toont `git ls-remote --tags` upstream `v12.0` … `v12.4` (server en web); de exacte versie wordt in de upgradefase opnieuw vastgesteld. Android-clients op 12.x-compatibiliteit controleren. |
| 3 | Alle repos en GHCR-images worden **publiek**, pas na een scan van de volledige historie op geheimen en privégegevens (bevindingen eerst aan de gebruiker). | §2.1: installatie zonder registry-login; registry-login alleen als fallback beschreven. |
| 4 | `JL_SYNC_PUSH_TOKEN` (upstream-sync): nog **open**. | Geen tokens in repo's; sync-push blijft uit tot het besluit valt. |
| 5 | my_house 0.2.0-release mag opnieuw. | Niet in de ronde van contract 1.2. |
| 6 | Release-tags `v0.1.0` voor de nieuwe repos (images naar GHCR met digests) zodra hun CI groen is. | Toegestaan; niet in de ronde van contract 1.2 zelf taggen. |
| 7 | Eén eigen **ontwerptaal** op Tailwind 4 + shadcn/ui + lucide. | §13. |
| D10 | Bestaande mini-pc: videoapp/andere projecten, **geen** Home Hub-diensten. | Status **Ingevuld** (vast besluit); niets van het platform wordt op de mini-pc gepland. |

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

Bestaande apps staan in §2.3 (eigen poorten). De Custom App-naam in deze tabel is ook de **vaste `app_id`** van de
dienst: een constante in de image, gebruikt bij enrollment (§3.3) en als JWT-`aud` (§4). Kiest de gebruiker bij een
handmatige installatie een andere appnaam, dan blijft de `app_id` gelijk; de Hub houdt de werkelijke TrueNAS-appnaam
apart bij in zijn register (gemeten via `app.query` op image-repository, door de gebruiker bevestigd). Eén instantie
per `app_id`. Hostpoorten zijn voorstellen: vóór installatie controleert de Hub via de
TrueNAS-API op conflicten met bestaande apps. Binnen de alles-in-één image houdt elke app intern dezelfde modulegrenzen
(api, worker, …) als aparte processen; in ontwikkeling/CI mogen die als losse processen of compose-diensten draaien.

**Eerste installatie (handmatig, 2 formulieren)**, beschreven in `jelly-leon-platform/install/truenas/INSTALLATIE.md`:
1. Custom App `ai-server-manager`: image + tag (§2.2), poort 30400, opslag `/appdata`. Bij eerste start toont de app een
   eenmalige **setupcode** in de app-logs (TrueNAS-web-UI → Apps → app → Logs); de wizard vraagt die vóór het eerste
   admin-account.
2. Custom App `ai-server-manager-executor`: image + tag, poort 30410, eigen opslag `/appdata`. Koppelen gebeurt via de
   web-UI (§3.9); de TrueNAS-schrijfkey voert de gebruiker alleen op de koppelpagina van de executor in.
Daarna installeert de Hub (via executor) de overige eigen apps (`appstore-en-fork`, `jelly-leon-platform`, …) als
standaard Custom App.

**Installatie via de API** (executor, `app.install`): TrueNAS `app.create` voor een standaard Custom App met de
formulierwaarden (image, ports, storage, env, resources, gpu) — in TrueNAS 24.10+ is dat de catalogus-app `ix-app`
(`catalog_app: "ix-app"`, `train: "stable"`, exacte `version`) met `values`; methodenaam en waardenschema per versie
ontdekken (`core.get_methods`) en tegen de officiële docs controleren — of `app.create` met `catalog_app`/`train`/`version`
voor een catalogusapp. **Nooit** `custom_compose_config`/`custom_compose_config_string`/`custom_app=true`.
Bronnen en zekerheid per feit: `jelly-leon-platform/docs/platform-v2/TRUENAS_APP_API.md`.

### 2.1 Publieke images en registry-login

- Na de scan uit besluit 3 zijn alle repos en GHCR-pakketten **publiek**. Installatie (handmatig én via de API) gebruikt
  dan **geen** registry-login. Tot de scan klaar is en de zichtbaarheid echt is omgezet, is installeren van een eigen image
  op een echte NAS **NIET GEVALIDEERD** (en voor een privé-pakket geblokkeerd).
- Registry-login wordt in `deploy/truenas/CUSTOM_APP.md` en `INSTALLATIE.md` alleen als **fallback** beschreven (TrueNAS
  registry-instelling met een token dat alleen pakketten mag lezen; gedrag met GHCR-tokens NIET GEVALIDEERD). Zo'n token
  is een geheim van de gebruiker in TrueNAS, nooit in een manifest, formulierveld van een app, repo of log.

### 2.2 Custom App-realiteit (gemeten in de bronnen, niet op een echte NAS)

Alles in deze paragraaf is gelezen in de broncode en docs van TrueNAS (bronnen, commits en zekerheid per feit:
`jelly-leon-platform/docs/platform-v2/TRUENAS_APP_API.md`) en is **NIET GEVALIDEERD (echte NAS)**. Welke TrueNAS- en
`ix-app`-versie op de NAS van de gebruiker staat, is onbekend (D01) tot de wizard het via de TrueNAS-API meet; de
regels hieronder zijn daarom zo gekozen dat ze ook gelden als het gedrag op de NAS anders blijkt.

- **Beveiligingscontext:** het ix-app-template (versie **1.4.8** in de stable-trein van de gelezen catalogus-commit)
  verwijdert `no-new-privileges` en roept `clear_caps()` aan: een Custom App draait met de standaard
  Docker-capabilities en zonder no-new-privileges. Een image die als root start om `/appdata` aan 568 te geven, gebruikt daarvoor `CHOWN`, `FOWNER`,
  `DAC_OVERRIDE`, `SETUID` en `SETGID` (alle in de Docker-standaardset; nooit om extra capabilities vragen). Daarom moet
  **elke image zelf** na de eigenaarschapsstap: (1) volledig naar 568:568 wisselen (`setgroups([])`, `setgid`, `setuid`;
  geen ambient capabilities), (2) `prctl(PR_SET_NO_NEW_PRIVS, 1)` zetten vóór de eerste `execve` van een dienstproces.
  Dit geldt voor **alle** processen, ook PID 1: na de eigenaarschapsstap draait er geen enkel proces meer als root. Een
  init (bv. `dumb-init`) die als root blijft draaien voldoet niet; óf de bewaker is zelf PID 1, ruimt zombies op en
  wisselt zelf (zoals de Hub), óf de init wordt pas ná de wissel gestart. De rooktest controleert voor **elk** proces in
  de container (inclusief PID 1, behalve de eigen `docker exec`-shell) `Uid 568` (AI-runner 569),
  `CapEff 0000000000000000` en `NoNewPrivs 1`, en draait de container **zonder** `--security-opt no-new-privileges` en
  zonder `--cap-drop` (zoals het formulier).
  De image werkt ook als de gebruiker "Custom User 568" aanvinkt: dan geen eigenaarschapsstap; is `/appdata` niet
  schrijfbaar, dan een Nederlandse melding in de app-log en healthcheck rood — nooit stil doorstarten.
- **Digest in het tagveld:** het formulier kent alleen `repository` + `tag`; de referentie wordt `"{repository}:{tag}"`.
  Eigen apps en upstream-images worden daarom ingevuld als tag **`<versie>@sha256:<64 hex>`** (geldige Docker-syntax,
  trekt op digest). Of TrueNAS met zo'n tag update-detectie doet, en of het formulier `@` accepteert, is
  **NIET GEVALIDEERD (echte NAS)**. Na elke installatie/update leest de executor de digest terug (`app.image.query`,
  `repo_digests`) en stopt + incident bij afwijking. Accepteert het formulier de tag met digest niet, dan alleen de
  exacte versie en geldt de digest-readback als controle.
- **Terugzetten van een Custom App:** `app.rollback` werkt alleen naar een eerder geïnstalleerde, lagere
  **catalogusversie**; een image-tagwijziging van een ix-app is géén versie. Terugzetten = `app.update` met de **vorige
  waarden** (de Hub/lifecycle bewaart vóór elke update de volledige vorige `values` inclusief tag+digest als
  terugzetrecept) plus — bij een schemawijziging — data herstellen via de eigenaar of snapshot (R3 bij DB-restore).
- **Catalogustreinen houden (in de gelezen commit) alleen de nieuwste versie:** een vastgezette `catalog.version` kan
  uit de catalogus verdwijnen; `app.create` faalt dan (`Version … not found`). Of TrueNAS oudere versies elders bewaart,
  is onzeker. Al geïnstalleerde versies blijven lokaal staan. Het installatie-/updateplan moet dit melden als blokkade
  `version_unavailable` en een manifest-update voorstellen (nieuwe vaste versie + test); **nooit** stil een nieuwere
  versie of `latest` installeren. Dit geldt ook voor de **`ix-app`-versie zelf** bij het installeren van een eigen
  Custom App: de vertaling naar formulierwaarden is per `ix-app`-versie getest; staat die versie niet meer in de
  catalogus, dan `version_unavailable` met als voorstel "vertaling voor de nieuwe `ix-app`-versie testen" (bij
  `app.update` van een al geïnstalleerde app speelt dit niet). Community-trein inschakelen
  (`catalog.update` `preferred_trains`) is R2.

### 2.3 Bestaande apps (MediaGuard, MSO, my_house, Jellyfin/Jelly Leon)

Bestaande apps zijn **geen** nieuwe diensten: ze houden wat werkt en krijgen alleen hiaten uit hun `DELTA_MATRIX.md`.
Bestaande integriteit, rollback en monitoring nooit dubbel bouwen, vervangen of uitschakelen.

| App (repo) | Custom App / image | Poorten (container → hostvoorstel) | Opslag en database | Eigen UI | Foutformaat bestaande routes |
|---|---|---|---|---|---|
| MediaGuard (`media-guard-ultimate`) | `mediaguard` · `ghcr.io/lvos04/mediaguard-core:<versie>-aio` | 30080 (UI/API) + fork-API's 38989/38990 (Sonarr) en 37878/37879 (Radarr), elk gelijk | SQLite-WAL; mounts `/config` (appdata), `/work` (staging/quarantaine), `/data` (media + downloads, één dataset voor hardlinks) | Next.js-web + Android | eigen (ongewijzigd) |
| MSO (`media-source-optimizer`) | `media-source-optimizer` · `ghcr.io/lvos04/media-source-optimizer:<versie>` | 38081 → 38081 | ingebouwde PostgreSQL, één `/appdata` (alles-in-één bestaat al) | eigen web | `{detail, code, correlation_id}` |
| my_house (`my_house`) | `smart-home` · `ghcr.io/lvos04/my_house:<versie>` (alles-in-één, **nieuw in P3**) | 8080 → 8088 (bestaande QR-koppelingen bewaren adres mét poort) | ingebouwde PostgreSQL, één `/appdata` (P3) | React/Vite-PWA + Android | `{"detail":{"code","message"}}` |
| Jellyfin / Jelly Leon (`jelly-leon`, `jelly-leon-web`) | `jelly-leon` · `ghcr.io/lvos04/jelly-leon:<versie>` | 8096 → 30460; staat er al een stock-Jellyfin (onbekend tot D07 het meet), dan blijft die ongemoeid op zijn eigen poort | Jellyfin-eigen database in `/config`, cache `/cache` | jelly-leon-web + clients | Jellyfin-API (ongewijzigd) |

Regels:
1. **Eigen poorten, eigen database, eigen UI, eigen foutformaat op bestaande routes.** Het contractformaat (§5),
   `Idempotency-Key`, paginering/ETag en de 1 MiB-grens gelden alleen op **nieuwe** routes (`/connector/v1/*`, `/healthz`,
   `/readyz`, en wat de delta-matrix als ontbrekend markeert). Bestaande clients (web, Android, MSO↔MediaGuard) mogen niet
   breken.
2. **Geen enrollment in v1.** De **Hub-adapter leeft in de Hub** (`ai-server-manager`) en gebruikt de **bestaande
   routes** met een **gescopete sleutel** die de gebruiker in de eigen UI van de app aanmaakt en in de Hub-UI invoert
   (vault, §3.10). Per app:
   - MediaGuard: bestaande `X-Api-Key`, sleutel `hub` met rol **viewer** voor het read-model; operator-rechten (alleen
     noodstop aan, één herzoek) pas nadat sleutels scopes hebben (P3-02).
   - MSO: heeft nu alleen sessie-auth; P3 bouwt een **machine-sleutel met scopes** (`read`; later `changes:approve`
     met `expected_preview_hash` + `Idempotency-Key`). Geen menselijk wachtwoord/CSRF-sessie in de Hub.
   - my_house: koppelcode met rol **viewer** uit de my_house-web-app, ingewisseld via de bestaande
     `POST /api/v1/pairing/redeem`; een viewer-token kan niets bedienen (403).
   - Jellyfin/Jelly Leon: geen gescopete API-sleutels in Jellyfin; v1 leest alleen openbare routes
     (`/System/Info/Public`, `/health`) en wat een eigen **niet-admin** Jellyfin-gebruiker mag zien. Een admin-API-sleutel
     wordt niet gebruikt tot de B03-plugin (P4) scopes biedt.
3. **Schrijven door de Hub** naar een bestaande app gaat alleen via de door die app ondersteunde goedkeuringsroute
   (MSO change sets, my_house `propose`/`apply` met ondertekend `ExecutionRequest` (§8), MediaGuard alleen noodstop
   **aan**) en is altijd gebonden aan `preview_hash`/ETag + `Idempotency-Key`. Waar een bestaande app een ondertekend
   `ExecutionRequest` verifieert, plakt de beheerder de **publieke** Hub-sleutelset (`jwks` + `policy_public_key`, in de
   Hub-UI kopieerbaar) in de eigen beheer-UI van die app; de app berekent de sleutelset-vingerafdruk (§4.5) en toont
   die ter vergelijking met de Hub-UI, en pint daarna de policy-sleutel. Zonder gepinde sleutel →
   `501 capability_unavailable`.
4. **Installatie:** bestaande apps worden als standaard Custom App met één alles-in-één image geïnstalleerd
   (MediaGuard/MSO: bestaat; **my_house: alles-in-één Custom App-image in P3**, plus herstelprocedures zonder terminal:
   updaten/terugdraaien via het formulier, wachtwoord vergeten, sleutelwissel/oude hoofdsleutel uploaden via de UI).
   Compose-/YAML-/`install.sh`-routes blijven alleen voor ontwikkeling/CI en worden zo gemarkeerd.
5. **Uiterlijk:** MediaGuard, MSO en my_house krijgen het uiterlijk van de platform-ontwerptaal (§13); functies,
   routes, gebruikersreizen en clientcontracten blijven gelijk. Jelly Leon valt erbuiten.
6. **Clients van de fork** (`jelly-leon-clients`): eigen Android-`applicationId` (androidtv ook `app_id`,
   `app_search_suggest_authority` en `app_search_suggest_intent_data`, plus de sharedpref-namen in de back-upregels) en
   eigen iOS/tvOS-bundle-id, geregistreerd als patch; Kotlin-`namespace` en technische identiteit "Jellyfin" blijven.
   Wat er precies verandert staat in `jelly-leon-clients` ADR-0004; de exacte ID's worden daar bij de patch vastgelegd.

## 3. Geheimen en koppelen

### 3.1 Uitgangspunten

- Nooit geheimen in het Custom App-formulier, in Git of in logs. Elke app maakt bij eerste start ontbrekende geheimen
  aan in `/appdata/secrets/` (map 0700, bestanden 0600, eigenaar 568:568, nooit een bestaand geheim overschrijven; de
  koppelstatus `hub-link.json` is geen gegenereerd geheim en wordt volgens §3.5 vervangen): eigen
  DB-wachtwoord/socket, `vault.key` (AES-256-GCM voor opgeslagen credentials), eigen Ed25519-identiteit. De Hub maakt
  daarnaast `policy-signing.ed25519`, `jwt-signing.ed25519`, `hub-identity.ed25519` en de eenmalige setupcode (alleen in
  de logs).
- Uitzondering op "geen geheimen in het formulier": het **eenmalige enrollment-token** (`HUB_ENROLLMENT_TOKEN`) mag als
  omgevingsvariabele in de Custom App staan; het vervalt na 60 min of na eerste gebruik en is daarna waardeloos.
- De Hub bewaart van de tokens en codes die hij **zelf uitgeeft** **alleen hashes** (SHA-256); een geheim wordt precies
  één keer getoond/teruggegeven (`Cache-Control: no-store`). Credentials van andere apps die de Hub zelf gebruikt,
  staan versleuteld in zijn vault (§3.10).

### 3.2 Overzicht enrollment (eigen nieuwe diensten)

1. **Via de API geïnstalleerd** (normaal vanaf P2): de Hub maakt een enrollment-token voor `app_id` en geeft bij
   `app.create`/`app.update` alleen deze env mee: `HUB_URL`, `HUB_KEY_FINGERPRINT` (niet geheim) en
   `HUB_ENROLLMENT_TOKEN` (de enige, kortlevende uitzondering op "geen geheimen in het formulier", §3.1).
2. **Handmatig geïnstalleerd**: de beheerder maakt in de Hub-UI óf een enrollment-token en vult `HUB_URL` +
   `HUB_ENROLLMENT_TOKEN` (+ `HUB_KEY_FINGERPRINT`) in het formulier van de Custom App in (**aanbevolen**: geen
   wedloop), óf een **koppelcode** die hij op de statuspagina van de dienst invoert (§3.7).
3. De dienst roept `POST {HUB_URL}/api/v1/services/enroll` aan (§3.3), controleert de vingerafdruk, bewaart service-token
   en gepinde Hub-sleutels in `/appdata/secrets/hub-link.json` (§3.5) en bevestigt met `GET /api/v1/services/self`.

Omgevingsvariabelen (exacte namen; alias `ENROLLMENT_TOKEN` vervalt — mag één release worden gelezen met een
waarschuwing in de log):

| Variabele | Verplicht | Formaat | Betekenis |
|---|---|---|---|
| `HUB_URL` | voor env-enrollment | `http(s)://<host>[:<poort>]` zonder pad, query, fragment of inloggegevens; geen loopback, geen link-local (`169.254.0.0/16`, `fe80::/10`) en geen `0.0.0.0`/`::` (loopback alleen met een expliciete ontwikkelvlag) | Adres van de Hub |
| `HUB_ENROLLMENT_TOKEN` | voor env-enrollment | `enr_` + 43 tekens base64url | Eenmalig token (60 min) |
| `HUB_KEY_FINGERPRINT` | nee (de Hub zet hem altijd bij installatie via de API) | `XXXX-XXXX-XXXX-XXXX` (§4.5) | Verwachte sleutelset-vingerafdruk; aanwezig ⇒ verplicht te controleren |

Dezelfde adresregels gelden voor het Hub-adres dat op de statuspagina wordt ingevuld (§3.7). Bij alle aanroepen naar
de Hub volgt de dienst **nooit** een redirect (3xx = storing, niet volgen) en negeert hij proxy-omgevingsvariabelen
(§5). Zonder `HUB_KEY_FINGERPRINT` is een env-enrollment *trust on first use*: de statuspagina en de Hub-UI tonen
daarna beide de vingerafdruk, zodat de beheerder ze kan vergelijken.

### 3.3 `POST /api/v1/services/enroll` — exact schema

Geen authenticatie (het token of de koppelcode is het bewijs); `Content-Type: application/json`; body ≤ 1 MiB;
**geen** `Idempotency-Key` (wordt genegeerd; herhaling is geregeld in §3.6).

**Verzoek** (onbekende velden → 422):

| Veld | Type | Verplicht | Regel |
|---|---|---|---|
| `app_id` | string | ja | de vaste `app_id` uit §2 (constante in de image, niet de door de gebruiker gekozen appnaam); patroon van TrueNAS-appnamen `^[a-z]([-a-z0-9]*[a-z0-9])?$`, 1–40 tekens; moet gelijk zijn aan de `app_id` van het token/de code (anders 401) |
| `enrollment_token` | string | precies één van beide | `^enr_[A-Za-z0-9_-]{43}$` (anders 422) |
| `pairing_code` | string | precies één van beide | ≤ 32 tekens; genormaliseerd: alleen letters/cijfers, hoofdletters, `O→0`, `I/L→1`; moet precies 12 tekens uit het Crockford-alfabet opleveren (anders 422; de Hub vergelijkt de SHA-256 van de genormaliseerde code) |
| `version` | string | ja | 1–64 tekens `^[0-9A-Za-z][0-9A-Za-z.+_-]*$` (versie van de dienst) |
| `base_url` | string \| null | ja (mag `null`) | ≤ 512, `http(s)://host[:poort][/pad]`; alleen informatief — de Hub belt de dienst via zijn eigen register (D03 + hostpoort uit `app.query`) en toont een afwijking als waarschuwing |
| `public_key_jwk` | object | ja | publieke Ed25519-JWK `{"kty":"OKP","crv":"Ed25519","x":"<43 base64url = 32 bytes, canoniek>","kid":"<RFC 7638-thumbprint>"}`; `kid` optioneel, maar indien aanwezig gelijk aan de RFC 7638-thumbprint (§4.5); `d`, `use`, `alg` of andere velden → 422. De Hub bewaart `{kty, crv, x, kid=thumbprint}` |

```json
{"app_id":"home-control-hub","enrollment_token":"enr_<43 tekens>","version":"0.1.0",
 "base_url":null,"public_key_jwk":{"kty":"OKP","crv":"Ed25519","x":"<43 tekens>","kid":"<thumbprint>"}}
```

**Antwoord `200 OK`** (ook bij een toegestane herhaling, §3.6), header `Cache-Control: no-store`:

| Veld | Type | Betekenis |
|---|---|---|
| `schema_version` | string | `"1.2"` |
| `service_id` | string (UUID) | registratie in de Hub; de dienst bewaart hem en controleert hem in dienst-JWT's (§4.3) |
| `app_id` | string | echo |
| `service_token` | string | `^svc_[A-Za-z0-9_-]{43}$`; dienst → Hub (§4.4); geen vaste vervaltijd |
| `token_type` | string | `"Bearer"` |
| `hub_issuer` | string | `"hub"` |
| `jwks` | object | `{"keys":[JWK,…]}`, ≥ 1 sleutel, elk `{"kty":"OKP","crv":"Ed25519","x","kid","use":"sig","alg":"EdDSA"}` — wordt **gepind** |
| `policy_public_key` | object | JWK zoals hierboven — de sleutel waarmee de Hub `ExecutionRequest`s ondertekent (§8); wordt **gepind** |
| `keyset_fingerprint` | string | `XXXX-XXXX-XXXX-XXXX` over `jwks` + `policy_public_key` (§4.5) |
| `jwks_url` | string | `"/api/v1/auth/jwks"` (relatief aan `HUB_URL`; alleen ter vergelijking, voegt nooit vertrouwen toe) |
| `events_inbox_url` | string | `"/api/v1/events/inbox"` |
| `key_rotation_url` | string | `"/api/v1/auth/key-rotations"` (§4.5) |
| `enrollment_replayed` | boolean | `true` als dit een toegestane herhaling was (§3.6) |

De dienst controleert vóór opslaan: alle velden aanwezig met het juiste type (onbekende extra velden in het antwoord
negeert hij); `schema_version` met major `1` (`"1.2"` in deze versie; een andere major → ongeldig); `app_id` gelijk;
`service_id` een UUID; `service_token` past in het patroon; elke JWK geldig Ed25519 zonder `d`, met `use:"sig"`,
`alg:"EdDSA"` en een `kid` die binnen `jwks.keys` uniek is; de **zelf berekende** `keyset_fingerprint` gelijk aan het
antwoord **en** — als opgegeven — gelijk aan
`HUB_KEY_FINGERPRINT` of de op de statuspagina ingevoerde vingerafdruk. Afwijking → niets opslaan, `last_error`
`hub_vingerafdruk_onjuist` (vingerafdruk) of `hub_antwoord_ongeldig` (de rest), definitief voor dit token (§3.6).
Aliassen uit eerdere aannames (`token`, `id`, `policy_public_jwk`, `kind`, `secret`) bestaan niet.

**Fouten** (contractformaat §5):

| HTTP | `code` | Wanneer | Gedrag van de dienst |
|---|---|---|---|
| 401 | `invalid_enrollment` | token/code onbekend, verlopen, al gebruikt (en geen toegestane herhaling), of `app_id` past niet — bewust één code, geen orakel | definitief voor dit token: nooit automatisch opnieuw; koppelcode mag de gebruiker opnieuw invoeren |
| 404 | (geen contractbody gegarandeerd) | endpoint bestaat niet (oude Hub) | definitief; melding "deze Hub-versie kent aanmelden niet" |
| 413 | `payload_too_large` | body > 1 MiB | definitief (fout in de dienst) |
| 422 | `validation_error` | schemafout, onbekend veld, beide of geen van `enrollment_token`/`pairing_code` | definitief (incompatibele dienst) |
| 429 | `rate_limited` + header `Retry-After` (s) | zodra er binnen de laatste 15 min **10** mislukte pogingen (401) van dit bron-IP zijn, krijgt elke volgende poging 429 (geteld in de database, blijft gelden over herstarts; een geslaagde enrollment wist de teller; 422/429 tellen niet mee). Let op: diensten op dezelfde NAS komen bij de Hub mogelijk binnen met één bron-IP (NIET GEVALIDEERD) en delen dan deze limiet | opnieuw na `Retry-After`, niet eerder |
| 500/502/503/504, netwerkfout | `internal_error` / `service_unavailable` | storing | opnieuw met exponentiële backoff + jitter (start 5 s, max. 15 min tussen pogingen); automatisch stoppen 60 min na de eerste poging → "maak een nieuw token in de Hub" |

### 3.4 Tokenformaten en levensduur

| Geheim | Formaat | Levensduur | Opslag in de Hub |
|---|---|---|---|
| enrollment-token | `enr_` + `secrets.token_urlsafe(32)` (43 tekens base64url) | 60 min na aanmaak, eenmalig (§3.6) | SHA-256 |
| koppelcode (diensten) | 12 tekens Crockford-base32 in groepen `XXXX-XXXX-XXXX` (~60 bit) | 60 min, eenmalig | SHA-256 van de genormaliseerde code |
| koppelcode (executor) | idem | 30 min, eenmalig | SHA-256 |
| service-token | `svc_` + 43 tekens base64url | geen vaste vervaltijd; na rotatie blijft het oude geldig tot 10 min na het eerste gebruik van het nieuwe (max. 24 uur, §3.8) | SHA-256 + laatste 4 tekens |
| Hub-JWT (gebruiker of dienst) | JWS compact, EdDSA | `exp − iat ≤ 120 s` | — (alleen `jti` in replaycaches) |

### 3.5 Opslag bij de dienst: `/appdata/secrets/hub-link.json`

Eén bestand, 0600, eigenaar 568:568, in `/appdata/secrets` (0700). Schrijven: nieuw bestand in dezelfde map
(`O_CREAT|O_EXCL`, 0600) → `fsync` → `rename` → `fsync` van de map, onder een exclusieve vergrendeling op
`/appdata/secrets/hub-link.lock` (API en worker kunnen allebei schrijven; lezen-wijzigen-schrijven altijd binnen de
vergrendeling). Elk proces leest het bestand opnieuw zodra inode of mtime verandert (of bij elk verzoek), zodat een
ontkoppeling, intrekking of rotatie door het ene proces direct voor het andere geldt. Het bestand staat **niet** in de
database, zodat een database-herstel geen oude koppeling, oude pins of een ingetrokken token terugbrengt, en DB-exports
(B12) geen credentials bevatten. Het service-token staat er onversleuteld in, net als `vault.key` in dezelfde map;
externe kopieën (offsite) van `/appdata/secrets` alleen versleuteld (04_GEGEVENS_EN_STORAGE punt 3). Bestaande
koppelingen in de database (vault) worden bij de eerste start van de 1.2-versie eenmalig naar dit bestand overgezet en
daarna uit de database verwijderd.

```json
{"schema_version":"1.2","state":"gekoppeld","app_id":"home-control-hub",
 "hub_url":"http://<NAS-adres>:30400","service_id":"<uuid>","via":"token",
 "first_linked_at":"2026-11-09T12:00:00Z","linked_at":"2026-11-09T12:00:00Z","confirmed_at":"2026-11-09T12:00:01Z",
 "service_token":"svc_<43 tekens>","service_token_last4":"<4>",
 "pins":{"jwt":[{"kid":"<kid>","jwk":{"kty":"OKP","crv":"Ed25519","x":"<x>"},"thumbprint":"<RFC 7638>",
                 "pinned_at":"…Z","source":"enroll"}],
         "policy":[{"kid":"…","jwk":{…},"thumbprint":"…","pinned_at":"…Z","source":"enroll"}],
         "keyset_fingerprint":"XXXX-XXXX-XXXX-XXXX","rotation_sequence":0},
 "previous_pins":null,"pending":null,"used_enrollment_token_sha256":["<hex>"],"last_error":null}
```

- `state` (stabiele toestand) ∈ `nooit_gekoppeld` (ook als het bestand ontbreekt), `gekoppeld`, `ontkoppeld`,
  `ingetrokken`. Alleen bij `gekoppeld` zijn `service_token` en `pins` gevuld en vertrouwt de dienst Hub-JWT's.
  `first_linked_at` blijft na de eerste geslaagde koppeling **altijd** staan (bepaalt §3.7).
- `pending` (`null` of een lopende poging, **naast** de stabiele toestand): `{"kind":"token|koppelcode",
  "secret_sha256":"<hex>","hub_url":"…","started_at":"…Z","attempts":n}` — nooit het geheim zelf. Een lopende poging
  verandert `state`, token en pins niet: een bestaande koppeling blijft tot het slagen geldig.
- `previous_pins`: de pins van vóór het laatste ontkoppelen/opnieuw koppelen, alleen voor audit; voegen nooit vertrouwen
  toe.
- `used_enrollment_token_sha256`: hashes van **afgehandelde** env-tokens (geslaagd of definitief mislukt), hooguit de
  20 laatste; een token in deze lijst wordt nooit opnieuw geprobeerd.
- `last_error`: `null` of `{"code":"<vaste code>","at":"…Z"}`; codes o.a. `hub_onbereikbaar`, `hub_weigerde`,
  `hub_antwoord_ongeldig`, `hub_vingerafdruk_onjuist`, `enroll_endpoint_ontbreekt`, `rate_limited`,
  `koppelen_onderbroken`, `token_verlopen_na_60_min`, `ingetrokken_door_hub`; de dienst toont er een vaste NL-melding bij.
- Publieke status (statuspagina, `/readyz`, `GET /connector/v1/hub-link`) toont alleen een **witte lijst** van velden:
  `state`, `koppelen_bezig` (= `pending` ≠ `null`), `hub_url`, `service_id`, `via`, `linked_at`, `first_linked_at`,
  `keyset_fingerprint`, `service_token_last4`, `last_error` (code + vaste NL-melding). Nooit `service_token` of
  `pending.secret_sha256`.

### 3.6 Volgorde, eenmaligheid, idempotentie en herstart halverwege

**Dienst:**
1. First-start-init maakt `vault.key` en de Ed25519-identiteit (vóór enige enrollment; nooit overschrijven).
2. Schrijf `pending` (hash van het geheim) → `POST /enroll`.
3. Bij 200: alle controles van §3.3 → schrijf **in één atomaire stap** `state: gekoppeld` met token, pins,
   `linked_at`, (eerste keer) `first_linked_at`, `pending: null` en (env-token) de hash in
   `used_enrollment_token_sha256` → `GET {HUB_URL}/api/v1/services/self` met het nieuwe token (zet `confirmed_at`).
4. Definitief mislukt (401/404/413/422, ongeldig antwoord, verkeerde vingerafdruk, of 60 min na `pending.started_at`
   nog geen succes): `pending: null`, `last_error`, en voor een env-token de hash in `used_enrollment_token_sha256`.
   `state`, token en pins blijven zoals ze waren; het ingevulde Hub-adres van een mislukte poging wordt nergens bewaard.
5. Herstart:
   - `pending.kind = token` en het env-token heeft dezelfde hash: stap 2 opnieuw (toegestane herhaling, zie Hub).
     Ander of geen env-token: `pending: null`, `last_error: koppelen_onderbroken`; een nieuw env-token start een nieuwe
     poging.
   - `pending.kind = koppelcode`: het geheim is na een herstart weg → `pending: null`,
     `last_error: koppelen_onderbroken`; de gebruiker voert dezelfde code (binnen 60 min: toegestane herhaling) of een
     nieuwe code opnieuw in.
   - `state: gekoppeld` zonder `confirmed_at`: alleen het bevestigen uit stap 3 opnieuw.

**Hub:**
- Een token/koppelcode wordt bij het eerste geslaagde gebruik in **één transactie** als gebruikt gemarkeerd (met
  `used_with_key_thumbprint` = RFC 7638-thumbprint van `public_key_jwk`) en het service-token wordt uitgegeven.
- **Toegestane herhaling** (dienst crashte vóór het opslaan): zelfde token/code, zelfde `app_id`, zelfde
  `public_key_jwk`-thumbprint, het token/de code is nog niet verlopen (60 min na aanmaak), en het eerder via deze grant
  uitgegeven service-token is **nog nooit gebruikt** (`last_used_at` leeg). Dan trekt de Hub dat ongebruikte token in,
  geeft een nieuw uit en antwoordt 200 met `enrollment_replayed: true`. Anders 401 `invalid_enrollment`.
  (Dit voegt voor een afluisteraar niets toe: wie het verzoek op het LAN ziet, ziet ook het antwoord met het token.
  Herhaalt zo iemand het verzoek, dan trekt hij hooguit het token van de dienst in; de bevestiging uit stap 3 faalt dan
  zichtbaar (§3.8, `ingetrokken`). Zodra de dienst zijn token gebruikt — stap 3 — is de herhaling dicht.)
- Bestaat de dienst al (herinstallatie of opnieuw koppelen), dan worden bij een nieuwe geslaagde enrollment alle oude
  tokens van die registratie ingetrokken en blijft `service_id` gelijk.
- `GET /api/v1/services/self` (Bearer service-token) → `{"service_id","app_id","status","version","enrolled_at",
  "keyset_fingerprint"}`; dient als bevestiging (zet `last_used_at`).

### 3.7 Koppelen via de statuspagina

- Het koppelformulier op `GET /` bestaat **alleen zolang de dienst nog nooit gekoppeld is** (`first_linked_at` leeg).
  Daarna toont de statuspagina alleen de status (witte lijst §3.5) en "ontkoppelen of opnieuw koppelen gaat via de
  Hub". Er is op de statuspagina **geen** ontkoppelen, geen "lokale ontkoppelcode" en geen herkoppelen na intrekking.
- Velden: Hub-adres, koppelcode, **Hub-vingerafdruk** (verplicht; de Hub-UI toont koppelcode en vingerafdruk samen met
  een kopieerknop). CSRF (double-submit-cookie, `SameSite=Strict`, HttpOnly) + `Origin`-controle; vaste Nederlandse
  meldingen; het ingevulde Hub-adres van een **mislukte** poging wordt nergens bewaard.
- Rate-limit: max. **5 pogingen per 15 min per bron-IP** (adres van de TCP-verbinding; `X-Forwarded-For` en andere
  headers nooit gebruiken) én max. 20 pogingen per 15 min voor de hele dienst. Teller in het geheugen mag als de dienst
  één API-proces heeft; anders gedeeld (database). Overschrijding → vaste melding, geen verzoek naar de Hub.
- Restrisico (gemeld, ADR-0011): vóór de eerste koppeling kan iemand op het LAN de dienst aan een eigen "Hub" koppelen.
  Beperking: env-enrollment (geen wedloop) is de aanbevolen weg; de statuspagina toont het gekoppelde adres en de
  vingerafdruk; de dienst heeft dan nog geen data of rechten; herstel = opnieuw koppelen via de Hub (§3.8).

### 3.8 Opnieuw koppelen, ontkoppelen, intrekken, rotatie

- **Opnieuw koppelen (alleen via de Hub):** de Hub maakt een nieuw enrollment-token en zet het via de executor
  (`app.update`, nieuwe env `HUB_ENROLLMENT_TOKEN` + `HUB_KEY_FINGERPRINT`, eventueel nieuwe `HUB_URL`) of de beheerder
  vult het zelf in het TrueNAS-formulier in. Een dienst die een env-token ziet waarvan de hash **niet** in
  `used_enrollment_token_sha256` staat, probeert te koppelen, ook als hij al gekoppeld, ontkoppeld of ingetrokken is
  (wie het formulier kan wijzigen is TrueNAS-beheerder). Slaagt het, dan vervangen token, pins en `hub_url` de oude;
  mislukt het, dan blijft een bestaande koppeling ongewijzigd.
- **Ontkoppelen (Hub → dienst):** `POST /connector/v1/hub-link/unlink` (§6) met dienst-JWT of gebruikers-JWT `admin`
  + `Idempotency-Key` → `state: ontkoppeld`, service-token gewist, pins naar `previous_pins` (alleen audit, geen
  vertrouwen). Daarna weigert de dienst elke Hub-JWT (401 `not_linked`). Daarna trekt de Hub de registratie in. Herhaalt
  de Hub een `unlink` waarvan hij het antwoord niet kreeg, dan krijgt hij 401 `not_linked`; dat telt voor de Hub als
  geslaagd (de dienst is ontkoppeld).
- **Intrekken (Hub):** `POST /api/v1/services/{id}/revoke` (admin, `Idempotency-Key`) trekt registratie en tokens in.
  Krijgt een dienst van de Hub **401** op een aanroep met zijn service-token, dan controleert hij met
  `GET /api/v1/services/self`; geeft ook dat 401, dan zet hij `state: ingetrokken` (`last_error: ingetrokken_door_hub`),
  weigert vanaf dan elke Hub-JWT (fail-closed), houdt zijn eigen data en toont "ingetrokken — opnieuw koppelen via de
  Hub". Netwerkfouten, 5xx en 429 zijn nooit een intrekking.
- **Rotatie service-token:** de dienst roept `POST /api/v1/services/self/rotate` aan (Bearer huidig token) →
  `{"service_id","service_token","oude_tokens_geldig_tot"}`; schrijft het nieuwe token atomair en bevestigt het met
  `GET /api/v1/services/self`. Oude tokens blijven geldig tot **10 min na het eerste gebruik van het nieuwe token**, maar
  hooguit 24 uur na de rotatie (`oude_tokens_geldig_tot` = de bovengrens). Een herhaalde rotatie trekt eerder
  uitgegeven, nooit gebruikte nieuwe tokens in. Gebruikt een dienst een ouder token terwijl het nieuwste nog nooit
  gebruikt is (crash tijdens de rotatie), dan zet de Hub `Hub-Token-Rotation: required` op het antwoord en roteert de
  dienst opnieuw.
- **Rotatie aanvragen (alleen door een beheerder):** `POST /api/v1/services/{id}/rotate` (admin, `Idempotency-Key`)
  **vraagt** rotatie aan (`202`, geen token in het antwoord — een token aan de beheerder tonen heeft geen zin, hij kan
  het niet afleveren). Daarna zet de Hub `Hub-Token-Rotation: required` op elke geauthenticeerde dienst-aanroep tot de
  dienst geroteerd heeft; de dienst roteert dan binnen 5 min. Is een token ouder dan 180 dagen, dan toont de Hub-UI een
  melding met de knop "rotatie aanvragen"; de Hub roteert **nooit op eigen initiatief** en de AI kan rotatie niet
  aanvragen (geheimen roteren is R2, 03_RISICO_AUTONOMIE; §8).

### 3.9 Executor koppelen

- Zelfde enroll-endpoint met `app_id: "ai-server-manager-executor"` en een **koppelcode (30 min)** + vingerafdruk op de
  statuspagina van de executor (`http://<NAS>:30410`). De executor pint vooral de policy-sleutel (§8).
- Na het koppelen vult de gebruiker op dezelfde pagina de **TrueNAS-API-key met schrijfrechten** in. De executor test de
  key live (`auth.login_with_api_key` + rolcontrole), versleutelt hem in zijn eigen vault en toont alleen de laatste 4
  tekens. De Hub ziet de schrijfkey nooit.
- **Uitzondering op §3.7:** ontkoppelen/opnieuw koppelen en de key roteren mag op de executorpagina, maar alleen na het
  invoeren van een TrueNAS-API-key met schrijfrechten die de executor live verifieert (bewijs van TrueNAS-beheer).
  "Live verifiëren" = `auth.login_with_api_key` + rolcontrole tegen het NAS-adres en de TLS-certificaatvingerafdruk die
  bij de eerste koppeling op deze pagina zijn vastgelegd en bevestigd (zoals de Hub, ADR-0010: een key gaat nooit naar
  een onvertrouwd of gewijzigd certificaat). Een ander NAS-adres of certificaat opgeven telt niet als bewijs; dat
  wijzigen vraagt eerst een geldige key op het vastgelegde adres. Rate-limit zoals §3.7.

### 3.10 Credentials van andere apps

Credentials van bestaande apps (MediaGuard-`X-Api-Key`, MSO-machine-sleutel, my_house-token, TrueNAS-read-only-key, …)
voert de gebruiker in de Hub-UI in; opslag versleuteld, alleen vault-referentie (`vault://<scope>/<naam>`) in tabellen.
UI toont nooit de waarde terug (alleen laatste 4 tekens + datum). Logs en evidence worden geredigeerd.

## 4. Authenticatie en rollen

### 4.1 Gebruikers en noodlogin (break-glass)

- **Gebruikers** loggen in op de Hub (lokaal account, argon2id; optioneel OIDC via Authentik zodra B13 actief is).
  Rollen: `admin`, `operator`, `viewer`, `kind` (kinderprofiel). Sessiecookie (HttpOnly, SameSite=Strict, Secure achter
  HTTPS) + CSRF-token voor muterende webcalls.
- **Noodlogin in de Hub** (vereist voor B13-001; `home-control-hub` is register en adviseur, nooit poortwachter):
  - lokaal **noodaccount** (rol `admin`, vlag `break_glass`), argon2id-wachtwoord (≥ 20 tekens) **plus verplichte TOTP**
    (RFC 6238); werkt zonder Authentik/OIDC en zonder enige netwerkaanroep naar `home-control-hub` of Authentik;
  - alleen vanaf privé-bereiken (RFC 1918, 100.64.0.0/10, fc00::/7) op basis van het echte bron-IP van de verbinding
    (de Hub-webserver negeert vervalste `X-Forwarded-For`); nooit vanaf internet. Restrisico: welk bron-IP de container
    achter de Docker-portpublicatie van TrueNAS ziet (echt clientadres of het gateway-adres van het bridge-netwerk, dat
    zelf in RFC 1918 valt) is **NIET GEVALIDEERD (echte NAS)**; de zelftest hieronder toont daarom het bron-IP zoals de
    Hub het voor dat verzoek ziet, en de wizard waarschuwt als dat een gateway-adres van Docker lijkt;
  - sessie max. 60 min (instelbaar 5–240), niet verlengbaar; elke noodlogin → audit + incident `auth.break_glass.used`
    + melding; daarna **rotatieplicht** (wachtwoord + TOTP opnieuw) tot bevestigd. Het noodaccount zelf verloopt niet
    (geen lock-out precies bij nood); herbevestiging elke 90 dagen (melding, geen blokkade);
  - rate-limit zoals inloggen, geteld per (account, bron-IP) en nooit alleen per account (anders kan iemand op het LAN
    het noodaccount blokkeren); zolang er geen werkend noodaccount is, kan "OIDC verplicht" niet aan (geen SSO-only
    lock-out); lokale login van het noodaccount wordt nooit door OIDC uitgeschakeld;
  - instellingen van het noodaccount en "OIDC verplicht" wijzigt alleen een beheerder in de Hub-UI; het zijn geen
    `action_id`'s en de AI kan ze niet voorstellen (§8, 03_RISICO_AUTONOMIE);
  - de Hub mag het beleid van `home-control-hub` (bereiken, sessieduur) cachen, maar alleen om te **verscherpen**
    binnen deze grenzen; zonder cache gelden de standaardwaarden;
  - `POST /api/v1/auth/break-glass/selftest` (admin): deterministische controle (account, TOTP ingesteld, bereik met een
    testadres binnen en een documentatie-adres (RFC 5737) buiten, plus het bron-IP van dit verzoek zoals de Hub het
    ziet en of dat als privé telt) zonder in te loggen; geen mutatie, dus geen `Idempotency-Key` — "authenticator
    offline → break glass blijft testbaar".

### 4.2 Hub-JWT met gebruikerscontext

- `POST /api/v1/auth/service-jwt` geeft een kortlevende JWT voor één dienst. Header `{"alg":"EdDSA","typ":"JWT","kid"}`.
  Claims (alle verplicht): `iss:"hub"`, `aud:"<app_id>"`, `sub:"<gebruiker-UUID>"`, `token_use:"user"`,
  `roles:[…]` ⊂ {`admin`,`operator`,`viewer`,`kind`}, `iat`, `nbf`, `exp` (`exp − iat ≤ 120 s`), `jti` (UUID v4).
- Diensten met ACL (search-ai, jelly-leon-plugin) dwingen rol/ACL zelf af op basis van deze JWT. Klokspeling max. 30 s.
  Rol `kind` wint altijd van andere rollen in dezelfde JWT.

### 4.3 Hub → dienst: dienst-JWT (keuze 1.2)

- De Hub authenticeert zich bij een eigen dienst met een **door de Hub ondertekende dienst-JWT**, per aanroep nieuw:
  claims `iss:"hub"`, `aud:"<app_id>"`, `sub:"hub"`, `token_use:"hub_service"`, `roles:["service"]`,
  `service_id:"<UUID van de registratie>"`, `iat`, `nbf`, `exp` (`≤ 120 s`), `jti` (UUID v4); zelfde ondertekensleutel
  als §4.2 (gepind).
- De dienst geeft hiervoor principal `service:hub` met rol `service` (de rechten per dienst staan in zijn eigen ADR;
  `service` is nooit `admin`). Weigeren met 401 `token_use_invalid` als: `token_use` ontbreekt of onbekend is;
  `token_use:"user"` met rol `service`; `token_use:"hub_service"` met `sub ≠ "hub"`, `roles ≠ ["service"]` of
  `service_id` ≠ de eigen opgeslagen `service_id`.
- **Een inkomend `Bearer <eigen service-token>` wordt niet meer geaccepteerd** (401, reden `service_token_not_accepted`).
  Reden: het service-token gaat bij elke dienst → Hub-aanroep over het LAN; wie het afluistert, mag daarmee niet als de
  Hub optreden. De Hub bewaart ook geen terugleesbaar service-token (alleen hashes).

### 4.4 Dienst → Hub

`Authorization: Bearer <service-token>` op de Hub-routes voor diensten (`/api/v1/events/inbox`,
`/api/v1/services/self`, `/api/v1/services/self/rotate`, Hub-connector-lezen). De Hub vergelijkt de SHA-256 in constante
tijd, werkt `last_used_at` bij en kan het token zonder herinstallatie roteren of intrekken (§3.8). Scopes per dienst op
de Hub-connector volgen in een volgende contractversie (open punt, ADR-0011); tot dan geen geheimen via die routes.

### 4.5 Sleutelpinning, vingerafdruk en rotatie

- **Vertrouwensset** van een dienst = de gepinde sleutels uit `hub-link.json` (`pins.jwt` voor JWT's, `pins.policy` voor
  `ExecutionRequest`s). Een JWT met een `kid` buiten de gepinde set → 401 `unknown_key`. Vergelijking op de sleutel
  zelf (`x`), niet alleen op `kid`.
- `GET /api/v1/auth/jwks` blijft bestaan (diagnose, vergelijking), maar een via HTTP opgehaalde JWKS **voegt nooit
  vertrouwen toe** en trekt niets in. Een dienst mag strenger zijn (bv. weigeren als de Hub lang onbereikbaar is).
- **Thumbprint** = RFC 7638: `base64url(SHA-256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}'))`.
- **Sleutelset-vingerafdruk** (voor mensen): `SHA-256` over de UTF-8-tekst
  `"jl-hub-keyset-v1\njwt:" + join(",", thumbprints van jwks.keys, gesorteerd op bytewaarde) + "\npolicy:" + thumbprint(policy_public_key)`;
  daarvan de eerste 80 bit als Crockford-base32 (alfabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, bits van links naar rechts),
  16 tekens in groepen van 4 (`XXXX-XXXX-XXXX-XXXX`). Invoer vergelijken na normalisatie (hoofdletterongevoelig,
  `O→0`, `I/L→1`, streepjes/spaties negeren). **Testvectoren** (publieke sleutels; alleen voor tests):
  - jwt `x = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo` (RFC 8037 A.1; thumbprint
    `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`), policy `x = A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`
    (thumbprint `1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y`) → **`MEGG-8GFG-2E4Y-K2RQ`**;
  - zelfde plus een tweede jwt-sleutel `x = Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc` (thumbprint
    `AkXIZFzonb59ZmGwyKgi3H3BwMi6amevqdKQiLZhdtc`) → **`CYRC-JS8C-14AN-JR17`**.
- **Nieuwe Hub-sleutel** alleen via (a) **opnieuw koppelen** (§3.8) of (b) een **ondertekende rotatie**:
  `GET /api/v1/auth/key-rotations?after=<sequence>` (zonder authenticatie, zoals `jwks`: de handtekening is het bewijs;
  ook bestaande apps met een geplakte sleutelset, §2.3, kunnen dit lezen) →
  `{"items":[{"sequence":n,"statement":"<JWS compact>"}]}`. JWS-header `{"alg":"EdDSA","kid":"<gepinde kid>",
  "typ":"hub-key-rotation+jws"}`; payload `{"type":"hub_key_rotation","iss":"hub","sequence":n,"issued_at":"…Z",
  "purpose":"jwt|policy","add":[JWK],"retire":["kid"]}`. **Eén statement wijzigt precies één doel** en is
  EdDSA-ondertekend met een **op dat moment gepinde** sleutel van dat doel (jwt-wijzigingen door een jwt-sleutel,
  policy-wijzigingen door een policy-sleutel). `sequence` strikt oplopend over beide doelen samen, zonder gaten, in
  volgorde toepassen; een ongeldig of ontbrekend statement stopt het toepassen (incident, geen verdere statements);
  nooit de laatste sleutel van een doel intrekken. Na toepassen: `rotation_sequence` en `keyset_fingerprint` in
  `hub-link.json` bijwerken (§3.5). Dienst pollt ≤ elke 15 min; een JWT met een onbekende `kid` krijgt direct 401
  `unknown_key` en zet op de achtergrond een extra poll in gang (max. 1× per 30 s; het verzoek wacht daar niet op).
  De Hub ondertekent pas met een nieuwe sleutel als elke actieve dienst via `GET /connector/v1/hub-link` een
  `rotation_sequence` ≥ die van de rotatie meldt. Sleutels roteren is een beheerdershandeling (R2), nooit een
  AI-actie. **De Hub heeft nog geen sleutelrotatie gebouwd:** tot dan geeft het endpoint `{"items":[]}`, roteert de
  Hub zijn sleutels niet, en is rotatie = opnieuw koppelen.

### 4.6 `jti` en replaycache

- Elke Hub-JWT (§4.2, §4.3) heeft een `jti`; zonder `jti` → 401 `jti_missing`.
- De dienst houdt een **persistente** replaycache (gedeeld door alle processen, bv. tabel) op `(iss, jti)` tot `exp` +
  30 s. Een **mutatie** (POST/PUT/PATCH/DELETE) met een al gebruikte `jti` → 401 `token_replayed`, behalve een exacte
  herhaling (zelfde `jti`, methode, pad en `Idempotency-Key`), die de idempotency-laag met het opgeslagen resultaat
  beantwoordt. Lezen (GET/HEAD) mag binnen de levensduur vaker. Replaycontrole niet mogelijk → 503
  `replay_check_unavailable` (fail-closed). De Hub haalt dus per mutatie een nieuwe JWT.

### 4.7 Fail-closed

- Diensten zonder geldige auth → 401 `{code:"unauthorized", details:{reason}}`; vaste `reason`-waarden (Engels, voor
  machines; de `message` is NL) met deze betekenis:

  | `reason` | Wanneer |
  |---|---|
  | `not_linked` | `state` ≠ `gekoppeld` en ≠ `ingetrokken` (nooit gekoppeld of ontkoppeld) |
  | `revoked` | `state: ingetrokken` |
  | `service_token_not_accepted` | `Bearer` is een `svc_`-token in plaats van een JWT (§4.3) |
  | `unknown_key` | `kid` of sleutel niet in de gepinde set (§4.5) |
  | `token_expired` | `exp` (+ 30 s speling) verstreken |
  | `invalid_token` | geen geldige JWS, handtekening, `alg` ≠ `EdDSA`, `iss`, `aud`, `nbf`, `iat`, `exp − iat > 120 s` |
  | `token_use_invalid` | de controles van §4.3 op `token_use`, `sub`, `roles` en `service_id` |
  | `jti_missing` | geen `jti` (§4.6) |
  | `token_replayed` | `jti` al gebruikt voor een andere mutatie (§4.6) |

  Controlevolgorde: `state` → tokensoort → handtekening/`kid` → claims → `token_use` → `jti`. Nooit "open access" bij
  verlopen/ingetrokken credentials (EX16): connector wordt `unknown` + incident.
- Restrisico: verkeer op het LAN is (nog) HTTP; pins beschermen de echtheid van sleutels, niet de vertrouwelijkheid van
  tokens. HTTPS komt met B10/B13 (TLS-route) en verandert dit contract niet.

## 5. Gemeenschappelijke API-regels

- Prefix per dienst: Hub `/api/v1/…`; overige diensten hun eigen prefix (bv. `/integrations/v1`, `/catalog/v1`,
  `/lifecycle/v1`, `/search/v1`, `/voice/v1`, `/media/v1`) **plus** het connectorcontract (§6).
- JSON, UUID's, tijden ISO-8601 UTC (`…Z`), paginering met `cursor`/`limit` (max 200), `ETag` op muteerbare objecten.
- Fout: HTTP-status + body `{"code": "<snake_case>", "message": "<NL tekst>", "details": {…}, "trace_id": "<uuid>"}`.
- Mutaties: header `Idempotency-Key` (UUID) verplicht; herhaling met zelfde key → zelfde resultaat, géén tweede uitvoering.
  Uitgezonderd (eenmalig van aard of geven bewust een nieuw geheim): setup, inloggen/uitloggen, wachtwoord, JWT-uitgifte,
  enrollment-token/koppelcode maken, `services/enroll`, `services/self/rotate` (ADR-0006).
- **Verzoekgrootte:** een ASGI-laag **vóór routering en authenticatie** telt de body tijdens het lezen (ook zonder
  `Content-Length`/chunked) en breekt bij > 1 MiB (1 048 576 bytes) af met `413 {"code":"payload_too_large",
  "details":{"max_bytes":1048576}}`; een te grote `Content-Length` wordt direct geweigerd. Een hogere grens alleen per
  route, met ADR en eigen bovengrens. Geldt voor alle nieuwe diensten en voor nieuwe routes van bestaande apps.
- `GET /healthz` (proces leeft) en `GET /readyz` (afhankelijkheden ok) op elke dienst, zonder auth, zonder geheimen.
- OpenAPI: elke dienst exporteert `docs/openapi/<dienst>.openapi.json`; CI faalt bij drift.
- Tijdlimieten: uitgaande calls standaard 5 s connect / 15 s read, retry met exponentiële backoff + jitter, max 3.
  Uitgaande calls negeren proxy-omgevingsvariabelen tenzij de beheerder expliciet een proxy instelt.

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
| `GET /connector/v1/hub-link` | **nieuw (alleen eigen diensten):** koppelstatus, witte lijst uit §3.5 + `pinned_kids:{jwt:[…],policy:[…]}`, `rotation_sequence`; dienst-JWT of gebruikers-JWT `viewer`+ |
| `POST /connector/v1/hub-link/unlink` | **nieuw (alleen eigen diensten):** ontkoppelen (§3.8); dienst-JWT of gebruikers-JWT `admin`, `Idempotency-Key` |

Ontbrekende functie → `capability_unavailable`/`unknown`, **nooit gesimuleerd succes**. Bestaande apps: §2.3 — de Hub
gebruikt hun **bestaande** routes; nieuwe routes in die apps alleen als hun delta-matrix ze als ontbrekend markeert
(bv. het bewaakte schrijfpad `propose`/`apply` in my_house, de dunne connectorlaag in MSO, alleen-lezen connector en
`/healthz`/`/readyz` in MediaGuard).

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
- `event_type`-namen: `<domein>.<object>.<gebeurtenis>` (precies drie segmenten; bv. `app.health.changed`,
  `backup.run.failed`, `action.run.executed`, `energy.reading.recorded`, `network.device.discovered`,
  `flow.action.requested`, `auth.break_glass.used`).

## 8. Risicobeleid, voorstel, goedkeuring en executor

**Stroom:** (AI, gebruiker, Node-RED-flow of spraak) → `ActionProposal` → **policy-engine in de Hub** (deterministisch,
policybestanden `ai-server-manager/policy/*.yaml` ingebakken in de Hub- én executor-image, read-only, hash `policy_hash`
vastgelegd) → bij R0/R1 automatisch (allowlist, cooldown, anti-flap), bij R2/R3 **menselijke goedkeuring per gebonden
diff** → de Hub ondertekent `ExecutionRequest` (Ed25519, policy-sleutel) → de executor-app of de eigenaar-connector voert
uit → readback → audit.

**AI-runner:** draait in de Hub-image als **eigen uid 569** (`asm-ai`), alle andere Hub-processen als 568.
`/appdata/secrets` (0700) en de databasesocket zijn van 568; 569 kan er niet bij. De runner controleert bij de start zelf
dat hij geen geheim, geen signing key en de database niet kan lezen en **weigert te starten** als dat wel kan. Start de
container niet als root, dan start de runner niet (AI blijft uit). AI staat standaard uit; geen externe of betaalde
aanroepen zonder D09.

`ActionProposal`:
```json
{"idempotency_key":"<uuid>","action_id":"app.restart","target":{"host_id":"nas-primary","app_id":"uptime-kuma"},
 "parameters":{"grace_seconds":30},"reason":"service unresponsive","actor":{"type":"ai","id":"hub-ai"},
 "expected_version":"<digest|etag>","risk_claim":"R1","evidence_ids":["evt-123"],"expires_in_seconds":300}
```
- `risk_claim` van AI/flow wordt **genegeerd** voor de beslissing; de policy bepaalt `risk_class` (EX18). Onbekende
  `action_id` → geweigerd. Er bestaat **geen** `shell.exec`, `sudo`, `docker.*`-socket of vrije-tekstcommando.
- Koppelen, ontkoppelen en intrekken van diensten, rotatie van service-tokens en Hub-sleutels, en het beheer van het
  noodaccount zijn **geen** `action_id`'s: ze lopen alleen via beheerdersroutes van de Hub (admin + audit) en de AI kan
  ze niet voorstellen of uitvoeren (03_RISICO_AUTONOMIE: geen wijzigingen in beveiligingsbeleid of privileges door de
  AI; geheimen roteren is R2). Alleen het meegeven van `HUB_*`-env bij `app.install`/`app.update` loopt mee in die
  (R2-)actie.
- Blokkades (altijd, ook met goedkeuring): pool `DEGRADED`/onbekend of backup-gate rood → geen opslag-/massamedia-mutaties
  (EX11/EX12); boiler-schakelen (elke route; EX27); auto-delete van torrents/downloads/media/foto's/datasets; wijzigen van
  policy/rollen/privileges door AI; betaalde acties.

`Approval` (gebonden): `approval_id, request_id, preview_hash, resource_etag, policy_hash, risk_class, approved_by,
approved_at, expires_at (≤ 15 min), one_time_nonce, backup_checkpoint_id, action_scope`. Wijzigt één gebonden veld
(bv. app-digest na preview, EX19) → goedkeuring vervalt, nieuwe diff nodig. Nonce eenmalig → replay geweigerd (EX20).

`ExecutionRequest` = `{proposal, approval|null, policy_decision{risk_class, rule_ids, policy_hash}, issued_at, expires_at,
nonce}` + `signature` (Ed25519 over canonieke JSON, sleutels gesorteerd, UTF-8, geen spaties).
**Executor** controleert zelf opnieuw: handtekening tegen de **gepinde** policy-sleutel (§4.5), vervaltijd, nonce (eigen
SQLite), `action_id` in eigen allowlist, parameterschema + harde grenzen, policy-hash gelijk aan eigen read-only kopie,
risicoklasse ≥ eigen herberekening, precondities via readback (ETag/digest). Daarna uitvoering via TrueNAS JSON-RPC,
before/after-hash, readback, afwijking → stop + incident. Executor-allowlist v1:

| action_id | klasse (min.) | TrueNAS-API (versie-afhankelijk via `core.get_methods`) |
|---|---|---|
| `app.restart` / `app.stop` / `app.start` | R1 (niet-kritiek) / R2 (kritiek, netwerk, DNS, auth) | `app.redeploy` / `app.stop` / `app.start` |
| `app.install` | R2 | `app.create` als standaard Custom App (`ix-app`-waarden) of catalogusapp — nooit custom compose |
| `app.update` | R2 | `app.update` (nieuwe gepinde image-tag/waarden, §2.2) of `app.upgrade` (catalogusapp, vaste versie) |
| `app.rollback` | R2 (R3 bij DB-restore) | Custom App: `app.update` met de bewaarde **vorige waarden** (§2.2); catalogusapp: `app.rollback` naar een eerder geïnstalleerde versie; data via eigenaar/snapshot |
| `app.uninstall` | R2 (container-only; data blijft) | `app.delete` met `remove_ix_volumes=false` |
| `app.uninstall_data` | R3 (aparte bevestiging, nooit door AI aangeboden) | — standaard **niet** aangeboden |
| `zfs.snapshot.create` | R1 | `pool.snapshot.create` (25.10) / `zfs.snapshot.create` (25.04) |
| `zfs.snapshot.clone_to_sandbox` | R1 (alleen naar sandbox-dataset) | `pool.snapshot.clone` / `zfs.snapshot.clone` |
| `notification.send` | R0 | via Gotify-adapter (geen TrueNAS) |

Een plan met een vastgezette catalogusversie die niet meer in de catalogus staat, geeft blokkade `version_unavailable`
(§2.2). TrueNAS-API: JSON-RPC 2.0 over WebSocket `wss://<NAS>/api/current` (versie-endpoint `/api/v25.10.x` waar
beschikbaar), `auth.login_with_api_key`. Methodenamen en -schema's per versie ontdekken (`core.get_methods`,
`system.version`); geen oude REST-API. Hub-api gebruikt een **read-only** key (aparte TrueNAS-gebruiker met
alleen-lezen-rol); alleen de executor heeft een key met schrijfrechten, en die key voert de gebruiker in op de
executorpagina (§3.9).

## 9. Manifeststandaard (B08-001, eigenaar `appstore-en-fork`)

`manifest_version: "1"` YAML met o.a.: `app_id`, `name`, `owner_repo`, `category`, `description_nl`,
`version`, `install: {method: custom_app | catalog_app}`, bij `custom_app`: `image: {repository, tag, digest}` (één
image; tag ≠ `latest`; digest verplicht voor upstream-images; voor eigen GHCR-images vult de release-CI de digest; de
vertaling naar het formulier zet `tag` als `<tag>@<digest>`, §2.2) + `custom_app: {storage, env, resources, gpu, run_as,
timezone, restart_policy, portal}` (het formulier van de standaard Custom App; **geen** `ports` meer), bij `catalog_app`:
`catalog: {train, app, version}` + `values`; een `compose`-veld is **verboden**,
`parameters` (getypt, met `source: wizard|dataset_picker|secret|generated|default`, nooit voorbeeldwaarden als echte waarde),
`storage: [{name, mount, kind: config|data|media|scratch, required_dataset_role}]`,
`network: {ports, host_network:false, host_network_reason}` — **`network.ports` is de enige bron** voor de poorten van het
formulier, `privileges: {privileged:false, cap_add:[], devices:[], gpu:none|intel_render}` + `privilege_reason`,
`healthcheck`, `backup: {db_export, snapshot_datasets, rpo, rto}`, `dependencies`, `sso: oidc|native|none`,
`risk: {install, update, uninstall}`, `upgrade: {migrations, tag_only_rollback_safe: bool}`, `decisions_required: [D01…]`,
`docs: [I-/A-doc]`, `validation_status`.

Wijzigingen in 1.2:
- `network.joins_platform_network` **vervalt** (apps delen nooit een Docker-netwerk, §2). Overgang: validator meldt
  `deprecated_field` (waarschuwing) bij `false`, fout `platform_network_not_supported` bij `true`; in `--strict`
  (release-CI) is elke `deprecated_field` een fout.
- `custom_app.ports` **vervalt**; de vertaling bouwt de formulierpoorten uit `network.ports`. Overgang: aanwezig en
  gelijk → `deprecated_field`; aanwezig en anders → `ports_inconsistent` (fout). `custom_app.portal.port` en
  `healthcheck.port` verwijzen naar een naam in `network.ports`.
- **GPU als optionele parameter:** `privileges.gpu` is het **maximum** (`none` of `intel_render`; `intel_render` vereist
  `privilege_reason` en `decisions_required` met D08). `custom_app.gpu` is `none`, `intel_render` of
  `{param: <naam>}` naar een parameter met nieuw type **`gpu`** (waarden `none|intel_render`, `source: wizard`,
  `decision: D08`, `required: false`); ontbreekt de waarde → `none`. `custom_app.gpu ≠ none` mag alleen als
  `privileges.gpu = intel_render`. De wizard biedt `intel_render` alleen aan als D08 een render-node via de TrueNAS-API
  heeft gemeten. Vertaling: `intel_render` → `resources.gpus.use_all_gpus: true` (volgens de bronnen in
  `appstore-en-fork/docs/TRUENAS_APP_VALUES.md` geeft dat alle niet-NVIDIA-GPU's en kan het formulier daar niet per GPU
  kiezen; NIET GEVALIDEERD (echte NAS); de preview meldt dat de app dan elke render-GPU krijgt). Eén specifieke
  render-node via `privileges.devices` is een open punt (B03/P4, toegang voor 568 tot de render-groep onbekend).

Weigeren vóór uitvoering (EX47): compose/YAML-installatie, `privileged`, Docker-socket, hostpad `/`, `/mnt` zonder
dataset, `/etc`, `/var/run`, `/root`, host network zonder reden, `latest`, ontbrekende digest, GPU zonder D08-meting.

## 10. Repo-indeling nieuwe Python-diensten

```
apps/api/            pyproject.toml, src/<pakket>/…, alembic/, tests/{unit,integration}
apps/web/            (alleen ai-server-manager) Next.js PWA + Playwright (360/390/768/1440), ontwerptaal §13
apps/executor/       (alleen ai-server-manager; eigen image)
policy/              (alleen ai-server-manager) policy YAML + hash
deploy/allinone/     Dockerfile (alles-in-één), supervisor, healthcheck, first-start-init (zie MSO als voorbeeld)
deploy/truenas/      CUSTOM_APP.md: exacte velden van het standaard Custom App-formulier (NL), geen YAML; tag met
                     digest (§2.2); publieke image, registry-login alleen als fallback (§2.1)
deploy/dev/          compose.yaml alleen voor ontwikkeling/CI (expliciet géén installatiemethode)
deploy/manifest/     <app_id>.manifest.yaml (manifeststandaard §9, install.method custom_app)
.env.example         alle variabelen gedocumenteerd, géén echte waarden (voor ontwikkeling; de Custom App heeft geen
                     verplichte variabelen; HUB_URL/HUB_ENROLLMENT_TOKEN/HUB_KEY_FINGERPRINT zijn optioneel)
docs/openapi/        geëxporteerde OpenAPI
docs/adr/            ADR-0001… (keuzes en waarom)
docs/platform-v2/    pakketdocs + DELTA_MATRIX.md (bestaande repos) + EVIDENCE.json
tests/e2e/           dienst-E2E met simulators (de Hub-simulator volgt §3.3 exact)
.github/workflows/   ci.yml (ruff, mypy, pytest + postgres-service, alembic up/down, openapi-drift, pip-audit,
                     alles-in-één image bouwen en starten met healthcheck en rooktest), release.yml (tag → GHCR push,
                     SBOM, digest in release/digests.json)
Makefile, VERSION (start 0.1.0), CHANGELOG.md, geen licentie toevoegen zonder vraag aan de gebruiker
```
Container: start als root alleen voor eigenaarschap van `/appdata`, daarna alle processen — ook PID 1 — als 568:568
(Hub-AI-runner 569), zonder capabilities, met zelf gezette `PR_SET_NO_NEW_PRIVS` (het formulier zet geen no-new-privileges en geen
cap_drop, §2.2), geen Docker-socket, healthcheck; resource-limieten worden in het formulier/de API-waarden gezet.

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
  `NIET GEVALIDEERD (hardware)`/`NIET GEVALIDEERD (account)`/`NIET GEVALIDEERD (Mac/Xcode)`. Meerdere waarden uit deze
  lijst mogen, gescheiden door `"; "` (bv. `Sim-getest; NIET GEVALIDEERD (echte NAS)`); toelichting hoort in
  `opmerking`. `Gereed`/`Geslaagd` alleen na echte acceptatie op de NAS — dat kan in deze bouwomgeving niet en wordt dus
  **nooit** gezet.
- Testmatrix (EX01–EX50): simulator-resultaat in `validatie` ("Sim-geslaagd"/"Sim-mislukt"); `status` blijft
  `Bezig` of `Geblokkeerd` tot een echte run.
- `ai-server-manager/tools/excel/update_excel.py` voegt alle EVIDENCE.json samen in
  `docs/platform-v2/08_EXCEL/TrueNAS_V2_Uitvoering_en_Afvinken.xlsx` (kolom **Validatie** toegevoegd).

## 12. Commit- en pushregels

Branch `ccr-c133d7a0-kuz1cv` in elke repo; geen PR's; geen force-push; kleine logische commits per fase/onderdeel,
NL-commitberichten, afgesloten met **de attributieregel(s) die de lopende sessie voorschrijft** (in deze programmaronde
één `Co-Authored-By:`-regel); **geen vaste sessielink** meer. Geen modelnaam of model-ID in code of docs. Vóór elke push
`git pull --rebase`; na elke push de GitHub Actions-run volgen tot groen of de blokkade exact melden.
`ai-factory` wordt niet aangeraakt. Bestaande integriteit, rollback en monitoring in MediaGuard/MSO/my_house nooit
dubbel bouwen, vervangen of uitschakelen. Release-tags `v0.1.0` voor nieuwe repos pas na groene CI (besluit 6).

## 13. Ontwerptaal

- **Eén eigen ontwerptaal** op **Tailwind CSS 4 + shadcn/ui + lucide** (iconen). Bron van waarheid:
  `ai-server-manager/docs/platform-v2/ONTWERPTAAL.md` + `ai-server-manager/design/ontwerptaal/` (tokens, componenten,
  voorbeelden). Die worden **apart door de design-agent** geleverd; dit contract beschrijft alleen reikwijdte en
  werkwijze, niet de ontwerptaal zelf. Zolang ze ontbreken, start geen UI-ombouw.
- **Reikwijdte:**
  - Hub-UI (`ai-server-manager/apps/web`): **alle** schermen; de P0-UI wordt omgezet.
  - Statuspagina's van de nieuwe diensten (`home-control-hub`, `appstore-en-fork`, `jelly-leon-platform`,
    `zoeken-en-persoonlijke-ai`, executor): **framework-vrije CSS** afgeleid uit **dezelfde tokens** (geen JS-framework,
    geen externe CDN; werkt zonder JavaScript).
  - **Uiterlijk** van MediaGuard, MSO en my_house: alleen het uiterlijk; functies, routes, gebruikersreizen en API's
    blijven gelijk (§2.3).
  - **Niet:** Jelly Leon (web en clients) houdt de Jellyfin-vormgeving met alleen de zichtbare naam "Jelly Leon".
- **Werkwijze:** elke UI-bouwstap krijgt **vooraf een ontwerpstap** (design-agent: schermontwerp en componentkeuze binnen
  de ontwerptaal) en **achteraf een ontwerpreview** (design-agent: afwijkingen van de ontwerptaal, toegankelijkheid
  WCAG 2.1 AA, 360/390/768/1440, licht/donker). De design-agent beslist zelfstandig; het resultaat wordt de gebruiker
  achteraf getoond. Bestaande eisen blijven: NL-teksten, waarde + eenheid + bron + laatst bijgewerkt, `unknown` nooit
  groen, aanraakdoelen ≥ 44 px, toetsenbord en screenreader.
