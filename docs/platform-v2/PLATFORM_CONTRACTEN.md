# Platformcontracten — TrueNAS Home Platform V2 (bouwcontract voor alle repos)

Versie: `contracts 1.3` · Peildatum 2026-11-10 · Eigenaar: `lvos04/ai-server-manager` (bron van waarheid).

- **Kopieën:** elke repo heeft in `docs/platform-v2/` een **byte-gelijke** kopie van dit bestand en van
  `CONTRACT_1.3_CONFORMITEIT.md`, met een drifttest die de sha256 van beide tegen de bron (vaste bron-commit) controleert.
  Een repo past een kopie nooit aan, ook niet om een link te repareren; een nieuwe kopie overnemen is een stap van de
  orkestratie. Bij verschil wint deze repo.
- **Verwijzingen** naar bestanden in deze repo staan als tekst `ai-server-manager:<pad>` (of als absolute GitHub-URL),
  nooit als relatieve link: in een kopie zou zo'n link kapot zijn. `CONTRACT_1.3_CONFORMITEIT.md` staat in dezelfde map.
- **Wat elke repo moet veranderen** om aan 1.3 te voldoen, met bestanden en moment (NU of een latere fase):
  `CONTRACT_1.3_CONFORMITEIT.md`. Keuzes en motivering: `ai-server-manager:docs/adr/ADR-0027-contract-1-3.md` (1.3),
  `ai-server-manager:docs/adr/ADR-0028-review-contract-1-3.md` (correcties uit de review van 1.3),
  `ai-server-manager:docs/adr/ADR-0011-contract-1-2.md` en `ai-server-manager:docs/adr/ADR-0012-review-contract-1-2.md`
  (1.2). Invoer van 1.3: `ai-server-manager:docs/platform-v2/CONTRACT_1.3_KANDIDATEN.md` (groepen A01–A36).
- Dit document maakt de pakketvoorstellen (`01_ARCHITECTUUR/02`, `03`, `07`, `08`) concreet zodat alle repos samenwerken.
  Het zegt **niets** over de echte NAS: alle NAS-gegevens (D01–D18) zijn onbekend tot de gebruiker ze in de
  onboarding-wizard invult of de wizard ze via de TrueNAS-API meet. Voorbeeldwaarden (IP-adressen, poolnamen zoals in
  oude installatiedocs, versies, GPU-modellen) zijn nooit echte waarden.

## Wijzigingslog 1.2 → 1.3 (2026-11-10)

Invoer: de 36 contractgroepen (klasse a) uit de inventaris (151 meldingen uit ronde 2, de ADR's, reviews en EVIDENCE van
alle repos sinds 1.2, B03 hoofdstuk 18 en ADR-0016…0020, de besluiten van de gebruiker en de P1-uitbreidingen van de
Hub). De groepen b (al opgelost), c (repowerk) en d (afgewezen) wijzigen het contract niet; de groepen e (Peil) gaan naar
Peil 1.1.1 (§13). Tussen haakjes de groep uit de inventaris.

**Besluiten van de gebruiker en bestaande apps**
1. §1.1 bijgewerkt: tien repos zijn publiek; MediaGuard verhuist naar een nieuwe publieke repo met schone historie;
   licentie **GPL-3.0** voor de eigen repos (nieuw besluit 8; §10 "geen licentie" vervalt); my_house 0.2.0 is
   gepubliceerd. Nieuw §1.2: open besluiten met wat tot dan geldt (A01).
2. Eigen app-ID's van de clients: "nooit een ID, accounttype, authority, permissie, `app_search_suggest_*`-waarde of
   sharedpref-naam gelijk aan die van een officiële app" vervangt "nooit `org.jellyfin.*`"; de gekozen ID's staan erbij
   (bevestiging gevraagd); Swiftfin zet de bundle-id op twee plekken (§1.1 besluit 1, §2.3 regel 6) (A02).
3. **Emby** is de bestaande mediaserver van de gebruiker (alleen lezen, nooit schrijven, blijft terugval). MediaGuard
   volgt Emby én Jelly Leon tegelijk; `GET /api/v1/mediaserver/status` krijgt **erbij** `servers[]`; authenticatie per
   server. **HARDE EIS**: kijkgeschiedenis en MediaGuard-voortgang blijven altijd beschikbaar (§2.3 regels 2, 3, 7, 8)
   (A03).
4. Jelly Leon volgt de upstream-conventies (`/config`, `/cache`, `/health`); Hub-koppeling van de plugin zonder
   enrollment (JL4); 12.x-authenticatie; 1 MiB per route in het Jellyfin-proces (§2.3 regel 9, §5) (A04).
5. MediaGuard-acties via de Hub zijn **gereserveerd** (niet toegestaan) tot besluit BG-05 én sleutelscopes in
   MediaGuard (P3-02); Jelly Leon als MediaGuard-viewerclient na BG-04 (§2.3 regels 2–3, §8) (A05).
6. Optionele model-apps: app `mt` in de apptabel, één producent per modelsoort, GPU alleen na een D08-meting en nooit op
   de GPU die voor AV1 of live-transcodes is toegewezen; adresregels voor model-apps (§1, §2) (A06).
7. "Terug naar de Hub" in een bestaande app haalt het adres uit een niet-geheime instelling; `HUB_URL` start daar geen
   enrollment (§2.3 regel 5) (A36).

**Beveiliging, koppelen en authenticatie**
8. Noodlogin: `100.64.0.0/10` telt standaard **niet** als privé; een beheerder kan het toestaan (§4.1) (A07).
9. `HEALTHCHECK`- en `docker exec`-processen wisselen als eerste handeling naar 568 met no_new_privs; bij een start als
   root wordt de bounding set geleegd; de rooktest controleert de healthcheck apart (§2.2) (A08).
10. Geheimen die een app niet zelf maakt: verplichte geheime waarden van catalogusapps maakt de Hub (vault) en geeft de
    executor alleen in de `values` mee; het OIDC-clientgeheim van de Hub zet de beheerder zelf over (§3.1) (A10).
11. Adresregels: alleen canonieke IP-vormen; een ongeldige `base_url` is nooit reden om een enroll-verzoek te weigeren;
    `HUB_*` zijn gereserveerd en geen manifestparameters (§3.2, §3.3, §9) (A11).
12. `hub-link.json`: onleesbaar = fail-closed (`koppelstatus_onleesbaar`, geen formulier); open codelijst met vaste
    aanvullingen; toegestane extra velden; lezers accepteren elke `1.x` (§3.5) (A12).
13. Herkomst van formulier-POST's op statuspagina's: `Referrer-Policy: same-origin`, exacte `Origin` (`null` → 403),
    `Sec-Fetch-Site`, browsertest met negatieve gevallen (§3.7, §3.9) (A13).
14. Koppelformulier: elke POST telt als poging; koppelen bezig → 409; meldingen alleen bij een echte poging; invoer nooit
    afkappen; één logregel per poging; **`Host`-beperking tegen DNS-rebinding** (§3.7) (A14).
15. "Gereed" op een statuspagina = `/readyz` in orde én gekoppeld en bevestigd; `/readyz` hangt niet van de koppeling af
    (§3.7, §5, §13) (A15).
16. JWT: `aud` is precies één string; reason-tabel aangevuld (geen header, geen `kid`); elke POST/PUT/PATCH/DELETE
    verbruikt de `jti`; authenticatie vóór schemavalidatie van de body (§4.2, §4.3, §4.6, §4.7) (A16).
17. Sleutelset-vingerafdruk over **alle** policy-sleutels (nieuwe testvector `HN69-2PHK-XV2D-X85W`; 1.2-vectoren
    blijven gelijk); `rotation_sequence` in het enroll-antwoord, `schema_version` `"1.3"`; oude tokens van een bestaande
    registratie pas intrekken bij het eerste gebruik van het nieuwe; "nooit de laatste sleutel" verduidelijkt (§3.3,
    §3.6, §4.5) (A17).
18. Dienst → Hub: vaste leesscopes per dienst (`inventaris.lezen`, `catalogus.lezen`, `besluiten.lezen`); zonder scope
    403 `scope_ontbreekt` (§4.4) (A18).
19. SSO via OIDC in de Hub: groep → rol in de Hub, sessieduur, https voor issuer en discovery, vaste regel voor het
    terugkeerpad (§4.1) (A27).

**API, connector en events**
20. Optionele Hub-routes voor eigen diensten: `POST /api/v1/monitoring/heartbeat` en `POST /api/v1/logs` (nieuw §6.1)
    (A19).
21. Uitzonderingen op `Idempotency-Key` aangevuld, met een statische test per repo (§5) (A20).
22. Eén foutcatalogus; 401 alleen voor authenticatie; paginering over een momentopname; invoer nooit eerst afkappen (§5)
    (A21).
23. Connector-health: totaal = de slechtste check; vaste checknamen `database`, `worker`, `jobs`, `hub_link` (§6) (A22).
24. Versheid: elke meting heeft `observed_at`; standaard `max_age` 900 s, per capability op te geven in `discover`;
    verouderd = `unknown` (nieuw §6.2) (A23).
25. Events: de grenzen van de Hub-inbox, vaste werkwoorden voor probleem en herstel, domeinen per eigenaar en een vaste
    lijst `service.*`-events (§7) (A24).
26. Ernst: vijf Peil-woorden in `payload.ernst` met een vaste afbeelding op de drie Hub-niveaus (§7) (A25).
27. `sso.access.revoked`/`sso.access.changed` dragen `issuer` en de OIDC-`sub`; de Hub koppelt op `(issuer, sub)` (§7)
    (A26).
28. Acties via de eigenaar-connector (`sso.*`, gereserveerde MediaGuard-acties) en back-upbevestiging door de Hub (§8)
    (A28).
29. TrueNAS-alleen-lezen: `core.subscribe` voor de event source `reporting.realtime` (§8) (A29).

**Installatie en manifest**
30. Begrip *standaard Custom App* = de catalogusapp `ix-app` (`custom_app: false` in `app.query`); derden-apps met één
    container standaard als Custom App, een catalogusapp met reden (`install.reason`) (§1, §2, §9) (A09).
31. Manifest: `accepted_findings`, `backup.db_export: stopped_snapshot`, documentsoort `kind: checklist`,
    `post_install_checks` en `container_port: same_as_host` (§9) (A30).
32. Adoptie van bestaande apps: documentsoort `kind: adoption`, eigenaar, statuswoorden (§9) (A31).
33. Monitorplan per app (`healthcheck.monitor`); de beheerder bevestigt het in Uptime Kuma (§9) (A32).

**Bewijs, ontwerp en kopieën**
34. EVIDENCE: nieuwe validatiewaarden `Intel-iGPU-getest (ontwikkelmachine)` en `Niet getest`; regels per blad; een
    `NIET GEVALIDEERD` in `blokkade` staat ook in `validatie`; ID's voor contractpunten en reviews (§11) (A33).
35. Ontwerpreview: dezelfde testmatrix en normen als ONTWERPTAAL §12 (320–1440, WCAG 2.2 AA) (§13, §10) (A34).
36. Kopieën byte-gelijk met drifttest; geen relatieve links naar deze repo (kop, §10) (A35).

**Keuzes bij het vaststellen** (motivering in ADR-0027):
- K1. De `Host`-beperking tegen DNS-rebinding (A14) is **aangenomen**: wie een statuspagina via een eigen domeinnaam
  opent, koppelt via env-enrollment (aanbevolen) of via de Hub, of opent de pagina via het IP-adres.
- K2. `servers[]` komt **naast** de bestaande velden van `GET /api/v1/mediaserver/status` (bestaande clients breken niet).
- K3. Bij een start als root **moet** de bounding set leeg (strenger dan het voorstel "aanbevolen"); bij "Custom User
  568" kan dat niet en mag `CapBnd` de Docker-standaardset zijn.
- K4. Log-sink: invoer `bericht` ≤ 8000 tekens (langer → 422), opslag na schoning hooguit 2000 tekens, gemarkeerd als
  ingekort; dat is opslag, geen afkappen van invoer vóór de controle.
- K5. Paginering met momentopname geldt voor lijsten die uit een meting komen (inventaris, catalogus, zoekresultaat);
  gewone tabellen met een stabiele sorteersleutel hebben die niet nodig.
- K6. Connector-itemtype `backup.self` van de Hub alleen voor gebruikers; `besluiten.lezen` krijgt standaard geen enkele
  dienst (gemeten op 2026-11-10: geen dienst leest besluiten van de Hub).
- K7. Het enroll-antwoord zegt `schema_version: "1.3"`; gemeten: alle diensten accepteren elke major-1-versie.
- K8. Foutcatalogus: naast de vaste codes staat alleen 423 `item_in_playback` (Jelly Leon, B03) als eigen statuscode;
  andere module-eigen situaties gebruiken `details.reason` of een eigen code onder 409.
- K9. ID's voor contractpunten in EVIDENCE: `C1.3-<REPO>-<nn>` zoals in `CONTRACT_1.3_CONFORMITEIT.md`.

### Correcties uit de onafhankelijke review (2026-11-10, blijft `contracts 1.3`; ADR-0028)

Het contract was nog nergens gekopieerd of gebouwd; deze correcties horen daarom bij 1.3 zelf. Ze lossen
tegenstrijdigheden met bestaande code, het B03-plan en het contract zelf op en kiezen steeds de veiligste lezing.
- RV1. Emby (§2.3 regel 3): "nooit schrijven in Emby" geldt voor de Hub, de executor, de AI, Jelly Leon en de
  overnametool; de **bestaande** Emby-koppeling van MediaGuard (bibliotheek bijwerken, afspeeltest, sessies) blijft
  werken (bestaande integriteit, Δ-MG-DUAL); geen nieuwe schrijfroute naar Emby.
- RV2. HARDE EIS (§2.3 regel 7): (a) geldt ook voor een upgrade die de database van een mediaserver migreert (10.11 →
  12.x en latere Jelly Leon-updates met upstream-migraties, zoals B03 §10.9); terugzetten = vorige image én snapshot;
  (b) zonder upgradebewijs ook geen MediaGuard-update via de Hub of de executor.
- RV3. Privacy (§2.3 regel 2): de Hub-adapter van MediaGuard volgt de veldenwitte lijst van de viewerclient (nooit
  `sessions`, `hold.reason`, `actions`, `tests`, `last`), zodat er via MediaGuard geen kijkgedrag in de Hub komt.
- RV4. Jelly Leon-plugin (§2.3 regel 9): de gekopieerde sleutelset bevat een `service_id`, zodat de controle van §4.3
  ook daar eenduidig is.
- RV5. `HUB_URL` voor my_house (§3.2, §2.3 regel 5): de vertaling zet alleen `HUB_URL`, nooit een token of
  vingerafdruk; geen manifestparameter.
- RV6. Onleesbaar koppelbestand (§3.5): vervangen bij de eerste schrijfactie van een poging met een nieuw env-token,
  vóór het verzoek aan de Hub; `/readyz` blijft 200; HTTP-uitkomst per vaste `last_error`-code.
- RV7. Koppelformulier (§3.7): ook een POST op een al gekoppelde dienst telt als poging (409 `al_gekoppeld`).
- RV8. Sleutelrotatie (§4.5): apps met een geplakte sleutelset tellen mee; de Hub ondertekent niet met een nieuwe
  sleutel zolang zo'n app de oude set gepind heeft.
- RV9. Controlevolgorde (§4.7): rol en `Idempotency-Key` pas ná de authenticatie.
- RV10. `Idempotency-Key` (§5): formulier-POST's van statuspagina's zijn uitgezonderd (met reden); andere
  uitzonderingen alleen met ADR.
- RV11. Log-sink (§6.1): `op` is een tijd met tijdzone, `trace_id` een UUID.
- RV12. Events (§7): niet gekoppeld = niet pushen en geen pogingen tellen (ook `unlinked`/`revoked`); de eigenaar van
  een event is (`source_app`, domein), zodat `media` van Jelly Leon en van MediaGuard niet botsen.
- RV13. Besluit 3 (§1.1): de overstap van MediaGuard naar de nieuwe publieke repo is gemeten uitgevoerd (repo publiek,
  archief privé). Of het GHCR-pakket `mediaguard-core` aan de nieuwe repo gekoppeld en publiek is, kon de review niet
  lezen (geen leesrecht op pakketten): dat blijft open (§1.2), en tot dan geen nieuwe MediaGuard-release.

## Eerdere wijzigingen

### Wijzigingslog 1.1 → 1.2 (2026-11-09)

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

#### Correcties uit de onafhankelijke review (2026-11-09, blijft `contracts 1.2`; ADR-0012)

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
  alles via de TrueNAS-API vanuit de platform-UI. `docker compose` mag alleen voor ontwikkeling, CI en de integrale
  E2E-testomgeving. Begrippen (TrueNAS en manifest): §2 "Begrippen".
- **Apps van derden:**
  - met **meerdere containers** (Authentik, Immich, …): de **officiële TrueNAS-catalogusapp** waar die bestaat (versie
    vastgezet, zie §2.2 over verdwijnende versies);
  - met **één container**: standaard een **Custom App met één gepinde image** (tag + digest), als 568:568 waar de image
    dat toestaat — ook als er een catalogusapp bestaat (geen afhankelijkheid van verdwijnende catalogusversies). Een
    catalogusapp alleen met een reden in het manifest (`install.reason`, §9). Restrisico, vermeld in het manifest: zonder
    no-new-privileges in het formulier kan een setuid-programma in een upstream-image binnen de container root worden.
- **Eén alles-in-één image per repo** (zoals MSO `deploy/allinone`): eigen ingebouwde PostgreSQL 16 (alleen unix-socket,
  geen netwerkpoort), API, worker en — alleen bij de Hub — de web-UI, onder een kleine procesbewaker; één datamap
  `/appdata`, één poort, healthcheck (§2.2), start als root alleen om `/appdata` aan 568:568 te geven en draait daarna
  alles als 568 (uitzondering: de AI-runner van de Hub als 569, §8). Geen wachtwoorden of geheimen in het formulier;
  geheimen maakt de app zelf bij eerste start in `/appdata/secrets` (uitzonderingen: §3.1). Bestaande apps: §2.3.
- Geen `latest`-tags. Elke image op exacte versie, base-images bovendien op `@sha256:`-digest.
- Geen shell/root voor AI, geen `sh -c`/`sudo`-endpoint, geen Docker-socket in een container, boiler nooit schakelen,
  geen betaalde API-overage (Claude alleen binnen inbegrepen credits, harde stop op 0 overage).
- **Lokale modellen** (Ollama-LLM, faster-whisper STT, Piper TTS, lokaal embeddingmodel, vertaalmotor `mt`) zijn
  **optionele apps, standaard uit**, elk een eigen app buiten de images van de afnemers:
  - **één producent per modelsoort:** één spraakherkenning voor B03-008, B07-004, F4 (taal) en F6 (transcripten); één
    embeddingproducent. Tot besluit BG-06 blijft de bestaande producent de enige (zoeken-en-persoonlijke-ai maakt de
    embeddings; Jelly Leon niet) en komt er geen tweede;
  - model-apps draaien **standaard zonder GPU**; een GPU alleen na een D08-meting van de render-node, en nooit op de GPU
    die D08/BG-27 toewijst aan MediaGuard-AV1 of live-transcodes. Dit contract noemt geen GPU-modellen als feit over de
    NAS; welke GPU's er zijn, meet D08. Geen torch, transformers of ctranslate2 in de jelly-leon-image;
  - adressen van model-apps: alleen loopback, RFC 1918 of ULA (`fc00::/7`; niet `100.64.0.0/10`), IP-controle per
    verbinding, geen redirects; het geheim van de model-app staat in de geheimenmap van de afnemer. Zonder model-app:
    klassieke terugval en `503 engine_unavailable` of `501 capability_unavailable`, nooit gesimuleerd succes.
- UI-taal Nederlands. Elke kaart: waarde + eenheid + bron + **laatst bijgewerkt**. Onbekend is `unknown`, nooit groen;
  een verouderde meting is `unknown` (§6.2). Ernst kent platformbreed de vijf Peil-woorden (§7). Uiterlijk volgens de
  platform-ontwerptaal (§13).
- Jellyfin-fork: technische identiteit/API blijft "Jellyfin" (clientcompatibiliteit); alleen de zichtbare naam is
  "Jelly Leon". De upstream-licentie (GPL-2.0) en upstream-credits blijven staan.
- Licentie van de eigen repos: **GPL-3.0** (besluit 8).

### 1.1 Besluiten van de gebruiker (vast)

| # | Besluit | Gevolg in dit contract |
|---|---|---|
| 1 | Android: **eigen applicationId**, naast de officiële app installeerbaar (android `applicationId`; androidtv daarnaast `app_id` en `app_search_suggest_authority`). iOS/tvOS: eigen bundle-id. (2026-11-09) | §2.3 regel 6. **Regel:** nooit een ID die gelijk is aan die van een officiële app (upstream of store), en geen accounttype, authority, permissie, `app_search_suggest_*`-waarde of sharedpref-naam (`backup_content.xml`/`backup_rules.xml`) die gelijk is aan die van de officiële app; CI bewaakt dit. **Gekozen ID's** (volgens de bouwopdracht van 2026-11-09 door de gebruiker gekozen; **bevestiging gevraagd**, §1.2): android `org.jellyfin.mobile.jellyleon`, androidtv `org.jellyfin.androidtv.jellyleon`. iOS/tvOS (Swiftfin): voorstel `org.jellyfin.swiftfin.jellyleon`, te bevestigen **vóór de eerste Apple-registratie** (NIET GEVALIDEERD (Mac/Xcode)). Na de eerste verspreiding verandert een ID niet meer. |
| 2 | Swiftfin 1.6.1 blijft. De **server gaat vóór P4 naar de nieuwste stabiele Jellyfin 12.x (.NET 10)** (jelly-leon + jelly-leon-web), zodat B03 direct op 12.x wordt gebouwd. (2026-11-09) | Aparte upgradefase P4-0. Identiteit "Jellyfin", zichtbare naam "Jelly Leon", GPL-2.0 blijven. De exacte 12.x-versie wordt in de upgradefase opnieuw vastgesteld (`git ls-remote --tags`). Android-clients op 12.x-compatibiliteit controleren. |
| 3 | Repos en GHCR-images **publiek**, pas na een scan van de volledige historie op geheimen en privégegevens. **Uitgevoerd op 2026-11-09:** tien repos zijn publiek. `media-guard-ultimate` niet: de huidige repo wordt `media-guard-ultimate-archief` (privé, ongewijzigd bewaard) en een nieuwe publieke `lvos04/media-guard-ultimate` met schone historie volgt na de Peil-ronde. **Gemeten op 2026-11-10** (GitHub-API, alleen lezen): `lvos04/media-guard-ultimate` is nu een nieuwe publieke repo met één startcommit ("publieke start (schone historie)") en `media-guard-ultimate-archief` is privé; daarmee zijn alle 11 repos publiek. | §2.1: installatie zonder registry-login. De zichtbaarheid van elk GHCR-pakket wordt per pakket gecontroleerd (de besluittekst noemt alleen de repos). Tot de nieuwe MediaGuard-repo en haar images gepubliceerd zijn, is installeren van MediaGuard zonder registry-login NIET GEVALIDEERD; tot het GHCR-pakket aan de nieuwe repo gekoppeld is, geen nieuwe MediaGuard-release (§1.2). |
| 4 | `JL_SYNC_PUSH_TOKEN` (upstream-sync): nog **open**. | Geen tokens in repo's; sync-push blijft uit tot het besluit valt (§1.2). |
| 5 | my_house 0.2.0-release mag opnieuw. **Uitgevoerd:** my_house 0.2.0 is gepubliceerd. | — |
| 6 | Release-tags `v0.1.0` voor de nieuwe repos (images naar GHCR met digests) zodra hun CI groen is. | Toegestaan; niet in een contractronde zelf taggen. |
| 7 | Eén eigen **ontwerptaal** op Tailwind 4 + shadcn/ui + lucide (Peil). | §13. |
| 8 | Licentie van de eigen repos: **GPL-3.0** (volledige tekst in `LICENSE`). Forks houden hun upstream-licentie (jelly-leon en jelly-leon-web GPL-2.0, jelly-leon-clients per subtree); upstream-credits blijven. (2026-11-09) | §10 (`LICENSE`). Ook de nieuwe MediaGuard-repo. |
| 9 | **Emby** is de huidige mediaserver van de gebruiker; de kijkgeschiedenis staat daar. Emby blijft de terugval tot de gebruiker hem zelf verwijdert. **HARDE EIS:** alle kijkgeschiedenis en de MediaGuard-voortgang blijven altijd beschikbaar. MediaGuard volgt Emby én Jelly Leon tegelijk. BG-01: Jelly Leon 12.x via `Authorization: MediaBrowser Token=…`, legacy-auth blijft uit. (2026-11-09) | §2.3 (rij Emby, regels 2, 3, 7, 8). Bron: `ai-server-manager:docs/adr/ADR-0020-kijkgeschiedenis-altijd-beschikbaar-en-emby-overname.md`, B03 §10.9. |
| D10 | Bestaande mini-pc: videoapp/andere projecten, **geen** Home Hub-diensten. | Status **Ingevuld** (vast besluit); niets van het platform wordt op de mini-pc gepland. |

### 1.2 Open besluiten (tot het besluit geldt de veiligste stand)

| Besluit | Waar | Tot het besluit geldt |
|---|---|---|
| BG-05: mag de Hub MediaGuard laten zoeken of herstellen (met goedkeuring per actie)? (vóór golf 3) | §2.3 regel 3, §8 | geen MediaGuard-acties via de Hub of Jelly Leon; alleen deeplinks (`handmatig_in_mediaguard`) |
| BG-04: eigen MediaGuard-sleutel (viewer) in Jelly Leon? (vóór golf 1) | §2.3 regel 2 | geen sleutel in Jelly Leon; MediaGuard-status daar `onbekend` |
| BG-06/BG-18: welke app levert spraak en embeddings, en in welke repo komt `mt`? (vóór P5) | §1, §2 | geen tweede producent; `mt` wordt niet gebouwd |
| `100.64.0.0/10` (Tailscale/CGNAT) toestaan voor de noodlogin? | §4.1 | niet toegestaan |
| Bevestiging van de Android-ID's (bron: alleen de bouwopdracht) en van de Swiftfin-bundle-id | §1.1 besluit 1 | ID's gebouwd, niet verspreid; geen Apple-registratie |
| GHCR-pakket van MediaGuard koppelen aan de nieuwe publieke repo | §1.1 besluit 3 | geen nieuwe MediaGuard-release |
| `JL_SYNC_PUSH_TOKEN` (besluit 4) | §1.1 | sync-push uit |
| BG-22 en de overige B03-besluiten per fase/golf | `ai-server-manager:docs/platform-v2/02_BOUWPLANNEN/B03_BESLUITEN.md` | de stand die daar per besluit staat |

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
| open (BG-06/BG-18) | `mt` (vertaalmotor, OPUS-MT via CTranslate2; optioneel, standaard uit) | eigen gepinde image; het model wordt eenmalig buiten de NAS omgezet, met herkomst (revisie, converterversie, commando) en sha256 | per image | voorstel bij installatie |

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

**Begrippen:** *standaard Custom App* = het formulier van TrueNAS, technisch de catalogusapp **`ix-app`** (in `app.query`:
`custom_app: false`). Het TrueNAS-veld `custom_app: true` betekent een **compose-app** (*Install via YAML*) en valt altijd
buiten het beleid (de Hub toont zo'n app als `custom_compose`). `install.method: custom_app` in het manifest (§9) betekent
uitsluitend het formulier (`ix-app`). *Catalogusapp* = een andere app uit de officiële TrueNAS-catalogus.

**Installatie via de API** (executor, `app.install`): TrueNAS `app.create` voor een standaard Custom App met de
formulierwaarden (image, ports, storage, env, resources, gpu) — in TrueNAS 24.10+ is dat de catalogus-app `ix-app`
(`catalog_app: "ix-app"`, `train: "stable"`, exacte `version`) met `values`; methodenaam en waardenschema per versie
ontdekken (`core.get_methods`) en tegen de officiële docs controleren — of `app.create` met `catalog_app`/`train`/`version`
voor een catalogusapp. **Nooit** `custom_compose_config`/`custom_compose_config_string`/`custom_app=true`.
Bronnen en zekerheid per feit: `jelly-leon-platform/docs/platform-v2/TRUENAS_APP_API.md`.

### 2.1 Publieke images en registry-login

- Na de scan uit besluit 3 zijn de repos en GHCR-pakketten **publiek** (MediaGuard: na de overstap naar de nieuwe repo).
  Installatie (handmatig én via de API) gebruikt dan **geen** registry-login. Zolang de zichtbaarheid van een pakket niet
  echt publiek is (per pakket gecontroleerd), is installeren van die image op een echte NAS **NIET GEVALIDEERD** (en voor
  een privé-pakket geblokkeerd).
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
  Docker-capabilities en zonder no-new-privileges. Een image die als root start om `/appdata` aan 568 te geven, gebruikt
  daarvoor `CHOWN`, `FOWNER`, `DAC_OVERRIDE`, `SETUID` en `SETGID` (alle in de Docker-standaardset; nooit om extra
  capabilities vragen). Daarom moet **elke image zelf** na de eigenaarschapsstap: (1) de **bounding set legen**
  (`PR_CAPBSET_DROP` voor elke capability; mislukt dat, dan stopt de start met een Nederlandse melding in de app-log,
  zoals bij een niet-schrijfbare `/appdata`), (2) volledig naar 568:568 wisselen (`setgroups([])`, `setgid`, `setuid`;
  geen ambient capabilities), (3) `prctl(PR_SET_NO_NEW_PRIVS, 1)` zetten vóór de eerste `execve` van een dienstproces.
  Dit geldt voor **alle** processen, ook PID 1: na de eigenaarschapsstap draait er geen enkel proces meer als root. Een
  init (bv. `dumb-init`) die als root blijft draaien voldoet niet; óf de bewaker is zelf PID 1, ruimt zombies op en
  wisselt zelf (zoals de Hub), óf de init wordt pas ná de wissel gestart.
- **Healthcheck en `docker exec`:** Docker start `HEALTHCHECK`- en `docker exec`-processen als de gebruiker van de image,
  buiten de procesboom van PID 1 (PPid 0): zonder "Custom User" dus als root, met de standaard-capabilities en zonder
  no_new_privs. Daarom: (1) het healthcheckcommando staat in **exec-vorm** (geen `sh -c`, geen shell-vorm) en is een
  klein programma dat als **eerste** handeling — bij root eerst de bounding set legen — `setgroups([])`, `setgid(568)`,
  `setuid(568)` en `prctl(PR_SET_NO_NEW_PRIVS, 1)` uitvoert (of al 568 is) en pas daarna iets controleert; mislukt de
  wissel, dan exit 1 (rood). (2) Het korte venster vóór de wissel is een gemeld restrisico. (3) Een eigen
  `docker exec` voor diagnose is geen dienstproces en valt buiten de rooktest.
- **Rooktest:** draait de container **zonder** `--security-opt no-new-privileges` en zonder `--cap-drop` (zoals het
  formulier) en controleert voor **elk** proces in de procesboom van PID 1 (inclusief PID 1; niet de eigen
  `docker exec`-shell) `Uid 568` (AI-runner 569), `CapEff`, `CapPrm` en `CapAmb` `0000000000000000`, `NoNewPrivs 1` en —
  bij een start als root — `CapBnd 0000000000000000`. De **healthcheck apart**: hetzelfde commando met een controlevlag
  meldt na de wissel `Uid 568`, `CapEff 0`, `CapPrm 0` en `NoNewPrivs 1`.
  De image werkt ook als de gebruiker "Custom User 568" aanvinkt: dan geen eigenaarschapsstap en kan de bounding set niet
  geleegd worden (`CapBnd` mag dan de Docker-standaardset zijn; `CapEff`, `CapPrm`, `CapAmb` 0 en `NoNewPrivs 1` blijven
  verplicht); is `/appdata` niet schrijfbaar, dan een Nederlandse melding in de app-log en healthcheck rood — nooit stil
  doorstarten.
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
  (`catalog.update` `preferred_trains`) is R2. Of een doelversie nog beschikbaar is, kan een dienst bij de Hub vragen
  (scope `catalogus.lezen`, §4.4).

### 2.3 Bestaande apps (MediaGuard, MSO, my_house, Jellyfin/Jelly Leon, Emby)

Bestaande apps zijn **geen** nieuwe diensten: ze houden wat werkt en krijgen alleen hiaten uit hun `DELTA_MATRIX.md`.
Bestaande integriteit, rollback en monitoring nooit dubbel bouwen, vervangen of uitschakelen.

| App (repo) | Custom App / image | Poorten (container → hostvoorstel) | Opslag en database | Eigen UI | Foutformaat bestaande routes |
|---|---|---|---|---|---|
| MediaGuard (`media-guard-ultimate`: nieuwe publieke repo met schone historie; oude historie in `media-guard-ultimate-archief`, privé; §1.1 besluit 3) | `mediaguard` · `ghcr.io/lvos04/mediaguard-core:<versie>-aio` (naam blijft; het pakket moet aan de nieuwe repo gekoppeld worden, §1.2) | 30080 (UI/API) + fork-API's 38989/38990 (Sonarr) en 37878/37879 (Radarr), elk gelijk | SQLite-WAL; mounts `/config` (appdata), `/work` (staging/quarantaine), `/data` (media + downloads, één dataset voor hardlinks) | Next.js-web + Android | eigen (ongewijzigd) |
| MSO (`media-source-optimizer`) | `media-source-optimizer` · `ghcr.io/lvos04/media-source-optimizer:<versie>` | 38081 → 38081 | ingebouwde PostgreSQL, één `/appdata` (alles-in-één bestaat al) | eigen web | `{detail, code, correlation_id}` |
| my_house (`my_house`) | `smart-home` · `ghcr.io/lvos04/my_house:<versie>` (alles-in-één, **nieuw in P3**) | 8080 → 8088 (bestaande QR-koppelingen bewaren adres mét poort) | ingebouwde PostgreSQL, één `/appdata` (P3) | React/Vite-PWA + Android | `{"detail":{"code","message"}}` |
| Jellyfin / Jelly Leon (`jelly-leon`, `jelly-leon-web`) | `jelly-leon` · `ghcr.io/lvos04/jelly-leon:<versie>` | 8096 → 30460; staat er al een stock-Jellyfin (onbekend tot D07 het meet), dan blijft die ongemoeid op zijn eigen poort | Jellyfin-eigen database in `/config`, cache `/cache` (regel 9) | jelly-leon-web + clients | Jellyfin-API (ongewijzigd) |
| **Emby** (bestaande mediaserver van de gebruiker; geen platform-repo) | bestaande installatie; installatiewijze, appnaam, image en versie onbekend tot D07 ze meet | onbekend tot D07 | eigen database (**kijkgeschiedenis**, regel 7) | eigen UI | Emby-API (ongewijzigd) |

Regels:
1. **Eigen poorten, eigen database, eigen UI, eigen foutformaat op bestaande routes.** Het contractformaat (§5),
   `Idempotency-Key`, paginering/ETag en de 1 MiB-grens gelden alleen op **nieuwe** routes (`/connector/v1/*`, `/healthz`,
   `/readyz`, en wat de delta-matrix als ontbrekend markeert). Bestaande clients (web, Android, MSO↔MediaGuard) mogen niet
   breken. Jelly Leon: regel 9.
2. **Geen enrollment in v1.** De **Hub-adapter leeft in de Hub** (`ai-server-manager`) en gebruikt de **bestaande
   routes** met een **gescopete sleutel** die de gebruiker in de eigen UI van de app aanmaakt en in de Hub-UI invoert
   (vault, §3.10). Per app:
   - MediaGuard: bestaande `X-Api-Key`, sleutel `hub` met rol **viewer** voor het read-model; operator-rechten (alleen
     noodstop aan, één herzoek) pas nadat sleutels scopes hebben (P3-02).
   - **MediaGuard volgt meerdere mediaservers tegelijk** (Δ-MG-DUAL en Δ-MG-AUTH; exitcriterium van P4-0): elke ingestelde
     mediaserver (Emby én Jelly Leon) wordt gevolgd; kijkpauze zodra iemand op één ervan kijkt; afspeeltest en
     NL-ondertitels per server. Authenticatie **per server**: Emby `X-Emby-Token`; Jelly Leon 12.x
     `Authorization: MediaBrowser Token=…` (legacy-auth blijft uit, BG-01). De Emby-koppeling wordt op geen enkel moment
     onderbroken; pas na de controlelijst "Emby verwijderen" (B03 §10.9.2) laat MediaGuard Emby los.
     `GET /api/v1/mediaserver/status` krijgt **erbij** een lijst `servers: [{server_id, kind, label, connected,
     hold: {active}, …}]` met één element per server; de bestaande velden op het hoogste niveau (`kind`, `url`,
     `connected`, `sessions`, `hold`, …) blijven bestaan voor bestaande clients (regel 1) en beschrijven de eerste
     ingestelde server. **Privacy:** de Hub-adapter volgt op deze route dezelfde veldenwitte lijst als de viewerclient
     van Jelly Leon hieronder (nooit `sessions`, `hold.reason`, `actions`, `tests` of `last` opslaan, loggen of tonen;
     alleen aantallen en `hold.active`): zo komt er ook via MediaGuard geen kijkgedrag (titels, gebruikers, apparaten)
     van Emby of Jelly Leon in de Hub (regel 9).
   - **Jelly Leon als MediaGuard-client** (alleen na besluit BG-04, §1.2): naast de Hub mag Jelly Leon een eigen
     MediaGuard-sleutel met rol **viewer** hebben, ingevoerd in Jelly Leon zelf. De rol wordt gecontroleerd met
     `GET /api/v1/auth/me` bij elke start en elk uur; een andere rol → sleutel niet opslaan en niet gebruiken. Alleen een
     routewitte lijst (GET + het niet-muterende `POST /api/v1/audio/inspect`) en de veldenwitte lijst van B03 §10.5 (nooit
     `sessions`, `hold.reason`, `actions`, `tests`, `last`); ruwe antwoorden nooit loggen of bewaren.
   - MSO: heeft nu alleen sessie-auth; P3 bouwt een **machine-sleutel met scopes** (`read`; later `changes:approve`
     met `expected_preview_hash` + `Idempotency-Key`). Geen menselijk wachtwoord/CSRF-sessie in de Hub.
   - my_house: koppelcode met rol **viewer** uit de my_house-web-app, ingewisseld via de bestaande
     `POST /api/v1/pairing/redeem`; een viewer-token kan niets bedienen (403).
   - Jellyfin/Jelly Leon: geen gescopete API-sleutels in Jellyfin; de Hub-adapter leest alleen openbare routes
     (`/System/Info/Public`, `/health`) en wat een eigen **niet-admin** Jellyfin-gebruiker mag zien, op 12.x met
     `Authorization: MediaBrowser Token=…` (`EnableLegacyAuthorization` blijft uit, BG-01). Een admin-API-sleutel wordt
     niet gebruikt. De Hub-koppeling van de B03-plugin: regel 9.
   - **Emby:** alleen lezen met een API-sleutel die de beheerder invoert (Hub-UI, vault §3.10, of de overnametool van
     B03-015); de client stuurt alleen `GET` (elke andere methode weigert hij vóór het netwerk). Gebruikt voor D07 en de
     overname (B03-015).
3. **Schrijven door de Hub** naar een bestaande app gaat alleen via de door die app ondersteunde goedkeuringsroute
   (MSO change sets, my_house `propose`/`apply` met ondertekend `ExecutionRequest` (§8), MediaGuard alleen noodstop
   **aan**) en is altijd gebonden aan `preview_hash`/ETag + `Idempotency-Key`. Waar een bestaande app een ondertekend
   `ExecutionRequest` verifieert, plakt de beheerder de **publieke** Hub-sleutelset (`jwks` + `policy_public_key`, in de
   Hub-UI kopieerbaar) in de eigen beheer-UI van die app; de app berekent de sleutelset-vingerafdruk (§4.5) en toont
   die ter vergelijking met de Hub-UI, en pint daarna de policy-sleutel. Zonder gepinde sleutel →
   `501 capability_unavailable`.
   - **Gereserveerde MediaGuard-acties** (Δ-CONTRACT-MG) — **niet toegestaan tot besluit BG-05 van de gebruiker én tot
     MediaGuard sleutelscopes heeft (P3-02):** `mediaguard.wanted.search`, `mediaguard.quarantine.release_check`,
     `mediaguard.file.reacquire`, `mediaguard.quality.report` en `mediaguard.subtitles.search`, elk minimaal R2 met
     goedkeuring per actie, uitgevoerd door MediaGuard zelf via een gescopete route (eigenaar-connector, §8).
     `mediaguard.quarantine.restore` is R3 en wordt nooit door de AI voorgesteld. Tot dan antwoorden Hub en Jelly Leon met
     `handmatig_in_mediaguard` en een deeplink — nooit gesimuleerd succes. (In B03 heten de acties zonder voorvoegsel; het
     voorvoegsel voorkomt botsingen in de allowlist, Δ-HUB-1.)
   - **Emby:** de Hub, de executor, de AI, Jelly Leon en de overnametool (B03-015) schrijven nooit in Emby (alleen
     `GET`, regel 2) en het platform stopt, updatet of verwijdert Emby nooit. De **bestaande** koppeling van MediaGuard
     met Emby (bibliotheek laten bijwerken na een vervanging, afspeeltest, sessies lezen) is bestaande integriteit van
     MediaGuard en blijft ongewijzigd werken (regel 1, Δ-MG-DUAL); er komt geen nieuwe schrijfroute naar Emby bij.
     Emby blijft de terugval tot de gebruiker hem zelf verwijdert na de controlelijst "Emby verwijderen" (B03 §10.9.2);
     app stoppen en data verwijderen blijven aparte stappen (APP-02/A4).
4. **Installatie:** bestaande apps worden als standaard Custom App met één alles-in-één image geïnstalleerd
   (MediaGuard/MSO: bestaat; **my_house: alles-in-één Custom App-image in P3**, plus herstelprocedures zonder terminal:
   updaten/terugdraaien via het formulier, wachtwoord vergeten, sleutelwissel/oude hoofdsleutel uploaden via de UI).
   Compose-/YAML-/`install.sh`-routes blijven alleen voor ontwikkeling/CI en worden zo gemarkeerd. Emby wordt door het
   platform niet geïnstalleerd of beheerd; in de appstore is Emby een adoptie-item (§9, `owner.soort: derde`).
5. **Uiterlijk:** MediaGuard, MSO en my_house krijgen het uiterlijk van de platform-ontwerptaal (§13); functies,
   routes, gebruikersreizen en clientcontracten blijven gelijk. Jelly Leon valt erbuiten.
   **"Terug naar de Hub"** (O-11) in een bestaande app haalt het Hub-adres uit een niet-geheime instelling van die app:
   het eigen instellingenregister (MediaGuard `system.hub_url`, MSO `systeem.hub_url`) of, als de app geen register
   heeft, de optionele omgevingsvariabele `HUB_URL` (my_house; bij installatie via de Hub zet de vertaling hem, §3.2).
   Validatie volgens §3.2; ongeldig of leeg ⇒ geen link.
   Nooit afleiden uit `Referer`, de URL of andere invoer. In een bestaande app start `HUB_URL` **geen** enrollment
   (regel 2).
6. **Clients van de fork** (`jelly-leon-clients`): eigen Android-`applicationId` (androidtv ook `app_id`,
   `app_search_suggest_authority` en `app_search_suggest_intent_data`, plus de sharedpref-namen in de back-upregels) en
   eigen iOS/tvOS-bundle-id volgens de regel en de ID's van §1.1 besluit 1, geregistreerd als patch; Kotlin-`namespace` en
   technische identiteit "Jellyfin" blijven. iOS: de bundle-id staat in `swiftfin/XcodeConfig/Shared.xcconfig` **én** in
   `project.pbxproj` (doel "Swiftfin iOS", configuratie Release, die wint); de patch wijzigt beide en CI controleert de
   effectieve build-instelling. Wat er precies verandert staat in `jelly-leon-clients` ADR-0004.
7. **HARDE EIS (besluit 9 van de gebruiker): kijkgeschiedenis en MediaGuard-voortgang blijven altijd beschikbaar.** Dat
   is alle kijkgeschiedenis (gezien-status, hervatpunten, favorieten, beoordelingen, onthouden spoorkeuzes, gebruikers,
   rechten) en de voortgang van MediaGuard.
   (a) Geen overstap van mediaserver en geen upgrade die de database van een mediaserver migreert (Emby → Jelly Leon,
   een bestaande Jellyfin → Jelly Leon, 10.11 → 12.x, en elke latere Jelly Leon-update met upstream-migraties; B03
   §10.9) zonder vóór/na-rapport per gebruiker en uitdrukkelijk akkoord van de gebruiker op elk verschil, ook op
   verschillen door upstream-migraties; de bestaande installatie blijft ongewijzigd als terugval; terugzetten = vorige
   image én snapshot samen, nooit alleen de image.
   (b) Elke MediaGuard-release, ook de eerste uit de nieuwe publieke repo, bewijst een upgrade op een **gevulde database
   van de vorige versie** zonder gegevensverlies; UI-rondes wijzigen geen datamodel. Zonder dat bewijs geen release en
   geen update op de NAS, ook niet via de Hub of de executor (hoe de Hub het bewijs ziet, legt een ADR in P3 vast; tot
   dan voert de Hub geen MediaGuard-update uit).
   (c) Geen platformactie, ook niet met goedkeuring, schrijft rechtstreeks in de database van Emby, Jelly Leon of
   MediaGuard.
8. **Emby-exportarchief (B12):** het blijvende JSON-exportarchief van de Emby-kijkgegevens (met sha256) is een
   B12-dekkingsitem (Δ-HUB-3). Zonder bevestigde dekking geen "Emby verwijderen".
9. **Jelly Leon volgt de upstream-conventies:** data in `/config` en `/cache` (geen `/appdata`), gezondheid op
   `/health` en `/System/Info/Public`; `/healthz` en `/readyz` zijn voor Jelly Leon niet verplicht. Nieuwe routes van de
   B03-plugin (`/media/v1/*`, `/connector/v1/*`) volgen §5 en §6, met deze afwijking: de 1 MiB-grens geldt in het
   Jellyfin-proces per route (`RequestSizeLimit(1048576)` plus een `Content-Length`-controle) en dus pas **na**
   authenticatie, tot de `IStartupFilter`-spike (B03-017) slaagt (ADR-0016); hogere grenzen alleen per route met ADR en
   eigen bovengrens.
   **Hub-koppeling van de plugin (JL4, ADR-0017):** geen enrollment. De beheerder plakt de publieke Hub-sleutelset in het
   Jellyfin-dashboard en vergelijkt de vingerafdruk (§4.5); daarna gelden §4.2–§4.7 (persistente `jti`-cache, `kind`
   wint). De gekopieerde set (stap "Hub-sleutelset kopiëren", Δ-HUB-JL) bevat naast `jwks`, `policy_public_key` en de
   vingerafdruk ook een `service_id`: de UUID die de Hub voor deze Jelly Leon-instantie (`app_id` `jelly-leon`) in zijn
   register maakt. De plugin pint die mee; in dienst-JWT's (§4.3) is dat de eigen opgeslagen `service_id`. Zonder pin
   401 `not_linked`. De Hub pollt `GET /connector/v1/events` (geen push: Jelly Leon heeft geen
   service-token). Naar de Hub gaan alleen aantallen en ondoorzichtige ID's: geen titels, bestandsnamen, paden,
   item-ID's, gebruikers- of apparaatnamen of IP-adressen. `propose`/`apply`/`rollback` geven in v1 501
   `capability_unavailable`.

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
- **Geheimen die een app niet zelf maakt:**
  - (a) **Catalogusapps met verplichte geheime waarden** in hun `values` (bv. Authentik `db_password`/`secret_key`): bij
    installatie via de API genereert de Hub ze (CSPRNG, ≥ 256 bit), bewaart ze versleuteld in zijn vault
    (`vault://app/<app_id>/<parameter>`) en geeft de executor ze alleen in de `values` van `app.create`/`app.update` mee
    (onderdeel van de R2-actie). Ze staan nooit in een manifest, preview-diff, auditdetail, log of evidence (alleen
    "gegenereerd" met datum). Het manifest markeert zo'n parameter met `source: generated` en `secret: true` (§9). Bij een
    handmatige installatie vult de gebruiker ze zelf in TrueNAS in (een geheim van de gebruiker, zoals het registry-token
    van §2.1). De Hub leest de app-configuratie nooit terug (de configuratie kan geheimen bevatten).
  - (b) **Geheimen die een dienst voor de Hub aanmaakt** (OIDC-`client_secret` van de Hub-client, B13-002): §4.4 blijft
    gelden — geen geheimen via Hub-connector, items of events. Tot een eigen ADR in P2 een eenmalige, versleutelde
    overdracht vastlegt, kopieert de beheerder het geheim zelf uit Authentik naar de Hub-UI (vault; alleen de laatste
    4 tekens zichtbaar).

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

**Adresregels (vorm):** een IPv4-adres alleen als `a.b.c.d` (vier decimale delen 0–255, zonder voorloopnul); een host
van alleen cijfers, punten en hex-delen die daar niet aan voldoet (bv. `127.1`, `2130706433`, `0x7f000001`, `010.0.0.1`,
`0`), is ongeldig; IPv6 alleen tussen `[]`; één punt aan het eind van een naam telt niet mee (`localhost.` =
`localhost`). Bij een hostnaam gelden de verboden bereiken ook voor het opgeloste adres, bij elke verbinding.

Dezelfde adresregels gelden voor het Hub-adres dat op de statuspagina wordt ingevuld (§3.7) en voor elk ander
Hub-adres in het platform (§2.3 regel 5). Bij alle aanroepen naar de Hub volgt de dienst **nooit** een redirect (3xx =
storing, niet volgen) en negeert hij proxy-omgevingsvariabelen (§5). Zonder `HUB_KEY_FINGERPRINT` is een
env-enrollment *trust on first use*: de statuspagina en de Hub-UI tonen daarna beide de vingerafdruk, zodat de
beheerder ze kan vergelijken.

`HUB_URL`, `HUB_ENROLLMENT_TOKEN` en `HUB_KEY_FINGERPRINT` zijn **geen manifestparameters** en staan niet in
`custom_app.env` (§9): de vertaling voegt ze bij `app.install`/`app.update` toe als de Hub koppelt (§8). Uitzondering
zonder koppeling: my_house leest `HUB_URL` alleen voor "Terug naar de Hub" (§2.3 regel 5); daar voegt de vertaling
alleen `HUB_URL` toe, nooit een token of vingerafdruk, en ook daar is het geen manifestparameter.

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
| `base_url` | string \| null | ja (mag `null`) | alleen informatief — de Hub belt de dienst via zijn eigen register (D03 + hostpoort uit `app.query`) en toont een afwijking als waarschuwing. De dienst stuurt `base_url` alleen als die voldoet aan `http(s)://host[:poort][/pad]`, ≤ 512 tekens en de adresregels van §3.2, anders `null`. De Hub weigert een enroll-verzoek **nooit** om de waarde van `base_url`: een string die niet aan de regels voldoet, bewaart hij als `null`, met een waarschuwing in de Hub-UI (alleen een ander type dan string/null → 422) |
| `public_key_jwk` | object | ja | publieke Ed25519-JWK `{"kty":"OKP","crv":"Ed25519","x":"<43 base64url = 32 bytes, canoniek>","kid":"<RFC 7638-thumbprint>"}`; `kid` optioneel, maar indien aanwezig gelijk aan de RFC 7638-thumbprint (§4.5); `d`, `use`, `alg` of andere velden → 422. De Hub bewaart `{kty, crv, x, kid=thumbprint}` |

```json
{"app_id":"home-control-hub","enrollment_token":"enr_<43 tekens>","version":"0.1.0",
 "base_url":null,"public_key_jwk":{"kty":"OKP","crv":"Ed25519","x":"<43 tekens>","kid":"<thumbprint>"}}
```

**Antwoord `200 OK`** (ook bij een toegestane herhaling, §3.6), header `Cache-Control: no-store`:

| Veld | Type | Betekenis |
|---|---|---|
| `schema_version` | string | `"1.3"` |
| `service_id` | string (UUID) | registratie in de Hub; de dienst bewaart hem en controleert hem in dienst-JWT's (§4.3) |
| `app_id` | string | echo |
| `service_token` | string | `^svc_[A-Za-z0-9_-]{43}$`; dienst → Hub (§4.4); geen vaste vervaltijd |
| `token_type` | string | `"Bearer"` |
| `hub_issuer` | string | `"hub"` |
| `jwks` | object | `{"keys":[JWK,…]}`, ≥ 1 sleutel, elk `{"kty":"OKP","crv":"Ed25519","x","kid","use":"sig","alg":"EdDSA"}` — wordt **gepind** |
| `policy_public_key` | object | JWK zoals hierboven — de sleutel waarmee de Hub `ExecutionRequest`s ondertekent (§8); wordt **gepind** |
| `keyset_fingerprint` | string | `XXXX-XXXX-XXXX-XXXX` over `jwks` + `policy_public_key` (§4.5) |
| `rotation_sequence` | integer ≥ 0 | **nieuw in 1.3:** de huidige reeks van de Hub-sleutelrotatie (§4.5). De dienst zet `pins.rotation_sequence` daarop en vraagt alleen `key-rotations?after=<waarde>`. Een Hub 1.2 stuurt het niet: dan geldt 0 |
| `jwks_url` | string | `"/api/v1/auth/jwks"` (relatief aan `HUB_URL`; alleen ter vergelijking, voegt nooit vertrouwen toe) |
| `events_inbox_url` | string | `"/api/v1/events/inbox"` |
| `key_rotation_url` | string | `"/api/v1/auth/key-rotations"` (§4.5) |
| `enrollment_replayed` | boolean | `true` als dit een toegestane herhaling was (§3.6) |

De dienst controleert vóór opslaan: alle velden aanwezig met het juiste type (behalve `rotation_sequence`, dat bij een
Hub 1.2 ontbreekt; onbekende extra velden in het antwoord negeert hij); `schema_version` met major `1` (`"1.3"` in deze
versie, `"1.2"` van een oudere Hub blijft geldig; een andere major → ongeldig); `app_id` gelijk; `service_id` een UUID;
`service_token` past in het patroon; elke JWK geldig Ed25519 zonder `d`, met `use:"sig"`, `alg:"EdDSA"` en een `kid` die
binnen `jwks.keys` uniek is; de **zelf berekende** `keyset_fingerprint` gelijk aan het antwoord **en** — als opgegeven —
gelijk aan `HUB_KEY_FINGERPRINT` of de op de statuspagina ingevoerde vingerafdruk. Afwijking → niets opslaan,
`last_error` `hub_vingerafdruk_onjuist` (vingerafdruk) of `hub_antwoord_ongeldig` (de rest), definitief voor dit token
(§3.6). Aliassen uit eerdere aannames (`token`, `id`, `policy_public_jwk`, `kind`, `secret`) bestaan niet.

**Fouten** (contractformaat §5):

| HTTP | `code` | Wanneer | Gedrag van de dienst |
|---|---|---|---|
| 401 | `invalid_enrollment` | token/code onbekend, verlopen, al gebruikt (en geen toegestane herhaling), of `app_id` past niet — bewust één code, geen orakel | definitief voor dit token: nooit automatisch opnieuw; koppelcode mag de gebruiker opnieuw invoeren |
| 404 | (geen contractbody gegarandeerd) | endpoint bestaat niet (oude Hub) | definitief; melding "deze Hub-versie kent aanmelden niet" |
| 413 | `payload_too_large` | body > 1 MiB | definitief (fout in de dienst; `last_error` `hub_incompatibel`) |
| 422 | `validation_error` | schemafout, onbekend veld, beide of geen van `enrollment_token`/`pairing_code` (nooit om de waarde van `base_url`) | definitief (incompatibele dienst; `last_error` `hub_incompatibel`) |
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
daarna uit de database verwijderd (onvolledig → `last_error` `overzetten_onvolledig`).

```json
{"schema_version":"1.3","state":"gekoppeld","app_id":"home-control-hub",
 "hub_url":"http://<NAS-adres>:30400","service_id":"<uuid>","via":"token",
 "first_linked_at":"2026-11-09T12:00:00Z","linked_at":"2026-11-09T12:00:00Z","confirmed_at":"2026-11-09T12:00:01Z",
 "service_token":"svc_<43 tekens>","service_token_last4":"<4>",
 "pins":{"jwt":[{"kid":"<kid>","jwk":{"kty":"OKP","crv":"Ed25519","x":"<x>"},"thumbprint":"<RFC 7638>",
                 "pinned_at":"…Z","source":"enroll"}],
         "policy":[{"kid":"…","jwk":{…},"thumbprint":"…","pinned_at":"…Z","source":"enroll"}],
         "keyset_fingerprint":"XXXX-XXXX-XXXX-XXXX","rotation_sequence":0},
 "previous_pins":null,"pending":null,"used_enrollment_token_sha256":["<hex>"],"last_error":null}
```

- `schema_version`: major `1`. Een dienst schrijft de versie van het contract dat hij volgt (`"1.3"`); een lezer
  accepteert elke `1.x` en negeert onbekende velden.
- `state` (stabiele toestand) ∈ `nooit_gekoppeld` (ook als het bestand ontbreekt), `gekoppeld`, `ontkoppeld`,
  `ingetrokken`. Alleen bij `gekoppeld` zijn `service_token` en `pins` gevuld en vertrouwt de dienst Hub-JWT's.
  `first_linked_at` blijft na de eerste geslaagde koppeling **altijd** staan (bepaalt §3.7).
- **Onleesbaar** (geen geldige JSON, een andere major van `schema_version`, ontbrekende verplichte velden, verkeerde
  eigenaar of rechten): **fail-closed**. De dienst vertrouwt geen Hub-JWT (401 `not_linked`), toont geen koppelformulier
  (onbekend telt als "al eens gekoppeld") en meldt in `/readyz`-details en de witte lijst
  `last_error.code = koppelstatus_onleesbaar` (`/readyz` blijft 200: de koppeling telt daar niet mee, §5). Een gewone
  schrijfactie zet zo'n bestand **nooit** stil terug naar `nooit_gekoppeld`. Moet de dienst het bestand vervangen
  (alleen bij een nieuw env-token, §3.8), dan bewaart hij het origineel eerst als `hub-link.json.onleesbaar-<UTC-tijd>`
  (0600) en zet hij `unreadable_replaced_at`. Dat gebeurt bij de eerste schrijfactie van die poging (`pending`, §3.6
  stap 2, of `last_error`), dus vóór het verzoek aan de Hub: zo staan `pending` en daarna de hash van het afgehandelde
  token vast, en probeert de dienst een geweigerd token na een herstart niet opnieuw. Zolang `first_linked_at` daarna
  leeg is, blijft de toestand voor §3.7 "onleesbaar" (geen formulier, geen vertrouwen). Herstel alleen met een nieuw
  env-token via de Hub (§3.8).
- `pending` (`null` of een lopende poging, **naast** de stabiele toestand): `{"kind":"token|koppelcode",
  "secret_sha256":"<hex>","hub_url":"…","started_at":"…Z","attempts":n}` — nooit het geheim zelf. Een lopende poging
  verandert `state`, token en pins niet: een bestaande koppeling blijft tot het slagen geldig.
- `previous_pins`: de pins van vóór het laatste ontkoppelen/opnieuw koppelen, alleen voor audit; voegen nooit vertrouwen
  toe.
- `used_enrollment_token_sha256`: hashes van **afgehandelde** env-tokens (geslaagd of definitief mislukt), hooguit de
  20 laatste; een token in deze lijst wordt nooit opnieuw geprobeerd.
- `last_error`: `null` of `{"code":"<vaste code>","at":"…Z"}` (geen trace-ID; weergave: Peil). De codelijst is **open**
  (snake_case, elke code met een vaste NL-melding van de dienst). Vast: `hub_onbereikbaar` (netwerkfout of 5xx),
  `hub_weigerde` (401), `hub_antwoord_ongeldig`, `hub_vingerafdruk_onjuist`, `enroll_endpoint_ontbreekt` (404),
  `rate_limited` (429), `koppelen_onderbroken`, `token_verlopen_na_60_min`, `ingetrokken_door_hub`, en nieuw in 1.3:
  `hub_incompatibel`
  (413/422 van de Hub), `token_ongeldig` (env-token past niet in het patroon), `vingerafdruk_ongeldig`
  (`HUB_KEY_FINGERPRINT` onleesbaar), `hub_adres_ongeldig` (`HUB_URL` breekt §3.2), `overzetten_onvolledig` (eenmalige
  overzetting uit de database onvolledig) en `koppelstatus_onleesbaar`. Bij `vingerafdruk_ongeldig` en
  `hub_adres_ongeldig` spreekt de dienst de Hub niet aan en markeert hij het token niet als afgehandeld (de beheerder kan
  het formulier verbeteren). De Hub-UI toont de meegeleverde NL-melding en hardcodeert geen codes.
- **Extra velden** mogen; oudere lezers negeren ze. Vastgelegd: `unreadable_replaced_at`, `token_rotation_requested_at`
  (een aangevraagde rotatie overleeft een herstart) en `key_rotation_blocked_sequence` (een geweigerde sleutelrotatie
  blijft zichtbaar). Ze komen niet in de witte lijst.
- Publieke status (statuspagina, `/readyz`, `GET /connector/v1/hub-link`) toont alleen een **witte lijst** van velden
  (een maximum: minder tonen mag):
  `state`, `koppelen_bezig` (= `pending` ≠ `null`), `hub_url`, `service_id`, `via`, `linked_at`, `first_linked_at`,
  `keyset_fingerprint`, `service_token_last4`, `last_error` (code + vaste NL-melding). Nooit `service_token` of
  `pending.secret_sha256`.

### 3.6 Volgorde, eenmaligheid, idempotentie en herstart halverwege

**Dienst:**
1. First-start-init maakt `vault.key` en de Ed25519-identiteit (vóór enige enrollment; nooit overschrijven).
2. Schrijf `pending` (hash van het geheim) → `POST /enroll`.
3. Bij 200: alle controles van §3.3 → schrijf **in één atomaire stap** `state: gekoppeld` met token, pins,
   `rotation_sequence`, `linked_at`, (eerste keer) `first_linked_at`, `pending: null` en (env-token) de hash in
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
- Bestaat de dienst al (herinstallatie of opnieuw koppelen), dan blijft `service_id` gelijk en trekt de Hub de oude
  tokens van die registratie pas in bij het **eerste gebruik van het nieuwe token** (`GET /api/v1/services/self`). Wordt
  het nieuwe token niet binnen 60 min gebruikt (bv. omdat de dienst het antwoord weigerde om een verkeerde
  vingerafdruk), dan trekt de Hub het nieuwe in en blijven de oude geldig: een mislukte herkoppeling breekt een bestaande
  koppeling niet (§3.8). Intrekken door de beheerder (§3.8) blijft direct.
- `GET /api/v1/services/self` (Bearer service-token) → `{"service_id","app_id","status","version","enrolled_at",
  "keyset_fingerprint"}`; dient als bevestiging (zet `last_used_at`).

### 3.7 Koppelen via de statuspagina

- Het koppelformulier op `GET /` bestaat **alleen zolang de dienst nog nooit gekoppeld is** (`first_linked_at` leeg en
  het koppelbestand leesbaar). Daarna toont de statuspagina alleen de status (witte lijst §3.5) en "ontkoppelen of
  opnieuw koppelen gaat via de Hub". Er is op de statuspagina **geen** ontkoppelen, geen "lokale ontkoppelcode" en geen
  herkoppelen na intrekking. Bij een onleesbaar koppelbestand (§3.5): geen formulier; een POST uit een oud tabblad gaat
  niet naar de Hub en krijgt `koppelstatus_onleesbaar`.
- Velden: Hub-adres, koppelcode, **Hub-vingerafdruk** (alle drie verplicht; de Hub-UI toont koppelcode en vingerafdruk
  samen met een kopieerknop). Veldnamen (informatief, zoals gebouwd): `hub_adres`, `koppelcode`, `hub_vingerafdruk`.
  Vaste Nederlandse meldingen; het ingevulde Hub-adres van een **mislukte** poging wordt nergens bewaard.
- **Herkomst** van elke formulier-POST op een statuspagina (koppelen, en bij de executor ook de sleutelformulieren,
  §3.9), naast de double-submit-cookie (`SameSite=Strict`, HttpOnly) met formuliertoken:
  1. De pagina's sturen `Referrer-Policy: same-origin` (nooit `no-referrer`: dan stuurt elke browser `Origin: null`).
  2. `Origin` moet exact gelijk zijn aan `<schema>://<Host-header>` van het verzoek; ontbreekt `Origin` of is hij
     `null` → 403 met de vaste melding (fail-closed).
  3. Stuurt de browser `Sec-Fetch-Site`, dan alleen `same-origin` of `none`; `same-site` (een andere app op hetzelfde
     NAS-adres) en `cross-site` → 403.
  4. **`Host`-beperking (DNS-rebinding):** een POST alleen als de `Host`-header (zonder poort) een IP-adres in de vorm
     van §3.2 is (IPv6 tussen `[]`), een naam zonder punt, of een naam onder `.local`, `.lan`, `.internal` of
     `.home.arpa`; anders 403 `host_niet_toegestaan` met de melding "Open deze pagina via het IP-adres van de NAS, of
     koppel via de Hub". Reden: een website die iemand op het LAN bezoekt, kan via DNS-rebinding dezelfde oorsprong
     krijgen (Origin = Host) en een nooit gekoppelde dienst aan een eigen "Hub" koppelen; rebinding gebruikt een publieke
     domeinnaam. Wie de statuspagina via een eigen domeinnaam opent, koppelt met env-enrollment (aanbevolen) of via de
     Hub.
  5. Een geweigerd verzoek gaat niet naar de Hub en verandert niets.
  6. Elke repo met een koppel- of sleutelformulier heeft een **browsertest** (Chromium) die het echte formulier tegen de
     echte dienst verstuurt, plus negatieve tests: `Origin: null`, een vreemde `Origin`, `Sec-Fetch-Site: same-site` en
     `cross-site`, een niet-toegestane `Host`, geen cookie.
- **Pogingen en rate-limit:** max. **5 pogingen per 15 min per bron-IP** (adres van de TCP-verbinding;
  `X-Forwarded-For` en andere headers nooit gebruiken) én max. 20 pogingen per 15 min voor de hele dienst. Elke
  formulier-POST die de herkomstcontrole doorstaat, telt mee voor beide limieten, ook bij ongeldige invoer, een lopende
  poging, een onleesbaar koppelbestand of een dienst die al eens gekoppeld is (die laatste krijgt 409 `al_gekoppeld` en
  gaat niet naar de Hub). Teller in het geheugen mag als de dienst één API-proces heeft; anders gedeeld
  (database). Overschrijding → vaste melding, geen verzoek naar de Hub.
- **Koppelen bezig** (`pending ≠ null`): de dienst stuurt niets naar de Hub en antwoordt met de vaste melding
  `koppelen_bezig` (HTTP 409). De voorwaarde voor het formulier blijft "nog nooit gekoppeld"; hoe een lopende poging
  getoond wordt, is een Peil-zaak.
- **Meldingen** horen bij een echte, recente poging van deze browser (sleutel in het geheugen, hooguit 15 min geldig),
  nooit bij alleen een query-parameter; een melding spreekt de koppelstatus nooit tegen.
- **Invoer** als geheel controleren, nooit eerst afkappen: koppelcode ≤ 32, vingerafdruk ≤ 64, Hub-adres ≤ 512 tekens;
  langer → veldfout.
- **Log:** elke afgehandelde poging geeft één regel in de app-log met code en trace-ID, zonder het ingevulde Hub-adres
  van een mislukte poging en zonder geheimen.
- **Gereed:** op de statuspagina betekent **Gereed**: `/readyz` in orde (§5) **én** `state: gekoppeld` met
  `confirmed_at`. Anders "Niet gereed" met de reden (wacht op koppeling, ontkoppeld, ingetrokken, koppelstatus
  onleesbaar); de pagina legt het verschil met `/readyz` uit. Het totaal is nooit groen zonder Gereed (§13).
- Restrisico (gemeld, ADR-0011, ADR-0027): vóór de eerste koppeling kan iemand op het LAN de dienst aan een eigen "Hub"
  koppelen. Beperking: env-enrollment (geen wedloop) is de aanbevolen weg; de `Host`-beperking hierboven; de
  statuspagina toont het gekoppelde adres en de vingerafdruk; de dienst heeft dan nog geen data of rechten; herstel =
  opnieuw koppelen via de Hub (§3.8).

### 3.8 Opnieuw koppelen, ontkoppelen, intrekken, rotatie

- **Opnieuw koppelen (alleen via de Hub):** de Hub maakt een nieuw enrollment-token en zet het via de executor
  (`app.update`, nieuwe env `HUB_ENROLLMENT_TOKEN` + `HUB_KEY_FINGERPRINT`, eventueel nieuwe `HUB_URL`) of de beheerder
  vult het zelf in het TrueNAS-formulier in. Een dienst die een env-token ziet waarvan de hash **niet** in
  `used_enrollment_token_sha256` staat, probeert te koppelen, ook als hij al gekoppeld, ontkoppeld, ingetrokken of
  onleesbaar (§3.5) is (wie het formulier kan wijzigen is TrueNAS-beheerder). Slaagt het, dan vervangen token, pins en
  `hub_url` de oude; mislukt het, dan blijft een bestaande koppeling ongewijzigd (ook bij de Hub, §3.6).
- **Ontkoppelen (Hub → dienst):** `POST /connector/v1/hub-link/unlink` (§6) met dienst-JWT of gebruikers-JWT `admin`
  + `Idempotency-Key` → `state: ontkoppeld`, service-token gewist, pins naar `previous_pins` (alleen audit, geen
  vertrouwen). Daarna weigert de dienst elke Hub-JWT (401 `not_linked`). Daarna trekt de Hub de registratie in. Herhaalt
  de Hub een `unlink` waarvan hij het antwoord niet kreeg, dan krijgt hij 401 `not_linked`; dat telt voor de Hub als
  geslaagd (de dienst is ontkoppeld).
- **Intrekken (Hub):** `POST /api/v1/services/{id}/revoke` (admin, `Idempotency-Key`) trekt registratie en tokens in.
  Krijgt een dienst van de Hub **401** op een aanroep met zijn service-token, dan controleert hij met
  `GET /api/v1/services/self`; geeft ook dat 401, dan zet hij `state: ingetrokken` (`last_error: ingetrokken_door_hub`),
  weigert vanaf dan elke Hub-JWT (fail-closed), houdt zijn eigen data en toont "ingetrokken — opnieuw koppelen via de
  Hub". Netwerkfouten, 5xx, 403 en 429 zijn nooit een intrekking.
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
  dienst geroteerd heeft; de dienst roteert dan binnen 5 min (een aanvraag overleeft een herstart van de dienst:
  `token_rotation_requested_at`, §3.5). Is een token ouder dan 180 dagen, dan toont de Hub-UI een
  melding met de knop "rotatie aanvragen"; de Hub roteert **nooit op eigen initiatief** en de AI kan rotatie niet
  aanvragen (geheimen roteren is R2, 03_RISICO_AUTONOMIE; §8).

### 3.9 Executor koppelen

- Zelfde enroll-endpoint met `app_id: "ai-server-manager-executor"` en een **koppelcode (30 min)** + vingerafdruk op de
  statuspagina van de executor (`http://<NAS>:30410`). De executor pint vooral de policy-sleutel (§8).
- Na het koppelen vult de gebruiker op dezelfde pagina de **TrueNAS-API-key met schrijfrechten** in. De executor test de
  key live (`auth.login_with_api_key` + rolcontrole), versleutelt hem in zijn eigen vault en toont alleen de laatste 4
  tekens. De Hub ziet de schrijfkey nooit.
- De regels van §3.7 voor herkomst, `Host`, pogingen, invoer, meldingen en log gelden voor **elk** formulier op de
  executorpagina.
- **Uitzondering op §3.7:** ontkoppelen/opnieuw koppelen en de key roteren mag op de executorpagina, maar alleen na het
  invoeren van een TrueNAS-API-key met schrijfrechten die de executor live verifieert (bewijs van TrueNAS-beheer).
  "Live verifiëren" = `auth.login_with_api_key` + rolcontrole tegen het NAS-adres en de TLS-certificaatvingerafdruk die
  bij de eerste koppeling op deze pagina zijn vastgelegd en bevestigd (zoals de Hub, ADR-0010: een key gaat nooit naar
  een onvertrouwd of gewijzigd certificaat). Een ander NAS-adres of certificaat opgeven telt niet als bewijs; dat
  wijzigen vraagt eerst een geldige key op het vastgelegde adres. Rate-limit zoals §3.7.

### 3.10 Credentials van andere apps

Credentials van bestaande apps (MediaGuard-`X-Api-Key`, MSO-machine-sleutel, my_house-token, Emby-API-sleutel (alleen
lezen), TrueNAS-read-only-key, …) voert de gebruiker in de Hub-UI in; opslag versleuteld, alleen vault-referentie
(`vault://<scope>/<naam>`) in tabellen. UI toont nooit de waarde terug (alleen laatste 4 tekens + datum). Logs en
evidence worden geredigeerd.

## 4. Authenticatie en rollen

### 4.1 Gebruikers, noodlogin (break-glass) en SSO

- **Gebruikers** loggen in op de Hub (lokaal account, argon2id; optioneel OIDC via Authentik zodra B13 actief is).
  Rollen: `admin`, `operator`, `viewer`, `kind` (kinderprofiel). Sessiecookie (HttpOnly, SameSite=Strict, Secure achter
  HTTPS) + CSRF-token voor muterende webcalls.
- **Noodlogin in de Hub** (vereist voor B13-001; `home-control-hub` is register en adviseur, nooit poortwachter):
  - lokaal **noodaccount** (rol `admin`, vlag `break_glass`), argon2id-wachtwoord (≥ 20 tekens) **plus verplichte TOTP**
    (RFC 6238); werkt zonder Authentik/OIDC en zonder enige netwerkaanroep naar `home-control-hub` of Authentik;
  - alleen vanaf privé-bereiken: **RFC 1918 en `fc00::/7`**, op basis van het echte bron-IP van de verbinding (de
    Hub-webserver negeert vervalste `X-Forwarded-For`); nooit vanaf internet. `100.64.0.0/10` (CGNAT, ook Tailscale)
    telt standaard **niet** als privé: met Tailscale-delen kunnen gasten in dat bereik zitten. Een beheerder kan het in
    de Hub-UI toestaan (audit, waarschuwing "alleen als je Tailscale niet met anderen deelt"; besluit van de gebruiker,
    §1.2). Dezelfde standaard geldt voor elke andere "privé"-controle in het platform. Restrisico: welk bron-IP de
    container achter de Docker-portpublicatie van TrueNAS ziet (echt clientadres of het gateway-adres van het
    bridge-netwerk, dat zelf in RFC 1918 valt) is **NIET GEVALIDEERD (echte NAS)**; de zelftest hieronder toont daarom het
    bron-IP zoals de Hub het voor dat verzoek ziet, en de wizard waarschuwt als dat een gateway-adres van Docker lijkt;
  - sessie max. 60 min (instelbaar 5–240), niet verlengbaar; elke noodlogin → audit + incident `auth.break_glass.used`
    + melding; daarna **rotatieplicht** (wachtwoord + TOTP opnieuw) tot bevestigd. Het noodaccount zelf verloopt niet
    (geen lock-out precies bij nood); herbevestiging elke 90 dagen (melding, geen blokkade);
  - rate-limit zoals inloggen, geteld per (account, bron-IP) en nooit alleen per account (anders kan iemand op het LAN
    het noodaccount blokkeren); zolang er geen werkend noodaccount is, kan "OIDC verplicht" niet aan (geen SSO-only
    lock-out); lokale login van het noodaccount wordt nooit door OIDC uitgeschakeld;
  - instellingen van het noodaccount, "OIDC verplicht" en het toestaan van `100.64.0.0/10` wijzigt alleen een beheerder
    in de Hub-UI; het zijn geen `action_id`'s en de AI kan ze niet voorstellen (§8, 03_RISICO_AUTONOMIE);
  - de Hub mag het beleid van `home-control-hub` (bereiken, sessieduur) cachen, maar alleen om te **verscherpen**
    binnen deze grenzen; zonder cache gelden de standaardwaarden;
  - `POST /api/v1/auth/break-glass/selftest` (admin): deterministische controle (account, TOTP ingesteld, bereik met een
    testadres binnen en een documentatie-adres (RFC 5737) buiten, plus het bron-IP van dit verzoek zoals de Hub het
    ziet en of dat als privé telt) zonder in te loggen; geen mutatie, dus geen `Idempotency-Key` — "authenticator
    offline → break glass blijft testbaar".
- **SSO via OIDC** (Hub als OIDC-client van Authentik, B13):
  - groep → rol stelt een beheerder in de **Hub** in (eigen tabel, audit); `home-control-hub` toont zijn koppelingen
    alleen als advies. Geen gekoppelde groep → geen toegang (geen standaardrol); `kind` wint;
  - SSO-sessieduur instelbaar 15–720 min (standaard 480), nooit langer dan de lokale sessieduur, met dezelfde
    inactiviteitsgrens;
  - issuer en discovery alleen `https://` (D17). `redirect_uri` mag `http://` zolang er geen TLS-route is (B10/B13): de
    code is beschermd door PKCE (S256) en het transactiecookie; de status toont dan de waarschuwing
    `redirect_uri_https: false`;
  - de Hub koppelt een SSO-identiteit op `(issuer, sub)`, nooit alleen op de gebruikersnaam (§7, `sso.access.*`);
  - **terugkeerpad na inloggen** (Hub én elke dienst of bestaande app met een eigen login): alleen een pad dat voldoet
    aan `^/(?![/\\])[!-~]*$`, hooguit 256 tekens, zonder `://` en zonder backslash; anders `/`. Nooit een volledige URL.

### 4.2 Hub-JWT met gebruikerscontext

- `POST /api/v1/auth/service-jwt` geeft een kortlevende JWT voor één dienst. Header `{"alg":"EdDSA","typ":"JWT","kid"}`.
  Claims (alle verplicht): `iss:"hub"`, `aud:"<app_id>"`, `sub:"<gebruiker-UUID>"`, `token_use:"user"`,
  `roles:[…]` ⊂ {`admin`,`operator`,`viewer`,`kind`}, `iat`, `nbf`, `exp` (`exp − iat ≤ 120 s`), `jti` (UUID v4).
- `aud` is **precies één string**, gelijk aan de eigen `app_id` van de ontvanger; een lijst (ook met de eigen `app_id`
  erin) → 401 `invalid_token` (zo werkt één JWT nooit bij meerdere diensten met elk een eigen replaycache).
- Diensten met ACL (search-ai, jelly-leon-plugin) dwingen rol/ACL zelf af op basis van deze JWT. Klokspeling max. 30 s.
  Rol `kind` wint altijd van andere rollen in dezelfde JWT.

### 4.3 Hub → dienst: dienst-JWT

- De Hub authenticeert zich bij een eigen dienst met een **door de Hub ondertekende dienst-JWT**, per aanroep nieuw:
  claims `iss:"hub"`, `aud:"<app_id>"` (één string, §4.2), `sub:"hub"`, `token_use:"hub_service"`, `roles:["service"]`,
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

`Authorization: Bearer <service-token>`. De Hub vergelijkt de SHA-256 in constante tijd, werkt `last_used_at` bij en kan
het token zonder herinstallatie roteren of intrekken (§3.8).

- **Routes voor elke ingeschreven dienst** (geen scope nodig; alleen de eigen gegevens): `POST /api/v1/events/inbox`
  (§7), `GET /api/v1/services/self`, `POST /api/v1/services/self/rotate`, en de optionele routes van §6.1
  (`POST /api/v1/monitoring/heartbeat`, `POST /api/v1/logs`).
- **Leesroutes met een vaste scope per dienst** (in de Hub vastgelegd, niet door de dienst te kiezen; een beheerder
  ziet de scopes in de Hub-UI). Zonder scope → 403 `scope_ontbreekt`; de dienst meldt dan eerlijk
  `capability_unavailable` (een 403 is nooit een intrekking, §3.8). **Nooit geheimen via deze routes.**

  | Scope | Routes | Diensten (v1) |
  |---|---|---|
  | `inventaris.lezen` | `GET /api/v1/apps`, `GET /api/v1/apps/{id}` (gepagineerd over een momentopname, §5) | appstore-en-fork, jelly-leon-platform |
  | `catalogus.lezen` | nieuwe route voor catalogusbeschikbaarheid (P2): `{train, app, version}` → `{beschikbaar: ja \| nee \| onbekend, gemeten_op}`, gemeten met de alleen-lezen TrueNAS-sleutel; zonder meting `onbekend` | home-control-hub, jelly-leon-platform |
  | `besluiten.lezen` | `GET /connector/v1/items?type=decision` van de Hub | standaard **geen**; alleen een dienst die een besluit aantoonbaar nodig heeft (lijst per besluittype, met ADR) |

  Andere connector-itemtypes van de Hub (zoals `backup.self`) zijn alleen voor gebruikers (`viewer`+), niet voor diensten,
  tot een scope is vastgelegd.

### 4.5 Sleutelpinning, vingerafdruk en rotatie

- **Vertrouwensset** van een dienst = de gepinde sleutels uit `hub-link.json` (`pins.jwt` voor JWT's, `pins.policy` voor
  `ExecutionRequest`s). Een JWT met een `kid` buiten de gepinde set → 401 `unknown_key`. Vergelijking op de sleutel
  zelf (`x`), niet alleen op `kid`.
- `GET /api/v1/auth/jwks` blijft bestaan (diagnose, vergelijking), maar een via HTTP opgehaalde JWKS **voegt nooit
  vertrouwen toe** en trekt niets in. Een dienst mag strenger zijn (bv. weigeren als de Hub lang onbereikbaar is).
- **Thumbprint** = RFC 7638: `base64url(SHA-256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}'))`.
- **Sleutelset-vingerafdruk** (voor mensen): `SHA-256` over de UTF-8-tekst
  `"jl-hub-keyset-v1\njwt:" + join(",", thumbprints van alle jwt-sleutels) + "\npolicy:" + join(",", thumbprints van alle policy-sleutels)`,
  **beide lijsten gesorteerd op bytewaarde**; daarvan de eerste 80 bit als Crockford-base32 (alfabet
  `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, bits van links naar rechts), 16 tekens in groepen van 4 (`XXXX-XXXX-XXXX-XXXX`).
  Met één policy-sleutel is dit gelijk aan 1.2. Tijdens een policy-rotatie (twee policy-sleutels) telt dus elke gepinde
  policy-sleutel mee, nooit alleen de laatst gepinde. Invoer vergelijken na normalisatie (hoofdletterongevoelig,
  `O→0`, `I/L→1`, streepjes/spaties negeren). **Testvectoren** (publieke sleutels; alleen voor tests):
  - jwt `x = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo` (RFC 8037 A.1; thumbprint
    `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`), policy `x = A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`
    (thumbprint `1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y`) → **`MEGG-8GFG-2E4Y-K2RQ`**;
  - zelfde plus een tweede jwt-sleutel `x = Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc` (thumbprint
    `AkXIZFzonb59ZmGwyKgi3H3BwMi6amevqdKQiLZhdtc`) → **`CYRC-JS8C-14AN-JR17`**;
  - **nieuw in 1.3:** één jwt-sleutel (`11qY…URo`) en **twee policy-sleutels** (`A6EH…Mbg` én `Kay6…bdc`, in elke
    volgorde) → **`HN69-2PHK-XV2D-X85W`**.
- **Nieuwe Hub-sleutel** alleen via (a) **opnieuw koppelen** (§3.8) of (b) een **ondertekende rotatie**:
  `GET /api/v1/auth/key-rotations?after=<sequence>` (zonder authenticatie, zoals `jwks`: de handtekening is het bewijs;
  ook bestaande apps met een geplakte sleutelset, §2.3, kunnen dit lezen) →
  `{"items":[{"sequence":n,"statement":"<JWS compact>"}]}`. JWS-header `{"alg":"EdDSA","kid":"<gepinde kid>",
  "typ":"hub-key-rotation+jws"}`; payload `{"type":"hub_key_rotation","iss":"hub","sequence":n,"issued_at":"…Z",
  "purpose":"jwt|policy","add":[JWK],"retire":["kid"]}`. **Eén statement wijzigt precies één doel** en is
  EdDSA-ondertekend met een **op dat moment gepinde** sleutel van dat doel (jwt-wijzigingen door een jwt-sleutel,
  policy-wijzigingen door een policy-sleutel). `sequence` strikt oplopend over beide doelen samen, zonder gaten, in
  volgorde toepassen; een ongeldig of ontbrekend statement stopt het toepassen (incident, geen verdere statements;
  `key_rotation_blocked_sequence`, §3.5). "Nooit de laatste sleutel van een doel intrekken" betekent: na het toepassen
  heeft het doel minstens één sleutel; vervangen (`add` + `retire`) in één statement mag. Na toepassen:
  `rotation_sequence` en `keyset_fingerprint` in `hub-link.json` bijwerken (§3.5). Een dienst begint bij de
  `rotation_sequence` uit het enroll-antwoord (§3.3), zodat hij geen statements hoeft te controleren die met al
  ingetrokken sleutels zijn ondertekend. Dienst pollt ≤ elke 15 min; een JWT met een onbekende `kid` krijgt direct 401
  `unknown_key` en zet op de achtergrond een extra poll in gang (max. 1× per 30 s; het verzoek wacht daar niet op).
  De Hub ondertekent pas met een nieuwe sleutel als elke actieve dienst via `GET /connector/v1/hub-link` een
  `rotation_sequence` ≥ die van de rotatie meldt. Apps met een **geplakte** sleutelset (§2.3 regel 3, de Jelly
  Leon-plugin van regel 9) hebben die route niet maar tellen wel mee: hoe de Hub weet dat zij de rotatie hebben (bv.
  bevestiging door de beheerder per app), legt een ADR vast vóór de rotatie gebouwd wordt; tot dan ondertekent de Hub
  niet met een nieuwe sleutel zolang zo'n app de oude set gepind heeft. Sleutels roteren is een beheerdershandeling
  (R2), nooit een AI-actie. **De Hub heeft nog geen sleutelrotatie gebouwd:** tot dan geeft het endpoint `{"items":[]}`,
  roteert de Hub zijn sleutels niet, en is rotatie = opnieuw koppelen.

### 4.6 `jti` en replaycache

- Elke Hub-JWT (§4.2, §4.3) heeft een `jti`; zonder `jti` → 401 `jti_missing`.
- De dienst houdt een **persistente** replaycache (gedeeld door alle processen, bv. tabel) op `(iss, jti)` tot `exp` +
  30 s. Een **mutatie** met een al gebruikte `jti` → 401 `token_replayed`, behalve een exacte herhaling (zelfde `jti`,
  methode, pad en `Idempotency-Key`), die de idempotency-laag met het opgeslagen resultaat beantwoordt. "Mutatie" =
  **elke** POST/PUT/PATCH/DELETE, ook zonder `Idempotency-Key` en ook als de route niets wijzigt (bv. `…/evaluate`,
  `…/verify`); zonder `Idempotency-Key` bestaat geen exacte herhaling. Lezen (GET/HEAD) mag binnen de levensduur vaker.
  Replaycontrole niet mogelijk → 503 `replay_check_unavailable` (fail-closed). De Hub haalt dus per POST/PUT/PATCH/DELETE
  een nieuwe JWT.

### 4.7 Fail-closed

- Diensten zonder geldige auth → 401 `{code:"unauthorized", details:{reason}}`; vaste `reason`-waarden (Engels, voor
  machines; de `message` is NL) met deze betekenis:

  | `reason` | Wanneer |
  |---|---|
  | `not_linked` | `state` ≠ `gekoppeld` en ≠ `ingetrokken` (nooit gekoppeld, ontkoppeld of koppelbestand onleesbaar) |
  | `revoked` | `state: ingetrokken` |
  | `service_token_not_accepted` | `Bearer` is een `svc_`-token in plaats van een JWT (§4.3) |
  | `unknown_key` | `kid` of sleutel niet in de gepinde set (§4.5); ook een JWS-header **zonder** `kid` |
  | `token_expired` | `exp` (+ 30 s speling) verstreken |
  | `invalid_token` | geen `Authorization`-header, een ander schema dan `Bearer`, een lege waarde; geen geldige JWS; een gepinde `kid` waarvan de handtekening niet klopt; `alg` ≠ `EdDSA`; `iss`, `aud` (ook `aud` als lijst, §4.2), `nbf`, `iat`, `exp − iat > 120 s` |
  | `token_use_invalid` | de controles van §4.3 op `token_use`, `sub`, `roles` en `service_id` |
  | `jti_missing` | geen `jti` (§4.6) |
  | `token_replayed` | `jti` al gebruikt voor een andere mutatie (§4.6) |

  Controlevolgorde: 1 MiB-laag (§5) → `state` → tokensoort → handtekening/`kid` → claims → `token_use` → `jti` →
  schemavalidatie van de body. Rol (403) en `Idempotency-Key` (400/409/422, §5) komen ook pas ná de authenticatie.
  Zonder geldige authenticatie dus altijd 401, ook bij een onleesbare of ongeldige body of een ontbrekende
  `Idempotency-Key`.
  Nooit "open access" bij verlopen/ingetrokken credentials (EX16): connector wordt `unknown` + incident.
- Restrisico: verkeer op het LAN is (nog) HTTP; pins beschermen de echtheid van sleutels, niet de vertrouwelijkheid van
  tokens. HTTPS komt met B10/B13 (TLS-route) en verandert dit contract niet.

## 5. Gemeenschappelijke API-regels

- Prefix per dienst: Hub `/api/v1/…`; overige diensten hun eigen prefix (bv. `/integrations/v1`, `/catalog/v1`,
  `/lifecycle/v1`, `/search/v1`, `/voice/v1`, `/media/v1`) **plus** het connectorcontract (§6).
- JSON, UUID's, tijden ISO-8601 UTC (`…Z`), paginering met `cursor`/`limit` (max 200), `ETag` op muteerbare objecten.
- **Paginering over een momentopname:** een lijst die uit een meting komt (bv. de Hub-inventaris, een catalogus of een
  zoekresultaat) hoort bij één momentopname. Elke pagina noemt `snapshot_id` (of de `observed_at` van de meting) en
  hetzelfde totaal; is die momentopname niet meer beschikbaar → 409 `snapshot_changed` (opnieuw beginnen). Een gewone
  tabel met een stabiele sorteersleutel heeft geen momentopname nodig.
- Fout: HTTP-status + body `{"code": "<snake_case>", "message": "<NL tekst>", "details": {…}, "trace_id": "<uuid>"}`.
- **Foutcatalogus** (één code per situatie, alle nieuwe routes; referentie: `ai-server-manager:apps/api/src/hub/deps.py`
  en `errors.py`, ADR-0016):

  | HTTP | `code` | Situatie |
  |---|---|---|
  | 400 | `idempotency_key_required` / `idempotency_key_invalid` | `Idempotency-Key` ontbreekt / is geen UUID |
  | 401 | `unauthorized` (+ `details.reason`, §4.7) | **alleen authenticatie:** geen of ongeldige aanmelding, sessie of token |
  | 403 | `forbidden` (+ `details.reason`) of een vaste eigen code (`scope_ontbreekt`, `source_mismatch`, `host_niet_toegestaan`) | aangemeld, maar niet toegestaan |
  | 404 | `not_found` | bestaat niet, ook bij "niet zichtbaar voor jou" (geen orakel) |
  | 409 | `idempotency_in_progress` | dezelfde sleutel is nog bezig |
  | 409 | `conflict` (+ `details.reason`) of een eigen code (bv. `koppelen_bezig`, `snapshot_changed`, `username_taken`) | toestand staat het niet toe |
  | 412 | `precondition_failed` (+ `details.huidige_etag`) | `If-Match`/ETag klopt niet |
  | 413 | `payload_too_large` (+ `details.max_bytes`) | body > 1 MiB (of de eigen routegrens) |
  | 422 | `validation_error` (+ `details.fouten[]`) | schemafout, onbekend veld, te lange invoer |
  | 422 | `idempotency_key_reused` | dezelfde sleutel met een andere body |
  | 422 | eigen code (bv. `invalid_totp`) | foute invoer **binnen** een geldige sessie |
  | 423 | `item_in_playback` | alleen Jelly Leon (B03): het item wordt afgespeeld |
  | 428 | `precondition_required` | `If-Match`/ETag ontbreekt waar verplicht |
  | 429 | `rate_limited` + `Retry-After` | te veel verzoeken |
  | 501 | `capability_unavailable` | functie bestaat niet of is (nog) niet beschikbaar — nooit gesimuleerd succes |
  | 503 | `<afhankelijkheid>_unavailable` (generiek `dependency_unavailable`) + `Retry-After` | afhankelijkheid tijdelijk weg (bv. `replay_check_unavailable`, `engine_unavailable`) |

  Een herhaling met dezelfde `Idempotency-Key` en dezelfde body → het oorspronkelijke antwoord met header
  `Idempotent-Replay: true`. Eigen situaties gebruiken `details.reason` of een eigen code onder 409 (of de vaste eigen
  codes in de tabel); nooit een tweede code voor een gedeelde situatie. Inloggen zelf blijft 401 bij foute gegevens; een
  verkeerde TOTP-code bij een al aangemelde handeling (bv. `break-glass/confirm`) is 422.
- **Invoer** als geheel controleren, nooit eerst afkappen; te lang → 422 (statuspagina: veldfout, §3.7).
- Mutaties: header `Idempotency-Key` (UUID) verplicht; herhaling met zelfde key → zelfde resultaat, géén tweede uitvoering.
  **Uitgezonderd**, met reden:
  - eenmalig van aard of geven bewust een nieuw geheim (ADR-0006): setup, inloggen/uitloggen, wachtwoord, JWT-uitgifte,
    enrollment-token/koppelcode maken, `services/enroll`, `services/self/rotate`; het starten van een OIDC-(test)login
    en de OIDC-callback (inloggen); noodaccount instellen, roteren en bevestigen (geeft een geheim één keer terug of
    bevestigt een eenmalige TOTP);
  - eigen deduplicatie: `POST /api/v1/events/inbox` (dedupe op `event_id` en `(source_app, source_event_id)`, §7),
    `POST /api/v1/monitoring/heartbeat` (dedupe op `observed_at`, §6.1), `POST /api/v1/logs` (dubbele levering
    aanvaard, §6.1);
  - geen bijwerking behalve audit en tellers: `…/selftest`, `…/evaluate`, `…/verify`;
  - formulier-POST's van een statuspagina (koppelen §3.7, de sleutelformulieren van de executor §3.9): een
    browserformulier kan geen header meesturen; bescherming via het formuliertoken, de herkomstcontrole, de
    pogingenlimiet, `koppelen_bezig` en de eenmaligheid van koppelcode en token;
  - `POST /connector/v1/propose`/`apply`/`rollback` **alleen zolang** ze 501 `capability_unavailable` geven.
  Andere uitzonderingen alleen met een ADR in de repo en een contractmelding voor de volgende versie.
  Elke repo heeft een **statische test** die faalt op een muterende route zonder `Idempotency-Key` die niet met reden in
  een uitzonderingslijst staat (voorbeeld: `ai-server-manager:apps/api/tests/unit/test_idempotency_routes.py`). Let op
  §4.6: ook zonder `Idempotency-Key` verbruikt een POST de `jti`.
- **Verzoekgrootte:** een ASGI-laag **vóór routering en authenticatie** telt de body tijdens het lezen (ook zonder
  `Content-Length`/chunked) en breekt bij > 1 MiB (1 048 576 bytes) af met `413 {"code":"payload_too_large",
  "details":{"max_bytes":1048576}}`; een te grote `Content-Length` wordt direct geweigerd. Een hogere grens alleen per
  route, met ADR en eigen bovengrens. Geldt voor alle nieuwe diensten en voor nieuwe routes van bestaande apps.
  Uitzondering: de B03-plugin in het Jellyfin-proces (per route, na authenticatie; §2.3 regel 9).
- `GET /healthz` (proces leeft) en `GET /readyz` (de dienst kan verkeer aannemen: database, schema, geheimen, eigen
  worker waar nodig) op elke dienst, zonder auth, zonder geheimen. De **koppeling met de Hub telt niet mee** voor
  `/readyz`: een niet-gekoppelde, ontkoppelde of ingetrokken dienst is ready (zodat TrueNAS hem niet herstart); de
  statuspagina toont het verschil (§3.7 "Gereed"). Jelly Leon: §2.3 regel 9.
- OpenAPI: elke dienst exporteert `docs/openapi/<dienst>.openapi.json`; CI faalt bij drift.
- Tijdlimieten: uitgaande calls standaard 5 s connect / 15 s read, retry met exponentiële backoff + jitter, max 3, en
  bij 429 of 503 nooit eerder dan `Retry-After`. Uitgaande calls negeren proxy-omgevingsvariabelen tenzij de beheerder
  expliciet een proxy instelt.

## 6. Connectorcontract (elke dienst én elke adapter voor bestaande apps)

| Endpoint | Doel |
|---|---|
| `GET /connector/v1/discover` | `{app_id, source_version, schema_version:"1.0", capabilities:[read,propose,apply,rollback,stream], permissions:[…], limits:{…, max_age_s:{"<capability of itemtype>": s}}, timestamp_utc}` (§6.2) |
| `GET /connector/v1/health` | `{status: healthy|degraded|down|unknown, observed_at, reason_code, checks:[{name,status,observed_at,detail}]}` (regels hieronder) |
| `GET /connector/v1/items?type=&cursor=&limit=` | alleen eigen data, gepagineerd, scopes gerespecteerd; elke meting met `observed_at` (§6.2) |
| `POST /connector/v1/propose` | voorstel → `{proposal_id, preview_hash, resource_etag, diff, blast_radius, risk_claim, rollback_recipe, requires_backup}` |
| `POST /connector/v1/apply` | alleen met door de Hub **ondertekend** `ExecutionRequest` (§8); resultaat met `readback` + before/after-hash |
| `POST /connector/v1/rollback` | alleen als eigenaar het ondersteunt; anders `501 {code:"capability_unavailable"}` |
| `GET /connector/v1/evidence/{id}` | geredigeerd bewijs, nooit geheimen |
| `GET /connector/v1/events?cursor=` | outbox voor polling (§7) |
| `GET /connector/v1/hub-link` | **alleen eigen diensten:** koppelstatus, witte lijst uit §3.5 + `pinned_kids:{jwt:[…],policy:[…]}`, `rotation_sequence`; dienst-JWT of gebruikers-JWT `viewer`+ |
| `POST /connector/v1/hub-link/unlink` | **alleen eigen diensten:** ontkoppelen (§3.8); dienst-JWT of gebruikers-JWT `admin`, `Idempotency-Key` |

**Health-regels:**
1. `status` = het **slechtste** van alle checks in de volgorde `healthy` < `unknown` < `degraded` < `down` (zoals het
   Peil-totaal: onbekend is nooit groen). Een check zonder verse meting (§6.2) telt als `unknown`.
2. Elke check heeft `name` (`^[a-z0-9_.-]{1,64}$`), `status`, `observed_at` en `detail`.
3. **Vaste namen** waar van toepassing: `database`; `worker` (`observed_at` = laatste hartslag); `jobs`
   (`detail.wachtrij`, `detail.bezig`, `detail.laatste_job_klaar`; een wachtrij die niet afneemt → `degraded`);
   `hub_link` (koppelstatus, alleen eigen diensten). Eigen namen mogen erbij. De Hub herkent "geeft 200 maar voert geen
   jobs uit" na één overgangsrelease alleen nog aan `worker` en `jobs`.

Ontbrekende functie → `capability_unavailable`/`unknown`, **nooit gesimuleerd succes**. Bestaande apps: §2.3 — de Hub
gebruikt hun **bestaande** routes; nieuwe routes in die apps alleen als hun delta-matrix ze als ontbrekend markeert
(bv. het bewaakte schrijfpad `propose`/`apply` in my_house, de dunne connectorlaag in MSO, alleen-lezen connector en
`/healthz`/`/readyz` in MediaGuard).

### 6.1 Optionele Hub-routes voor eigen diensten (service-token, §4.4)

Beide zijn **optioneel**: zonder heartbeat geldt de connector-health (§6), zonder log-sink alleen de eigen logs. Ze
lezen of wijzigen niets bij de dienst en voeren nooit iets uit.

- **`POST /api/v1/monitoring/heartbeat`** — body `{status: healthy|degraded|down, observed_at, verwacht_interval_s
  (10–3600, standaard 60), checks: [≤ 20 × {name ^[a-z0-9_.-]{1,64}$, status: healthy|degraded|down|unknown,
  detail ≤ 200}], worker: {laatste_hartslag, wachtrij, bezig, laatste_job_klaar, jobs_stil_na_s (60–86400, standaard
  900)}}`; tijden met tijdzone; onbekende velden → 422; `observed_at` hooguit 5 min van de Hub-klok (anders 422).
  Antwoord 202 `{status:"accepted", beoordeling}` of 200 `{status:"duplicate", …}` (dedupe op `(dienst, observed_at)`);
  hooguit één per 5 s (429 + `Retry-After: 5`). De Hub beoordeelt zelf (worker stil, jobs stil, falende checks →
  `degraded`). Uitblijven: na 3 × `verwacht_interval_s` is de meting verouderd en de binnenkant `unknown` (§6.2).
- **`POST /api/v1/logs`** (log-sink) — body `{regels: [1–200 × {op, niveau, bericht, logger, trace_id?, velden}]}`
  met `op` (tijd met tijdzone), `niveau` ∈ `debug|info|warning|error|critical`, `bericht` (1–8000 tekens), `logger`
  (≤ 96), `trace_id` (UUID, optioneel) en `velden` (object); onbekende velden of te lange invoer → 422. De Hub
  schoont vóór opslag (geheimen, adressen volgens zijn redactieregels), bewaart per regel hooguit 2000 tekens van het
  geschoonde bericht en hooguit 4 KiB `velden` (groter → alleen de sleutelnamen met `_ingekort: true`); dat inkorten is
  opslag, geen afkappen van invoer vóór de controle. Per dienst ≤ 1000 regels per minuut (instelbaar): regels boven de
  grens worden geweigerd en geteld (`{opgeslagen, geweigerd, bron}`, 202); zonder ruimte 429 + `Retry-After: 60`.
  Retentie 14 dagen en hooguit 50 000 regels (instelbaar).

### 6.2 Versheid (`observed_at` en `max_age`)

Elke meting die een dienst doorgeeft (connector-health, items, heartbeat, statuspagina) heeft `observed_at`. Een meting
ouder dan haar `max_age` is `unknown` met `reason_code: meting_verouderd` en de tijd van de laatste meting; de oude
waarde wordt nooit als actueel doorgegeven (wel als "laatst bekend", gedempt, §13). Standaard `max_age` = **900 s**.
Een bron mag per capability of itemtype een andere waarde opgeven in `GET /connector/v1/discover` →
`limits.max_age_s: {"<naam>": s}`. Een afnemer mag strenger zijn (eerder `unknown`, nooit groen), nooit soepeler dan
de bron; een instelbare cache-TTL van de afnemer (bv. de Hub-inventaris) maakt een meting nooit verser dan haar bron.

## 7. Event-envelope

```json
{"schema_version":"1.0","event_id":"<uuid>","source_app":"mediaguard","source_event_id":"<bron-id>",
 "event_type":"media.download.failed","entity":{"type":"media_item","id":"<safe-id>"},
 "timestamp_utc":"2026-11-09T04:00:00Z","trace_id":"<uuid>","correlation_id":"<uuid|null>",
 "actor":{"type":"system|user|ai|flow","id":"<id>"},"classification":"public|internal|sensitive",
 "payload":{…geschoond…},"payload_ref":null}
```
- Push: `POST {HUB_URL}/api/v1/events/inbox` (service-token). Dedupe op `event_id` én `(source_app, source_event_id)`.
  Antwoord 202 `accepted` of 200 `duplicate`.
- Bron houdt een outbox (retry met backoff, dead-letter na 10 pogingen, zichtbaar in Hub). Zonder native events: Hub pollt
  `/connector/v1/events` of bestaande routes met cursor/ETag/watermark. Geen exact-once-aanname. Zolang een eigen dienst
  niet gekoppeld is (§3.5: geen `state: gekoppeld`), pusht hij niet en telt hij geen pogingen; events blijven in de
  outbox tot een nieuwe koppeling. Dat geldt ook voor `service.hub_link.unlinked` en `service.hub_link.revoked`: die
  kan de dienst pas na een nieuwe koppeling afleveren (de Hub kent de toestand al, §3.8).
- **Grenzen** (zoals de Hub-inbox ze afdwingt; een bron valideert vóór verzending tegen dezelfde regels, zodat een event
  niet pas als dead-letter opvalt): onbekende velden → 422; `schema_version` `"1.0"`; `event_type` ≤ 128 tekens en
  `^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$` (precies drie segmenten); `source_app` = de `app_id` van het service-token (anders
  403 `source_mismatch`); `source_event_id` 1–200 tekens; `entity.type` `^[a-z0-9_.-]{1,64}$`; `entity.id` 1–200 tekens;
  `actor.id` 1–128 tekens; `payload` ≤ 16 KiB als JSON (groter: zelf inkorten met `_ingekort: true` of `payload_ref`
  ≤ 512 tekens); `timestamp_utc` met tijdzone.
- **`event_type`-namen:** `<domein>.<object>.<gebeurtenis>` (bv. `app.health.changed`, `backup.run.failed`,
  `action.run.executed`, `energy.reading.recorded`, `network.device.discovered`, `flow.action.requested`,
  `auth.break_glass.used`). Het derde segment is het werkwoord:
  - **probleem:** `failed`, `crashed`, `down`, `degraded`, `stalled`, `blocked`, `rejected`, `saturated`, `conflict`;
  - **herstel:** `recovered`, `succeeded`, `resolved`, `restored`;
  - de rest is informatie.
  `entity` is het **stabiele onderwerp** (de taak, de app, de bron — niet de run), zodat probleem en herstel dezelfde
  vingerafdruk (soort × bron × onderwerp) krijgen. `app.health.changed` draagt `payload.status` ∈
  `healthy|degraded|down|unknown`; `unknown` is nooit een herstel.
- **Domeinen per eigenaar** (eerste segment): Hub `auth`, `alert`, `audit`, `backup`, `inventory`, `monitoring`,
  `notification`, `onboarding`, `action`; home-control-hub `sso`, `energy`, `network`, `automation`, `flow`;
  appstore-en-fork `catalog`; jelly-leon-platform `lifecycle`; zoeken-en-persoonlijke-ai `search`, `voice`; jelly-leon
  `media` (eventtypes van B03 §10.10); MediaGuard (via de Hub-adapter) `media`. Gedeeld: `app` (alleen
  `app.health.changed` over de eigen app) en `service` (alleen de vaste lijst hieronder). De eigenaar van een event is
  het paar (`source_app`, domein): `media` van `jelly-leon` en `media` van `mediaguard` zijn twee bronnen met elk hun
  eigen regels. Een event buiten het eigen domein verwerkt de Hub alleen als algemene informatie, nooit met de regels
  van de eigenaar.
- **Vaste `service.*`-events** van elke eigen dienst (`entity: {type: "service", id: <app_id>}`):
  `service.hub_link.linked` (payload `{via: token|koppelcode}`), `service.hub_link.unlinked`,
  `service.hub_link.revoked`, `service.token.rotated`, `service.key_rotation.applied`, `service.key_rotation.rejected`.
  De oude namen `service.enrollment.completed`, `service.hub_link.paired` en `service.hub_key.rotation_rejected`
  vervallen; één release lang mag een dienst beide namen sturen.
- **Ernst:** platformbreed de vijf Peil-woorden `kritiek`, `hoog`, `middel`, `laag`, `info`. Een event mag
  `payload.ernst` met één van deze waarden meegeven (optioneel; zonder ernst bepaalt de Hub-regel het; `payload.severity`
  vervalt na één overgangsrelease). De Hub mag intern drie niveaus houden met deze vaste afbeelding: `kritiek` →
  kritiek; `hoog` en `middel` → waarschuwing; `laag` en `info` → info. De UI toont de bronwaarde als die er is, anders
  kritiek → Kritiek, waarschuwing → Middel, info → Info. Alleen kritiek escaleert.
- **`sso.access.revoked` en `sso.access.changed`** (bron alleen `home-control-hub`, via de inbox): `entity: {type:
  "authentik_user", id: <gebruikersnaam>}`, `payload` met verplicht `issuer`, `sub` (de OIDC-`sub` die de Hub-client
  krijgt; bij `sub_mode=hashed_user_id` de gehashte gebruikers-ID — NIET GEVALIDEERD tegen een echte Authentik, te
  controleren tegen de broncode van Authentik) en `preferred_username`. De Hub koppelt op `(issuer, sub)`; alleen als
  `sub` ontbreekt (overgang) op `preferred_username`. Zo'n event trekt alleen sessies in en geeft nooit rechten.

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
- Koppelen, ontkoppelen en intrekken van diensten, rotatie van service-tokens en Hub-sleutels, scopes van diensten, en
  het beheer van het noodaccount (incl. `100.64.0.0/10` toestaan) zijn **geen** `action_id`'s: ze lopen alleen via
  beheerdersroutes van de Hub (admin + audit) en de AI kan ze niet voorstellen of uitvoeren (03_RISICO_AUTONOMIE: geen
  wijzigingen in beveiligingsbeleid of privileges door de AI; geheimen roteren is R2). Alleen het meegeven van
  `HUB_*`-env en van door de Hub gegenereerde catalogusgeheimen (§3.1) bij `app.install`/`app.update` loopt mee in die
  (R2-)actie.
- Blokkades (altijd, ook met goedkeuring): pool `DEGRADED`/onbekend of backup-gate rood → geen opslag-/massamedia-mutaties
  (EX11/EX12); boiler-schakelen (elke route; EX27); auto-delete van torrents/downloads/media/foto's/datasets; wijzigen van
  policy/rollen/privileges door AI; betaalde acties; elke rechtstreekse schrijfactie in de database van Emby, Jelly Leon
  of MediaGuard (§2.3 regel 7).

`Approval` (gebonden): `approval_id, request_id, preview_hash, resource_etag, policy_hash, risk_class, approved_by,
approved_at, expires_at (≤ 15 min), one_time_nonce, backup_checkpoint_id, action_scope`. Wijzigt één gebonden veld
(bv. app-digest na preview, EX19) → goedkeuring vervalt, nieuwe diff nodig. Nonce eenmalig → replay geweigerd (EX20).

**Back-upbevestiging:** `requires_backup: true` (uit `propose` of uit de tabel hieronder) ⇒ de Hub bindt in de
`Approval` een `backup_checkpoint_id` van een B12-back-up van die app met status `geverifieerd`, niet ouder dan het RPO
uit het manifest (§9). Een checkpoint dat een gebruiker opgeeft, is nooit bewijs. Een dienst die vóór de goedkeuring een
back-upgate toont (bv. B13-005), vertrouwt een checkpoint alleen als het met een dienst-JWT van de Hub binnenkomt;
anders blijft de gate `onbekend`.

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

**Acties via de eigenaar-connector** (naast de executor-allowlist; de eigenaar voert uit via `POST /connector/v1/apply`
met een door de Hub ondertekend `ExecutionRequest` — gepinde policy-sleutel, `preview_hash`, `resource_etag`, nonce,
vervaltijd — en controleert zelf opnieuw, net als de executor):

| `action_id` | eigenaar | klasse (min.) | `requires_backup` | AI mag voorstellen | sinds |
|---|---|---|---|---|---|
| `sso.oidc.hub.register` | home-control-hub | R2 | ja (Authentik-database) | nee (wijzigt toegang) | apply in P2 |
| `sso.sessions.revoke` | home-control-hub | R2 | nee | nee | apply in P2 |
| `mediaguard.wanted.search`, `mediaguard.quarantine.release_check`, `mediaguard.file.reacquire`, `mediaguard.quality.report`, `mediaguard.subtitles.search` | media-guard-ultimate | R2 | per actie | volgens beleid | **gereserveerd** tot BG-05 en P3-02 (§2.3 regel 3) |
| `mediaguard.quarantine.restore` | media-guard-ultimate | R3 | ja | **nooit** | **gereserveerd** tot BG-05 en P3-02 |
| my_house `propose`/`apply`, MSO change sets | eigen lijst in hun `DELTA_MATRIX.md` | ≥ R1 | per actie | volgens beleid | P3 |

Een plan met een vastgezette catalogusversie die niet meer in de catalogus staat, geeft blokkade `version_unavailable`
(§2.2). TrueNAS-API: JSON-RPC 2.0 over WebSocket `wss://<NAS>/api/current` (versie-endpoint `/api/v25.10.x` waar
beschikbaar), `auth.login_with_api_key`. Methodenamen en -schema's per versie ontdekken (`core.get_methods`,
`system.version`); geen oude REST-API. Hub-api gebruikt een **read-only** key (aparte TrueNAS-gebruiker met
alleen-lezen-rol); alleen de executor heeft een key met schrijfrechten, en die key voert de gebruiker in op de
executorpagina (§3.9). De alleen-lezen-sleutel van de Hub gebruikt leesmethoden plus `core.subscribe`/`core.unsubscribe`
voor een **vaste lijst event sources** (nu alleen `reporting.realtime`, rol `REPORTING_READ`): abonneren, één bericht
lezen, opzeggen (ook na een time-out). Een andere event source vraagt een contractwijziging. (Bronwaarneming in de
broncode van TrueNAS 25.10.8; NIET GEVALIDEERD (echte NAS).)

## 9. Manifeststandaard (B08-001, eigenaar `appstore-en-fork`)

`manifest_version: "1"` YAML met o.a.: `app_id`, `name`, `owner_repo`, `category`, `description_nl`,
`version`, `install: {method: custom_app | catalog_app, reason}`, bij `custom_app`: `image: {repository, tag, digest}` (één
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

**Begrippen** (§2): `install.method: custom_app` = uitsluitend het formulier (`ix-app`); een compose-app
(`custom_app: true` in TrueNAS) is nooit toegestaan.

Wijzigingen in 1.2 (blijven gelden):
- `network.joins_platform_network` **vervalt** (apps delen nooit een Docker-netwerk, §2). Overgang: validator meldt
  `deprecated_field` (waarschuwing) bij `false`, fout `platform_network_not_supported` bij `true`; in `--strict`
  (release-CI) is elke `deprecated_field` een fout.
- `custom_app.ports` **vervalt**; de vertaling bouwt de formulierpoorten uit `network.ports`. Overgang: aanwezig en
  gelijk → `deprecated_field`; aanwezig en anders → `ports_inconsistent` (fout). `custom_app.portal.port` en
  `healthcheck.port` verwijzen naar een naam in `network.ports`.
- **GPU als optionele parameter:** `privileges.gpu` is het **maximum** (`none` of `intel_render`; `intel_render` vereist
  `privilege_reason` en `decisions_required` met D08). `custom_app.gpu` is `none`, `intel_render` of
  `{param: <naam>}` naar een parameter met type **`gpu`** (waarden `none|intel_render`, `source: wizard`,
  `decision: D08`, `required: false`); ontbreekt de waarde → `none`. `custom_app.gpu ≠ none` mag alleen als
  `privileges.gpu = intel_render`. De wizard biedt `intel_render` alleen aan als D08 een render-node via de TrueNAS-API
  heeft gemeten. Vertaling: `intel_render` → `resources.gpus.use_all_gpus: true` (volgens de bronnen in
  `appstore-en-fork/docs/TRUENAS_APP_VALUES.md` geeft dat alle niet-NVIDIA-GPU's en kan het formulier daar niet per GPU
  kiezen; NIET GEVALIDEERD (echte NAS); de preview meldt dat de app dan elke render-GPU krijgt). Eén specifieke
  render-node via `privileges.devices` is een open punt (B03/P4, toegang voor 568 tot de render-groep onbekend).

Wijzigingen in 1.3 (validator en schema: appstore-en-fork):
- **Catalogusapp met reden** (§1): `install.method: catalog_app` vraagt `install.reason`: `meerdere_containers` of een
  NL-reden waarom een catalogusapp nodig is bij één container; ontbreekt de reden → waarschuwing
  `install_reason_ontbreekt` (in `--strict` een fout). Het manifest van een upstream-image als Custom App noemt het
  restrisico "zonder no-new-privileges kan een setuid-programma binnen de container root worden" (in
  `privilege_reason`).
- **Gereserveerde namen:** een parameter- of `custom_app.env`-naam die met `HUB_` begint → fout `reserved_env` (§3.2).
- **Geheime parameters die de Hub maakt** (§3.1 a): `source: generated` + `secret: true`; dan geen `secret_in_form`-fout,
  en de waarde staat nooit in het manifest.
- **`accepted_findings: [{code, reden_nl}]`** — alleen voor waarschuwingen uit een vaste lijst:
  `backup_db_export_none`, `secret_in_form` (alleen bij een parameter met `source: generated` en `secret: true`) en
  `digest_pending_release` (alleen vóór de eerste release van een eigen image). `--strict` faalt op elke andere
  waarschuwing én op een geaccepteerde code die niet (meer) optreedt. Fouten zijn nooit te accepteren. Een losse
  uitzonderingenlijst buiten het manifest vervalt.
- **`backup.db_export: stopped_snapshot`** (app stoppen + ZFS-snapshot van de dataset) voor apps zonder exportfunctie
  (bv. SQLite zonder export); de stilstand telt mee in `rto`.
- **Documentsoort `kind: checklist`** (`install.method: none`) voor I-documenten zonder installatie (bv. I01, I02), met
  een eigen JSON Schema; de validator van manifest v1 weigert hem als installatie.
- **`post_install_checks: [{id, soort: http|handmatig, beschrijving_nl}]`** voor open eerste-gebruik-vensters (bv. een
  standaardwachtwoord of een open setup-pagina) en runtime-kenmerken die pas bij starten blijken (bv. een
  niet-schrijfbare `/tmp` als 568). De Hub toont ze na installatie als taak voor de beheerder; tot de beheerder ze
  bevestigt, is de app niet "gezond" (gate).
- **`network.ports[].container_port: same_as_host`** voor catalogusapps waarvan de container op de gekozen hostpoort
  luistert.
- **Monitorplan:** `healthcheck.monitor: {pad, verwachte_status, timeout_s, interval_s}`. De Hub (B09) maakt per app uit
  het dienstenregister (D03 + hostpoort) en het manifest een monitorplan; hij past Uptime Kuma niet zelf aan. De
  beheerder neemt het plan over in de Uptime Kuma-UI en bevestigt per monitor; dat heet "handmatig bevestigd", nooit
  "gevalideerd door de Hub". Zonder bevestiging blijft I08-08-03 NIET GEVALIDEERD.
- **Adoptie** (bestaande, niet door het platform geïnstalleerde apps): documentsoort **`kind: adoption`** met
  `installable: false` en een eigen schema; alleen gemeten of door een beheerder bevestigde velden (niets gokken); de
  validator van manifest v1 weigert hem (`adoption_manifest_not_installable`). `owner: {soort: derde|bestaand|eigen_los|
  eigen, repo (alleen bij eigen repos), bevestigd_door, bevestigd_op}` — "eigenaar" is wie de app beheert, los van de
  data-eigenaar uit 02_DATA_EIGENAARSCHAP. Status: `onbekend` (in de acceptatietekst "unmanaged") · `kandidaat`
  (herkend, wacht op bevestiging) · `adopted` (`status_nl` "Geïmporteerd"). Herkenning alleen op de exacte
  catalogusappnaam of de exacte image-repository, nooit op de appnaam; altijd een voorstel dat een beheerder bevestigt.
  Emby (§2.3) is zo'n item met `owner.soort: derde`.

Weigeren vóór uitvoering (EX47): compose/YAML-installatie, `privileged`, Docker-socket, hostpad `/`, `/mnt` zonder
dataset, `/etc`, `/var/run`, `/root`, host network zonder reden, `latest`, ontbrekende digest, GPU zonder D08-meting,
`HUB_*` als parameter of env, een geheime waarde in een manifest.

## 10. Repo-indeling nieuwe Python-diensten

```
apps/api/            pyproject.toml, src/<pakket>/…, alembic/, tests/{unit,integration}
apps/web/            (alleen ai-server-manager) Next.js PWA + Playwright; testmatrix en normen van §13
apps/executor/       (alleen ai-server-manager; eigen image)
policy/              (alleen ai-server-manager) policy YAML + hash
deploy/allinone/     Dockerfile (alles-in-één), supervisor, healthcheck (exec-vorm, wisselt eerst naar 568, §2.2),
                     first-start-init (zie MSO als voorbeeld)
deploy/truenas/      CUSTOM_APP.md: exacte velden van het standaard Custom App-formulier (NL), geen YAML; tag met
                     digest (§2.2); publieke image, registry-login alleen als fallback (§2.1)
deploy/dev/          compose.yaml alleen voor ontwikkeling/CI (expliciet géén installatiemethode)
deploy/manifest/     <app_id>.manifest.yaml (manifeststandaard §9, install.method custom_app)
.env.example         alle variabelen gedocumenteerd, géén echte waarden (voor ontwikkeling; de Custom App heeft geen
                     verplichte variabelen; HUB_URL/HUB_ENROLLMENT_TOKEN/HUB_KEY_FINGERPRINT zijn optioneel)
docs/openapi/        geëxporteerde OpenAPI
docs/adr/            ADR-0001… (keuzes en waarom)
docs/platform-v2/    pakketdocs + byte-gelijke kopie van PLATFORM_CONTRACTEN.md en CONTRACT_1.3_CONFORMITEIT.md
                     (drifttest, kop van dit document) + DELTA_MATRIX.md (bestaande repos) + EVIDENCE.json (§11)
tests/e2e/           dienst-E2E met simulators (de Hub-simulator volgt §3.3 exact)
tests/ui/            browsertest (Chromium) van de statuspagina en zijn formulieren, met de negatieve gevallen van §3.7
.github/workflows/   ci.yml (ruff, mypy, pytest + postgres-service, alembic up/down, openapi-drift, pip-audit,
                     statische Idempotency-Key-test (§5), EVIDENCE-test (§11), contract-drifttest,
                     alles-in-één image bouwen en starten met healthcheck en rooktest), release.yml (tag → GHCR push,
                     SBOM, digest in release/digests.json)
Makefile, VERSION (start 0.1.0), CHANGELOG.md, LICENSE (GPL-3.0, §1.1 besluit 8)
```
Container: start als root alleen voor eigenaarschap van `/appdata`, daarna bounding set leeg en alle processen — ook
PID 1 — als 568:568 (Hub-AI-runner 569), zonder capabilities, met zelf gezette `PR_SET_NO_NEW_PRIVS` (het formulier zet
geen no-new-privileges en geen cap_drop, §2.2); healthcheck volgens §2.2; geen Docker-socket; resource-limieten worden in
het formulier/de API-waarden gezet. De eisen van dit hoofdstuk gelden voor nieuwe Python-diensten; de webclient
(jelly-leon-web, onderdeel van de app `jelly-leon`) en de apparaat-apps (jelly-leon-clients) hebben geen eigen image of
Custom App.

## 11. Bewijs en Excel (EVIDENCE.json)

Elke repo houdt `docs/platform-v2/EVIDENCE.json` bij — een lijst met objecten:
```json
{"id":"B01-003","status":"Bezig","validatie":"Sim-getest","bewijs":"commit <sha>; tests/e2e/test_install.py::test_privileged_manifest_rejected",
 "blokkade":"","opmerking":"","repo":"ai-server-manager","bijgewerkt":"2026-11-09"}
```
- `id` = exacte ID uit de Excel (`B01-003`, `I23-23-05`, `APP-07`, `EX17`, `JLT-12`, `D04`). Daarnaast mogen
  **contractpunten** en **reviews** een eigen regel hebben: `C1.3-<code>` met de code uit `CONTRACT_1.3_CONFORMITEIT.md`
  (bv. `C1.3-HCH-01`), `C1.2-<code>` uit de 1.2-lijst (bv. `C1.2-H5`) en `REVIEW-<repo>-<onderwerp>` (bv.
  `REVIEW-zoeken-en-persoonlijke-ai-statuspagina`), met de statussen van het blad Werkpakketten.
  `ai-server-manager/tools/excel/update_excel.py` zet die niet in de bestaande bladen, maar meldt ze in een eigen
  overzicht (nooit stil weglaten).
- `status` ∈ Excel-lijst: Werkpakketten/Fasen `Niet gestart|Bezig|Gereed|Geblokkeerd|N.v.t.`; Testmatrix
  `Niet gestart|Bezig|Geslaagd|Mislukt|Geblokkeerd|N.v.t.`; Besluiten `Open|Ingevuld|Getest|Geblokkeerd|N.v.t.`.
- **Regel (gekozen door gebruiker):** code + CI + simulator-E2E geslaagd ⇒ `status: Bezig` (of `Geblokkeerd` als echte
  NAS/hardware/account nodig is). `Gereed`/`Geslaagd` alleen na echte acceptatie op de NAS — dat kan in deze
  bouwomgeving niet en wordt dus **nooit** gezet.
- **`validatie`** = één of meer waarden uit deze vaste lijst, gescheiden door `"; "` (bv.
  `Sim-getest; NIET GEVALIDEERD (echte NAS)`); toelichting hoort in `opmerking`. **Een lege `validatie` is nooit
  toegestaan.**

  | Waarde | Waar |
  |---|---|
  | `Sim-geslaagd` / `Sim-mislukt` | Testmatrix (`EX..`, `JLT-..`): simulator-resultaat; `status` blijft `Bezig` of `Geblokkeerd` tot een echte run |
  | `Sim-getest` / `Unit-getest` | werkpakketten, installatiestappen, contractpunten en reviews |
  | `Intel-iGPU-getest (ontwikkelmachine)` | **nieuw in 1.3:** functioneel bewijs en bovengrens op de iGPU van de ontwikkelmachine; zegt niets over de GPU's van de NAS, die blijven `NIET GEVALIDEERD (hardware)` |
  | `NIET GEVALIDEERD (echte NAS)` / `NIET GEVALIDEERD (hardware)` / `NIET GEVALIDEERD (account)` / `NIET GEVALIDEERD (Mac/Xcode)` | overal, aanvullend waar nodig |
  | `Niet getest` | **nieuw in 1.3:** alleen bij status `Niet gestart` |

- **Consistentie:** elke `NIET GEVALIDEERD (…)` die in `blokkade` staat, staat ook in `validatie`.
- Elke repo heeft een test die deze regels op zijn eigen `EVIDENCE.json` controleert (voorbeeld:
  `ai-server-manager:apps/api/tests/unit/test_evidence_contract.py`).
- `ai-server-manager/tools/excel/update_excel.py` voegt alle EVIDENCE.json samen in
  `docs/platform-v2/08_EXCEL/TrueNAS_V2_Uitvoering_en_Afvinken.xlsx` (kolom **Validatie** toegevoegd).

## 12. Commit- en pushregels

Branch `ccr-c133d7a0-kuz1cv` in elke repo; geen PR's; geen force-push; kleine logische commits per fase/onderdeel,
NL-commitberichten, afgesloten met **de attributieregel(s) die de lopende sessie voorschrijft** (in deze programmaronde
één `Co-Authored-By:`-regel); **geen vaste sessielink** meer. Geen modelnaam of model-ID in code of docs. Vóór elke push
`git pull --rebase`; na elke push de GitHub Actions-run volgen tot groen of de blokkade exact melden.
`ai-factory` wordt niet aangeraakt. Bestaande integriteit, rollback en monitoring in MediaGuard/MSO/my_house nooit
dubbel bouwen, vervangen of uitschakelen. Release-tags `v0.1.0` voor nieuwe repos pas na groene CI (besluit 6); een
MediaGuard-release alleen met het upgradebewijs van §2.3 regel 7.

## 13. Ontwerptaal

- **Eén eigen ontwerptaal (Peil)** op **Tailwind CSS 4 + shadcn/ui + lucide** (iconen). Bron van waarheid:
  `ai-server-manager/docs/platform-v2/ONTWERPTAAL.md` + `ai-server-manager/design/ontwerptaal/` (tokens, componenten,
  voorbeelden, sjabloon van de statuspagina's), ADR-0015. Die levert de design-agent; dit contract beschrijft alleen
  reikwijdte en werkwijze, niet de ontwerptaal zelf. Verbeterpunten uit de reviews (sjabloonblokken, tonen en iconen,
  meldingsrol, renderer, driftregel van de kopieën, woorden) gaan via een nieuwe Peil-versie (Peil 1.1.1); een repo
  neemt ze over via die versie, nooit door het sjabloon lokaal te omzeilen.
- **Reikwijdte:**
  - Hub-UI (`ai-server-manager/apps/web`): **alle** schermen.
  - Statuspagina's van de nieuwe diensten (`home-control-hub`, `appstore-en-fork`, `jelly-leon-platform`,
    `zoeken-en-persoonlijke-ai`, executor): **framework-vrije CSS** afgeleid uit **dezelfde tokens** (geen JS-framework,
    geen externe CDN; werkt zonder JavaScript). "Gereed" op zo'n pagina volgt §3.7; het totaal is nooit groen zonder
    Gereed.
  - **Uiterlijk** van MediaGuard, MSO en my_house: alleen het uiterlijk; functies, routes, gebruikersreizen en API's
    blijven gelijk (§2.3).
  - **Niet:** Jelly Leon (web en clients) houdt de Jellyfin-vormgeving met alleen de zichtbare naam "Jelly Leon".
- **Werkwijze:** elke UI-bouwstap krijgt **vooraf een ontwerpstap** (design-agent: schermontwerp en componentkeuze binnen
  de ontwerptaal) en **achteraf een ontwerpreview** (design-agent: afwijkingen van de ontwerptaal en toegankelijkheid).
  De design-agent beslist zelfstandig; het resultaat wordt de gebruiker achteraf getoond.
- **Normen en testmatrix** (gelijk aan ONTWERPTAAL §12): breedtes **320, 360, 390, 768, 1024 en 1440 px**, licht en
  donker; **WCAG 2.2 AA** (axe-tags `wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22aa` = 0), focus nooit bedekt (2.4.11),
  tekstafstand van 1.4.12 zonder overloop, reflow op 320 px getest met het systeemlettertype van de CI-runner. De
  controles mogen in de functionele Playwright-suite of in een apart reviewgereedschap draaien (zoals
  `ai-server-manager:apps/web/review`), zolang ze in CI draaien. Bestaande eisen blijven: NL-teksten, waarde + eenheid +
  bron + laatst bijgewerkt, `unknown` nooit groen, aanraakdoelen ≥ 44 px, toetsenbord en screenreader.
