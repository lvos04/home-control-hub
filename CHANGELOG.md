# Wijzigingen

## 0.1.0 — B11 Node-RED-automatisering (fase P2, ADR-0016, nog niet uitgebracht)

Alles hieronder is met een Node-RED-simulator en een Hub-simulator getest. De aannames over Node-RED zelf zijn
gemeten tegen de gepinde image in lokale containers, met het eigen profiel van deze app (niet met het manifest van
`jelly-leon-platform`). **Niet gevalideerd op een echte NAS**, met een echte Hub of met echte apparaten.
NIET GEVALIDEERD (echte NAS): niet als Custom App op TrueNAS geïnstalleerd; zie STAPPEN_P6.md.

**Nieuw**
- **Node-RED als bron (B11-001).** Isolatiemeting (wat niet meetbaar is heet *niet meetbaar*, nooit *in orde*; een
  anonieme lezer moet 401 krijgen, besluit C-11), het editor-adres alleen voor een beheerder. Het
  beveiligingsprofiel (`POST …/automation/hardening-profile`) is geen installatiestap: besluit C-12 kiest een
  voorziening zonder geheim in het formulier via de manifeststandaard; het profiel vervalt daarna of wordt
  daaraan gelijkgetrokken. Grof blokkeren (besluit van de gebruiker): staat er ergens in de configuratie van
  Node-RED een exec-node, een onbekend type of een module buiten de allowlist, of iets wat de dienst niet kan
  plaatsen (een vormfout in id, type, z, wires of links, een id of z langer dan 120 tekens, een NUL of een losse
  surrogaat in een tekst, ook in een label, een dubbele id, een node buiten elk bekend tabblad, een draad of link
  naar een id die nergens staat of naar iets wat geen node in een tabblad is), dan worden **alle** flows van Node-RED
  geblokkeerd tot het weg is. Het tabblad met de oorzaak (of dat ermee verbonden is) krijgt die bevinding zelf, elk
  ander tabblad de reden `bron_geblokkeerd` met de oorzaak en de plaats; daarna blijven ze gepauzeerd tot een
  beheerder ze hervat. Blokkeren bij mislukken (besluit van de gebruiker): loopt de synchronisatie vast nadat
  Node-RED antwoordde (bij het lezen, in de scan, het flowregister of de opslag), dan worden in een aparte transactie
  alle flows geblokkeerd met reden `synchronisatie_mislukt` en is de check `automatisering` degraded; nooit de oude
  stand. Dat geldt ook als Node-RED wel antwoordde maar de dienst het antwoord niet kan gebruiken: groter dan
  16 MiB, geen geldige JSON of niet de verwachte vorm, een onverwachte status, een Node-RED zonder aanmelding, een
  geweigerde aanmelding (401), ontbrekende rechten (403), een onbekend pad (404) of een doorverwijzing (3xx)
  (`antwoord_te_groot`, `antwoord_ongeldig`, `onverwacht_antwoord`, `niet_beveiligd`, `aanmelding_geweigerd`,
  `geen_rechten`, `niet_gevonden`, `redirect`; de meting van de bron noemt de oorzaak). Eerst bleef bij een Node-RED
  zonder aanmelding of een geweigerde aanmelding de stand staan, zodat een flow met een exec-node die de dienst niet
  kon lezen, actief bleef. Antwoordt Node-RED niet (onbereikbaar, time-out) of met een serverfout (5xx), dan blijft
  de stand van de flows staan en zegt alleen de synchronisatie eerlijk `ok: false`. Zie ADR-0016 kop 2. Een
  Node-RED zonder aanmelding wordt geweigerd.
- **Eventtypencatalogus (B11-002).** Events worden bewaard met een catalogusstatus en per flow in volgorde
  afgeleverd, met herhalen en dead-letter. Een onbekende schema-versie blijft zichtbaar en wordt gemeld.
- **Veilige acties (B11-003).** Een flow vraagt een actie aan met een eigen flow-token; de Hub beslist. Deze dienst
  voert nooit iets uit. Alleen de acties van de vaste lijst uit contract §8 kunnen worden aangevraagd; al het
  andere wordt geweigerd. De boiler schakelen, Emby als doel, verwijderen, shell, beleid wijzigen, betaalde acties
  en onzichtbare of niet-ASCII-tekens in een doel worden altijd geweigerd, ook met een ruim token. Hetzelfde event
  vijf keer geeft één verzoek. Limiet per flow en actie, en per flow over alle acties samen. Een losse surrogaat in
  het doel of de parameters (ook in een sleutel of diep genest) is een invoerfout (`422 validation_error`), geen
  serverfout (uitzondering: een verzoek dat de harde weigerlijst toch weigert, zie onder **Gewijzigd**); hetzelfde
  geldt voor een doel of parameters die dieper dan 32 niveaus genest zijn.
- **Proefrun (B11-004).** Vaste voorbeeld-events; actieverzoeken worden alleen gesimuleerd. Een flow met nodes die
  zelf naar buiten gaan start alleen na een uitdrukkelijke bevestiging. Raakt een flow geblokkeerd terwijl zijn
  proefrun al loopt, dan wordt die proefrun direct afgesloten (`mislukt`, `flow_geblokkeerd`; open voorbeeld-events
  naar dead-letter): hij geeft niets meer, zijn verzoeken worden geweigerd (niet meer gesimuleerd), een ack of nack
  daarna wordt geweigerd (`409 proefrun_afgesloten`) en hij telt ook na het opheffen van de blokkade niet meer. Een
  voorbeeld-event is alleen binnen zijn eigen lopende proefrun een trigger: daarbuiten (proefrun klaar, verlopen of
  afgesloten, ook na hervatten) wordt een actieverzoek ermee geweigerd en vastgelegd (`403
  voorbeeld_buiten_proefrun`), nooit aangevraagd bij de Hub.
- **Versies en herstel (B11-005).** Versleutelde momentopnamen (credentials alleen als door Node-RED versleuteld
  blok), een diff zonder waarden, en herstel als voorstel dat alleen met een door de Hub ondertekend ExecutionRequest
  wordt uitgevoerd. De huidige stand wordt eerst zelf bewaard; na het schrijven wordt teruggelezen. Synchronisatie,
  blokkeren bij mislukken en herstel schrijven het flowregister onder één slot: een herstel dat tegelijk met de
  worker loopt, legt de flows niet meer stil. Op dat slot wordt hooguit 30 seconden gewacht; daarna
  `409 flowregister_bezig` en is er niets gewijzigd (een herstel houdt dan zijn nonce; de worker probeert het in de
  volgende ronde opnieuw). Het blokkeren bij mislukken wacht wél tot het slot vrij is en geeft nooit op; eerst kon
  het na 30 seconden opgeven met `409 flowregister_bezig` ("er is niets gewijzigd") terwijl de flows open bleven.
  Loopt een herstel vast nádat het naar Node-RED schreef (ook bij het sluiten van de verbinding of een databasefout
  bij het vastleggen), of geeft Node-RED dan op het schrijven of het teruglezen een antwoord dat de dienst niet kan
  gebruiken, dan worden alle flows geblokkeerd (blokkeren bij mislukken) en is het antwoord
  `500 herstel_niet_vastgelegd`. Het bewaren van het antwoord bij de Idempotency-Key en de commit vallen daarbuiten
  (ADR-0016 kop 6, punt 4). Het credentials-bestand telt alleen als de datamap van Node-RED **alleen-lezen** is
  gekoppeld (gemeten met `fstatvfs`); een beschrijfbare koppeling is `niet_gekoppeld`, met de reden
  `niet_alleen_lezen` in de synchronisatie. Een herstel zet het credentials-bestand alleen terug als ook de huidige
  inloggegevens vast te leggen zijn; anders gaan alleen de flows terug en zeggen voorstel en antwoord dat (eerst
  werden de huidige inloggegevens dan vervangen zonder dat terugdraaien ze kon terugzetten).
- Connector-health: check `automatisering` (alleen als Node-RED is ingesteld).
- `deploy/truenas/NODE_RED_CUSTOM_APP.md`: verwijst naar het manifest van `jelly-leon-platform`
  (`install/manifests/node-red.manifest.yaml`, 568:568) als installatieweg en beschrijft alleen wat in deze app
  wordt ingesteld, plus de controlelijst voor wat de app niet kan meten. Meetprogramma `tools/node_red_verify.py`
  met rapport `docs/b11/node-red-verificatie.json`.
- Rooktest van de image: de flow-API geeft zonder flow-token `401 flow_token_ontbreekt` en met een onbekend
  flow-token `401 flow_token_ongeldig`; migratie `0005` is uitgevoerd. Nieuwe test: de manifestvalidator weigert
  een variant van het manifest met een Docker-socket.

**Gewijzigd**
- `POST /connector/v1/apply` vraagt nu een `Idempotency-Key` en een ondertekend ExecutionRequest. Alleen
  `automation.flows.restore` is uitvoerbaar; de SSO-acties blijven `501 capability_unavailable`.
- Migratie `0005`. Nieuwe optionele instellingen `HCH_NODE_RED_SYNC_INTERVAL_S`, `HCH_NODE_RED_DATA_DIR` en
  `HCH_NODE_RED_ALLOWED_MODULES`. Nieuwe afhankelijkheid `bcrypt`.
- Manifest: optionele afhankelijkheid `node-red` (verwijst naar het manifest van `jelly-leon-platform`); de
  upgradenotitie noemt migratie `0005`.
- Het beveiligingsprofiel noemt als gebruiker 568:568, de installatiegebruiker van het manifest van
  `jelly-leon-platform`. De standaardgebruiker 1000 van de image is alleen nog de meting "draait niet als root" in
  `tools/node_red_verify.py`. Argumenten, accounts en `credentialSecret` van het profiel zijn niet gewijzigd
  (besluit C-12).
- Een NUL-teken of een losse surrogaat in een tekstveld van de flow-API of de beheer-API (ook in de lijst toegestane
  acties van een flow-token, de voorbeelden van een proefrun, de uitkomst die de Hub meldt en een event van de Hub)
  is een invoerfout (`422`), geen serverfout; er wordt niets vastgelegd. Uitzondering: weigert de harde weigerlijst
  een actieverzoek van een flow ook als elk van die tekens een `?` is (bijvoorbeeld een dataset verwijderen of de
  boiler schakelen, of de boiler of Emby in het doel of de parameters van een andere actie, tot 8 kB net als zonder
  die tekens), dan blijft het de vastgelegde weigering (`403`, rij, audit, `flow.action.rejected`), zonder doel,
  parameters en reden. Een cursor met zo'n teken is `400 invalid_cursor`. Zie ADR-0016 kop 4.
- `POST /connector/v1/propose` en `POST /connector/v1/apply`: een NUL-teken of een losse surrogaat in het verzoek
  (ook in een sleutel, ook in een sleutel die met `_sa` begint) is `422 validation_error` vóór er iets gebeurt; eerst
  gaf dat een serverfout (`500`) of werd het aangenomen. Bij `apply` wordt dan geen nonce verbruikt en niets bewaard.
  Een verzoek dat dieper genest is dan 64 niveaus is ook `422 validation_error` (eerst vanaf ongeveer 990 niveaus een
  serverfout). Beide controles zitten centraal in `idempotency.run_idempotent` en gelden dus ook voor de andere
  wijzigingen, voor het deel van het verzoek dat zij daar laten vastleggen; de verzoek-hash van de Idempotency-Key
  ziet nu ook sleutels die met `_sa` beginnen. Zie ADR-0016 kop 6.
- Rechten op de beheer-API vastgelegd in ADR-0016 kop 2 en getest per route: beleid en toegang (profiel, eigenaar,
  triggers, grenzen, flow-tokens) alleen voor de beheerder, bediening (pauzeren, isolatie meten, momentopname,
  opnieuw aanbieden, proefrun) ook voor de operator; een viewer of kind krijgt op elke schrijvende route `403`, de
  Hub (dienst-JWT) op elke route van de beheerder en de operator.
- Een databasefout zet de parameterwaarden (mogelijk een geheim of token) niet meer in de foutmelding en de
  app-log (`hide_parameters=True`, V-094).
- Een NUL-teken of losse surrogaat in de credential van `PUT …/sources/{id}` is `422 validation_error`, geen serverfout (KLEIN-22).

**Bekende grenzen**
- De Hub verwerkt `flow.action.requested` nog niet en kent `automation.flows.restore` nog niet in zijn policy: een
  verzoek blijft op *aangevraagd* staan en herstel werkt alleen tegen de simulator.
- De schermen voor flows staan in de Hub en zijn nog niet gebouwd.
- Het manifest van `jelly-leon-platform` heeft sinds stap S-P2-410 geen anoniem lezen meer (besluit C-11: `adminAuth`
  zonder anonieme rechten), maar nog geen beheerder of dienstaccount (besluit C-12). Tegen zo'n Node-RED kan deze app
  zich niet aanmelden: de isolatie heet `onbekend` met de fout `geen_aanmelding` en wordt niet gemeten, ook
  `anoniem_geweigerd` niet.
- Koppel de dataset van een Node-RED volgens het manifest niet aan deze app: daar staat ook de sleutel van de
  credentials (`.config.runtime.json`). Versies van flows worden dan zonder credentials bewaard.
- Het koppelen van Node-RED in de Hub (adres, isolatie meten, versies, terugzetten) is nog niet beschikbaar.

## 0.1.0 — onafhankelijke review contract 1.3 (QA, ADR-0015, nog niet uitgebracht)

**Gerepareerd**
- CI sloeg 12 tests stil over: de controle van het manifest met de 1.3-validator van appstore-en-fork en de
  byte-gelijkheid van de renderer met de Peil-referentie `bouw/sjabloon.py`. CI installeert nu de validator op een vaste
  commit en haalt de referentie op de gepinde Peil-commit; ontbreekt een van beide, dan faalt CI.
- Connector-health: de check `bronnen` gaf een verouderde meting het tijdstip van de vraag als `observed_at` en meldde
  `meting_verouderd` ook als een andere bron vers `down` was. Nu: `observed_at` = de oudste meting die meetelt,
  `detail.laatste_meting_verouderd`, en een verse storing blijft de oorzaak (`bron_down`).
- `hub-link.json` krijgt na het aanmaken expliciet modus 0600, zodat geërfde ACL's van een dataset het bestand niet
  ruimer maken (dan zou de dienst zijn eigen koppeling als onleesbaar lezen). Op een echte NAS: NIET GEVALIDEERD.
- Juiste logregel als een onleesbaar koppelbestand wel apart is gezet maar zijn rechten niet aangepast konden worden.
- Manifest: de upgradenotitie noemt migratie `0004`.

**Extra getest**
- Interop met de echte Hub (ai-server-manager, contract 1.3): `hub-link.json` 1.3 met `rotation_sequence`, en
  `service.hub_link.linked` afgeleverd in de inbox van de echte Hub (alleen lokaal).

## 0.1.0 — contract 1.3 en Peil 1.1.1 (ADR-0014, nog niet uitgebracht)

**Statuspagina (contract 1.3 §3.7, Peil 1.1.1)**
- Sjabloon Peil 1.1.1 (gepinde kopie van `ai-server-manager@0a7143b`) met een renderer in één doorgang. Nieuwe
  toestanden: *koppelstatus onleesbaar* (Storing "Onleesbaar", geen formulier, code en pad, geen live-regio) en
  *koppelen bezig* (geen formulier, starttijd). Niet ingestelde onderdelen heten "Niet ingesteld" en tellen niet mee;
  groen heet "Alles gezond".
- Een koppel-POST wordt alleen aangenomen met een `Host` die een IP-adres, een naam zonder punt of een naam onder
  `.local`/`.lan`/`.internal`/`.home.arpa` is (anders 403 `host_niet_toegestaan`, DNS-rebinding), met
  `Sec-Fetch-Site` `same-origin`/`none` en een exacte `Origin` (ontbreekt of `null` → 403 `herkomst_onjuist`).
  `Referrer-Policy` is nu `same-origin`.
- Elke POST na de herkomstcontrole telt als poging, ook bij een al gekoppelde dienst (409 `al_gekoppeld`), een
  onleesbaar koppelbestand (409 `koppelstatus_onleesbaar`) of een lopende poging (409 `koppelen_bezig`). Invoer wordt
  niet meer afgekapt (te lang = veldfout). Eén logregel per POST. De melding na koppelen werkt alleen met een sleutel van
  deze browser (15 min).

**API en koppeling (contract 1.3 §3–§7)**
- Eerst aanmelden, dan body, rol en `Idempotency-Key`: een onleesbare body zonder geldige aanmelding is nu 401 (was 422).
- `idempotency_key_reused` (422) vervangt `idempotency_key_conflict` (409); `precondition_failed` met `huidige_etag`;
  een geweigerde noodtoegang is 403 `forbidden` met `details.reason`.
- `rotation_sequence` uit het enroll-antwoord; `hub-link.json` met `schema_version` `"1.3"`; ook een andere major,
  ontbrekende verplichte velden of te ruime rechten maken het bestand onleesbaar (fail-closed).
- Een Hub-hostnaam wordt per verbinding opgelost en gecontroleerd; geen verbinding als hij naar loopback, link-local of
  `0.0.0.0`/`::` wijst.
- Connector-health: totaal = slechtste check; vaste namen `database`, `worker`, `jobs`, `hub_link`; de worker schrijft
  een hartslag; `discover` noemt `limits.max_age_s`.
- Events: eigen domeinen en de vaste `service.*`-lijst worden vóór verzending gecontroleerd; `service.*` gaat over
  `{type: service, id: home-control-hub}`; `payload.ernst`; nieuw `sso.authentik_sync.recovered`;
  `sso.access.*` met `issuer`, `sub` en `preferred_username`.
- Noodtoegang: `100.64.0.0/10` (CGNAT/Tailscale) telt alleen nog als privé als een beheerder het toestaat
  (`cgnat_toegestaan`, migratie 0004). Een bestaande registratie met zo'n bereik geeft zonder toestemming geen toegang.
- Groep → rol-koppelingen dragen `advies: true` (de Hub beheert ze).

**Image, manifest en CI**
- `healthcheck.py --controle`; de rooktest controleert ook CapPrm, CapAmb en (start als root) CapBnd, en de healthcheck
  apart.
- Manifest: kop 1.3, `healthcheck.monitor`, `accepted_findings`.
- CI: contract-drift online; de ontwerpreview meet ook 1024 px en draait de browsertest van het koppelformulier.

## 0.1.0 — onafhankelijke review contract 1.2 (QA, ADR-0013, nog niet uitgebracht)

**Gerepareerd**
- Een onleesbaar `/appdata/secrets/hub-link.json` blijft fail-closed, ook als er daarna iets geschreven wordt (bv. een
  mislukt env-token). Vroeger werd het stil vervangen door "nooit gekoppeld" en kwam het koppelformulier terug. Het
  origineel blijft bewaard als `hub-link.json.onleesbaar-<tijd>`. `/readyz` meldt `koppelstatus_onleesbaar`. Herstel
  gaat via een nieuw token van de Hub.
- Een bronmeting ouder dan 15 minuten is nu ook in `GET /integrations/v1/sources`, de connector-items en
  `GET /connector/v1/health` `unknown` (`meting_verouderd`), nooit meer de laatst bekende stand.
- Een Hub-JWT met `aud` als lijst wordt geweigerd (`invalid_token`); `aud` moet precies `home-control-hub` zijn.
- Hub- en bronadressen met een IP-adres in een afwijkende vorm worden geweigerd. Voorbeelden: `127.1`, `2130706433`,
  `0x7f000001`, `0`, `010.0.0.1`, en `localhost.` met een punt achteraan. Een IP-adres moet `a.b.c.d` zijn.
- De healthcheck zet ook no-new-privileges als de container als 568 start (Custom User).
- `EVIDENCE.json` verwijst alleen nog naar tests die bestaan; een nieuwe test bewaakt dat.
- De ontwerpreview in CI (`ontwerpreview.py --uit tests/ui/review-uit`) beoordeelde door een padfout 0 metingen en
  slaagde toch. Nu is het pad absoluut en faalt de review als het aantal metingen niet klopt. De eerdere CI-claims
  zijn gecorrigeerd.
- CI: GitHub-acties naar de huidige majors (Node 24), op commit-SHA gepind.

## 0.1.0 — onafhankelijke ontwerpreview van de statuspagina (ADR-0012, nog niet uitgebracht)

**Gewijzigd (alleen woorden, redenen en meldingen op `GET /`; het Peil-sjabloon is ongewijzigd)**
- Een bronmeting ouder dan 15 minuten telt in "Wat deze dienst doet" als **Onbekend** ("1 verouderd (laatst bekend …).
  Metingen ouder dan 15 minuten tellen als onbekend."), nooit meer als de laatst bekende stand. Vroeger stond een meting
  van dagen oud als Gezond.
- De pil van een controle draagt altijd het vaste Peil-woord bij het icoon (Onbekend/Storing). De precieze
  koppeltoestand ("Niet gekoppeld", "Ingetrokken door de Hub", "Koppelen bezig", …) opent de reden.
- Beheerherstel heeft per niveau een reden (Onbekend: "Het herstelregister is nog niet volledig ingevuld of getest.").
- "Koppelen bezig" noemt waarmee gekoppeld wordt en de laatste melding, en zegt dat het formulier pas weer werkt als de
  poging klaar is (geen "over een minuut" meer).
- Na een mislukte poging zegt de melding dat alle velden opnieuw moeten (waarden worden bewust niet teruggezet).
- De kop is korter. Het totaal noemt "Wat deze dienst doet" en "Sleutels van de Hub" krijgt geen kleine letters meer.
  "1 van 1 bron" staat in het enkelvoud. De variabelenaam `HUB_ENROLLMENT_TOKEN` staat niet meer in de melding (op
  320 px gaf hij overloop met de tekstafstand van WCAG 1.4.12), maar in de controle.

**Nieuw**
- `make ontwerpreview` (`tests/ui/ontwerpreview.py` + `.mjs`) draait ook in CI (job `statuspagina-ui`). Het start de
  echte dienst als proces tegen de Hub-simulator en zet 14 toestanden klaar. Chromium meet elke toestand op
  320/360/390/768/1440 px in licht en donker: axe (WCAG 2.2 AA), contrast in de pagina, doelen, focus, tekstafstand en
  de Peil-statusregels.
- `docs/ontwerp/PEIL_REVIEW.md` met bevindingen, reparaties en een overdracht aan Peil (S-1…S-8), en
  `docs/ontwerp/peil-review/` met de schermafdrukken.

## 0.1.0 — statuspagina in Peil (HC11, nog niet uitgebracht)

**Gewijzigd (ADR-0011)**
- `GET /` gebruikt het framework-vrije sjabloon van de ontwerptaal **Peil 1.1.0** (versie-gepinde kopie met
  herkomstkop in `design/ontwerptaal/`, O-14): geen JavaScript, CSP `default-src 'none'`, licht en donker volgens het
  systeem, Peil-woorden (Gezond · Beperkt · Storing · Onbekend · Niet gereed), "Gekoppeld" als neutrale pil.
- Het eerste signaal is nooit groen als de dienst niet gereed is; gereed = database, schema, sleutels **en** een door
  de Hub bevestigde koppeling.
- Koppelformulier-velden heten nu `hub_adres`, `koppelcode` en `hub_vingerafdruk` (zoals het sjabloon). Een mislukte
  poging geeft direct de pagina terug met een passende HTTP-status (400/403/409/422/429/502/503), vaste melding,
  code en de trace-ID van het verzoek (selecteerbaar; ook in log en audit); geen `?melding=<fout>`-redirects meer.
- Niet meer op de statuspagina: dienst-ID, "gekoppeld via" en de laatste 4 tekens van het service-token (staan in
  `GET /connector/v1/hub-link`).
- Het formulier blijft zichtbaar tijdens een lopende koppelpoging; verzenden geeft dan 409 `koppelen_bezig` zonder
  verzoek naar de Hub.

**Nieuw**
- `tools/peil_kopie.py` (controleer / vergelijk --online / bijwerken) en een CI-stap die drift met ai-server-manager
  laat falen; `HCH_PEIL_DIR` in de image (sha256 gecontroleerd bij het bouwen).
- UI-tests (`tests/ui`, Playwright + axe-core) over negen toestanden uit de echte app × licht/donker × 320–1440 px, en
  schermafdrukken in `docs/screenshots/peil/statuspagina/`.

## 0.1.0 — platformcontract 1.2 (nog niet uitgebracht)

**Breaking (contract 1.2, ADR-0010)**
- Koppelen volgens §3.3: enroll-verzoek met `enrollment_token` of `pairing_code` (geen `kind`/`secret`/prefixes meer),
  `public_key_jwk` alleen `{kty, crv, x, kid}`; het antwoord wordt volledig gecontroleerd en de
  sleutelset-vingerafdruk zelf berekend (`HUB_KEY_FINGERPRINT` of het veld op de statuspagina moet kloppen).
- De koppeling staat in `/appdata/secrets/hub-link.json` (0600, atomair, gedeeld door API en worker) in plaats van in
  de database; een oude koppeling wordt bij de eerste start eenmalig overgezet en daarna uit de database verwijderd.
- Inkomend alleen Hub-JWT's: gebruikers-JWT (`token_use: user`) of dienst-JWT (`token_use: hub_service`). Een
  `Bearer`-service-token wordt geweigerd (`service_token_not_accepted`). Vaste Engelse `reason`-waarden (§4.7);
  `jti` op elke JWT; replaycache op `(iss, jti)` voor elke mutatie (migratie `0003`).
- Hub-sleutels worden gepind; de JWKS wordt niet meer via HTTP opgehaald. Nieuwe sleutels alleen via een
  ondertekende rotatie (`/api/v1/auth/key-rotations`) of opnieuw koppelen. Instellingen `HCH_JWKS_*` vervallen.
- Routes `GET /integrations/v1/enrollment` en `POST /integrations/v1/enrollment/unpair` vervangen door
  `GET /connector/v1/hub-link` en `POST /connector/v1/hub-link/unlink`. De lokale ontkoppelcode en het formulier
  `/ontkoppelen` bestaan niet meer.
- Statuspagina: koppelformulier alleen zolang de dienst nog nooit gekoppeld is, met verplichte Hub-vingerafdruk;
  rate-limit 5 pogingen per 15 min per bron-IP en 20 per dienst.

**Nieuw**
- Bevestigen met `services/self` (ook periodiek), intrekking pas na 401 op `services/self`, tokenrotatie op
  `Hub-Token-Rotation: required` (ook na een onderbroken rotatie), herhaling na herstart halverwege (§3.6).
- `HUB_KEY_FINGERPRINT`; `ENROLLMENT_TOKEN` wordt nog één release gelezen met een waarschuwing.
- Alle uitgaande calls negeren proxy-omgevingsvariabelen en volgen geen redirects.
- Image: geen `dumb-init` meer; de bewaker is PID 1, ruimt zombies op, draait als 568 zonder capabilities en zet zelf
  `PR_SET_NO_NEW_PRIVS`. De rooktest draait zoals het TrueNAS-formulier (zonder no-new-privileges en cap-drop) en
  controleert elk proces.
- Manifest volgens §9 (geldig volgens de validator van appstore-en-fork); `CUSTOM_APP.md` met tag + digest en
  registry-login alleen als terugval.
- Kopie van `PLATFORM_CONTRACTEN.md` en `CONTRACT_1.2_CONFORMITEIT.md` met een test op byte-gelijkheid;
  `EVIDENCE.json` volgens §11 (alleen vaste validatiewaarden).

## 0.1.0 — P1-aanvulling B13-002…005 (nog niet uitgebracht)

**Nieuw**
- Authentik via de officiële API (`/api/v3`), **alleen lezen**: versiedetectie, API-capabilities per versie
  (gecontroleerd tegen de officiële `schema.yml` van 2024.10 t/m 2026.8), least-privilege-controle van het token,
  geschoonde toestand (whitelist; nooit `client_secret`, sleutels, e-mail of attributen).
- B13-002: `POST /connector/v1/propose` met `sso.oidc.hub.register` — OIDC-provider + applicatie voor de Hub als
  R2-voorstel met diff, exacte verzoeken, `resource_etag`, `preview_hash`, rollbackrecept; `expected_version`-drift →
  409. Toepassen eerlijk `501 nog_niet_toepasbaar` (in de database afgedwongen). Alleen-lezen controle van een
  bestaande Hub-client (`GET /integrations/v1/sso/oidc/hub/check`).
- B13-002: replaybescherming — een Hub-JWT (`jti`) mag voor één wijziging gebruikt worden (retry met dezelfde
  `Idempotency-Key` blijft mogen); wijziging zonder `jti` geweigerd.
- B13-003: SSO-dekkingsmatrix met bron (docs-URL/broncode + datum + verificatiestatus) per app, loginroute
  native/oidc met handmatige installatiecontrole, groep → rol per app.
- B13-004: Authentik-events (logins, wijzigingen) met watermerk, afwijkingsregels als events naar de Hub,
  rechtenkaart met verschillen en `sso.access.revoked`; worker elke 300 s (`HCH_AUTHENTIK_SYNC_INTERVAL_S`).
- B13-005: configuratie-export (API + geredigeerde flow-blueprints + MFA-apparaten van beheerders), pre-upgrade-gate
  volgens de officiële upgraderegels (nooit "groen" op aannames), herstelcheck, voorstel `sso.sessions.revoke`.
- Migratie `0002` (alleen nieuwe tabellen). Nep-Authentik voor unit-, integratie- en dienst-E2E-tests.

**Nulmeting/omgeving**
- Rooktest leest geheimen en de back-upmap via een wegwerpcontainer (werkte alleen als root); test met verkeerde
  rechten deterministisch. Back-uptest kiest de nieuwste `pg_restore` (machines met meerdere PostgreSQL-clients).
- Integratietests maken de database ~50× sneller leeg (DELETE i.p.v. TRUNCATE).

**Review P1 (onafhankelijke QA, ADR-0009)**
- Eventtypen `sso.authentik.sync.failed`, `sso.authentik.upgrade_gate.evaluated` en
  `sso.authentik.restore_check.completed` hernoemd naar `sso.authentik_sync.failed`,
  `sso.authentik_upgrade_gate.evaluated` en `sso.authentik_restore_check.completed` (contract §7; de Hub-inbox weigerde
  vier segmenten). `events.emit` dwingt het patroon af; lange id's afgekapt, te grote payload ingekort.
- Least privilege van het Authentik-token nooit meer `ok`: `te_ruim` / `onbekend` / `deels_gecontroleerd`
  (systeemrechten gecontroleerd, rolrechten niet via de API te zien).
- `/sso/rights` wordt `verouderd` als Authentik niet meer volledig gelezen kan worden (velden `freshness`,
  `snapshot_taken_at`).
- Controle van een bestaande Hub-client: alleen actieve, niet-omgekeerde bindingen tellen; ontbrekende groepen →
  afwijking.
- Een gat in de Authentik-events wordt een blijvende afwijking `events_onvolledig`.

**Validatie:** Sim-getest (nep-Hub, nep-Authentik). NIET GEVALIDEERD met een echte Authentik, domeinnaam (D17) of NAS.

## 0.1.0 — P0 (nog niet uitgebracht)

**Nieuw**
- Integratiedienst `integrations` (FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 16) op poort 30420.
- Contract 1.1: foutformaat met `trace_id`, `Idempotency-Key` op alle mutaties, ETag/If-Match, cursor-paginering,
  `/healthz` + `/readyz`, connectorcontract (`discover`, `health`, `items`, `evidence`, `events`; `propose`, `apply`
  en `rollback` geven eerlijk `501 capability_unavailable`), outbox met event-envelope en push naar de Hub-inbox.
- Authenticatie: Hub-JWT (EdDSA, `iss=hub`, `aud=home-control-hub`, levensduur ≤ 120 s) via een JWKS-cache die
  fail-closed is; service-token uit de enrollment.
- Koppelen met de Hub: eenmalig token uit de omgeving (worker) of koppelcode op de statuspagina; zonder Hub eerlijk
  *niet gekoppeld*; ontkoppelen met de lokale ontkoppelcode uit de app-log.
- B13-001: herstelregister voor beheeraccounts zonder geheimen, herstelmethodes (minstens twee, waarvan één zonder
  SSO), noodtoegang alleen vanaf LAN/VPN-bereiken met sessieduur en herbevestiging, zelftest die werkt met Authentik
  offline, handmatige oefeningen, activaties met rotatieplicht, versleutelde herstelkit (scrypt + AES-256-GCM).
- B10/B11/B14: datamodellen met database-invarianten (geen malware zonder bewijs, meters altijd alleen-lezen, geen
  CPU-schatting zonder kalibratie, netwerkwijzigingen minimaal R2) en inventaris; SSO-dekkingsmatrix en
  energie-dekkingsmatrix met status *te verifiëren*/*onbekend*.
- Alles-in-één image met procesbewaker, first-start-init van `/appdata/secrets`, back-up vóór migraties en
  healthcheck; installatie-instructie voor het standaard TrueNAS Custom App-formulier; manifest; CI en release.

**Aangescherpt na de onafhankelijke P0-review** (ADR-0006)
- Geen migratie zonder geslaagde back-up vooraf (was: migratie ging door als `pg_dump` mislukte).
- Verzoeken > 1 MiB worden vóór de authenticatie geweigerd (`413 payload_too_large`).
- Herstelkit openen begrensd (geheugen van de sleutelafleiding, nonce, formaat); geen 500 meer bij vreemde kits.
- Statuspagina toont alleen het totaalniveau van het herstelregister.
- Ongebruikte instellingen `HCH_TRUSTED_PROXIES` en `HCH_EMERGENCY_ADMIN_MAX_DAYS` verwijderd.
- Extra tests: auth/rollen/Idempotency-Key op elke route, JWT-randgevallen, B13-003 (geen header-SSO), B10-002 in
  het datamodel, back-up vóór migratie; rooktest met minimale capabilities en controle op dataverlies.

**Validatie:** Unit-, integratie- (PostgreSQL) en dienst-E2E-tests met simulators; image-rooktest in Docker.
NIET GEVALIDEERD op een echte NAS, met echte Authentik of met echte accounts.
