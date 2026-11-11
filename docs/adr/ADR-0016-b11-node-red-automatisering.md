# ADR-0016 — B11 Node-RED-automatisering (B11-001…005, fase P2)

Status: aanvaard · Datum: 2026-11-11 · Fase: P2 · Bouwplan `B11_AUTOMATISERING.md`, installatie `I10_NODE_RED.md`,
platformcontract `contracts 1.3` (§4, §5, §6, §7, §8) · Volgt op ADR-0015

## Context

Tot nu toe had B11 alleen een datamodel en een inventaris; de data-endpoints gaven `501 capability_unavailable`.
Deze ronde bouwt de vijf werkpakketten:

| ID | Acceptatie uit de Excel |
|---|---|
| B11-001 flow-netwerkisolatie | Viewer kan de editor niet bereiken en een custom exec-node is geblokkeerd |
| B11-002 eventtypencatalogus | Een event met onbekende schema-versie verdwijnt niet stil |
| B11-003 veilige acties | Een flow mag zonder admin geen dataset-delete uitvoeren |
| B11-004 simulatie en tests | Geen echte apparaten gewijzigd tijdens een test |
| B11-005 herstel en versiebeheer | Undo herstelt oude flows inclusief credentials zonder geheimen te loggen |

**Wat wel en niet is gemeten**

- Alles is getest met een in-repo Node-RED-simulator (`apps/api/tests/fakes/node_red_fake.py`) en een Hub-simulator
  (`tests/e2e/sim_hub.py`): **Sim-getest**.
- De aannames over Node-RED zelf zijn daarnaast nagemeten tegen de **gepinde officiële image** in lokale
  Docker-containers op de ontwikkelmachine (`tools/node_red_verify.py`, 39 controles, uitkomst in
  `docs/b11/node-red-verificatie.json`). De simulator volgt precies die gemeten feiten
  (`test_fake_matches_the_verified_image_facts`). Die meting is gedaan met het eigen profiel van deze dienst
  (gebruiker 1000, eigen argumenten), niet met het manifest van `jelly-leon-platform` (zie besluit 1).
- NIET GEVALIDEERD (echte NAS): niet als Custom App op TrueNAS geïnstalleerd; zie STAPPEN_P6.md.
- **NIET GEVALIDEERD (echte NAS):** de installatie via het Custom App-formulier, de netwerkafscherming op de NAS, de
  dataset-rechten, een echte Hub die actieverzoeken beoordeelt en echte apparaten.

## Besluiten

### 1. Node-RED is een eigen standaard Custom App; deze dienst leest en bewaakt

- **Installatieweg (bijgewerkt 2026-11-11, besluiten C-11 en C-12 van de gebruiker):** Node-RED wordt geïnstalleerd
  als standaard Custom App volgens het manifest van `jelly-leon-platform` (`install/manifests/node-red.manifest.yaml`,
  ADR-0023 daar; installatiestap I10 hoort bij die repo), nooit met YAML of compose. Dat manifest draait Node-RED als
  568:568 en zet de instellingen via de omgevingsvariabele `FLOWS`. `deploy/truenas/NODE_RED_CUSTOM_APP.md` verwijst
  daarnaar en beschrijft alleen wat in deze dienst wordt ingesteld; het bevat geen eigen formuliervelden.
- **Besluit C-11:** geen anonieme toegang tot de editor; alleen bruikbaar via een beheerder. De controle
  `anoniem_geweigerd` (401) blijft zoals hij is. Het manifest van `jelly-leon-platform` volgt dit pas na stap
  S-P2-410 (tot dan "anoniem alleen lezen"). De controle draait alleen als deze dienst zich kan aanmelden: zodra er
  een dienstaccount is (besluit C-12) en het manifest nog "anoniem alleen lezen" heeft, geeft ze een afwijking.
  Zonder dienstaccount (zo staat het bij een Node-RED volgens het manifest tot de voorziening van C-12) meet de
  dienst niets: `snapshots.run_isolation_check` geeft `onbekend` met de fout `geen_aanmelding` en een lege lijst
  controles (`nodered.client_from_source`), en de andere routes geven `409 node_red_niet_ingesteld`.
- **Besluit C-12:** het beveiligingsprofiel hieronder is een tweede beschrijving van de installatie en zet geheimen
  (wachtwoord-hashes, `credentialSecret`) in het Custom App-formulier, tegen contract §3.1 ("Nooit geheimen in het
  Custom App-formulier"). De manifeststandaard (`appstore-en-fork`) krijgt een voorziening voor een beheerder en een
  dienstaccount zonder geheim in het formulier (ontwerp in stap S-P2-510, bouw na fase P2); het profiel vervalt
  daarna of wordt daaraan gelijkgetrokken. Tot dan wordt het profiel niet gewijzigd of uitgebreid, en het is geen
  installatiestap. Wat hieronder over het profiel staat, beschrijft de bestaande code.
- Image `docker.io/nodered/node-red`, tag `5.0.9`, vastgezet op de digest van de multi-arch-index
  (`catalog.NODE_RED_DIGEST`); dezelfde digest als in het manifest van `jelly-leon-platform` (daar tag `5.0.9-24`).
- Het profiel zet de instellingen als **argumenten** (`--define=<sleutel>=<waarde>`, één per regel, zonder shell).
  Gemeten: de omgevingsvariabele `NODE_RED_CREDENTIAL_SECRET` wordt door de image **niet** gebruikt; alleen
  `--define=credentialSecret=…` werkt. Gevolg: met het profiel staan de `credentialSecret` en de bcrypt-hashes in de
  formulierwaarden van TrueNAS. Dit is gemeld als contractpunt (zie onderaan) en is de aanleiding van besluit C-12.
- `POST /integrations/v1/automation/hardening-profile` (alleen beheerder) maakt die argumenten: `adminAuth` met twee
  accounts (`hub-dienst` met alleen `flows.read`, `flows.write`, `nodes.read`, `settings.read`, `diagnostics.read`;
  `beheerder` voor de editor), `nodesExcludes` (`90-exec.js`), geen externe modules, geen palette-installatie, een
  eigen `credentialSecret`. Het beheerwachtwoord en de argumenten worden één keer getoond; bewaard blijft alleen wat
  de dienst zelf nodig heeft, versleuteld in de vault. Een herhaald verzoek met dezelfde `Idempotency-Key` krijgt het
  gemaskeerde antwoord.
- De dienst **weigert een onbeveiligde Node-RED** (`niet_beveiligd`): zonder aanmelding wordt er niets gelezen en
  niets geschreven.

### 2. Isolatie wordt gemeten, niet aangenomen (B11-001)

- `POST …/automation/isolation/check` meet wat via de admin-API meetbaar is: aanmelding verplicht, anoniem 401,
  exec-node niet geladen, alleen modules van de allowlist (`HCH_NODE_RED_ALLOWED_MODULES`, standaard alleen de kern
  `node-red`), geen externe modules in function-nodes, credentials met een eigen sleutel, rechten van het
  dienstaccount.
- Wat alleen op de NAS zelf te zien is (`niet_root`, `geen_docker_socket`, `prive_netwerk`) krijgt de stand
  `niet_meetbaar` en staat als controlelijst in `deploy/truenas/NODE_RED_CUSTOM_APP.md`. Het wordt nooit als
  "in orde" gemeld.
- Een meting ouder dan 15 minuten telt niet meer: de stand is dan `onbekend`.
- **De editor:** `GET …/automation/editor` geeft het adres alleen aan een beheerder (viewer en operator: 403). Node-RED
  zelf vraagt daarnaast een eigen aanmelding. Deze dienst is geen proxy voor de editor.
- **Exec-node en grof blokkeren:** gemeten is dat Node-RED een flow met een uitgesloten exec-node gewoon aanneemt
  (de node draait niet, maar de flow staat er). Daarom scant de dienst elke gelezen configuratie zelf: elke node (in
  een tabblad, in een subflow of als configuratienode, gebruikt of niet) tegen de verboden typen, de geïnstalleerde
  typen en de allowlist, én of hij elke node kan plaatsen. Niet te plaatsen is: een element dat geen object is met
  `id` en `type` als niet-lege tekst, `z` als tekst (of zonder `z`: een configuratienode), `wires` als lijst van
  lijsten met teksten en `links` als lijst met teksten (`vorm_ongeldig`); een dubbele id (`dubbele_id`); een node met
  een `z` die geen tabblad of subflow is (`tabblad_onbekend`); een draad of link naar een id die nergens staat,
  bijvoorbeeld de id `<instantie>-<node>` die Node-RED een node in een subflow-instantie pas tijdens het draaien
  geeft (`verwijzing_onbekend`); en een draad of link van of naar iets wat geen node in een tabblad of subflow is,
  zoals een configuratienode zonder `z` of een tabblad zelf (`niet_plaatsbaar`). **Besluit van de gebruiker
  (2026-11-11, "grof blokkeren"):** staat er **ergens** in de configuratie iets verbodens of iets wat de dienst niet
  kan plaatsen, dan worden **alle** flows van de bron geblokkeerd tot het weg is. Reden: Node-RED levert berichten
  tussen tabbladen ook af langs wegen die een scan per tabblad niet betrouwbaar volgt (gemeten op de gepinde image:
  een junction of `link in` zonder `z`, een uitgang als tekst, een draad naar een subflow-instantie-id, een dubbele
  id, een `z` als lijst); de dienst bootst Node-RED niet na om een uitzondering te maken. Voor de melding blijft de
  precieze uitkomst per tabblad: het tabblad met de oorzaak, of dat er via een subflow, een configuratienode, een
  gewone draad, een link-node of een eigenschap mee verbonden is, krijgt de bevinding zelf (`verboden_node`,
  `onbekend_type`, `module_niet_toegestaan` of een van de codes hierboven; een niet te plaatsen node met de `z` van
  een bekend tabblad telt voor dat tabblad); elk ander tabblad krijgt de reden `bron_geblokkeerd`, met per oorzaak
  de code, de node en de plaats (tabblad, subflow of `configuratie`). Zo'n flow wordt **geblokkeerd**, en per flow
  gaat een event `flow.policy.blocked` naar de Hub. Een geblokkeerde flow krijgt geen events (ook afleveringen die
  al wachtten, blijven staan) en geen nieuwe tokens; elk actieverzoek wordt geweigerd (403) en vastgelegd, met reden
  `flow_geblokkeerd`, of de eigen reden als het verzoek ook om een andere reden niet mag (bijvoorbeeld
  `onbekende_actie`); er gaat dan geen actieverzoek naar de Hub (wel, zoals bij elke weigering, het event
  `flow.action.rejected`). Een bestaand token blijft bestaan, maar opent alleen nog: de eigen stand lezen
  (`GET …/flow-api/me` toont de status en de reden, en `GET …/flow-api/actions/{id}`), `claim` (geeft niets) en het
  bevestigen (`ack`/`nack`) van een aflevering die al vóór de blokkade was opgehaald; die wordt niet opnieuw
  afgeleverd zolang de flow geblokkeerd is. Er gaat dus niets naar de flow en geen actieverzoek van de flow naar de
  Hub. Is de oorzaak weg, dan blijft elke flow die geblokkeerd was gepauzeerd tot een beheerder of operator hem
  bewust hervat (ook een flow die alleen `bron_geblokkeerd` was).
- **Grens van de blokkade:** de blokkade geldt voor wat deze dienst doet (events afleveren, actieverzoeken
  doorsturen, tokens uitgeven); Node-RED zelf blijft de flows draaien. Omdat bij elke bevinding alle flows van de
  bron geblokkeerd zijn, maakt het voor de blokkade niet uit langs welke weg tabbladen tijdens het draaien berichten
  delen zonder dat het in de configuratie staat (de global context, een `http in` in het ene tabblad die een
  `http request` uit het andere naar Node-RED zelf ontvangt, mqtt of websocket via een broker, tcp/udp en bestanden):
  een niet-geblokkeerd tabblad naast een geblokkeerd bestaat niet. Wat de scan niet ziet, is wat een toegestane node
  tijdens het draaien doet. De harde grens ligt daarom bij Node-RED zelf: met het manifest van jelly-leon-platform
  (`install/manifests/node-red.manifest.yaml`) laadt Node-RED alleen de kernnodes uit `nodesIncludes` (geen exec,
  function, file, mqtt, `http in`, websocket, tcp of udp; wel `http request`), staat installeren via het palet uit en
  kunnen function-nodes geen externe modules laden. De scan is daarbovenop de vangst voor wat Node-RED toch aanneemt.
  Die kanalen zijn niet getest, alleen vastgesteld uit de werking van Node-RED.

### 3. Eventtypencatalogus en afleveren (B11-002)

- De catalogus volgt §7: domeinen per eigenaar, de gedeelde domeinen `app` en `service` alleen met de vaste typen en
  alleen over de eigen app, en per type een schema per versie.
- Elk aangeboden event wordt bewaard met een catalogusstatus. Een **onbekende schema-versie** wordt bewaard, is
  zichtbaar in `GET …/automation/events`, wordt niet afgeleverd en geeft een event `automation.event.rejected` (één
  keer per uur per soort). Het antwoord is dan `202` met `catalog_status`, niet `201`.
- Een **kapotte envelope** (onbekend veld, verkeerd type) is `422` en wordt niet bewaard: daar is niets betrouwbaars
  aan om te tonen.
- Afleveren gaat per flow en **per bron in volgorde**: een mislukte aflevering houdt latere events van dezelfde bron
  tegen. Herhalen met oplopende wachttijd, na 10 pogingen `dead_letter` (zichtbaar, opnieuw aan te bieden door een
  operator). Dubbele events worden één keer afgeleverd.
- **Lussen:** elk actieverzoek draagt de keten van flows mee. Een event dat door een eigen actie van de flow is
  veroorzaakt, gaat niet naar die flow terug; een keten langer dan 8 wordt geweigerd.
- Events met classificatie `sensitive` of hoger gaan nooit naar een flow.
- **Bron van de events:** `POST …/automation/events` neemt alleen een dienst-JWT van de Hub aan. De eigen events van
  deze dienst (outbox) biedt de worker zelf aan de flows aan.

### 4. Flows vragen aan, de Hub beslist (B11-003)

- Een flow praat met een eigen **flow-API** (`/integrations/v1/automation/flow-api/*`) en een **flow-token** (`flw_…`,
  één keer getoond, alleen de hash bewaard, per flow, met een lijst toegestane acties). Een flow krijgt pas een token
  als hij een eigenaar heeft.
- De flow-API opent niets anders: met een flow-token is elke andere route `401`, en een Hub-JWT (ook van een
  beheerder) is op de flow-API `401 flow_token_ongeldig`.
- `POST …/flow-api/actions` voert **nooit** iets uit. Een toegestaan verzoek wordt een event `flow.action.requested`
  voor de Hub; de Hub maakt er een ActionProposal van en beslist met zijn eigen policy. Een `risk_claim` van de flow
  wordt bewaard als informatie en verder genegeerd.
- **Alleen de vaste lijst (fail-closed).** Een flow mag alleen de acties van de executor-allowlist v1 uit contract §8
  aanvragen, zonder `app.uninstall_data` (die wordt nooit aangeboden): `notification.send`, `app.restart`,
  `app.stop`, `app.start`, `app.install`, `app.update`, `app.rollback`, `app.uninstall`, `zfs.snapshot.create` en
  `zfs.snapshot.clone_to_sandbox` (`actions.FLOW_ACTIONS`). Elke andere actie wordt hier al geweigerd met
  `onbekende_actie`, ook als ze onder een andere naam iets verwijdert, terugdraait of schakelt (bijvoorbeeld
  `zfs.dataset.rm`, `zfs.snapshot.rollback` of `energy.device.switch`). Opdrachten voor apparaten in huis lopen via
  het beleid van my_house (B11-003), niet via een flow. Een nieuwe actie voor flows vraagt eerst een regel in contract
  §8 en daarna een bewuste wijziging van de lijst; een test vergelijkt de lijst met de tabel in de contractkopie.
- **Altijd geweigerd**, ook als een beheerder het token ruim heeft gemaakt (`403` met `details.reason`, plus een
  event `flow.action.rejected`; ernst `hoog` bij `boiler_nooit`, `shell_verboden`, `destructief_verboden`,
  `onbekende_actie`, `ongeldige_tekens` en `emby_nooit_door_platform`):
  - `ongeldige_tekens` — het doel (sleutels en waarden) en de namen van parameters mogen alleen zichtbare
    ASCII-tekens en de spatie bevatten: geen onzichtbare tekens (zoals een zero-width space), geen letters uit een
    ander schrift;
  - `boiler_nooit` — actie-ID en doel worden altijd doorzocht; ook parameters, behalve bij acties die alleen tekst
    afleveren (`notification.send`), zodat een melding óver de boiler wel kan. Elke tekst wordt eerst genormaliseerd
    (NFKC, zonder accenten, onzichtbare tekens en scheidingstekens), zodat ook `boi ler` of `Hot Water` telt;
  - `emby_nooit_door_platform` — elk verzoek met Emby als doel (contract §2.3 regel 3; dezelfde herkenning als
    `policy/apps.yaml` van de Hub, hier ruimer: elk doel met "emby" in een waarde);
  - `destructief_verboden` — verwijderen of wissen, bijvoorbeeld `zfs.dataset.delete`;
  - `shell_verboden`, `beleid_verboden`, `betaald_verboden`, `geheim_in_parameters`, `onbekende_actie`.
- **"Zonder admin" is streng gelezen:** een destructieve actie kan nooit via een flow, ook niet met goedkeuring. Wie
  een dataset wil verwijderen, doet dat zelf in de Hub.
- Een tokenscope mag alleen acties van de vaste lijst bevatten, of een patroon `<voorvoegsel>.*` dat minstens één
  actie van die lijst dekt (`app.*`, `zfs.*`, `zfs.snapshot.*`); anders wordt het token al bij het uitgeven
  geweigerd (`422`), bijvoorbeeld bij `energy.*` of `media.*`. Een patroon dekt nooit meer dan de acties van de
  lijst.
- **Ontdubbeling:** hetzelfde event dat vijf keer binnenkomt geeft één aflevering en één actieverzoek (sleutel over
  flow, event, actie en exacte parameters). Elke mutatie vraagt een `Idempotency-Key`.
- **Grenzen:** standaard 30 verzoeken per uur per flow en actie, en daarnaast 30 per uur per flow over alle acties
  samen; ook geweigerde verzoeken tellen mee (elk verzoek is een event naar de Hub), zodat een ruime scope geen
  onbegrensde stroom verzoeken geeft. Een rij `*` in de grenzen van een flow geldt voor alle acties van die flow
  samen. Een beheerder kan dit alleen strenger zetten. Een afgeremd verzoek (`429`) wordt niet vastgelegd.
- Zonder koppeling met de Hub is een verzoek `503 hub_unavailable`: er wordt niets in een wachtrij gezet dat later
  ongezien alsnog uitgevoerd zou worden.
- De Hub meldt de uitkomst terug met `POST …/action-requests/{id}/result` (alleen dienst-JWT). Een eindstand
  (`uitgevoerd`, `geweigerd`, `mislukt`) verandert daarna niet meer.

### 5. Proefrun (B11-004)

- Een proefrun levert **vaste voorbeeld-events** af (alleen-lezen, met checksum, gemarkeerd als voorbeeld). Een
  gewijzigde voorbeeldset is een fout, geen stil succes.
- Tijdens een proefrun krijgt elk actieverzoek het antwoord `gesimuleerd`: er gaat niets naar de Hub, de
  verzoeklimiet wordt niet aangesproken en er wordt niets op Node-RED geschreven.
- **Grens van de afscherming (eerlijk gemeld):** de dienst kan alleen het pad via de flow-API afschermen. Een flow
  met nodes die zelf naar buiten gaan (HTTP, MQTT, TCP, …) kan de dienst niet tegenhouden. Zo'n proefrun start
  alleen na een uitdrukkelijke bevestiging (`bevestig_niet_afgeschermd`), en de run zegt dat erbij.
- Eén proefrun tegelijk per flow; een verlaten proefrun verloopt na 15 minuten, daarna stromen echte events weer.

### 6. Versies en herstel (B11-005)

- **Momentopnamen:** de worker leest Node-RED elke `HCH_NODE_RED_SYNC_INTERVAL_S` seconden (standaard 60; `0` = uit)
  en legt bij een wijziging een momentopname vast, versleuteld in de eigen vault (AES-GCM, gebonden aan de
  momentopname). Een beheerder kan er ook zelf één maken.
- **Credentials:** `GET /flows` geeft nooit credentials terug (gemeten). Ze komen alleen mee als de datamap van
  Node-RED **alleen-lezen** aan deze app is gekoppeld (`HCH_NODE_RED_DATA_DIR`), en dan alleen als het door Node-RED
  zelf versleutelde blok uit `flows_cred.json`. Een onversleuteld bestand wordt nooit meegenomen. Node-RED schrijft
  zelf in die map: het bestand wordt daarom nooit via een symbolische koppeling gelezen, moet een gewoon bestand
  zijn (geen FIFO, map of apparaat) en wordt begrensd gelezen (hooguit 4 MiB); anders is de stand `onleesbaar`.
  Zonder die koppeling zegt de momentopname `credentials_status: niet_gekoppeld`. De code leest alleen dat bestand en
  ontsleutelt het niet. Dat is geen afscherming: bij een Node-RED volgens het manifest van `jelly-leon-platform`
  (geen eigen `credentialSecret`) staat de sleutel in dezelfde dataset (`.config.runtime.json`), en een koppeling
  van die dataset geeft deze dienst (ook 568) leestoegang tot de sleutel. De installatiedocumenten raden die
  koppeling daarom af; een koppeling zonder de sleutel volgt pas na een besluit (voorziening C-12, S-P2-510). De
  meting in `docs/b11/node-red-verificatie.json` is gedaan met het eigen profiel, waar de sleutel een argument was.
- **Diff:** alleen nodes en veldnamen, nooit waarden.
- **Herstellen is een voorstel plus een ondertekende opdracht:**
  1. `POST /connector/v1/propose` met `automation.flows.restore` maakt een voorstel (R2) met diff, `preview_hash` en
     `resource_etag`. Er verandert niets.
  2. `POST /connector/v1/apply` voert alleen uit met een door de Hub **ondertekend ExecutionRequest**. De dienst
     controleert zelf opnieuw: handtekening (Ed25519 over canonieke JSON, tegen de gepinde Hub-sleutels),
     geldigheid (hooguit 15 minuten), nonce, actie op de allowlist, parameterschema, risicoklasse (eigen berekening
     is de ondergrens), goedkeuring door een mens gebonden aan precies deze diff, en de precondities (Node-RED
     ongewijzigd sinds het voorstel).
  3. Vóór het schrijven wordt de huidige stand als momentopname vastgelegd; na het schrijven leest de dienst terug
     en vergelijkt de checksum.
- **Wie mag `apply` aanroepen:** een beheerder of de Hub-dienst. De bescherming zit in de ondertekende opdracht, niet
  in wie hem aflevert.
- **Geen spoor bij onzin:** een verzoek zonder geldige vorm, handtekening of geldigheid wordt geweigerd en nergens
  vastgelegd. Een geldig ondertekend verzoek dat om een andere reden wordt geweigerd, wordt wél vastgelegd; de nonce
  is dan verbruikt.
- **Herhalen:** dezelfde `Idempotency-Key` geeft hetzelfde antwoord; hetzelfde verzoek met een nieuwe sleutel is
  `409 nonce_al_gebruikt`. Een onderbroken herstel wordt nooit blind herhaald: eerst teruglezen.
- **Terugdraaien:** `POST /connector/v1/rollback` blijft `501`. Een herstel draai je terug met een nieuw voorstel
  naar de momentopname van vóór het herstel.
- **Andere `credentialSecret`:** Node-RED weigert het blok dan zelf (gemeten: `400`); er verandert niets en de dienst
  meldt `credentials_niet_te_ontsleutelen`.
- Een momentopname met een flow die inmiddels verboden is, kan niet worden teruggezet.
- De acties `sso.*` blijven op `apply` `501 capability_unavailable` (reden `nog_niet_toepasbaar`), zonder een nonce
  te verbruiken. `discover` noemt `apply` alleen voor `automation.flows.restore`.

### 7. Foutcodes

| Situatie | Antwoord |
|---|---|
| Node-RED niet ingesteld of onbeveiligd | `409 node_red_niet_ingesteld` |
| Node-RED onbereikbaar | `503 node_red_unavailable` met `Retry-After: 30` |
| Node-RED antwoordt met een fout | `502 node_red_fout` |
| Weigering door beleid | `403 forbidden` met `details.reason` |
| Te veel verzoeken van een flow | `429 rate_limited` |
| Hub niet gekoppeld bij een actieverzoek | `503 hub_unavailable` |

Een storing van Node-RED is nooit een succes: er is geen gesimuleerd resultaat.

### 8. Health

De connector-health krijgt een eigen check `automatisering`, alleen als Node-RED is ingesteld ("niet ingesteld" is
geen meting). `degraded` bij een gemeten afwijking in de isolatie, een mislukte synchronisatie
(`synchronisatie_mislukt`), een geblokkeerde flow of een `dead_letter`; `unknown` als de isolatie niet vers is
gemeten.

## Gevolgen

- Migratie `0005` (momentopnamen, flow-tokens, events, afleveringen, herstel). Terug naar een oudere image kan alleen
  met de back-up of de dataset-snapshot van vóór de update. Een geweigerd actieverzoek zonder reden (van vóór `0005`,
  of na terug naar `0004`) krijgt bij de upgrade de reden `reden_onbekend`. De upgrade is getest op een gevulde
  `0004`-database (gebruikers en SSO, kluis, audit en de automatiseringstabellen): heen, terug, opnieuw heen en de
  back-up van vóór de upgrade teruggezet, telkens zonder verschil (`test_migratie_0005_gevuld.py`). Rijen die `0005`
  niet kan aannemen (dubbele triggers, een `risk_claim` buiten R0–R3) laten de upgrade in zijn geheel stoppen; de
  database blijft dan ongewijzigd op `0004`.
- Nieuwe afhankelijkheid `bcrypt` (voor de `adminAuth`-hash zoals Node-RED hem verwacht).
- Nieuwe optionele instellingen: `HCH_NODE_RED_SYNC_INTERVAL_S`, `HCH_NODE_RED_DATA_DIR`,
  `HCH_NODE_RED_ALLOWED_MODULES`.
- De schermen (flowoverzicht, triggers, proefrun, versies) horen in de Hub-UI en zijn hier niet gebouwd; deze dienst
  levert de API.

## Meldingen bij het contract

Waar het contract niets zegt of zichzelf tegenspreekt, is de veiligste lezing gekozen:

1. **§4 kent alleen Hub-JWT's.** Een flow in Node-RED kan geen Hub-JWT krijgen. Gekozen: eigen flow-tokens die
   alleen de flow-API openen.
2. **§7 kent geen pad waarlangs de Hub events van andere apps doorstuurt** naar deze dienst, en geen regel dat de
   Hub `correlation_id` of de keten van flows doorgeeft. Gebouwd is de ontvangende kant; zonder Hub-zijde komen er
   alleen eigen events bij flows.
3. **De payload van `flow.action.requested` staat niet in §7** en de Hub heeft er nog geen verwerker voor. Tot dan
   blijft elk verzoek op `aangevraagd` staan.
4. **`automation.flows.restore` staat niet in de actietabel van §8.** Een echte Hub kan er nu geen geldig
   ExecutionRequest voor uitgeven; herstel werkt dus alleen tegen de simulator.
5. **De `policy_hash`** in een ExecutionRequest kan een eigenaar-connector niet tegen een policybestand controleren;
   alleen de vorm en de samenhang worden gecontroleerd.
6. **Het formaat van het ExecutionRequest** staat alleen in `ai-server-manager` (`apps/policy`,
   `docs/EXECUTION_REQUEST.md`), niet in het contract. De `403`-codes daar wijken af van de foutcatalogus in §5;
   hier is §5 gevolgd (`403 forbidden` met `details.reason`).
7. **`preview_hash` en `resource_etag`:** de SSO-voorstellen gebruiken kale hex, het Hub-formaat `sha256:<hex>`.
   Herstelvoorstellen volgen het Hub-formaat; `expected_version` neemt beide aan.
8. **Geen eventdomeinen voor MSO en my_house** in §7, terwijl B11-002 ze noemt. Hun events vallen nu buiten de
   catalogus (bewaard, niet afgeleverd).
9. **Het entiteitstype van `app.health.changed`** ligt in §7 niet vast; alleen de eigenaar wordt gecontroleerd.
10. **Instellingen van een derde app via het formulier:** met het profiel van deze dienst kan dat alleen met
    `--define`-argumenten, waardoor een geheim in de formulierwaarden staat (zie besluit 1). Opgelost door besluit
    C-12: de installatieweg is het manifest van `jelly-leon-platform` (zonder gebruikers en zonder
    `credentialSecret`), en de manifeststandaard krijgt een voorziening voor een beheerder en een dienstaccount
    zonder geheim in het formulier (ontwerp S-P2-510 in `appstore-en-fork`, bouw na P2). Tot die voorziening er is,
    heeft een volgens het manifest geïnstalleerde Node-RED geen beheerder en geen dienstaccount voor deze dienst.
11. **B11-003 "zonder admin"** is gelezen als: nooit via een flow.
12. **B11-004** kan alleen het pad via de flow-API afschermen (zie besluit 5).
