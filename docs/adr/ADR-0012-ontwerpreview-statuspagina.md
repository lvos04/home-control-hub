# ADR-0012 — Onafhankelijke ontwerpreview van de statuspagina (Peil)

Status: aanvaard · Datum: 2026-11-09 · Fase: contract 1.2 §13 (ontwerpreview achteraf) · Ontwerptaal Peil 1.1.0
(`ai-server-manager/docs/platform-v2/ONTWERPTAAL.md`, `design/ontwerptaal/COMPONENTEN.md`, ADR-0015 van
ai-server-manager) · Volgt op ADR-0011 (statuspagina in Peil, zelfreview van de bouwer)

## Context
Contract §13 vraagt na elke UI-bouwstap een ontwerpreview door de ontwerpagent. ADR-0011 had alleen een zelfreview.
Deze review is onafhankelijk gedaan door de ontwerpagent, op de **draaiende dienst**: API en worker als processen, een
eigen PostgreSQL-database per toestand en de Hub-simulator. Chromium vult zelf het koppelformulier in. Er zijn 14
toestanden bekeken, elk op 320/360/390/768/1440 px in licht en donker. De bevindingen, de meetwaarden en de
schermafdrukken staan in `docs/ontwerp/PEIL_REVIEW.md`.

Grens van deze review: **alleen uiterlijk, teksten en toegankelijkheid**. Het sjabloon (`statuspagina.html`/`.css`) is
een versie-gepinde kopie (O-14) en wordt hier niet gewijzigd. Punten in het sjabloon gaan als voorstel naar de
Peil-eigenaar (ai-server-manager). Wat de dienst invult (woorden, redenen, meldingen) is wel aangepast.

## Besluiten
1. **Pilwoord = vast Peil-woord bij het icoon van de toon.** In een controle tekent het sjabloon het icoon van de toon
   (`#i-<toon>`): Onbekend = `circle-help`, Storing = `octagon-x`. Woorden als "Niet gekoppeld", "Ingetrokken",
   "Koppelen bezig", "Niet bevestigd", "Onleesbaar" of "Onvolledig" naast `circle-help`/`octagon-x` braken de vaste
   koppeling "één icoon per betekenis" (ONTWERPTAAL §7) en de woordenlijst (§11.1). Daarom zegt de pil nu **Onbekend**
   of **Storing**, en begint de reden direct eronder met de precieze toestand ("Niet gekoppeld: …", "Ingetrokken door
   de Hub: …"). Het koppelblok houdt zijn eigen pil met `link-2-off`/`link-2` uit het sjabloon. Dat is ook de waarde
   die `/readyz` voor `hub_koppeling` geeft (`unknown`).
2. **Een verouderde meting is nooit groen** (Peil §4.1 regel 4 en §4.4; 05_OPERATIES: "nooit healthy op stale cache").
   De stand van een domein in "Wat deze dienst doet" komt alleen uit **verse** metingen van de ingestelde bronnen.
   Een meting ouder dan **15 minuten** (`BRON_MAX_LEEFTIJD`) telt als Onbekend. De reden zegt dan "Verouderd: laatste
   meting <tijd>, ouder dan 15 minuten; die stand tonen we niet." Vóór deze review toonde een Authentik-meting van drie
   dagen oud nog **Gezond**. Waarom 15 minuten: het contract noemt geen TTL voor bronmetingen, en 15 minuten is gelijk aan
   `inventory_ttl_seconds` van de Hub. Een kortere TTL zou alleen meer "Onbekend" geven, nooit groen ten onrechte.
3. **Onbekend altijd met reden**, ook bij Beheerherstel. Per niveau staat er een vaste zin zonder accountnamen of
   aandachtspunten. Bij Onbekend is dat "Het herstelregister is nog niet volledig ingevuld of getest.". Vroeger stond
   bij elk niveau dezelfde zin, die niet uitlegde waarom het niveau onbekend was.
4. **Koppelen bezig.** De reden noemt nu waarmee gekoppeld wordt (het token uit het Custom App-formulier, of een
   koppelcode) en de laatste melding (bijvoorbeeld "de Hub was niet bereikbaar"). Ook staat er dat het formulier pas weer
   werkt als deze poging klaar is. "Laad de pagina over een minuut opnieuw" is weg: dat was onjuist, want de worker
   blijft het tot 60 minuten proberen.
5. **Na een mislukte poging staat in de melding dat alle velden opnieuw moeten** ("Ingevulde waarden bewaren we bewust
   niet: vul alle velden opnieuw in."). Ingevulde waarden worden om veiligheidsredenen nooit teruggezet (ADR-0011
   besluit 6). WCAG 2.2 3.3.7 (Redundant Entry) staat dat toe, maar de gebruiker moet het wel weten. Bij wachten
   (`te_veel_pogingen`, `rate_limited`, `koppelen_bezig`) en bij `al_gekoppeld` staat de zin er niet, want opnieuw
   invullen helpt dan niet.
6. **Microcopy volgens de woordenlijst.**
   - De kop is korter. "TrueNAS Home Platform" staat al op de regel erboven en "Alle schermen staan in de Hub" in de voet.
   - Het totaal noemt het blok waar de afwijkingen staan: "Gereed. Wat deze dienst doet: 1 storing · 1 beperkt ·
     1 onbekend.". Ook geeft het geen kleine letters meer aan eigennamen: "Gereed, maar beperkt: Sleutels van de Hub."
     in plaats van "… sleutels van de hub.".
   - "1 van 1 bron" in het enkelvoud.
   - Na intrekken of ontkoppelen staat er alleen "Opnieuw koppelen gaat via de Hub." zonder "Ontkoppelen".
   - De reden bij een onleesbaar koppelbestand herhaalt de melding niet meer, maar verwijst ernaar.
7. **Geen lange woorden in een melding** (WCAG 1.4.12). Met de tekstafstand van 1.4.12 gaf het woord
   "(HUB_ENROLLMENT_TOKEN)." in de melding bij een onleesbaar koppelbestand 9 px overloop op 320 px. Het sjabloon
   breekt lopende tekst niet. De melding verwijst nu naar de controle, en daar staat de variabelenaam in 14 px in een
   bredere kolom. De gebruiker moet de naam kunnen overnemen, daarom is een onzichtbaar breekteken geen optie.
8. **De betekenis van het totaal verandert niet** (ADR-0011 besluit 5): het totaal is de slechtste van de eigen
   controles en de gereedheid, en de bronnen tellen niet mee. Het Peil-prototype `statuspagina-gekoppeld.html` laat een
   beperkte bron wél meetellen. Dat is een inhoudelijke keuze en geen uiterlijk. Daarom staat het als aanbeveling in
   PEIL_REVIEW.md (A-1); de toelichting naast de pil noemt de afwijkingen al expliciet.
9. **Ontwerpreview als herhaalbare test.** `tests/ui/ontwerpreview.py` (processen en toestanden) en
   `tests/ui/ontwerpreview.mjs` (browser en metingen) draaien in CI in de job `statuspagina-ui`, en lokaal met
   `make ontwerpreview`. *(Correctie, ADR-0013: tot de review van contract 1.2 beoordeelde de CI-stap door een
   padfout 0 metingen; nu faalt het script ook als het aantal metingen niet klopt.)* Het script faalt bij elke
   overtreding van deze eisen:
   - axe WCAG 2.2 AA heeft overtredingen;
   - tekstcontrast is lager dan 4,5:1, of een betekenisdragende rand, een icoon of de focusring is lager dan 3:1;
   - een doel is kleiner dan 44 px, of er is overloop, tekst kleiner dan 14 px of een ellips;
   - een focusring is bedekt of valt buiten beeld;
   - een pil heeft geen icoon of geen woord, onbekend of verouderd is groen, of het totaal is groen terwijl de dienst
     niet gereed is;
   - de CSP ontbreekt of de pagina geeft CSP- of scriptfouten;
   - de tekstafstand van 1.4.12 geeft op 320 px overloop of afgekapte tekst.

## Gevolgen
- Unit-tests zijn er voor elk besluit: pilwoord en icoon, verouderd, reden bij herstel, koppelen bezig, opnieuw invullen
  en de kop. De bestaande tests zijn aangepast aan de nieuwe woorden.
- `/readyz` (`health.py`, controle `bronnen`) gebruikt nog wel de laatst bekende probe zonder leeftijdsgrens. Dat is
  API-gedrag en valt buiten deze review; het staat als vervolgpunt in PEIL_REVIEW.md (V-1). *Opgelost in ADR-0013
  (het ging om de connector-health en de bronweergave in de API, niet om `/readyz`).*
- Validatie: **Sim-getest** (de echte dienst en de Hub-simulator in Chromium). NIET GEVALIDEERD zijn een echte
  schermlezer (NVDA/TalkBack), een echte telefoon in fel licht, de pagina achter de portpublicatie van TrueNAS en de
  echte Hub.

## Gemeld aan de Peil-eigenaar (sjabloon 1.1.0, niet hier te wijzigen)
S-1 ontbrekend beleidsicoon `ban` voor "Alleen meten"; S-2 geen icoon per controle (`link-2-off`, `clock-alert`) en
geen verouderd-variant met arcering; S-3 `role="alert"` vast, ook voor de infomelding en voor een fout die bij het
laden al bestond; S-4 leeg koppelblok bij een onleesbaar koppelbestand en geen aparte weergave voor koppelen bezig (al
gemeld in ADR-0011); S-5 geen "(verplicht)" bij de velden (COMPONENTEN §20); S-6 in de rijen van de controles loopt de
tijd onder 400 px onder de naam door, en niet in alle rijen gelijk; S-7 "Hub openen" als knop; S-8 lopende tekst in
meldingen en redenen breekt niet midden in een woord (`overflow-wrap`). De specificaties staan in PEIL_REVIEW.md
§"Overdracht aan Peil".
