# Ontwerpreview: statuspagina van home-control-hub (Peil 1.1.0, herhaald op Peil 1.1.1)

> **Herhaald op 10 november 2026 (Peil 1.1.1, contract 1.3; ADR-0014).** De gepinde kopie is 1.1.1
> (`ai-server-manager@0a7143b`). Dezelfde review, nu op **320, 360, 390, 768, 1024 en 1440 px** (contract 1.3 §13 =
> ONTWERPTAAL §12), 14 toestanden × 6 breedtes × licht/donker = **168 metingen, 0 overtredingen**: 0 axe (WCAG
> 2.0/2.1/2.2 A en AA, ook 0 best-practice), tekst ≥ **8,34:1**, betekenisdragende randen ≥ 4,86:1, iconen ≥ 5,41:1,
> focusring ≥ 7,79:1, geen overloop, geen doel < 44 px, focus nooit bedekt; elke pil heeft icoon en woord, groen alleen
> met "Gezond" (rij) of "Alles gezond" (totaal); de verouderde meting (Authentik, 3 dagen oud) is nu een
> **Verouderd**-pil (telt niet mee). Daarna de **browsertest van het koppelformulier** tegen dezelfde echte dienst
> (`tests/ui/herkomst.mjs`): Origin `null` (pagina met no-referrer), een vreemde site, een buurapp op hetzelfde adres
> (met het echte formuliertoken), geen cookie en een publieke domeinnaam (DNS-rebinding) → elk 403 met de vaste code en
> niets naar de Hub; daarna koppelt het echte formulier (303). De S-punten van §6 zijn in Peil 1.1.1 opgelost (E01–E10:
> sjabloonblok onleesbaar, koppelen bezig, tonen, meldingsrol, codes, renderer in één doorgang, skiplink, novalidate).
> Afdrukken: `docs/ontwerp/peil-review/` (opnieuw gemaakt). NIET GEVALIDEERD blijven de echte schermlezer, telefoon en
> NAS. De tekst hieronder is de oorspronkelijke review van 1.1.0.

**Soort:** onafhankelijke ontwerpreview achteraf (contract 1.2 §13), door de ontwerpagent, na de bouwstap HC11
(ADR-0011, zelfreview van de bouwer) · **Datum:** 9 november 2026 · **Besluit:**
[ADR-0012](../adr/ADR-0012-ontwerpreview-statuspagina.md)
**Maatstaf (bindend):** `ai-server-manager/docs/platform-v2/ONTWERPTAAL.md` (Peil 1.1.0), `design/ontwerptaal/COMPONENTEN.md`
(C-03, C-14, C-36, C-55), ADR-0015 van ai-server-manager, de prototypes `statuspagina.html` en
`statuspagina-gekoppeld.html` met hun schermafdrukken in `shots/`, en WCAG 2.2 AA.
**Validatie:** **Sim-getest**: de echte dienst draaide als proces tegen de Hub-simulator, in Chromium. NIET GEVALIDEERD
zijn een echte schermlezer (NVDA/TalkBack), een echte telefoon in fel licht, de pagina achter de portpublicatie van TrueNAS
op een echte NAS en een echte Hub.

---

## 1. Oordeel in het kort

De statuspagina volgt Peil goed. Over alle 14 toestanden, op 320, 360, 390, 768 en 1440 px, in licht en donker, gaf de
meting het volgende:

- **0 axe-overtredingen** (WCAG 2.0/2.1/2.2 A en AA, ook geen best-practice-overtredingen);
- alle tekst haalt **≥ 8,34:1** (Peil-eis AAA ≥ 7:1, WCAG ≥ 4,5:1);
- betekenisdragende randen ≥ 4,86:1, iconen ≥ 5,71:1, focusring ≥ 7,79:1;
- geen overloop, geen doel kleiner dan 44 px, geen tekst kleiner dan 14 px;
- de focus is altijd zichtbaar en nergens bedekt;
- elke pil heeft een icoon en een woord.

Het eerste signaal is nooit groen als de dienst niet gereed is.

Toch vond de review één **harde fout tegen Peil**. Een bronmeting van drie dagen oud stond als **Gezond** (groen) in
"Wat deze dienst doet". Peil §4.1 regel 4 zegt: "Verouderde data is nooit gezond". Deze fout is gerepareerd.

Daarnaast zijn zes zwakkere punten gerepareerd, allemaal in wat de dienst zelf invult:

1. Statuswoorden die niet bij hun icoon horen.
2. "Onbekend" zonder reden bij Beheerherstel.
3. Een misleidende wachttijd bij "Koppelen bezig".
4. Na een fout zei de pagina niet dat alle velden opnieuw moeten.
5. Een overloop van 9 px op 320 px met de tekstafstand van WCAG 1.4.12, in de melding bij een onleesbaar koppelbestand.
6. Kleine tekstfouten, zoals "hub" met kleine letter en "1 van 1 bronnen".

Acht punten zitten in het sjabloon zelf. Dat sjabloon is een versie-gepinde kopie en wordt hier niet gewijzigd; de
punten gaan als overdracht naar de Peil-eigenaar (§6).

## 2. Werkwijze

**De echte dienst, geen losse HTML.** `tests/ui/ontwerpreview.py` start de Hub-simulator (`tests/e2e/sim_hub.py`) via
uvicorn. Per toestand start het een eigen home-control-hub: `python -m integrations api`, waar nodig ook `worker`, met een
eigen PostgreSQL-database `hch_review_<n>` en een eigen `/appdata`. Chromium bezoekt de dienst
(`tests/ui/ontwerpreview.mjs`) en vult het koppelformulier zelf in. Dat gaat met de echte CSRF-cookie
(`SameSite=Strict`), de Origin-controle en de 303-doorverwijzing. Omdat een POST-antwoord niet te herladen is, meet het
script per toestand op dezelfde pagina. Het wisselt thema (`prefers-color-scheme`) en breedte zonder te herladen.

| Toestand | Hoe bereikt | HTTP |
|---|---|---|
| `niet-gekoppeld` | nieuwe dienst, nooit gekoppeld | 200 |
| `koppelen-mislukt` | browser verstuurt een onbekende koppelcode met de juiste vingerafdruk; de Hub weigert | 400 `hub_weigerde` |
| `vingerafdruk-onjuist` | geldige koppelcode met de vingerafdruk van een andere Hub | 400 `hub_vingerafdruk_onjuist` |
| `invoer-ongeldig` | Hub-adres met een pad | 422 `ongeldig_hub_adres` |
| `te-veel-pogingen` | zes pogingen achter elkaar vanaf één adres | 429 `te_veel_pogingen` |
| `koppelen-bezig` | token in de Custom App-variabelen, Hub antwoordt niet (de worker probeert het opnieuw) | 200 |
| `gekoppeld` | browser koppelt met een geldige code; melding "Gekoppeld met de Hub" | 303 → 200 |
| `gekoppeld-met-bronnen` | gekoppeld, met testdata: bronnen gezond, beperkt, storing, nooit gemeten en een meting van 3 dagen oud | 200 |
| `niet-bevestigd` | gekoppeld, `confirmed_at` leeg in `hub-link.json` | 200 |
| `sleutelrotatie-geweigerd` | gekoppeld, geweigerde sleutelrotatie in `hub-link.json` | 200 |
| `ingetrokken` | de Hub trekt in; de worker ziet 401 op `services/self` | 200 |
| `ontkoppeld` | de Hub ontkoppelt via `POST /connector/v1/hub-link/unlink` (dienst-JWT) | 200 |
| `niet-gereed` | eigen database onbereikbaar | 200 |
| `onleesbaar` | `hub-link.json` is geen JSON | 200 |

**Metingen per toestand × thema × breedte (140 in totaal):**

- **axe-core 4.14:** de tags `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22a` en `wcag22aa`; best-practice
  apart.
- **Contrast in de gerenderde pagina:** lagen en opacity zijn meegerekend, net als in `bouw/controle.cjs` van Peil.
  - tekst: eis 4,5:1, en 3:1 voor grote tekst;
  - betekenisdragende randen tegen hun omgeving: eis 3:1 (`.pil`, velden, knoppen, `.selecteer`, `.melding`);
  - iconen tegen hun vlak: eis 3:1;
  - focusring tegen de omgeving en tegen de halo: eis 3:1.
- **Aanraakdoelen:** ≥ 44 × 44 px. Alleen inline links in lopende tekst zijn uitgezonderd (WCAG 2.5.8, Peil §6).
- **Lay-out en tekst:** geen overloop, tekst ≥ 14 px, geen ellips.
- **Tab-doorloop:** vanaf het begin. De eerste tabstop moet de skiplink zijn. Elke ring is ≥ 3 px, staat in beeld en
  wordt niet bedekt; dat is per regelvak gemeten.
- **Structuur:** één h1, geen kopsprong, geen dubbele id's, geen kapotte `aria-*`-verwijzing.
- **Peil-regels:**
  - elke pil heeft icoon en woord;
  - geen groen voor Onbekend, Verouderd of "Niet …";
  - een verouderde meting is nooit groen;
  - het totaal is niet groen als de dienst niet gereed is;
  - Onbekend heeft altijd een reden.
- **Eén keer per toestand, op 320 px:** de tekstafstand van WCAG 1.4.12 (regelhoogte 1,5, letters 0,12 em, woorden
  0,16 em, alinea's 2 em) mag geen overloop en geen afgekapte tekst geven. Ook is gecontroleerd dat de CSP
  `default-src 'none'` is en dat er geen CSP- of paginafouten zijn.

Daarnaast zijn alle schermafdrukken met het oog vergeleken met de prototypes `statuspagina*.html` (shots 360–1440). Ook
zijn de ingevulde teksten nagelopen tegen de woordenlijst (ONTWERPTAAL §11).

**Gebruikte vaardigheden:** design-critique (indeling van §4), accessibility-review (§4.5), ux-copy (§4.6),
design-system (§4.4), design-handoff (§6). De dataviz-vaardigheid is niet gebruikt: op de statuspagina staan geen
grafieken, dus er was geen grafiekkeuze te maken.

**Opnieuw draaien:**
```sh
make ontwerpreview        # = python tests/ui/ontwerpreview.py → tests/ui/review-uit/ (JSON per toestand, samenvatting.json, afdrukken/)
```
CI draait dezelfde stap in de job `statuspagina-ui` en bewaart `tests/ui/review-uit/` als artefact `statuspagina-peil`.

## 3. Meetresultaten

Laagste gemeten waarde over 70 metingen per thema (14 toestanden × 5 breedtes):

| Meting | Eis | Licht vóór | Licht na | Donker vóór | Donker na | Welk paar |
|---|---|---|---|---|---|---|
| axe-overtredingen (WCAG 2.2 AA) | 0 | 0 | 0 | 0 | 0 | — |
| axe best-practice | 0 | 0 | 0 | 0 | 0 | — |
| Tekstcontrast | ≥ 4,5 (Peil ≥ 7) | 8,34 | 8,34 | 9,32 | 9,32 | licht: linktekst in de voet (`--link` op `--background`); donker: knoptekst (`--primary-foreground` op `--primary`) |
| Betekenisdragende rand | ≥ 3 | 4,86 | 4,86 | 5,69 | 5,69 | stippelrand `--border-strong` van de trace-ID op `--down-bg` |
| Icoon | ≥ 3 | 5,71 | 5,71 | 7,58 | 7,58 | licht: `octagon-x` (`--down`) op `--down-bg`; donker: `info` op `--info-bg` |
| Focusring | ≥ 3 | 7,79 | 7,79 | 8,04 | 8,04 | `--ring` naast `--down-bg` (link in de foutmelding) |
| Overloop (px) | 0 | 0 | 0 | 0 | 0 | — |
| Doelen < 44 px (geen inline link) | 0 | 0 | 0 | 0 | 0 | — |
| Tekst < 14 px | 0 | 0 | 0 | 0 | 0 | — |
| Focus bedekt of buiten beeld | 0 | 0 | 0 | 0 | 0 | — |
| Metingen met een Peil-statusfout | 0 | **5** | **0** | **5** | **0** | verouderde Authentik-meting was Gezond (`gekoppeld-met-bronnen`, alle breedtes) |
| Tekstafstand WCAG 1.4.12 op 320 px (overloop, 1× per toestand) | 0 px | **9 px** (onleesbaar) | **0** | — | — | woord "(HUB_ENROLLMENT_TOKEN)." in de melding (16 px) |

De tekstafstandcontrole is pas na de eerste meetronde toegevoegd. De waarde "vóór" komt uit de pagina met de
reparaties R-1 t/m R-6 (de melding bij een onleesbaar koppelbestand was toen nog niet gewijzigd), dus uit dezelfde
tekst als vóór de review.

Wat niet als fout telt:
- Decoratieve randen (kaartrand `--border`) halen 1,77–2,01:1. Peil wil dat zo: `--border` "draagt nooit betekenis",
  en kaarten zijn herkenbaar aan hun kop.
- Inline links zijn uitgezonderd: "Hub openen" (93 × 22 px) en "Naar het veld …" in de foutmelding.

De volledige uitvoer (`samenvatting.json`, een JSON per toestand met elke meting en de aria-boom) staat in het
CI-artefact. Lokaal staat die in `tests/ui/review-uit/`.

## 4. Bevindingen

### 4.1 Eerste indruk (2 seconden)
- **Wat het oog eerst ziet:** bij een fout de rode melding met titel, code en trace-ID; anders de totaalpil met de vette
  toelichting. Dat is terecht.
- **Niet gekoppeld:** de pil "Niet gereed" is gestippeld met `circle-help`, met "Deels onbekend — wacht op koppeling met
  de Hub". Dat is eerlijk en gelijk aan het prototype.
- **Gekoppeld met afwijkende bronnen:** een groene pil "Gezond" met de vette regel "… 1 storing …" geeft een gemengd
  signaal. Dat is verduidelijkt (R-6), en de onderliggende keuze staat als aanbeveling A-1.
- **Donker thema:** rustig en goed leesbaar. Er zijn geen witte vlakken of "glow"; de foutmelding houdt een duidelijke
  rand.

### 4.2 Bruikbaarheid

| # | Bevinding | Toestand | Ernst | Wat er nu is |
|---|---|---|---|---|
| B-1 | Een meting van 3 dagen oud stond als **Gezond** bij "Authentik en toegangsbeheer (B13)". Groen voor verouderde data mag nooit (Peil §4.1 regel 4, §4.4; 05_OPERATIES). | gekoppeld-met-bronnen | **Kritiek** | Gerepareerd (R-2): Onbekend, met "1 verouderd (laatst bekend …). Metingen ouder dan 15 minuten tellen als onbekend." |
| B-2 | "Koppelen bezig" zei "Laad de pagina over een minuut opnieuw". Met een token blijft de worker het tot 60 minuten proberen, en de reden van het wachten (de Hub antwoordt niet) ontbrak. Ook leek het formulier eronder bruikbaar, maar het gaf 409. | koppelen-bezig | Middel | Gerepareerd (R-4): de reden noemt het token, de laatste melding met code en dat het formulier pas weer werkt als de poging klaar is. |
| B-3 | Na een mislukte poging zijn alle velden leeg (bewust, ADR-0011). De melding zei niet dat alles opnieuw moet. | alle fouttoestanden met formulier | Middel | Gerepareerd (R-5): "Ingevulde waarden bewaren we bewust niet: vul alle velden opnieuw in." |
| B-4 | Beheerherstel "Onbekend" had geen reden waarom (dezelfde zin bij elk niveau). | alle met database | Middel | Gerepareerd (R-3): een vaste reden per niveau, zonder details uit het register. |
| B-5 | Bij een onleesbaar koppelbestand blijft het blok "Koppeling met de Hub" leeg (alleen de kop). | onleesbaar | Middel | Sjabloon (S-4); de melding bovenaan en de controle leggen het uit. |
| B-6 | Tijdens "Koppelen bezig" staat het koppelformulier er, terwijl verzenden 409 geeft. | koppelen-bezig | Laag | Sjabloon (S-4); de reden waarschuwt nu (R-4). |
| B-7 | "Hub openen" is de enige weg naar de Hub, maar het is een inline link (22 px hoog). | gekoppeld | Laag | Mag volgens WCAG 2.5.8 en Peil (inline in lopende tekst); voorstel S-7. |
| B-8 | Met de tekstafstand van WCAG 1.4.12 past "(HUB_ENROLLMENT_TOKEN)." in de foutmelding niet meer op 320 px: 9 px horizontale overloop. Het sjabloon breekt lopende tekst in een melding niet. | onleesbaar | Middel | Gerepareerd (R-8): de variabelenaam staat nu in de reden van de controle (14 px, bredere kolom); de melding verwijst ernaar. Sjabloon: S-8. |

### 4.3 Visuele hiërarchie
- **Leesvolgorde:** kop → (melding) → Status → Koppeling → (Koppelen) → Wat deze dienst doet → voet. Dat is gelijk aan
  het prototype en aan ONTWERPTAAL §13.2. Op mobiel staat het formulier pas als derde blok; de skiplink springt bij een
  fout direct naar het foute veld, wat goed is.
- **De kop was te lang:** 4–5 regels op 360 px, met "TrueNAS Home Platform" en "Alle schermen staan in de Hub" dubbel.
  Ingekort (R-6), nu 3–4 regels.
- **Controlerijen onder 400 px:** de tijd valt soms onder de naam (bij "Proces") en soms naast de pil (bij een lange
  naam). Dat is sjabloon-CSS (S-6); het is niet storend, maar wel onrustig.
- **Wit en ritme:** blokken `p-4`, gat 16 px, randen in plaats van schaduw. Dat volgt Peil §6.

### 4.4 Consistentie met Peil (tokens, woorden, iconen)

**Tokens:** de pagina gebruikt alleen de `<style>` uit het sjabloon (hex uit `tokens.mjs`). De dienst voegt geen CSS,
kleuren of inline-stijlen toe. De twee inline-stijlen (`margin-bottom` en `color:inherit` in de melding) komen uit het
sjabloon.

**Pillen:** de woorden en iconen vóór en na de review.

| Plek | Woord vóór | Icoon (sjabloon) | Peil §7/§11.1 | Na de review |
|---|---|---|---|---|
| Controle "Koppeling met de Hub" | Niet gekoppeld / Koppelen bezig / Niet bevestigd / Ingetrokken / Ontkoppeld | `circle-help` (Onbekend) | `circle-help` hoort alleen bij **Onbekend**; "Niet gekoppeld" hoort bij `link-2-off` | **Onbekend** + reden die begint met de toestand ("Niet gekoppeld: …") |
| Zelfde controle | Onleesbaar / Onvolledig | `octagon-x` (Storing) | `octagon-x` hoort bij **Storing** | **Storing** + "Koppelbestand onleesbaar: …" |
| Koppelblok | Niet gekoppeld / Ingetrokken / Ontkoppeld · Gekoppeld | `link-2-off` · `link-2` neutraal | goed | ongewijzigd (sjabloon) |
| Totaal | Niet gereed · Storing · Beperkt · Gezond | `circle-help` · `octagon-x` · `triangle-alert` · `circle-check` | goed (prototype) | ongewijzigd |
| Boiler | Alleen meten | `lock` (gate) | beleid = **`ban`** (§4.6 T-15, §7) | ongewijzigd; het sjabloon heeft geen `ban` (S-1) |
| Wat deze dienst doet | Gezond/Beperkt/Storing/Onbekend | passend | goed, maar verouderd werd Gezond | verouderd → Onbekend (R-2) |

Opmerking voor de Peil-eigenaar: het eigen prototype `statuspagina.html` toont "(?) Niet gekoppeld" in de controlelijst.
Dat botst met de vaste icoonkoppeling van §7 (zie S-2).

### 4.5 Toegankelijkheid (WCAG 2.2 AA)

| Criterium | Uitkomst | Toelichting |
|---|---|---|
| 1.1.1 Niet-tekstuele inhoud | voldoet | Iconen zijn `aria-hidden` en staan altijd naast een woord. |
| 1.3.1 Info en relaties | voldoet | Landmarks (`header`/`main`/`footer`), één h1, h2 per blok, `dl` voor feiten, `ul` met label voor de controles, `label for` bij elk veld. |
| 1.4.1 Gebruik van kleur | voldoet | Elke status heeft icoon + woord + vorm (stippel = onbekend); de veldfout heeft icoon + tekst + `aria-invalid`. |
| 1.4.3 / 1.4.6 Contrast | voldoet (AAA) | Tekst ≥ 8,34:1 (licht) en ≥ 9,32:1 (donker). |
| 1.4.10 Reflow | voldoet | Geen overloop op 320 px; codes en trace-ID breken. |
| 1.4.11 Niet-tekstueel contrast | voldoet | Velden 5,89/6,11:1, knop 9,45/8,63:1, stippelranden ≥ 4,86:1, iconen ≥ 5,71:1. |
| 1.4.12 Tekstafstand | voldoet na R-8 | Getest op 320 px in elke toestand: vóór R-8 gaf `onleesbaar` 9 px overloop; nu nergens overloop en niets afgekapt. |
| 2.1.1 Toetsenbord | voldoet | Alles bereikbaar met Tab; er is geen JavaScript. |
| 2.4.1 Blokken overslaan | voldoet | De skiplink is de eerste tabstop; bij een fout springt hij naar het foute veld. |
| 2.4.2 Paginatitel | voldoet | De titel noemt de toestand, bijvoorbeeld "Home Control Hub — niet gekoppeld (koppelen mislukt)". |
| 2.4.7 / 2.4.11 Focus zichtbaar en niet bedekt | voldoet | Tweekleurige ring (3 px + halo 2 px) ≥ 7,79:1; geen vaste balken. |
| 2.5.8 Doelgrootte (minimum) | voldoet | Alles ≥ 44 px, behalve inline links (uitzondering). |
| 3.3.1 / 3.3.3 Foutidentificatie en suggestie | voldoet | Melding (titel, wat, wat je kunt doen, code, trace-ID) + veldfout met hersteltekst + link naar het veld. |
| 3.3.2 Labels of instructies | voldoet | Label + hulptekst via `aria-describedby`. "(verplicht)" ontbreekt (alle drie de velden zijn verplicht), zie S-5. |
| 3.3.7 Herhaalde invoer | voldoet (uitzondering veiligheid) | Waarden worden bewust niet teruggezet; de melding zegt dat nu (R-5). |
| 3.3.8 Toegankelijke authenticatie | voldoet | Plakken is toegestaan (geen blokkade); de code en de vingerafdruk komen uit de Hub. |
| 4.1.2 Naam, rol, waarde | voldoet | Native elementen; `aria-invalid` bij de fout. |
| 4.1.3 Statusberichten | deels | De infomelding "Gekoppeld met de Hub" heeft `role="alert"` (hoort `status` te zijn), net als een fout die bij het laden al bestond (`onleesbaar`). Dat is sjabloon (S-3). |

**Schermlezer (afgeleid uit de aria-boom, niet met een echte schermlezer):** de totaalpil en de toelichting worden als
één alinea voorgelezen ("Niet gereed Deels onbekend — …"). De controles worden als lijst "Controles" voorgelezen, met per
rij naam, woord, tijd en reden. Een test met NVDA of TalkBack staat open (V-3).

### 4.6 Microcopy (Peil §11)

| Waar | Vóór | Na | Waarom |
|---|---|---|---|
| Kop | "Integratiedienst van het TrueNAS Home Platform: … Alle schermen staan in de Hub; dit is alleen de statuspagina." | "Integratiedienst voor netwerk en privacy, Node-RED-automatisering, Authentik en toegangsbeheer, en energie en resources. Dit is alleen de statuspagina." | Dubbel met de regel erboven en met de voet; 1–2 regels korter op mobiel. |
| Totaal (gezond) | "Gereed; onderdelen hieronder: 1 storing · 1 beperkt · 1 onbekend." | "Gereed. Wat deze dienst doet: 1 storing · 1 beperkt · 2 onbekend." | Noemt het blok waar de afwijkingen staan. |
| Totaal (beperkt) | "Gereed; beperkt: sleutels van de hub." | "Gereed, maar beperkt: Sleutels van de Hub." | Eigennaam "Hub" niet in kleine letters; leest als zin. |
| Controle koppeling | pil "Niet gekoppeld", reden "Zonder koppeling voert …" | pil **Onbekend**, reden "Niet gekoppeld: zonder koppeling voert …" | Vaste woorden bij het icoon (§4.4). |
| Ingetrokken/ontkoppeld | "… Ontkoppelen of opnieuw koppelen gaat via de Hub." | "Ingetrokken door de Hub: … Opnieuw koppelen gaat via de Hub." | Ontkoppelen kan dan niet meer. |
| Laatste fout | "Laatste melding (9 nov 2026, 11:50 UTC, code hub_weigerde): Koppelen mislukt: …" | "Laatste melding, 9 nov 2026, 11:50 UTC (code hub_weigerde): Koppelen mislukt: …" | Leest beter. |
| Bronnen | "1 van 1 bronnen ingesteld · laatst gemeten 6 nov 2026 …" (en groen) | "1 van 1 bron ingesteld: 1 verouderd (laatst bekend 6 nov 2026, 17:54 UTC). Metingen ouder dan 15 minuten tellen als onbekend." | Enkelvoud, telling per soort en het vaste "laatst bekend" uit §11.1. |
| Koppelen bezig | "Er loopt een koppelpoging. Laad de pagina over een minuut opnieuw." | "Koppelen bezig met het token HUB_ENROLLMENT_TOKEN uit de Custom App; de dienst probeert het zelf opnieuw. Het formulier hieronder werkt pas weer als deze poging klaar is. Laatste melding, …" | Klopt nu, en zegt waarom en wat je kunt doen. |
| Melding onleesbaar | "… Herstel: zet in het formulier van de Custom App een nieuw eenmalig token van de Hub (HUB_ENROLLMENT_TOKEN)." | "… Herstel: maak in de Hub een nieuw eenmalig token en zet het in het formulier van de Custom App; welke variabele dat is, staat hieronder bij Status." en in de controle: "Koppelbestand onleesbaar: … Herstel: een nieuw eenmalig token van de Hub in de variabele HUB_ENROLLMENT_TOKEN van de Custom App." | WCAG 1.4.12 (B-8); de herstelstappen beginnen nu in de Hub, waar het token ontstaat. |
| Fout `koppelen_bezig` | "… Wacht een minuut en laad de pagina opnieuw." | "Er loopt al een koppelpoging. Er is niets naar de Hub gestuurd. Hoe die poging ervoor staat, zie je hieronder bij Status, regel Koppeling met de Hub." | Een vaste minuut was onjuist. |
| Fout `ongeldig_formulier` | "… Vul het opnieuw in. Er is niets naar de Hub gestuurd." | "… Er is niets naar de Hub gestuurd. Ingevulde waarden bewaren we bewust niet: vul alle velden opnieuw in." | Eén vaste zin voor alle fouten met formulier. |
| Beheerherstel | één zin voor elk niveau | per niveau: "Het herstelregister is nog niet volledig ingevuld of getest." / "… heeft aandachtspunten." / "Alleen het totaalniveau staat hier; …" | Onbekend en Beperkt altijd met reden, zonder details. |

Goed bevonden en dus ongewijzigd:
- de meldingen "Koppelen is mislukt" en "Koppelen is niet gestart" (verschil tussen wel en niet naar de Hub);
- "Er is niets naar de Hub gestuurd.";
- de knop "Koppelen met de Hub" (werkwoord + object);
- "Trace-ID (selecteer en kopieer)";
- de veldhulpteksten, gelijk aan §11.2 "Statuspagina-veld";
- "Alleen meten — schakelen is altijd uitgeschakeld (beleid). Er is bewust geen schakelaar.";
- "Bijgewerkt … (bij het laden van deze pagina)".

Er staan geen uitroeptekens, geen "OK", geen "Weet je het zeker?" en geen groen voor "Gekoppeld".

## 5. Reparaties (in deze repo; alleen woorden, redenen en meldingen die de dienst invult)

| # | Wat | Waar | Test |
|---|---|---|---|
| R-1 | Pilwoord = vast Peil-woord bij het icoon van de toon; de precieze koppeltoestand opent de reden. | `apps/api/src/integrations/status_page.py` `_koppel_controle` | `test_pill_words_follow_the_icon`, `test_link_problems_make_the_service_not_ready`, `test_not_linked_is_never_green_and_shows_last_error` |
| R-2 | Verouderde bronmeting (> 15 min) en nooit gemeten = Onbekend. Telling per soort, "laatst bekend", enkelvoud/meervoud. | `_domein_rij`, `BRON_MAX_LEEFTIJD` | `test_stale_measurement_is_never_green`, `test_sources_and_recovery_level_in_service_block`; ontwerpreview-regel "verouderde meting groen" |
| R-3 | Beheerherstel: een vaste reden per niveau. | `_HERSTEL_REDEN` | `test_recovery_level_always_has_a_reason` |
| R-4 | Koppelen bezig: waarmee, laatste melding en de waarschuwing over het formulier; foutmelding `koppelen_bezig` zonder vaste minuut. | `_koppel_controle`, `FOUTEN` | `test_pending_reason_names_the_attempt_and_the_last_error` |
| R-5 | Na een mislukte poging met formulier: "vul alle velden opnieuw in". | `bouw_model`, `OPNIEUW_INVULLEN_NL` | `test_failed_attempt_says_fields_must_be_filled_in_again` |
| R-6 | Kortere kop; duidelijkere toelichting bij het totaal; "Hub" niet in kleine letters; "Opnieuw koppelen gaat via de Hub" na intrekken/ontkoppelen; de reden bij onleesbaar verwijst naar de melding. | `DIENST_OMSCHRIJVING`, `_totaal`, `_koppel_controle` | `test_header_copy_is_short_and_not_repeated`, `test_refused_key_rotation_is_limited_but_ready`, `test_linked_and_confirmed_is_healthy_with_neutral_link_pill` |
| R-7 | De ontwerpreview als herhaalbare test op de draaiende dienst (lokaal en in CI; in CI beoordeelde hij tot ADR-0013 door een padfout 0 metingen, nu faalt hij als het aantal metingen niet klopt). | `tests/ui/ontwerpreview.py`, `tests/ui/ontwerpreview.mjs`, `Makefile` (`ontwerpreview`), `.github/workflows/ci.yml` | 140 metingen + 14 tekstafstandcontroles, 0 overtredingen |
| R-8 | Geen woord van 20 tekens meer in de foutmelding (16 px); de variabelenaam staat in de controle. | `bouw_model` (melding onleesbaar), `_koppel_controle` | `test_pill_words_follow_the_icon`; ontwerpreview-regel "tekstafstand" |

Het sjabloon (`design/ontwerptaal/statuspagina.html`/`.css`) is **niet** gewijzigd: de Peil-kopie blijft byte-gelijk
aan `lvos04/ai-server-manager@172ee87` (`tools/peil_kopie.py controleer`).

## 6. Overdracht aan Peil (sjabloon 1.1.0 → voorstel 1.2.0)

Voor de eigenaar van `ai-server-manager/design/ontwerptaal` (`bouw/statuspagina.sjabloon.html`,
`bouw/statuspagina.bron.css`). Elke diensten krijgt dit pas na een nieuwe Peil-versie, met `tools/peil_kopie.py bijwerken`.

| # | Onderdeel | Probleem | Specificatie | Toegankelijkheid |
|---|---|---|---|---|
| S-1 | Symbool `i-beleid` | "Alleen meten" (boiler, T-15) heeft nu het slot-icoon van de gate (`lock`). Peil §4.6/§7: beleid = `ban`. | Lucide `ban` als `<symbol id="i-beleid">`; nieuwe toon `beleid` (klasse `.pil-beleid` = stijl van `.pil-gate`: `--gate-bg`, 2 px `--gate`, `--gate-ink`, radius 4 px). Toonlijst: `gezond \| beperkt \| storing \| onbekend \| gate \| beleid`. | Icoon `aria-hidden`, woord blijft "Alleen meten". |
| S-2 | Icoon per controle | Een controle kan alleen het icoon van haar toon tonen, dus geen "Niet gekoppeld" met `link-2-off` en geen "Verouderd" met `clock-alert`. Het eigen prototype toont "(?) Niet gekoppeld". | Optioneel veld `{{icoon}}` per rij (vaste lijst: `niet-gekoppeld`, `gekoppeld`, `verouderd`), standaard `{{toon}}`. Nieuw symbool `i-verouderd` (`clock-alert`) en een klasse `.pil-verouderd` (stippel 2 px `--stale` + arcering 135° `--stale-hatch` op `--stale-bg`, tekst `--unknown-ink`). | Verouderd ≥ 4,5:1 op de donkerste arceerpixel (zoals in de Hub). |
| S-3 | Rol van de melding | `role="alert"` staat vast. De infomelding ("Gekoppeld met de Hub") hoort `role="status"` te hebben, en een fout die bij het laden al bestond geen alert (C-14: "geen alert-spam"). | Plek `{{melding_rol}}` met vaste waarden `alert` (fout van dít verzoek) · `status` (info) · leeg (fout die al bestond). | WCAG 4.1.3. |
| S-4 | Koppelblok zonder toestand | Bij een onleesbaar koppelbestand is het blok leeg. Tijdens "koppelen bezig" staat het formulier er terwijl verzenden 409 geeft. | Blok `koppelstatus_onleesbaar` (pil Storing + "Het koppelbestand is onleesbaar; herstel staat in de melding bovenaan.") en een vlag `koppelen_bezig` die het formulier verbergt en een pil "Koppelen bezig" (`hourglass`, neutraal) toont. Al voorgesteld in ADR-0011. | Zero empty screens (C-17). |
| S-5 | "(verplicht)" | De drie verplichte velden hebben geen zichtbare markering (C-36: "(verplicht)" in muted). | `<span class="hulp">(verplicht)</span>` in het label, of één zin boven het formulier: "Alle velden zijn verplicht." | WCAG 3.3.2. |
| S-6 | Rijopbouw onder 400 px | `.checks li` met `flex-wrap`: de tijd valt soms onder de naam en soms naast de pil, dus rijen ogen ongelijk. | Raster: `grid-template-columns: 1fr auto` met naam + pil op regel 1 en tijd + reden op regel 2 (zoals C-04 "< 640: naam links en badge rechts op één regel, reden eronder"). | Geen effect op de leesvolgorde. |
| S-7 | "Hub openen" | Enige weg naar de Hub, maar een inline link van 22 px hoog. | `.knop .knop-secundair` (44 px) na de alinea, met tekst "Hub openen". | 2.5.8 al voldaan; dit is gebruiksgemak. |
| S-8 | Lange woorden in meldingen | `.melding p` en `.checks .reden` breken niet midden in een woord. Een variabelenaam of adres in lopende tekst geeft op 320 px met de tekstafstand van 1.4.12 overloop (gemeten: 9 px). | `overflow-wrap: anywhere` op `.melding p`, `.checks .reden` en `.feiten dd` (voor `code` geldt het al, Peil §5). | WCAG 1.4.10/1.4.12. |

## 7. Aanbevelingen en vervolg

- **A-1 (inhoud, niet uiterlijk; niet aangepast):** in het Peil-prototype `statuspagina-gekoppeld.html` maakt een beperkte
  bron het totaal **Beperkt**. Hier telt de stand van de bronnen niet mee in het totaal (ADR-0011 besluit 5). Voorstel:
  laat een **verse** meting met Storing of Beperkt in "Wat deze dienst doet" het totaal hooguit **Beperkt** maken ("Gereed,
  maar beperkt: Energie en resources (B14)"). Niet ingestelde en verouderde domeinen tellen dan niet mee, anders wordt de
  pagina nooit groen. Dit vraagt een besluit van de bouwer of de gebruiker.
- **V-1 (API, buiten deze review):** `GET /readyz` (`health.py`, controle `bronnen`) gebruikt nog de laatst bekende
  probe zonder leeftijdsgrens. Dezelfde grens van 15 minuten is daar aan te raden ("nooit healthy op stale cache").
  **Opgelost in ADR-0013:** het ging niet om `/readyz` (dat heeft geen controle op bronnen), maar om
  `GET /connector/v1/health` (controle `bronnen`), `GET /integrations/v1/sources` en de connector-items. Die gebruiken
  nu dezelfde grens (`sources.PROBE_MAX_AGE`): een oudere meting is `unknown` (`meting_verouderd`).
- **V-2:** de schermlezertekst van het totaal leest pil en toelichting aan elkaar ("Niet gereed Deels onbekend …"). Dat
  is te verbeteren met een scheidingsteken in het sjabloon (S-reeks) of met `aria-describedby`.
- **V-3:** een echte schermlezertest (NVDA/TalkBack), een echte telefoon in fel licht en de pagina via
  `http://<NAS-adres>:30420` op een echte NAS: NIET GEVALIDEERD.
- **V-4:** S-1 t/m S-8 overnemen in Peil 1.2.0, en daarna de kopie bijwerken met `make test test-ui schermafdrukken
  ontwerpreview`.

## 8. Schermafdrukken

- **Na de review, uit de draaiende dienst:** `docs/ontwerp/peil-review/`
  - alle 14 toestanden op 390 px, in licht en donker;
  - `koppelen-mislukt` en `gekoppeld-met-bronnen` ook op 320, 360, 768 en 1440 px;
  - vóór/na van de belangrijkste reparatie: `voor-gekoppeld-met-bronnen-licht-390.png` (Authentik groen bij een meting van
    3 dagen oud) en `gekoppeld-met-bronnen-licht-390.png` (Onbekend).

  De PNG's zijn verkleind met pngquant (kleurenpalet, verlies onzichtbaar). Alle 140 afdrukken (14 toestanden × 5 breedtes ×
  2 thema's) staan in `tests/ui/review-uit/afdrukken/` en in het CI-artefact.
  - **Peil 1.1.1 (10 november 2026):** opnieuw gemaakt uit de herhaalde review (168 afdrukken, 6 breedtes); in de map:
    alle toestanden op 390 px en `gekoppeld-met-bronnen`, `koppelen-mislukt` en `onleesbaar` op alle breedtes.
- **Vaste set van de UI-tests (HC11), opnieuw gemaakt na de reparaties:** `docs/screenshots/peil/statuspagina/`.
- **Referentie (Peil):** `ai-server-manager/design/ontwerptaal/shots/statuspagina*-{licht,donker}-{360,390,768,1440}.png`.
