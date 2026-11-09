# ADR-0011 — Statuspagina in Peil (HC11)

Status: aanvaard · Datum: 2026-11-09 · Fase: contract 1.2 §13 + ontwerptaal Peil 1.1.0
(`CONTRACT_1.2_CONFORMITEIT.md` §2 HC11; `ai-server-manager/docs/platform-v2/ONTWERPTAAL.md` §13.2, §14, O-14;
ADR-0015 van ai-server-manager)

## Context
De statuspagina (`GET /`) had eigen inline-CSS en eigen woorden ("nooit gekoppeld", groene "klaar"-tag). Contract 1.2
§13 vraagt voor de statuspagina's van de nieuwe diensten framework-vrije CSS uit dezelfde tokens als de Hub; Peil
levert daarvoor één sjabloon (`statuspagina.html`, CSS en lucide-iconen inline, geen JavaScript) dat elke dienst als
**versie-gepinde kopie met herkomstkop** overneemt, met een CI-stap die drift detecteert (§13.2/§14, O-14). Het
gedrag van contract 1.2 §3.7 (formulier alleen zolang nooit gekoppeld, verplichte vingerafdruk, geen lokale
ontkoppelcode) was al gebouwd (ADR-0010, HC5) en blijft; deze ADR legt vast hoe dat gedrag op het sjabloon valt.

## Ontwerpstap vooraf (scherm en componenten binnen Peil)
Contract §13 vraagt een ontwerpstap vóór en een ontwerpreview na elke UI-bouwstap. In deze ronde is geen aparte
ontwerpagent ingezet; de bouwer heeft beide stappen zelf gedaan, strikt binnen het sjabloon (geen eigen CSS, geen
eigen componenten). Dat is een **zelfreview**, geen onafhankelijke ontwerpreview (zie Gevolgen).

**Opbouw** (vast in het sjabloon): kop → (melding) → Status → Koppeling met de Hub → (Koppelen) → Wat deze dienst
doet → voet (`/healthz`, `/readyz`). De executorblokken (`schrijfsleutel_formulier`, `executor_beheer`) blijven uit.

| Toestand | Koppelblok | Formulier | Totaalpil | Melding | HTTP |
|---|---|---|---|---|---|
| Niet gekoppeld (`first_linked_at` leeg) | `koppelformulier`: pil Onbekend "Niet gekoppeld" + stappen | ja | Onbekend · **Niet gereed** | — | 200 |
| Koppelen mislukt | idem | ja, veld met `aria-invalid` + veldfout | Onbekend · Niet gereed | fout: titel, vaste tekst, **code**, **trace-ID** (selecteerbaar), link naar het veld; skiplink naar het veld | 400/403/409/422/429/502/503 |
| Gekoppeld en bevestigd | `gekoppeld`: **neutrale** pil "Gekoppeld", sinds, Hub, vingerafdruk, "Hub openen" | nee | Gezond (alleen als gereed) | na koppelen: info "Gekoppeld met de Hub" | 303 → 200 |
| Gekoppeld, niet bevestigd | `gekoppeld` | nee | Onbekend · Niet gereed | — | 200 |
| Ontkoppeld / ingetrokken | `ontkoppeld` / `ingetrokken`: pil Onbekend + "Opnieuw koppelen gaat via de Hub" | nee | Onbekend · Niet gereed | — | 200 |
| Niet gereed (database, schema, sleutels) | volgens de koppeling | volgens de koppeling | **Storing** | — | 200 |
| Koppelbestand onleesbaar | geen blok (zie besluit 4) | nee | Storing | fout `koppelstatus_onleesbaar` + trace-ID | 200 |

**Controles (Status)**: Proces · Eigen database · Databaseschema · Sleutels van de dienst · Koppeling met de Hub
(alleen als er iets ontbreekt) · Sleutels van de Hub (alleen bij een geweigerde sleutelrotatie: Beperkt).
**Wat deze dienst doet**: per domein (B10, B11, B13, B14) de slechtste stand van de *ingestelde* bronnen met
"x van n bronnen ingesteld · laatst gemeten …", anders Onbekend met "Nog geen bron ingesteld … tot dan tonen we geen
stand"; Beheerherstel (B13-001) alleen het totaalniveau (Gezond/Beperkt/Onbekend); Boiler als gate "Alleen meten —
schakelen is altijd uitgeschakeld (beleid). Er is bewust geen schakelaar."

## Besluiten
1. **Versie-gepinde kopie** in `design/ontwerptaal/`: `statuspagina.html` en `statuspagina.css` = één herkomstkop
   (`<!-- Herkomst: Peil 1.1.0 · sha256:<bron> · bron lvos04/ai-server-manager@172ee87… design/ontwerptaal/… · … -->`)
   + de bron byte-gelijk; `HERKOMST.json` pint versie, commit, bronbranch en sha256. Zelfde kopformaat als de andere
   diensten. `tools/peil_kopie.py` (alleen standaardbibliotheek): `controleer` (offline: kop, inhoud, HERKOMST, en de
   `<style>` in het sjabloon gelijk aan de CSS), `vergelijk --bron/--online`, `bijwerken`.
2. **Drift in CI**: elke run `controleer` + `vergelijk --online` (de bron is publiek op GitHub; 4 herhalingen bij
   netwerkfouten). Fout = de kopie wijkt af van de gepinde commit, of de bronbranch heeft **dezelfde versie met andere
   inhoud**. Een **nieuwere** versie op de bronbranch is een waarschuwing, geen fout: een versie-gepinde kopie wordt
   bewust bijgewerkt (met nieuwe UI-tests en schermafdrukken), niet stil meegenomen. Daarnaast vergelijkt een
   unit-test lokaal met `../ai-server-manager` als die checkout er is, en weigert de image-build een kopie waarvan de
   sha256 niet bij de kop past.
3. **Renderer** (`integrations/peil.py`): de plekken van de referentie-renderer (`{{x}}`, `ALS`, `NIET`, `ELK`), maar
   in **één doorgang** (een ingevulde waarde wordt nooit opnieuw als sjabloon gelezen) en alles HTML-escaped. Toon-
   waarden alleen uit de vaste lijst `gezond|beperkt|storing|onbekend|gate` (anders een programmeerfout). Het
   ontwikkelaarscommentaar bovenaan het sjabloon gaat niet mee naar de pagina; er staat één korte herkomstregel.
4. **Precies één koppeltoestand** (`koppeltoestand()`): niet ooit gekoppeld → `koppelformulier`; anders `gekoppeld`,
   `ingetrokken` of `ontkoppeld`. Twee gevallen die het sjabloon niet kent:
   - **Onleesbaar koppelbestand** (fail-closed, ADR-0010 besluit 4): geen van de vier blokken (het koppelblok heeft
     dan alleen zijn kop), wel een foutmelding met code `koppelstatus_onleesbaar` + trace-ID (ook in de log) en de
     controle "Koppeling met de Hub" = Storing met de herstelweg. Een blok kiezen dat iets anders zegt ("ontkoppeld
     door de Hub") zou onwaar zijn.
   - **Lopende koppelpoging** (`pending`, bv. het env-token): het formulier blijft staan (het sjabloon koppelt
     formulier en "Niet gekoppeld" aan één vlag); een verzending wordt atomair geweigerd met 409 `koppelen_bezig`
     zonder verzoek naar de Hub, en de controle zegt "Koppelen bezig". Dit vervangt het deel "en er geen koppelpoging
     loopt" van ADR-0010 besluit 10; contract §3.7 vraagt alleen "zolang nooit gekoppeld".
5. **Eerste signaal nooit groen als de dienst niet gereed is.** Gereed = database, schema, sleutels **én** een door
   de Hub bevestigde koppeling (`confirmed_at`). Totaal = slechtste controle (Storing > Beperkt > Onbekend > Gezond);
   een vangnet maakt "Gezond" Onbekend als de dienst niet gereed is. Label "Niet gereed" + "Deels onbekend — <reden>"
   (zoals het Peil-prototype); "Gezond" alleen als gereed, met de telling van wat in "Wat deze dienst doet" afwijkt.
   `/readyz` blijft ongewijzigd (een niet-gekoppelde dienst is wel *ready* voor verkeer); de pagina noemt dat verschil
   in de regel "Gereed".
6. **Foutweergave**: een mislukte `POST /koppelen` geeft **direct** de pagina terug (geen redirect), met een passende
   HTTP-status (`ongeldig_formulier` 403, `al_gekoppeld`/`koppelen_bezig` 409, ongeldige invoer 422,
   `hub_weigerde`/`hub_vingerafdruk_onjuist` 400, `te_veel_pogingen`/`rate_limited` 429 + `Retry-After: 900`,
   Hub-fouten 502, `database_onbereikbaar` 503), een vaste NL-melding, de vaste code en de trace-ID van dát verzoek
   (= `X-Trace-Id`; ook in de logregel en in het auditspoor `hub.pair_failed`). Ingevulde waarden worden nooit
   teruggetoond (de velden hebben geen `value`) en het Hub-adres van een mislukte poging nergens bewaard. Een geslaagde
   poging → `303` naar `/?melding=gekoppeld`; die infomelding verschijnt alleen als de dienst echt gekoppeld is. Andere
   `?melding=`-waarden worden genegeerd (geen weerspiegelde invoer).
7. **Minder op de pagina dan de witte lijst toestaat**: het sjabloon toont van de koppeling alleen sinds, Hub-adres
   en vingerafdruk; `service_id`, `via` en `service_token_last4` staan niet meer op de statuspagina (wel in
   `GET /connector/v1/hub-link`). Een opgeslagen `last_error` staat als reden bij de controle "Koppeling met de Hub"
   (met code en tijd), niet als melding: die heeft geen trace-ID van dit verzoek.
8. **Tijd**: de tijdzone van het proces (TZ van de container; onbekend op de NAS), met afkorting:
   "9 nov 2026, 11:56 UTC"; `<time datetime>` met offset.
9. **Image**: de kopie staat in `/usr/local/lib/hch/ontwerptaal/` (`HCH_PEIL_DIR`); de build controleert de sha256.
   Ontbreekt het sjabloon toch, dan geeft `GET /` 503 platte tekst met code `statuspagina_sjabloon_ontbreekt` +
   trace-ID; de API zelf blijft werken.
10. **UI-tests**: `tests/ui/genereer_toestanden.py` legt negen toestanden vast uit de echte app (PostgreSQL +
    Hub-simulator, vaste trace-ID's, TZ UTC) met body en headers; `statuspagina.spec.ts` (Playwright 1.65, axe-core
    4.14, Chromium) toetst elke toestand × licht/donker × 320/360/390/768/1024/1440 px. Schermafdrukken van de vijf
    verplichte toestanden × 360/768/1440 × licht/donker staan in `docs/screenshots/peil/statuspagina/`.

## Ontwerpreview achteraf (zelfreview van de bouwer)
Gecontroleerd op de schermafdrukken en met de UI-tests:
- Peil-regels: groen alleen voor gemeten en goed; "Gekoppeld" neutraal (`link-2`); onbekend altijd met stippelrand
  en reden; geen "In orde"/"Klaar"/"Actueel"; formulierfout rood alleen na een verzendpoging; boiler als gate zonder
  schakelaar; vaste woorden Gezond · Beperkt · Storing · Onbekend · Niet gereed.
- Toegankelijkheid: axe-core (WCAG 2.0/2.1/2.2 A+AA + best practices) 0 overtredingen, geen overloop op 320 px,
  doelen ≥ 44 px, tekst ≥ 14 px, één h1, geen dubbele id's of kapotte `aria-*`-verwijzingen, skiplink als eerste
  tabstop, ring ≥ 3 px en in beeld (390 en 1440), stippelrand blijft bij forced colors.
- Gevonden en hersteld: de toelichting naast de groene pil was een lange vette zin; nu kort ("Gereed; onderdelen
  hieronder: 5 onbekend.").
- Niet gedaan: echte schermlezer (NVDA/TalkBack), echte telefoon in fel licht (ONTWERPTAAL §12/§15 punt 7).

## Gevolgen
- Alle statusregels staan in één pure functie (`bouw_model`) met unit-tests per toestand en een invariantentest over
  alle combinaties (nooit groen als niet gereed, alleen toegestane tonen, geen resterende plekken, één h1).
- Een nieuwe Peil-versie in ai-server-manager laat CI waarschuwen; bijwerken = `tools/peil_kopie.py bijwerken`, dan
  tests, UI-tests en schermafdrukken opnieuw.
- Validatie: **Sim-getest** (echte app + Hub-simulator in Chromium). Op een echte NAS, met een echte Hub en met een
  echte schermlezer: NIET GEVALIDEERD.
- De ontwerpreview is een zelfreview; een onafhankelijke review door de ontwerpagent staat open (followup).

## Gemeld als contract-/ontwerptaalpunt
- Het sjabloon 1.1.0 kent geen toestand voor een **onleesbaar koppelbestand** en geen aparte weergave voor een
  **lopende koppelpoging**; zie besluit 4. Voorstel voor Peil: een blok `koppelstatus_onleesbaar` en een vlag die het
  formulier los van de status "Niet gekoppeld" kan verbergen.
- ONTWERPTAAL §13.2 zegt "een CI-stap vergelijkt de checksum met de versie in ai-server-manager en faalt bij drift",
  zonder te zeggen of een nieuwere bronversie drift is. Gekozen: alleen dezelfde versie met andere inhoud is drift;
  een nieuwere versie is een waarschuwing (besluit 2).
- "Gereed" op de statuspagina (inclusief bevestigde koppeling) is strenger dan `/readyz` (verkeer kunnen aannemen).
  Het contract definieert "gereed" voor de statuspagina niet; gekozen is de strengste lezing.
