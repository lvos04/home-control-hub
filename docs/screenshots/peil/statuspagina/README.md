# Schermafdrukken — statuspagina in Peil 1.1.1 (HC11, contract 1.3)

Gemaakt met `make schermafdrukken` (Playwright 1.65, Chromium, `locale nl-NL`, TZ UTC) uit de **echte app** tegen de
Hub-simulator (`tests/ui/genereer_toestanden.py`; vaste trace-ID's). Validatie: **Sim-getest** — geen echte Hub,
geen echte NAS, geen echte telefoon of schermlezer.

Nieuwe afdrukken staan per proef onder `tests/ui/test-results/`. Met de Playwright-optie `--output` kies je een eigen uitvoermap.

| Bestand | Toestand |
|---|---|
| `energie-leeg-…` | Er is nog geen actieve woningbron. |
| `energie-bezig-…` | De ingestelde bron wacht op de eerste vermogensmeting. |
| `energie-gemeten-…` | Meetkwaliteit en meettijd per rol, inclusief nul watt, een schatting en een open boilerafwijking. |
| `energie-verouderd-…` | Elke verlopen rol toont onbekend vermogen en zijn laatst bekende meettijd. |
| `energie-storing-…` | De bronlezing mislukte, met de eerder geregistreerde afwijking nog in beeld. |
| `niet-gekoppeld-<thema>-<breedte>.png` | nog nooit gekoppeld: koppelformulier (Hub-adres, koppelcode, vingerafdruk); totaal "Niet gereed" |
| `koppelen-mislukt-…` | de Hub weigerde de koppelcode: HTTP 400, code `hub_weigerde`, selecteerbare trace-ID, veldfout bij Koppelcode |
| `gekoppeld-…` | gekoppeld en door de Hub bevestigd, met de melding na het koppelen; "Gekoppeld" is een neutrale pil |
| `ingetrokken-…` | de Hub trok de koppeling in (`services/self` gaf 401); opnieuw koppelen alleen via de Hub |
| `niet-gereed-…` | eigen database onbereikbaar: totaal "Niet gereed" (Storing), niets geschat |
| `onleesbaar-…` | koppelbestand onleesbaar (Peil 1.1.1): Storing "Onleesbaar", geen formulier, code en pad, geen live-regio |
| `koppelen-bezig-…` | er loopt een koppelpoging (Peil 1.1.1): "Koppelen bezig" met de starttijd, geen formulier |

De 40 energieafdrukken tonen het blok op 360, 390, 768 en 1440 px in licht en donker.
De overige afdrukken tonen de hele pagina in beide thema's op 360, 768 en 1440 px. De UI-tests draaien daarnaast
ook 320, 390 en 1024 px en vijf extra toestanden (ongeldige invoer, te veel pogingen, ontkoppeld, een POST met
`Origin: null` en de pagina via een domeinnaam). CI bewaart dezelfde afdrukken als artefact `statuspagina-peil`.

De paginabrede afdrukken zijn voor Peil 1.1.1 en contract 1.3 opnieuw gemaakt en verkleind met
`pngquant --quality=80-95` (ADR-0014). De afdrukken van de 14 toestanden uit de eerdere ontwerpreview
staan in `docs/ontwerp/peil-review/` (ADR-0012). De metingen van het energieblok staan in
`docs/ontwerp/PEIL_REVIEW.md`.
