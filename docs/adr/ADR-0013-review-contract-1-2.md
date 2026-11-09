# ADR-0013 — Onafhankelijke review contract 1.2 (QA): fail-closed-gaten en controleerbaar bewijs

Status: aanvaard · Datum: 2026-11-09 · Fase: contract 1.2 (`PLATFORM_CONTRACTEN.md` 1.2, `CONTRACT_1.2_CONFORMITEIT.md`)
· Volgt op ADR-0010 (contract 1.2 toegepast), ADR-0011 (statuspagina in Peil) en ADR-0012 (ontwerpreview)

## Context
Na de bouwronde voor contract 1.2 (HC1–HC11, A1–A7) is de repo onafhankelijk gecontroleerd. Alle CI-stappen zijn
lokaal opnieuw gedraaid: lint, typen, unit, integratie, migraties op/neer, OpenAPI- en Peil-drift, dienst-E2E,
UI-tests, ontwerpreview, image bouwen en de rooktest. Daarnaast is de code gelezen tegen §1–§13 en is gezocht naar
open-bij-fout, verouderde data als gezond, gaten in de invoervalidatie en bewijs dat niet (meer) klopt. De
contractkopieën zijn byte-gelijk aan de bron (sha256 gecontroleerd). Alles hieronder is **Sim-getest**; niets is op een
echte NAS, met een echte Hub-installatie of met echte accounts gevalideerd.

## Bevindingen en besluiten

1. **Onleesbaar `hub-link.json` werd stil teruggezet naar "nooit gekoppeld" (open bij fout).**
   Bij een onleesbaar bestand vertrouwde de dienst terecht niets en toonde hij geen koppelformulier. Maar elke gewone
   schrijfactie verving het bestand door een lege status, bijvoorbeeld `pending`, `last_error` of de hash van een
   mislukt env-token. Daarna was `first_linked_at` leeg en verscheen het formulier weer. Iemand op het LAN kon de
   dienst dan aan een eigen "Hub" koppelen.
   **Besluit:**
   - `HubLinkStore.update()` bewaart het onleesbare origineel als `hub-link.json.onleesbaar-<tijd>` (0600, zelfde map).
   - De nieuwe status krijgt het extra veld `unreadable_replaced_at`. Dat is een aanvulling op §3.5, net als de velden
     uit ADR-0010.
   - Zolang daarna niet opnieuw gekoppeld is (`first_linked_at` leeg), geldt de status als onleesbaar: geen formulier,
     geen Hub-JWT vertrouwd.
   - `/readyz` en de witte lijst melden dan `last_error.code = koppelstatus_onleesbaar`. Zonder die melding leek
     `state` ten onrechte "nooit gekoppeld".
   - Herstel blijft zoals §3.8 voorschrijft: een nieuw env-token van de Hub. Na een geslaagde koppeling is de markering
     weg.
   - Een mislukt env-token wordt wel als afgehandeld onthouden. De worker probeert het dus niet elke ronde opnieuw.

2. **Bronmetingen zonder leeftijdsgrens in de API ("nooit healthy op stale cache").**
   ADR-0012 voerde de grens van 15 minuten alleen op de statuspagina in. ADR-0012 noemde als vervolgpunt (V-1)
   `/readyz`, maar het ging om iets anders: `GET /integrations/v1/sources`, de connector-items van type `source` en de
   controle `bronnen` in `GET /connector/v1/health` gaven een oude `healthy`-meting nog als gezond door. `/readyz` heeft
   geen controle op bronnen.
   **Besluit:** één regel voor alles, `sources.PROBE_MAX_AGE` (15 min), die de statuspagina ook gebruikt.
   - Een oudere meting is `unknown` met `reason_code: meting_verouderd`.
   - De tijd van de laatste meting blijft zichtbaar (`observed_at`).
   - De oude stand en de oude details worden niet getoond.
   - De connector-health telt verouderde metingen apart (`detail.verouderd`).

3. **`aud` als lijst werd geaccepteerd.**
   PyJWT accepteert standaard een lijst-`aud` waarin `home-control-hub` voorkomt, bijvoorbeeld
   `["home-control-hub","zoeken-en-persoonlijke-ai"]`. Zo'n JWT is bij meerdere diensten bruikbaar, terwijl elke
   dienst een eigen replaycache heeft. §4.2/§4.3 schrijven `aud:"<app_id>"` voor.
   **Besluit:** `strict_aud` plus een eigen controle op precies de string, anders `invalid_token`. De Hub
   (`hub/keys.py`) en de simulator zetten `aud` al als string.

4. **Afwijkende IPv4-vormen omzeilden de adresregels van §3.2.**
   Voorbeelden: `127.1`, `2130706433`, `0x7f000001`, `0`, `010.0.0.1`, en `localhost.` met een punt achteraan. Ook
   bij die vormen maakt de resolver er loopback of `0.0.0.0` van.
   **Besluit:** een host van alleen cijfers, punten en hex-delen moet een gewoon `a.b.c.d`-adres zijn, en een punt
   achteraan telt niet mee. Dit geldt voor het Hub-adres (env en statuspagina) en voor de adressen van bronnen.

5. **Healthcheck zonder no-new-privileges bij start als 568.**
   Start de container als "Custom User" 568, dan wisselde `healthcheck.py` niet, en daardoor zette het script ook geen
   `PR_SET_NO_NEW_PRIVS`.
   **Besluit:** het script zet no-new-privileges nu altijd, en stopt als het nog root is. De rooktest controleert dit
   ook voor de container die als 568 start.

6. **Bewijs wees naar tests die niet meer bestaan (EERLIJKHEID, §11).**
   In `EVIDENCE.json` stonden bij EX16 en B13-002 zeven verwijzingen naar tests die met contract 1.2 vervallen of
   hernoemd zijn, zoals de JWKS-cache en de lokale ontkoppelcode. Er stond ook een sjabloonrest `{T}`.
   **Besluit:**
   - De verwijzingen zijn vervangen door de huidige tests.
   - Een nieuwe unit-test (`test_contract_docs.py::test_evidence_references_existing_tests`) controleert voortaan elk
     genoemd testbestand en elke genoemde testfunctie, en meldt sjabloonresten.

7. **De ontwerpreview in CI mat niets en meldde toch "0 overtredingen" (EERLIJKHEID).**
   CI roept `python tests/ui/ontwerpreview.py --uit tests/ui/review-uit` aan met een relatief pad. Het browserscript
   draait met cwd `tests/ui`. Daardoor schreef het naar `tests/ui/tests/ui/review-uit`, terwijl de beoordeling
   `tests/ui/review-uit` las. De CI-log van run 42674398952 zegt dan ook "0 metingen; … overtredingen: 0".
   Lokaal (`make ontwerpreview`, absoluut standaardpad) werd wel echt gemeten.
   **Besluit:**
   - Het pad wordt absoluut gemaakt.
   - De beoordeling faalt als het aantal metingen 0 is of afwijkt van het aantal dat de browser gedaan heeft
     (toestanden × breedtes × 2 thema's).
   - De CI-claims in TESTRAPPORT, ADR-0012, PEIL_REVIEW en EVIDENCE (EX16) zijn gecorrigeerd.

8. **CI-acties op Node 20.**
   checkout, setup-python, setup-buildx, build-push en login zijn bijgewerkt naar dezelfde gepinde majors als in
   ai-server-manager en appstore-en-fork. Elke SHA is met `git ls-remote` tegen de tag gecontroleerd.

Elke reparatie heeft een test die op de vorige code faalt. Dat is gecontroleerd: de oude bronbestanden zijn tijdelijk
teruggezet en de nieuwe tests faalden toen.

## Gevolgen
- `hub-link.json` kan het extra veld `unreadable_replaced_at` bevatten. Oudere versies negeren onbekende velden
  (`extra="ignore"`).
- In de API gaan bronnen na 15 minuten zonder nieuwe meting naar `unknown`. Er is (nog) geen periodieke probe in de
  worker. Een bron blijft dus `unknown` (`meting_verouderd`) tot de Hub of een beheerder opnieuw meet. Dat is bewust:
  liever eerlijk onbekend dan oud groen.
- Wie een IP-adres in een verkorte vorm invulde, krijgt nu een duidelijke Nederlandse fout en moet `a.b.c.d` gebruiken.

## Punten voor de contracteigenaar
- §3.5 zegt niet wat een dienst moet doen met een onleesbaar `hub-link.json`. Gekozen is de veiligste lezing: onbekend
  telt als "al eens gekoppeld" (geen formulier, niets vertrouwd), ook nadat het bestand vervangen is. Herstel gaat
  alleen via een nieuw env-token. Voorstel: dit in §3.5 vastleggen, met de code `koppelstatus_onleesbaar`.
- §4.2/§4.3 noemen `aud:"<app_id>"`, maar zeggen niet expliciet dat een lijst ongeldig is. Voorstel: "precies één
  string; een lijst → `invalid_token`", voor alle diensten.
- §3.2 zegt niet in welke vorm een IP-adres in `HUB_URL` mag staan. Voorstel: alleen `a.b.c.d` of IPv6 tussen `[]`.
