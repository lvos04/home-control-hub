# Schermafdrukken — statuspagina in Peil (HC11)

Gemaakt met `make schermafdrukken` (Playwright 1.65, Chromium, `locale nl-NL`, TZ UTC) uit de **echte app** tegen de
Hub-simulator (`tests/ui/genereer_toestanden.py`; vaste trace-ID's). Validatie: **Sim-getest** — geen echte Hub,
geen echte NAS, geen echte telefoon of schermlezer.

| Bestand | Toestand |
|---|---|
| `niet-gekoppeld-<thema>-<breedte>.png` | nog nooit gekoppeld: koppelformulier (Hub-adres, koppelcode, vingerafdruk); totaal "Niet gereed" |
| `koppelen-mislukt-…` | de Hub weigerde de koppelcode: HTTP 400, code `hub_weigerde`, selecteerbare trace-ID, veldfout bij Koppelcode |
| `gekoppeld-…` | gekoppeld en door de Hub bevestigd, met de melding na het koppelen; "Gekoppeld" is een neutrale pil |
| `ingetrokken-…` | de Hub trok de koppeling in (`services/self` gaf 401); opnieuw koppelen alleen via de Hub |
| `niet-gereed-…` | eigen database onbereikbaar: totaal "Storing", niets geschat |

Thema's `licht` en `donker` (`prefers-color-scheme`), breedtes 360, 768 en 1440 px. De UI-tests draaien daarnaast
ook 320, 390 en 1024 px en vier extra toestanden (ongeldige invoer, te veel pogingen, ontkoppeld, onleesbaar
koppelbestand). CI bewaart dezelfde afdrukken als artefact `statuspagina-peil`.
