# ADR-0015 — Onafhankelijke review contract 1.3 en Peil 1.1.1 (QA)

Status: aanvaard · Datum: 2026-11-10 · Fase: contract 1.3 (`PLATFORM_CONTRACTEN.md` `contracts 1.3`,
`CONTRACT_1.3_CONFORMITEIT.md` hoofdstuk 2) · Volgt op ADR-0014 (contract 1.3 en Peil 1.1.1 toegepast)

## Context

Na de bouwronde voor contract 1.3 (C1.3-HCH-01…14) is de repo onafhankelijk gecontroleerd op HEAD `40fb53f`.

**Opnieuw gedraaid, zoals de CI het doet:**
- lint, typen, unit en integratie;
- migraties op en neer, OpenAPI-drift, contract- en Peil-drift (offline en online);
- dienst-E2E, Playwright, ontwerpreview met de browsertest van het koppelformulier;
- image bouwen met de rooktest, pip-audit en actionlint.

**Daarnaast:**
- de code gelezen tegen §1–§13 en tegen elk NU-punt van de conformiteitslijst;
- de interoptest gedraaid tegen de **echte** Hub, die inmiddels 1.3 volgt (ai-server-manager `5e21775`);
- het manifest gevalideerd met de gepushte 1.3-validator van appstore-en-fork (`cca4403`).

Alles hieronder is **Sim-getest** of lokaal tegen de echte Hub-code getest. Niets is op een echte NAS, met een echte
Authentik of met echte accounts gevalideerd.

## Wat standhield (zelf nagemeten)

- **Byte-gelijke kopieën:**
  - `PLATFORM_CONTRACTEN.md`, `CONTRACT_1.3_CONFORMITEIT.md` en de 1.2-lijst zijn byte-gelijk aan ai-server-manager
    `0a7143b`. Na die commit zijn ze in de bron niet meer gewijzigd (gemeten tot `5e21775`).
  - Het Peil-sjabloon 1.1.1 is byte-gelijk aan de bron.
- **NU-punten:** C1.3-HCH-01…14 zijn gebouwd en met tests gedekt, ook de negatieve gevallen. C1.3-HCH-15 is P2 en
  staat terecht open.
- **Herkomst van het koppelformulier:**
  - de HTTP-tests en de browsertest in Chromium tegen de draaiende dienst slagen (5 negatieve gevallen en 1 echt
    formulier);
  - elke weigering gaat niet naar de Hub, verandert niets en telt niet als poging.
- **Ontwerpreview:** 168 metingen, 0 overtredingen.
- **Rooktest:** 34/34, ook CapBnd 0 bij een start als root en de healthcheck apart.
- **Interop met de echte Hub:** lukt, ook met de 1.3-regels van de Hub.

## Bevindingen en besluiten

1. **Twaalf tests werden in CI stil overgeslagen.** Het ging om:
   - de controle van het manifest met de 1.3-validator (C1.3-HCH-13);
   - de tien gevallen "renderer byte-gelijk aan de referentie `bouw/sjabloon.py`" (Peil 1.1.1, E07).

   Ze draaiden alleen lokaal, omdat ze een checkout van appstore-en-fork en ai-server-manager naast deze repo nodig
   hebben. De CI-run gaf "708 passed, 12 skipped". De claims "byte-gelijk getest" en "manifest geldig in --strict" waren
   dus niet door CI gedekt.

   **Besluit:**
   - CI installeert de validator in een eigen venv op een vaste commit (alleen lezen, `--require-hashes`).
   - CI haalt `bouw/sjabloon.py` op de gepinde bron-commit uit `design/ontwerptaal/HERKOMST.json`.
   - Met `HCH_MANIFEST_VALIDATOR_VERPLICHT=1` en `HCH_PEIL_REFERENTIE_VERPLICHT=1` falen die tests als de bron
     ontbreekt, in plaats van over te slaan.
   - Een statische test bewaakt dat de CI deze stappen houdt.
   - Over blijft één overgeslagen test: de vergelijking met een lokale checkout van de Peil-bron. CI vergelijkt die
     kopie online (`tools/peil_kopie.py vergelijk --online`).

2. **Connector-health: verouderde bron kreeg "nu" als meettijd en kon een verse storing verbergen.**
   §6.2 zegt: een verouderde meting is `unknown` met `meting_verouderd` **en de tijd van de laatste meting**. De check
   `bronnen` zette bij een verouderde meting `observed_at` op het moment van de vraag. Daarnaast meldde hij ook
   `meting_verouderd` als een andere bron vers `down` was. Dan stond er `status: down` met de verkeerde oorzaak.

   **Besluit:**
   - `observed_at` is de oudste meting die meetelt.
   - `detail.laatste_meting_verouderd` noemt de tijd van de laatste verouderde meting, zonder de oude stand.
   - Een verse storing of beperking blijft de oorzaak (`bron_down`/`bron_degraded`).
   - Gedekt met een nieuwe integratietest.

3. **Koppelbestand: modus expliciet 0600.**
   §3.5 maakt een `hub-link.json` met rechten ruimer dan 0600 onleesbaar (fail-closed). Geërfde ACL's van een dataset
   (bv. NFSv4 op TrueNAS) kunnen een nieuw bestand ruimer maken dan de gevraagde 0600. De dienst zou dan zijn eigen
   koppeling als onleesbaar lezen.

   **Besluit:**
   - De schrijver zet de modus na het aanmaken met `fchmod` op 0600, zoals de eigen geheimen dat al deden.
   - Unit-getest met een nagebootste ruimere modus; de test faalt zonder de wijziging.
   - Echte ZFS-ACL's: **NIET GEVALIDEERD (echte NAS)**.

4. **Logregel bij het apart zetten van een onleesbaar bestand.** Een mislukte `chmod` gaf "kon niet apart worden
   gezet", terwijl het bestand al hernoemd was. Dat gebeurt bij een bestand van een andere eigenaar.

   **Besluit:** hernoemen en `chmod` zijn gescheiden. Het bewaarde bestand staat altijd in de map `secrets` (0700).

5. **Manifest:** de upgradenotitie noemde migratie `0004` niet. Aangevuld. Het manifest is opnieuw geldig in
   `--strict` (0 fouten; alleen het geaccepteerde `digest_pending_release`).

6. **Interop:** de lokale test tegen de echte Hub controleert nu ook drie 1.3-punten:
   - `schema_version` `"1.3"` en `rotation_sequence` in `hub-link.json`;
   - het event `service.hub_link.linked` wordt in de inbox van de echte Hub afgeleverd: geen weigering, geen
     dead-letter.

7. **EVIDENCE:** C1.3-HCH-13 is bijgewerkt. De validator is nu gepusht en draait in CI. Er is een reviewregel
   `REVIEW-home-control-hub-contract-1.3`.

## Contractmeldingen (voor de volgende versie)

1. **Rechten van `hub-link.json` op TrueNAS-datasets.** "Rechten ruimer dan 0600 = onleesbaar" (§3.5) kan bij geërfde
   NFSv4-ACL's alle diensten treffen. Dat geldt ook als de dienst het bestand zelf met 0600 aanmaakt.
   - **Voorstel:** het contract schrijft voor dat de dienst de modus zelf op 0600 zet (`fchmod`). Daarnaast een
     acceptatietest op een echte NAS met het dataset-preset *Apps*.
   - Tot dan blijft het fail-closed.
2. **Issuer in `sso.access.*` (aanvulling op ADR-0014, melding 1).**
   - Gemeten in ai-server-manager `5e21775`, `apps/api/src/hub/oidc/service.py` (`handle_event`): als het event een
     `issuer` meegeeft, filtert de Hub op `OidcIdentity.issuer == issuer`.
   - Leest deze dienst de issuer via een ander Authentik-adres dan de Hub, dan trekt de Hub **niets** in. Hij legt
     alleen `accounts: 0` vast in de audit, zonder incident. Een intrekking die stil niets doet, is "open bij fout".
   - **Voorstel (C1.3-ASM-10):** bij een issuer die niet de eigen issuer is, koppelt de Hub op `sub` en valt hij terug
     op `preferred_username`. Een intrekking die 0 accounts raakt terwijl er een `sub` was, wordt een waarschuwing.
3. **Versheid van een samengestelde check (§6.2).** Het contract zegt niet welke `observed_at` een check krijgt die
   meerdere metingen samenvat. Gekozen: de oudste meting die meetelt. Zo is de check nooit verser dan zijn oudste bron.

## Gevolgen

- **CI heeft nu twee extra bronnen nodig:** GitHub (appstore-en-fork op een vaste commit) en
  raw.githubusercontent.com (één bestand op de gepinde Peil-commit). Zijn die niet bereikbaar, dan faalt CI. Het
  resultaat wordt dus nooit stil als geslaagd geteld.
- Een nieuwe Peil-kopie (`tools/peil_kopie.py bijwerken`) neemt in CI automatisch de referentie van de nieuwe commit
  mee. Een nieuwe validatorversie vraagt een bewuste wijziging van `VALIDATOR_COMMIT`.
