# ADR-0014 — Contract 1.3 en Peil 1.1.1 toegepast

Status: aanvaard · Datum: 2026-11-10 · Fase: conformiteitsronde contract 1.3 (C1.3-HCH-01…14) + Peil 1.1.1

## Context

`ai-server-manager` heeft `contracts 1.3` vastgesteld (met de reviewcorrecties RV1–RV13, ADR-0027/0028 daar) en Peil
1.1.1 uitgebracht. `CONTRACT_1.3_CONFORMITEIT.md` hoofdstuk 2 noemt voor deze repo vijftien punten: veertien **NU**
(C1.3-HCH-13 "na C1.3-ASF-08") en één voor **P2** (C1.3-HCH-15). Daarnaast gelden de gemeenschappelijke regels voor
de vijf eigen diensten en de ALG-punten (kopieën, EVIDENCE, Peil). Alles hieronder is gebouwd en getest met
simulators (Sim-getest); niets is op een echte NAS, met een echte Hub of met een echte Authentik gevalideerd.

## Besluiten

1. **Kopieën (C1.3-ALG-01, C1.3-HCH-14).** `PLATFORM_CONTRACTEN.md` en `CONTRACT_1.3_CONFORMITEIT.md` zijn byte-gelijke
   kopieën van `ai-server-manager@0a7143b`; de 1.2-lijst blijft als historie (ook byte-gelijk aan dezelfde commit). De
   pins staan in `docs/platform-v2/CONTRACT_HERKOMST.json`; `tools/contract_kopie.py` controleert offline en online
   (CI: drift op de gepinde commit = fout, een nieuwere bron = waarschuwing, zoals de pinregel E08 van Peil). De
   drifttest (`test_contract_docs.py`) vergelijkt lokaal ook met de werkmap van de bron.
2. **Peil 1.1.1.** Nieuwe gepinde kopie van het sjabloon (zelfde bron-commit). De renderer leest het sjabloon nu als
   boom en vult in één doorgang in (E07); byte-gelijk getest met `bouw/sjabloon.py` voor elke toestand. Het paginamodel
   volgt COMPONENTEN §29.1:
   - koppeltoestand `koppelstatus_onleesbaar` (Storing "Onleesbaar", geen formulier; melding zonder live-regio en
     zonder trace-ID, met code en pad) en de vlag `koppelen_bezig` (formulier en stappen weg, starttijd erbij);
   - tonen: niet gekoppeld/ontkoppeld/ingetrokken → `niet-gekoppeld`; domein zonder ingestelde bron → `gate` "Niet
     ingesteld"; leeg herstelregister → `gate` "Niet ingevuld"; alleen verouderde metingen → `verouderd` "Verouderd ·
     laatst bekend HH:MM"; boiler → `beleid` "Alleen meten";
   - meldingsrol: `alert` voor de fout van dít verzoek, `status` na een geslaagde koppeling, leeg voor een toestand die
     bij het laden al bestond;
   - totaal (E10): het slechtste van de eigen controles en de verse metingen in het dienstblok; het dienstblok maakt
     het hooguit Beperkt; gate, beleid en verouderd tellen niet; een Onbekend in het dienstblok geeft "Deels
     onbekend". Niet gereed met een beperkt onderdeel in het dienstblok: pil Beperkt, toelichting "<reden niet
     gereed>. Daarnaast beperkt: <onderdeel>." Groen heet "Alles gezond" (§11.1).
3. **Herkomst van de formulier-POST (C1.3-HCH-01).** Volgorde: `Host`-beperking (403 `host_niet_toegestaan`) →
   `Sec-Fetch-Site` (alleen `same-origin`/`none`) → exacte `Origin` = `<schema>://<Host>` (ontbreekt of `null` → 403)
   → formuliercookie. Voor de Origin- en Sec-Fetch-Site-weigering gebruiken we de code `herkomst_onjuist` (zoals
   appstore-en-fork), voor het cookie `ongeldig_formulier`. Een weigering gaat niet naar de Hub, verandert niets en
   telt niet als poging. Wie de pagina via een domeinnaam opent (GET), ziet direct een melding dat koppelen hier niet
   kan, vóór het formulier is ingevuld. `Referrer-Policy: same-origin`.
4. **Pogingen (C1.3-HCH-02).** Na de herkomst telt elke POST: ook een al gekoppelde dienst (409 `al_gekoppeld`, RV7),
   een onleesbaar koppelbestand (409 `koppelstatus_onleesbaar`) en een lopende poging (409 `koppelen_bezig`). Invoer
   wordt als geheel gecontroleerd (Hub-adres ≤ 512, koppelcode ≤ 32, vingerafdruk ≤ 64; vroeger werd eerst
   afgekapt). Per POST precies één logregel (de enrollmentlaag logt een koppelcodepoging alleen op DEBUG). Na een
   geslaagde poging verwijst de 303 naar `/?melding=<sleutel>`; de sleutel staat 15 minuten in het geheugen, gekoppeld
   aan de hash van het formuliercookie (de image draait één API-proces). `?melding=gekoppeld` alleen toont niets meer.
5. **Eerst aanmelden (C1.3-HCH-03, RV9).** FastAPI leest een JSON-body vóór de afhankelijkheden: een onleesbare body
   zonder aanmelding gaf 422. `AuthFirstRoute` leest de body eerst begrensd in (de 1 MiB-laag blijft stap 1, ook
   chunked), authenticeert dan (en verbruikt de `jti` van een mutatie) en pas daarna volgen body, rol en
   `Idempotency-Key`. Een statische test eist dat elke route met een aanmelding zo werkt.
6. **Koppelbestand en enrollment (C1.3-HCH-04/05).** `rotation_sequence` uit het enroll-antwoord (Hub 1.2: 0) wordt
   `pins.rotation_sequence`; daarna alleen `key-rotations?after=<n>`. Het bestand krijgt `schema_version` `"1.3"`; een
   lezer accepteert elke `1.x`. Onleesbaar is nu ook: een andere major, ontbrekende `schema_version`/`state`, een andere
   eigenaar of rechten ruimer dan 0600. Overige 4xx van de Hub (niet in de tabel van §3.3) = `hub_incompatibel`.
7. **Adresregels na DNS-resolutie (§3.2).** `HubClient` lost een hostnaam zelf op, weigert als **een** van de adressen
   loopback (zonder ontwikkelvlag), link-local, `0.0.0.0`/`::` of een IPv4-mapped vorm daarvan is, en verbindt met het
   gecontroleerde adres (`Host` en TLS-SNI blijven de naam). Elke verbinding opnieuw: DNS-rebinding kan zo niet naar
   een verboden adres leiden.
8. **Connector-health (C1.3-HCH-07).** Totaal = slechtste check; vaste namen `database`, `worker`, `jobs`, `hub_link`
   (vroeger `hub_koppeling` en `outbox`). De worker schrijft na elke ronde een hartslag in `service_state`; stil (> 3
   rondes, minstens 60 s) of een mislukte stap → `degraded`, nog nooit → `unknown`. `jobs` = de outbox (wachtrij, bezig
   = in herhaling, laatste job klaar; dead-letter of een gekoppelde wachtrij die > 1 uur niet afneemt → `degraded`).
   **Niet ingesteld is geen check:** zonder ingestelde bron geen check `bronnen`, zonder accounts geen check
   `herstelregister` (zoals E10: anders wordt het totaal nooit groen). Een ingestelde bron zonder verse meting is
   `unknown` (`meting_verouderd`). Schema niet actueel → `down` (de dienst neemt dan geen verkeer aan).
   `discover.limits.max_age_s = {source: 900, health: 900}`.
9. **Events (C1.3-HCH-06/08).** `events.emit` controleert de regels van de Hub-inbox vóór verzending: eigen domeinen,
   de vaste `service.*`-lijst met `entity = {type: service, id: home-control-hub}`, `app` alleen
   `app.health.changed`, `payload.ernst` uit de vijf Peil-woorden. Werkwoorden nagelopen: de enige probleemreeks
   zonder herstel was `sso.authentik_sync.failed`; die krijgt `sso.authentik_sync.recovered` met hetzelfde onderwerp.
   Bestaande namen blijven (de Hub heeft er regels voor, `hub/incidents/rules.py`). Ernst: afwijkingen krijgen `ernst`
   = hun severity (laag/middel/hoog; `severity` blijft één overgangsrelease), sync-fout `middel`, herstel `info`,
   geweigerde sleutelrotatie `hoog`, intrekking `middel`.
   `sso.access.revoked`/`changed` dragen `issuer`, `sub` en `preferred_username`. De `sub` volgt de `sub_mode` van de
   provider van de Hub-applicatie (slug uit het laatste voorstel `sso.oidc.hub.register`, anders `hub`):
   `hashed_user_id` → `User.uid`, `user_id` → `pk`, `user_uuid` → `uuid`, `user_username` → gebruikersnaam (gelezen in
   de broncode van Authentik 2026.8.5: `providers/oauth2/id_token.py` `_resolve_sub`, `core/models.py` `User.uid`; de
   velden `uid`/`uuid` opnieuw tegen de officiële schema's 2024.10.5–2026.8.5 gecontroleerd). De `issuer` komt uit de
   discovery van die provider. Bij `user_email`, `user_upn`, een onbekende modus, geen Hub-client of een onleesbare
   discovery: `issuer`/`sub` `null` en `sub_onbekend` met de reden; we slaan geen e-mailadressen op. Een verwijderde
   gebruiker houdt zijn `sub` uit de vorige momentopname (`ids` in de rechtenmomentopname). NIET GEVALIDEERD tegen een
   echte Authentik.
10. **100.64.0.0/10 (C1.3-HCH-10).** Telt standaard niet als privé. Een beheerder kan het per noodtoegang toestaan
    (`cgnat_toegestaan`, migratie 0004, audit, waarschuwing). Een registratie van vóór 1.3 met zo'n bereik blijft
    staan, maar geeft zonder toestemming geen toegang meer (verscherpen, nooit stil verruimen); de herstelstatus meldt
    het. De Hub mag dit beleid cachen, maar alleen om te verscherpen.
11. **Groep → rol is advies (C1.3-HCH-11).** Elke koppeling draagt `advies: true` met de uitleg dat de Hub de
    koppeling vastlegt. Ze geeft nergens zelf toegang.
12. **Healthcheck (C1.3-HCH-12).** `healthcheck.py --controle` doet dezelfde wissel en meldt Uid, CapEff, CapPrm,
    CapAmb, CapBnd en NoNewPrivs. De rooktest controleert per proces ook CapPrm/CapAmb 0 en bij een start als root
    CapBnd 0, en de healthcheck apart.
13. **Foutcatalogus (§5).** Gedeelde situaties hebben nu één code: `idempotency_key_reused` (422, was 409
    `idempotency_key_conflict`), `precondition_failed` met `huidige_etag`, 403 `forbidden` met `details.reason`
    (`noodtoegang_geweigerd` was een eigen 403-code), 413 met `details.max_bytes`. De bestaande 502/503-codes van de
    Authentik-routes (P1) blijven: de catalogus geldt voor nieuwe routes en de Hub leest ze.
14. **Manifest (C1.3-HCH-13).** Kop 1.3, `healthcheck.monitor`, `accepted_findings` alleen `digest_pending_release`.
    Geldig met de 1.3-validator van appstore-en-fork in `--strict` (lokaal: die commits zijn nog niet gepusht, dus nog
    niet in CI).

## Niet gedaan (met reden)

- **C1.3-HCH-15 (P2):** catalogusbeschikbaarheid via `catalogus.lezen`, `apply` met een ondertekend
  `ExecutionRequest`, overdracht van het `client_secret`. Open in EVIDENCE.
- B10/B11/B14 blijven bij hun datamodel (`501 capability_unavailable`); het dienstblok toont ze als "Niet ingesteld"
  zolang er geen bron is, niet als `niet-beschikbaar` (dat zou het totaal nooit groen laten worden voor iets wat in
  deze fase niet bestaat).

## Contractmeldingen (voor de volgende versie)

1. **Issuer in `sso.access.*`.** Authentik bouwt de issuer uit het adres van het verzoek (`build_absolute_uri`). De
   issuer die deze dienst via zijn eigen Authentik-adres leest, kan dus afwijken van die van de Hub (bv. http-adres op
   het LAN tegenover de https-route van de Hub). Voorstel: de Hub koppelt op `sub` binnen zijn eigen issuer en valt
   terug op `preferred_username` als de issuer niet de zijne is (een event trekt alleen in).
2. **`sub_mode` `user_email`/`user_upn`** zijn niet te volgen zonder e-mailadressen of attributen op te slaan; het
   contract kan expliciet maken dat `sub` dan `null` is.
3. **`Sec-Fetch-Site` in de browsertest.** Chromium stuurt `Sec-Fetch-*` niet naar een niet-"potentially trustworthy"
   adres (gewoon `http://192.168.x.x`). Op een echt LAN beschermen vooral `Origin` en `Host`. De browsertest
   (`tests/ui/herkomst.mjs`) laat de browser zelf `Origin: null` (pagina met `no-referrer`), een vreemde site, een buurapp
   op hetzelfde adres, geen cookie en een domeinnaam maken; de waarden `same-site`/`cross-site` van de header zelf zijn
   met HTTP-tests gedekt.
4. **Health en "niet ingesteld".** "Totaal = slechtste check" zegt niet wat er gebeurt met iets wat niet is ingesteld.
   Gekozen: geen check (besluit 8). Het contract kan dat net als E10 vastleggen.
5. **Herkomstcode.** Alleen `host_niet_toegestaan` staat vast; voor Origin/Sec-Fetch-Site gebruiken diensten nu
   `herkomst_onjuist` (deze repo, appstore-en-fork) of `herkomst_geweigerd` (zoeken-en-persoonlijke-ai). Voorstel:
   `herkomst_onjuist` in de vaste lijst.
6. **400-codes.** `invalid_cursor` (en hier `invalid_type`, `invalid_domain`) staan niet in de tabel van §5 maar de
   referentie van de Hub gebruikt `invalid_cursor` ook. Voorstel: opnemen of naar 422 `validation_error` verwijzen.

## Gevolgen

- De Hub moet de check `hub_link` (niet meer `hub_koppeling`) en `jobs` (niet meer `outbox`) lezen; de vaste namen
  komen uit het contract.
- Een noodtoegang met een 100.64-bereik moet na de update bewust opnieuw worden toegestaan.
- De statuspagina ziet er anders uit (Peil 1.1.1); schermafdrukken en ontwerpreview zijn opnieuw gemaakt.
