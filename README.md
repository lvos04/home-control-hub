# home-control-hub

[Broncode op Forgejo](https://git.medialeon.nl/leon/home-control-hub) · [![CI](https://git.medialeon.nl/leon/home-control-hub/badges/workflows/ci.yml/badge.svg?branch=ccr-c133d7a0-kuz1cv)](https://git.medialeon.nl/leon/home-control-hub/actions?workflow=ci.yml&branch=ccr-c133d7a0-kuz1cv)

Integratiedienst van **TrueNAS Home Platform V2**: B10 netwerk/privacy, B11 Node-RED, B13 Authentik/SSO (met
beheerherstel B13-001) en B14 energie/resources. Een zelfstandige API-dienst met alleen een kleine Nederlandse
statuspagina; alle schermen staan in de Hub (`ai-server-manager`).

**Status (fase P1 + B11 uit fase P2, platformcontract 1.3, Peil 1.1.1):** kern volgens `contracts 1.3`
(`docs/platform-v2/PLATFORM_CONTRACTEN.md`, byte-gelijke kopie met drifttest; conformiteit C1.3-HCH-01…14 in ADR-0014:
koppelformulier met herkomst- en Host-beperking, eerst aanmelden, connector-health met vaste checks, events met
domeinen/werkwoorden/ernst en `issuer`/`sub` in `sso.access.*`, `100.64.0.0/10` alleen met toestemming; koppelen met
de Hub volgens §3.3–§3.8, alleen Hub-JWT's tegen gepinde sleutels, image zonder enig rootproces; ADR-0010/0013/0014;
onafhankelijke review van contract 1.3 in ADR-0015)
+ B13-001 (accountrecovery en admin-toegang; de noodlogin zelf zit in de Hub) en
B13-002…005 (Authentik via de officiële API: versiedetectie, OIDC-client voor de Hub als R2-voorstel, SSO-dekking per
app met bron, audit/afwijkingen, configuratie-export, pre-upgrade-gate en herstelcheck) gebouwd en met simulators
getest. **Wijzigingen in Authentik worden alleen voorgesteld, nooit uitgevoerd** (toepassen vereist een door de Hub
ondertekend ExecutionRequest, fase P2).

**B11 Node-RED-automatisering (B11-001…005, ADR-0016)** is gebouwd en met een Node-RED-simulator en een
Hub-simulator getest: isolatie meten en flows met verboden nodes blokkeren, eventtypencatalogus met afleveren aan
flows, veilige acties (een flow vraagt aan, de Hub beslist; boiler, verwijderen en shell worden altijd geweigerd),
proefrun met vaste voorbeeld-events, en versies met herstel via een door de Hub ondertekend ExecutionRequest. De
aannames over Node-RED zijn nagemeten tegen de gepinde image in lokale containers
(`docs/b11/node-red-verificatie.json`, gemeten met het eigen profiel van deze app, niet met het manifest van
`jelly-leon-platform`). De schermen staan in de Hub en zijn hier niet gebouwd.
NIET GEVALIDEERD (echte NAS): niet als Custom App op TrueNAS geïnstalleerd; zie STAPPEN_P6.md.

**B14-001 energiemeters.** B14 leest my_house rechtstreeks met een eigen viewer-koppeling. Een beheerder stelt
`my_house` in via `PUT /integrations/v1/sources/my_house`. Gebruik het HTTPS-adres met
`/api/v1/homes/<woning-UUID>` en zet `enabled` aan. Geef het viewer-token met doel `hub` als `credential` op.
Vul in `my_house_pairing` de waarden `server_id`, `client_id` en `home_id` uit het koppelantwoord in
(`server.server_id`, `client.id` en `server.home_id`). De kluis bewaart token en binding samen na controle.
Een oude koppeling zonder deze ID's of een andere bestemming vraagt opnieuw om de bevestigde koppelgegevens.

`GET /integrations/v1/energy/meters` geeft de logische meetkanalen van de woning met bron, vermogen in watt,
kwaliteitslabel en eigen meettijd. `GET /integrations/v1/energy/coverage` en connectoritem `energy.coverage`
geven de dekking per verwachte rol. De client herkent P1 aan de expliciete rol `grid` in het dagoverzicht en
leest het bijbehorende vermogen en de meettijd uit `energy/live`. De boiler en de gedeelde airco-buitenunit
leveren hun eigen rol, tijd en opgeslagen kwaliteit in dat liveantwoord. Alleen `measured` geeft `gemeten`,
`estimated` geeft `geschat`. Bij een ontbrekend of afgeleid bronlabel blijft het vermogen onbekend.
De bron levert voor deze kanalen geen fysiek serienummer.

| Toestand bij B14 | Energieverzoek | Dekking per rol |
| --- | --- | --- |
| Bron uit, kluiswaarde ontbreekt of oude koppeling zonder ID's | Geen | Onbekend |
| HTTP, ongeldig certificaat of afwijkend adres | Geen | Onbekend |
| Serverbewijs, client-ID of woning ontbreekt of wijkt af | Geen | Onbekend |
| Rol en doel verschillen van de combinatie `viewer` en `hub` | Geen | Onbekend |
| Bevestigde koppeling, verse rol met getal en bronlabel `measured` | GET | Gemeten, ook bij 0 W |
| Bevestigde koppeling, verse rol met getal en bronlabel `estimated` | GET | Geschat |
| Bevestigde koppeling, meting verlopen of meetbewijs onvolledig | GET | Onbekend |
| Controle vervalt tussen twee verzoeken of vóór een herpoging | Geen volgend energieverzoek | Onbekend |

De connector geeft de eigen bronmeettijd als `observed_at` door en publiceert de grens van 300 seconden in
`discover`. Bij overschrijding krijgt de rol de code `meting_verouderd`. Bij uitval wordt het vermogen onbekend.
De laatste bekende meettijd blijft herkenbaar bij dezelfde koppeling. Apparaatnamen, vermogen van binnenunits en CPU-belasting leveren
geen meterbewijs. De huidige bron meldt geen losse NAS-meter. De fysieke toewijzing vraagt besluit D14 en
beproeving met de meters in huis (N-P6-06).

**B14-002 energietijdreeks.** Met een leesrol geeft `GET /integrations/v1/energy/usage` het verbruik en de
variabele energiekosten. Kies `period=day|week|month` en een lokale `date`. Een week begint op maandag.
`role` kiest `p1_net` (standaard), `boiler_socket` of `airco_outdoor`. Gebruik `direction=import`
voor afname en `direction=export` voor teruglevering. Het antwoord vermeldt de tijdzone van de woning.
De optionele parameter `timezone` controleert of de aanroeper dezelfde zone gebruikt.

De worker leest iedere vijf minuten de uur-export van vandaag, gisteren en één eerdere woningdag uit
de laatste 31 dagen. Na een herstart vervolgt hij die terugblik. Eerder opgeslagen dagen blijven
opvraagbaar. Alleen afgesloten uren komen in het archief. Elke hoeveelheid in het rapport heeft een bron
en een kwaliteit. Voor een dag- of periodetotaal moeten alle uren een waarde hebben.

| Toestand | Wat het rapport toont |
| --- | --- |
| Overgang naar zomertijd in een woning met een uur tijdverschil | 23 afzonderlijke UTC-uren op de lokale dag |
| Terug naar wintertijd | 25 UTC-uren, ook beide voorkomens van het teruggezette uur |
| Gemeten nul | 0 kWh met bronkwaliteit |
| Gat, strijdige bronrijen of door de bron overgeslagen tellerreset | Onbekend uur en onvolledig dag- en periodetotaal |
| Geldig uurtotaal bij een gemelde tellerreset | Bronwaarde met `counter_reset` |
| Meterwissel | Opeenvolgende meters tellen elk in hun eigen uren. Bij twee apparaten in hetzelfde uur is de verdeling onbekend. |
| Minstens één geschat uur en alle uren aanwezig | Geschat totaal met herkomst |
| Geen eenduidige prijs voor het hele uur of ontbrekende woningvaluta | Onbekend bedrag, met de beschikbare kWh ernaast |

De bron levert een apparaatnaam per gebonden rol. De dienst leidt daar binnen de gekoppelde woning een
meter-ID uit af. Een naamswijziging kan daardoor als wissel verschijnen en identiek benoemde meters zijn
in de export niet te onderscheiden. De gebruiker ziet de meter-ID. De kosten gebruiken de afnameprijs
of terugleververgoeding uit de tarieflijst in de woningvaluta. Vaste dagkosten vallen buiten dit
verbruiksbedrag. Bij afwijkende T1/T2-prijzen ontbreekt een eenduidige prijs voor de hoofdteller.

Schema 0009 bewaart vier decimalen per uur, gaten zonder bekende meter en de herkomst van een
bronschatting zonder opgegeven zekerheid. Een terugmigratie naar 0008 stopt zodra zulke rijen hun
betekenis of precisie zouden verliezen. Herstel in dat geval de voor-upgradeback-up in een aparte datamap.
Bij meerdere terugstappen legt de dienst elke revisie apart vast, zodat de back-up van de volgende stap
het bijbehorende schema kan lezen.

De gegevensroutes van B10 en de overige gegevensroutes van B14 voor werklast en advies geven
`501 capability_unavailable`.
**Niets is op een echte NAS, met een echte Authentik of met een Node-RED op de NAS gevalideerd** (zie
`docs/platform-v2/EVIDENCE.json`).

## Installeren

Uitsluitend als **standaard TrueNAS Custom App** (image + tag, poort `30420`, opslag `/appdata`) — geen YAML, geen
compose, geen terminal. Normaal installeert het platform deze app via de TrueNAS-API. Zie
[`deploy/truenas/CUSTOM_APP.md`](deploy/truenas/CUSTOM_APP.md) en het manifest
[`deploy/manifest/home-control-hub.manifest.yaml`](deploy/manifest/home-control-hub.manifest.yaml).
Node-RED zelf is een eigen standaard Custom App; de installatieweg is het manifest van `jelly-leon-platform`
(`install/manifests/node-red.manifest.yaml`). Wat je in deze app instelt om Node-RED te bewaken:
[`deploy/truenas/NODE_RED_CUSTOM_APP.md`](deploy/truenas/NODE_RED_CUSTOM_APP.md).

## Wat erin zit

| Onderdeel | Waar |
|---|---|
| API (`/integrations/v1`), connectorcontract (`/connector/v1`), `/healthz`, `/readyz`, statuspagina `GET /` | `apps/api/src/integrations/` |
| Auth (§4): alleen Hub-JWT's (gebruiker of dienst-JWT) tegen de gepinde sleutels, vaste `reason`-waarden, `jti` + replaycache. Enige uitzondering: de flow-API van B11 neemt alleen flow-tokens aan, en die openen niets anders (ADR-0016) | `security/auth.py`, `security/replay.py`, `security/hubkeys.py`, `domains/automation/flowapi.py` |
| Koppelen (§3): env-token (worker) of koppelcode + vingerafdruk op de statuspagina (alleen vóór de eerste koppeling); `/appdata/secrets/hub-link.json`; bevestigen, intrekken, token- en sleutelrotatie; `GET /connector/v1/hub-link` en `POST …/unlink` | `enrollment.py`, `hublink_store.py`, `status_page.py`, `connector.py` |
| Statuspagina `GET /` in de ontwerptaal Peil 1.1.1 (versie-gepinde kopie van het sjabloon, renderer in één doorgang, geen JavaScript; herkomst, `Host`-beperking en pogingen volgens contract 1.3 §3.7; ADR-0011/0014) | `status_page.py`, `peil.py`, `design/ontwerptaal/`, `tools/peil_kopie.py` |
| Byte-gelijke kopie van het platformcontract 1.3 met drifttest (offline en online) | `docs/platform-v2/CONTRACT_HERKOMST.json`, `tools/contract_kopie.py`, `apps/api/tests/unit/test_contract_docs.py` |
| UI-tests van de statuspagina (Playwright + axe-core, 320–1440 px, licht/donker) en schermafdrukken | `tests/ui/`, `docs/screenshots/peil/statuspagina/` |
| Onafhankelijke ontwerpreview van de statuspagina tegen de draaiende dienst (14 toestanden, 320–1440 incl. 1024; ADR-0012) en de browsertest van het koppelformulier met de negatieve herkomstgevallen (contract 1.3 §3.7 punt 6) | `tests/ui/ontwerpreview.py`/`.mjs`, `tests/ui/herkomst.mjs`, `docs/ontwerp/PEIL_REVIEW.md`, `docs/ontwerp/peil-review/` |
| Hub-simulator volgens §3.3 (ook de nep-Hub van de integratietests) | `tests/e2e/sim_hub.py` |
| B13-001: herstelregister, noodtoegang LAN/VPN, zelftest met Authentik offline, versleutelde herstelkit | `domains/sso/` |
| B13-002…005: Authentik-client (alleen lezen, gecontroleerd tegen de officiële schema's), voorstellen, SSO-mapping, audit, export/gate/herstelcheck | `domains/sso/authentik/`, `oidc_hub.py`, `proposals.py`, `mapping.py`, `authaudit.py`, `backup.py` |
| Nep-Authentik voor tests (vorm van de officiële API) en schemacontrole | `apps/api/tests/fakes/authentik_fake.py`, `tools/authentik_schema_check.py` |
| B11-001: Node-RED-client (alleen de admin-API, geen redirects), isolatiemeting, flowbeleid (exec-node en modules buiten de allowlist blokkeren), geen eigen beveiligingsprofiel meer (vervallen volgens besluit C-12, S-P3-360, ADR-0016) | `domains/automation/nodered.py`, `policy.py`, `catalog.py` |
| B11-002: eventtypencatalogus, inbox, afleveren per flow in volgorde met herhalen en dead-letter | `domains/automation/eventcatalog.py`, `inbox.py` |
| B11-003: flow-API met flow-tokens; actieverzoeken worden `flow.action.requested` voor de Hub, nooit een eigen uitvoering | `domains/automation/flowapi.py`, `actions.py` |
| B11-004: proefrun met vaste voorbeeld-events | `domains/automation/simulate.py`, `samples.py` |
| B11-005: versleutelde momentopnamen, diff zonder waarden, herstel als voorstel + ondertekend ExecutionRequest (Ed25519, canonieke JSON, eigen hercontrole) | `domains/automation/snapshots.py`, `restore.py`, `security/execreq.py` |
| Nep-Node-RED voor tests (volgt de gemeten feiten van de gepinde image) en het meetprogramma tegen de echte image | `apps/api/tests/fakes/node_red_fake.py`, `tests/e2e/sim_node_red.py`, `tools/node_red_verify.py`, `docs/b11/` |
| B10 netwerkinventaris en B14-001 energiemeters en dekkingsmatrix | `domains/network`, `domains/energy` |
| Migraties (Alembic) | `apps/api/alembic/` |
| Alles-in-één image (PostgreSQL 16 via unix-socket + API + worker; de procesbewaker is PID 1, wisselt naar 568 zonder capabilities en zet no-new-privileges) | `deploy/allinone/` |
| OpenAPI | `docs/openapi/home-control-hub.openapi.json` |
| Besluiten | `docs/adr/` |
| Noodprocedure (gebruikers) | `docs/runbooks/NOODTOEGANG.md`, `docs/runbooks/AUTHENTIK_BACKUP_UPGRADE.md` |

## Ontwikkelen

```sh
python3.12 -m venv .venv && .venv/bin/pip install -e 'apps/api[dev]'
make lint test e2e          # ruff, mypy, unit + integratie (PostgreSQL), dienst-E2E met simulator
make image smoke            # image bouwen en starten zoals via het Custom App-formulier
                            # controleert o.a. UID 568, CapEff 0, NoNewPrivs 1 en 'Niet ingesteld' bij B11 zonder bron
make openapi                # OpenAPI opnieuw exporteren (CI faalt bij drift)
.venv/bin/python tools/node_red_verify.py   # meet de aannames over Node-RED tegen de gepinde image (lokale Docker;
                            # haalt de image op; schrijft docs/b11/node-red-verificatie.json)
make test-ui                # statuspagina in Chromium: axe-core, overloop, CSP, focus (Node 22; eenmalig
                            # 'cd tests/ui && npx playwright install chromium')
make schermafdrukken        # idem + afdrukken naar docs/screenshots/peil/statuspagina/
# Gebruik een bijgewerkte Forgejo-werkkopie van ai-server-manager op de bronbranch uit de herkomstbestanden.
python3 tools/peil_kopie.py vergelijk --bron ../ai-server-manager
python3 tools/contract_kopie.py vergelijk --bron ../ai-server-manager
make ontwerpreview          # draaiende dienst + Hub-simulator: 14 toestanden × 320–1440 × licht/donker (axe WCAG 2.2 AA,
                            # contrast, doelen, focus, tekstafstand, Peil-statusregels) + browsertest herkomst
                            # (tests/ui/herkomst.mjs) → tests/ui/review-uit/
make interop HUB_PY=<venv>/bin/python   # lokale Hub, connector en Node-RED-simulator
```

Voor de B11-interop is `ai-server-manager@f37bcf8` getoetst. Maak een `git archive` van die commit en installeer
`apps/policy` en `apps/api` uit het archief met `pip install -e` in de eigen venv. De proef gebruikt ook de
back-upfixture uit dat archief. Hij volgt een flowverzoek tot het Hub-voorstel en een goedgekeurd R2-herstel tot
de readback. De connector weigert hetzelfde ondertekende verzoek zodra één letter verandert. De vier
energieproeven gebruiken daarnaast het lokale pakket `shc_api` van `my_house` met zijn afhankelijkheden.

Integratietests gebruiken een lokale PostgreSQL 16 (`HCH_TEST_ADMIN_URL`, standaard `postgres@127.0.0.1:5432`) met
databases `hch_test_*`. `deploy/dev/compose.yaml` is alleen voor ontwikkeling — **geen** installatiemethode.

Licentie: **GPL-3.0** (zie [`LICENSE`](LICENSE); besluit van de eigenaar, 2026-11-09).
