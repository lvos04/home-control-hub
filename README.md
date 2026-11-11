# home-control-hub

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
`jelly-leon-platform`). De schermen staan in de Hub en zijn hier niet gebouwd. NIET GEVALIDEERD (echte NAS): niet
als Custom App op TrueNAS geïnstalleerd; zie STAPPEN_P6.md.

B10/B14 hebben alleen datamodel en inventaris; hun data-endpoints geven eerlijk `501 capability_unavailable`.
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
| B11-001: Node-RED-client (alleen de admin-API, geen redirects), isolatiemeting, flowbeleid (exec-node en modules buiten de allowlist blokkeren), beveiligingsprofiel (geen installatiestap; vervalt of wordt gelijkgetrokken volgens besluit C-12, ADR-0016) | `domains/automation/nodered.py`, `policy.py`, `catalog.py` |
| B11-002: eventtypencatalogus, inbox, afleveren per flow in volgorde met herhalen en dead-letter | `domains/automation/eventcatalog.py`, `inbox.py` |
| B11-003: flow-API met flow-tokens; actieverzoeken worden `flow.action.requested` voor de Hub, nooit een eigen uitvoering | `domains/automation/flowapi.py`, `actions.py` |
| B11-004: proefrun met vaste voorbeeld-events | `domains/automation/simulate.py`, `samples.py` |
| B11-005: versleutelde momentopnamen, diff zonder waarden, herstel als voorstel + ondertekend ExecutionRequest (Ed25519, canonieke JSON, eigen hercontrole) | `domains/automation/snapshots.py`, `restore.py`, `security/execreq.py` |
| Nep-Node-RED voor tests (volgt de gemeten feiten van de gepinde image) en het meetprogramma tegen de echte image | `apps/api/tests/fakes/node_red_fake.py`, `tests/e2e/sim_node_red.py`, `tools/node_red_verify.py`, `docs/b11/` |
| B10/B14: datamodellen met database-invarianten en inventaris (alles *te verifiëren*) | `domains/network`, `energy` |
| Migraties (Alembic) | `apps/api/alembic/` |
| Alles-in-één image (PostgreSQL 16 via unix-socket + API + worker; de procesbewaker is PID 1, wisselt naar 568 zonder capabilities en zet no-new-privileges) | `deploy/allinone/` |
| OpenAPI | `docs/openapi/home-control-hub.openapi.json` |
| Besluiten | `docs/adr/` |
| Noodprocedure (gebruikers) | `docs/runbooks/NOODTOEGANG.md`, `docs/runbooks/AUTHENTIK_BACKUP_UPGRADE.md` |

## Ontwikkelen

```sh
python3.12 -m venv .venv && .venv/bin/pip install -e 'apps/api[dev]'
make lint test e2e          # ruff, mypy, unit + integratie (PostgreSQL), dienst-E2E met simulator
make image smoke            # image bouwen en rooktest zoals het formulier (elk proces 568, CapEff 0, NoNewPrivs 1)
make openapi                # OpenAPI opnieuw exporteren (CI faalt bij drift)
.venv/bin/python tools/node_red_verify.py   # meet de aannames over Node-RED tegen de gepinde image (lokale Docker;
                            # haalt de image op; schrijft docs/b11/node-red-verificatie.json)
make test-ui                # statuspagina in Chromium: axe-core, overloop, CSP, focus (Node 22; eenmalig
                            # 'cd tests/ui && npx playwright install chromium')
make schermafdrukken        # idem + afdrukken naar docs/screenshots/peil/statuspagina/
make peil-drift             # Peil-kopie offline en tegen ai-server-manager op GitHub
make contract-drift         # contractkopie (contracts 1.3) offline en tegen ai-server-manager op GitHub
make ontwerpreview          # draaiende dienst + Hub-simulator: 14 toestanden × 320–1440 × licht/donker (axe WCAG 2.2 AA,
                            # contrast, doelen, focus, tekstafstand, Peil-statusregels) + browsertest herkomst
                            # (tests/ui/herkomst.mjs) → tests/ui/review-uit/
```

Integratietests gebruiken een lokale PostgreSQL 16 (`HCH_TEST_ADMIN_URL`, standaard `postgres@127.0.0.1:5432`) met
databases `hch_test_*`. `deploy/dev/compose.yaml` is alleen voor ontwikkeling — **geen** installatiemethode.

Licentie: **GPL-3.0** (zie [`LICENSE`](LICENSE); besluit van de eigenaar, 2026-11-09).
