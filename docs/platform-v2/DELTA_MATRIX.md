# Delta-matrix home-control-hub (P0 + P1-B13, 2026-11-09)

Nieuwe repo: vóór P0 bestond alleen documentatie. *Bestaand* = al aanwezig vóór deze fase; *P0 gebouwd* = in deze
fase gebouwd en met simulators getest; *ontbrekend* = nog te bouwen. Geen enkele regel is op een echte NAS gevalideerd.

| Onderdeel | Bestaand | P0 gebouwd | Ontbrekend |
|---|---|---|---|
| Kern: auth §4, enrollment §3, foutformaat, idempotency, healthz/readyz, connector §6, outbox §7 | — | ja | Hub-zijde (enroll-endpoint, inbox) in `ai-server-manager` |
| Alles-in-één image + Custom App-instructie + manifest + CI/release | — | ja | echte installatie op TrueNAS; GHCR-release met digest |
| B13-001 accountrecovery en admin-toegang | — | register, noodtoegang LAN/VPN, zelftest met Authentik offline, oefeningen, activaties, herstelkit | noodlogin in de Hub; schermen in de Hub-UI; echte oefening op de NAS |
| B13-002 OIDC Hub | JWT-validatie van Hub-tokens (iss/aud/tijden, fail-closed) | **P1:** Authentik-client (officiële API, alleen lezen, versiedetectie, schema's 2024.10–2026.8 gecontroleerd), R2-voorstel provider + applicatie + groepsbindingen (preview/diff/preview_hash/resource_etag), alleen-lezen controle bestaande client, JWT-replay (jti) | toepassen met ondertekend ExecutionRequest (P2); OIDC-login in de Hub (ai-server-manager); echte Authentik + D17 |
| B13-003 SSO-mapping per app | dekkingsmatrix-structuur; geen header-SSO (getest) | **P1:** per app bron + verificatiestatus (docs/broncode), loginroute native/oidc met handmatige testbevestiging, groep → rol | testlogin per app op een echte installatie |
| B13-004 audit en rechten | — | **P1:** events met watermerk, afwijkingsregels → events, rechtenkaart met verschillen, `sso.access.revoked`, least-privilege-controle token, viewer-sweep | schermen in de Hub-UI; ijking van de regels op echte data |
| B13-005 back-up en upgrade | — | **P1:** geschoonde configuratie-export, pre-upgrade-gate (officiële upgraderegels), herstelcheck (rechten, 2FA, clients), voorstel sessies intrekken | database-back-up/-restore van Authentik (Hub/executor), sandbox-herstel, uitvoeren (P2) |
| B10-001 netwerktopologie | — | inventaris + datamodel (geen malware zonder bewijs) | NetAlertX-adapter, LAN-gegevens (D03) |
| B10-002…006 | — | alleen schema | alles |
| B11-001 flow-netwerkisolatie | — | Node-RED-client, isolatiemeting (anoniem 401, besluit C-11), flowbeleid (exec-node en vreemde modules blokkeren), editor-adres alleen voor een beheerder; beveiligingsprofiel bestaat maar is geen installatiestap (besluit C-12); aannames gemeten tegen de gepinde image (lokaal, eigen profiel) | installatie van Node-RED op de NAS via het manifest van jelly-leon-platform (I10), netwerkafscherming en dataset-rechten daar; beheerder en dienstaccount zonder geheim in het formulier (C-12: ontwerp S-P2-510, bouw na P2); scherm in de Hub |
| B11-002 eventtypencatalogus | — | catalogus volgens §7, inbox, afleveren per flow in volgorde, herhalen, dead-letter, onbekende schema-versie bewaard en gemeld | het pad waarlangs de Hub events van andere apps doorstuurt (niet in het contract) |
| B11-003 veilige acties | — | flow-API met flow-tokens, vaste weigeringen (boiler, verwijderen, shell, beleid, betaald), ontdubbeling, limieten, `flow.action.requested` naar de Hub | verwerking van het verzoek in de Hub (ActionProposal, policy, uitkomst terug) |
| B11-004 simulatie en tests | — | proefrun met vaste voorbeeld-events; actieverzoeken worden alleen gesimuleerd | afscherming van nodes die zelf naar buiten gaan (kan deze dienst niet; alleen met bevestiging) |
| B11-005 herstel en versiebeheer | — | versleutelde momentopnamen, diff zonder waarden, herstel als voorstel + ondertekend ExecutionRequest, readback | `automation.flows.restore` in de policy van de Hub (een echte Hub geeft er nog geen opdracht voor uit) |
| B14-001 dekkingsmatrix | — | structuur met status *onbekend*, kwaliteitslabels, DB-invarianten | D14, readback my_house |
| B14-002…005 | — | alleen schema | alles |

Review P0 (2026-11-09): aanscherpingen in ADR-0006; geen nieuwe functionaliteit, wel fail-closed gedrag en tests.

P1 B13-002…005 (2026-11-09): zie ADR-0007/ADR-0008. Alles Sim-getest tegen de in-repo nep-Authentik; geen echte
Authentik, domeinnaam (D17) of NAS.

Contract 1.3 + Peil 1.1.1 (2026-11-10): conformiteitsronde C1.3-HCH-01…14 (ADR-0014). Geen nieuwe domeinfunctionaliteit;
wel de statuspagina (herkomst, `Host`-beperking, pogingen, Peil 1.1.1), eerst aanmelden, foutcatalogus,
`rotation_sequence`, adresregels na DNS-resolutie, connector-health met vaste checks en worker-hartslag, events
(domeinen, werkwoorden, ernst, `issuer`/`sub`), `100.64.0.0/10` alleen met toestemming, healthcheck-controlevlag en
het manifest. Open: C1.3-HCH-15 (P2). Alles Sim-getest; niets op een echte NAS, Hub of Authentik gevalideerd.

Review contract 1.3 (2026-11-10, ADR-0015): geen nieuwe functionaliteit. Manifestvalidator en Peil-referentierenderer
draaien nu verplicht in CI; de connector-check `bronnen` noemt bij een verouderde meting de tijd van die meting en laat
een verse storing de oorzaak; `hub-link.json` krijgt expliciet 0600. Interop met de echte Hub (1.3) lokaal geslaagd.

P2 B11-001…005 (2026-11-11, ADR-0016): Node-RED-automatisering gebouwd. Alles Sim-getest tegen de in-repo
Node-RED-simulator en de Hub-simulator; de aannames over Node-RED zelf zijn gemeten tegen de gepinde image in lokale
containers (`docs/b11/node-red-verificatie.json`, 39 controles). Niet gevalideerd: Node-RED op de NAS, een echte Hub
die actieverzoeken en herstel beoordeelt, en echte apparaten. De installatiestappen I10-10-01…06 staan in de
Excel-lijst van `jelly-leon-platform`; de installatieweg van Node-RED is het manifest daar
(`install/manifests/node-red.manifest.yaml`). Dit repo levert de bewaking en `deploy/truenas/NODE_RED_CUSTOM_APP.md`,
dat naar dat manifest verwijst en alleen beschrijft wat hier wordt ingesteld (besluiten C-11 en C-12).
NIET GEVALIDEERD (echte NAS): niet als Custom App op TrueNAS geïnstalleerd; zie STAPPEN_P6.md.
