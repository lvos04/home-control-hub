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
| B11-001 flow-netwerkisolatie | — | inventaris, verbodslijst exec-node (te verifiëren), datamodel | Node-RED-installatie (I10), isolatie, editor-auth |
| B11-002…005 | — | alleen schema | alles |
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
