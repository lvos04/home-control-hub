# Wijzigingen

## 0.1.0 — onafhankelijke ontwerpreview van de statuspagina (ADR-0012, nog niet uitgebracht)

**Gewijzigd (alleen woorden, redenen en meldingen op `GET /`; het Peil-sjabloon is ongewijzigd)**
- Een bronmeting ouder dan 15 minuten telt in "Wat deze dienst doet" als **Onbekend** ("1 verouderd (laatst bekend …).
  Metingen ouder dan 15 minuten tellen als onbekend."), nooit meer als de laatst bekende stand. Vroeger stond een meting
  van dagen oud als Gezond.
- De pil van een controle draagt altijd het vaste Peil-woord bij het icoon (Onbekend/Storing). De precieze
  koppeltoestand ("Niet gekoppeld", "Ingetrokken door de Hub", "Koppelen bezig", …) opent de reden.
- Beheerherstel heeft per niveau een reden (Onbekend: "Het herstelregister is nog niet volledig ingevuld of getest.").
- "Koppelen bezig" noemt waarmee gekoppeld wordt en de laatste melding, en zegt dat het formulier pas weer werkt als de
  poging klaar is (geen "over een minuut" meer).
- Na een mislukte poging zegt de melding dat alle velden opnieuw moeten (waarden worden bewust niet teruggezet).
- De kop is korter. Het totaal noemt "Wat deze dienst doet" en "Sleutels van de Hub" krijgt geen kleine letters meer.
  "1 van 1 bron" staat in het enkelvoud. De variabelenaam `HUB_ENROLLMENT_TOKEN` staat niet meer in de melding (op
  320 px gaf hij overloop met de tekstafstand van WCAG 1.4.12), maar in de controle.

**Nieuw**
- `make ontwerpreview` (`tests/ui/ontwerpreview.py` + `.mjs`) draait ook in CI (job `statuspagina-ui`). Het start de
  echte dienst als proces tegen de Hub-simulator en zet 14 toestanden klaar. Chromium meet elke toestand op
  320/360/390/768/1440 px in licht en donker: axe (WCAG 2.2 AA), contrast in de pagina, doelen, focus, tekstafstand en
  de Peil-statusregels.
- `docs/ontwerp/PEIL_REVIEW.md` met bevindingen, reparaties en een overdracht aan Peil (S-1…S-8), en
  `docs/ontwerp/peil-review/` met de schermafdrukken.

## 0.1.0 — statuspagina in Peil (HC11, nog niet uitgebracht)

**Gewijzigd (ADR-0011)**
- `GET /` gebruikt het framework-vrije sjabloon van de ontwerptaal **Peil 1.1.0** (versie-gepinde kopie met
  herkomstkop in `design/ontwerptaal/`, O-14): geen JavaScript, CSP `default-src 'none'`, licht en donker volgens het
  systeem, Peil-woorden (Gezond · Beperkt · Storing · Onbekend · Niet gereed), "Gekoppeld" als neutrale pil.
- Het eerste signaal is nooit groen als de dienst niet gereed is; gereed = database, schema, sleutels **en** een door
  de Hub bevestigde koppeling.
- Koppelformulier-velden heten nu `hub_adres`, `koppelcode` en `hub_vingerafdruk` (zoals het sjabloon). Een mislukte
  poging geeft direct de pagina terug met een passende HTTP-status (400/403/409/422/429/502/503), vaste melding,
  code en de trace-ID van het verzoek (selecteerbaar; ook in log en audit); geen `?melding=<fout>`-redirects meer.
- Niet meer op de statuspagina: dienst-ID, "gekoppeld via" en de laatste 4 tekens van het service-token (staan in
  `GET /connector/v1/hub-link`).
- Het formulier blijft zichtbaar tijdens een lopende koppelpoging; verzenden geeft dan 409 `koppelen_bezig` zonder
  verzoek naar de Hub.

**Nieuw**
- `tools/peil_kopie.py` (controleer / vergelijk --online / bijwerken) en een CI-stap die drift met ai-server-manager
  laat falen; `HCH_PEIL_DIR` in de image (sha256 gecontroleerd bij het bouwen).
- UI-tests (`tests/ui`, Playwright + axe-core) over negen toestanden uit de echte app × licht/donker × 320–1440 px, en
  schermafdrukken in `docs/screenshots/peil/statuspagina/`.

## 0.1.0 — platformcontract 1.2 (nog niet uitgebracht)

**Breaking (contract 1.2, ADR-0010)**
- Koppelen volgens §3.3: enroll-verzoek met `enrollment_token` of `pairing_code` (geen `kind`/`secret`/prefixes meer),
  `public_key_jwk` alleen `{kty, crv, x, kid}`; het antwoord wordt volledig gecontroleerd en de
  sleutelset-vingerafdruk zelf berekend (`HUB_KEY_FINGERPRINT` of het veld op de statuspagina moet kloppen).
- De koppeling staat in `/appdata/secrets/hub-link.json` (0600, atomair, gedeeld door API en worker) in plaats van in
  de database; een oude koppeling wordt bij de eerste start eenmalig overgezet en daarna uit de database verwijderd.
- Inkomend alleen Hub-JWT's: gebruikers-JWT (`token_use: user`) of dienst-JWT (`token_use: hub_service`). Een
  `Bearer`-service-token wordt geweigerd (`service_token_not_accepted`). Vaste Engelse `reason`-waarden (§4.7);
  `jti` op elke JWT; replaycache op `(iss, jti)` voor elke mutatie (migratie `0003`).
- Hub-sleutels worden gepind; de JWKS wordt niet meer via HTTP opgehaald. Nieuwe sleutels alleen via een
  ondertekende rotatie (`/api/v1/auth/key-rotations`) of opnieuw koppelen. Instellingen `HCH_JWKS_*` vervallen.
- Routes `GET /integrations/v1/enrollment` en `POST /integrations/v1/enrollment/unpair` vervangen door
  `GET /connector/v1/hub-link` en `POST /connector/v1/hub-link/unlink`. De lokale ontkoppelcode en het formulier
  `/ontkoppelen` bestaan niet meer.
- Statuspagina: koppelformulier alleen zolang de dienst nog nooit gekoppeld is, met verplichte Hub-vingerafdruk;
  rate-limit 5 pogingen per 15 min per bron-IP en 20 per dienst.

**Nieuw**
- Bevestigen met `services/self` (ook periodiek), intrekking pas na 401 op `services/self`, tokenrotatie op
  `Hub-Token-Rotation: required` (ook na een onderbroken rotatie), herhaling na herstart halverwege (§3.6).
- `HUB_KEY_FINGERPRINT`; `ENROLLMENT_TOKEN` wordt nog één release gelezen met een waarschuwing.
- Alle uitgaande calls negeren proxy-omgevingsvariabelen en volgen geen redirects.
- Image: geen `dumb-init` meer; de bewaker is PID 1, ruimt zombies op, draait als 568 zonder capabilities en zet zelf
  `PR_SET_NO_NEW_PRIVS`. De rooktest draait zoals het TrueNAS-formulier (zonder no-new-privileges en cap-drop) en
  controleert elk proces.
- Manifest volgens §9 (geldig volgens de validator van appstore-en-fork); `CUSTOM_APP.md` met tag + digest en
  registry-login alleen als terugval.
- Kopie van `PLATFORM_CONTRACTEN.md` en `CONTRACT_1.2_CONFORMITEIT.md` met een test op byte-gelijkheid;
  `EVIDENCE.json` volgens §11 (alleen vaste validatiewaarden).

## 0.1.0 — P1-aanvulling B13-002…005 (nog niet uitgebracht)

**Nieuw**
- Authentik via de officiële API (`/api/v3`), **alleen lezen**: versiedetectie, API-capabilities per versie
  (gecontroleerd tegen de officiële `schema.yml` van 2024.10 t/m 2026.8), least-privilege-controle van het token,
  geschoonde toestand (whitelist; nooit `client_secret`, sleutels, e-mail of attributen).
- B13-002: `POST /connector/v1/propose` met `sso.oidc.hub.register` — OIDC-provider + applicatie voor de Hub als
  R2-voorstel met diff, exacte verzoeken, `resource_etag`, `preview_hash`, rollbackrecept; `expected_version`-drift →
  409. Toepassen eerlijk `501 nog_niet_toepasbaar` (in de database afgedwongen). Alleen-lezen controle van een
  bestaande Hub-client (`GET /integrations/v1/sso/oidc/hub/check`).
- B13-002: replaybescherming — een Hub-JWT (`jti`) mag voor één wijziging gebruikt worden (retry met dezelfde
  `Idempotency-Key` blijft mogen); wijziging zonder `jti` geweigerd.
- B13-003: SSO-dekkingsmatrix met bron (docs-URL/broncode + datum + verificatiestatus) per app, loginroute
  native/oidc met handmatige installatiecontrole, groep → rol per app.
- B13-004: Authentik-events (logins, wijzigingen) met watermerk, afwijkingsregels als events naar de Hub,
  rechtenkaart met verschillen en `sso.access.revoked`; worker elke 300 s (`HCH_AUTHENTIK_SYNC_INTERVAL_S`).
- B13-005: configuratie-export (API + geredigeerde flow-blueprints + MFA-apparaten van beheerders), pre-upgrade-gate
  volgens de officiële upgraderegels (nooit "groen" op aannames), herstelcheck, voorstel `sso.sessions.revoke`.
- Migratie `0002` (alleen nieuwe tabellen). Nep-Authentik voor unit-, integratie- en dienst-E2E-tests.

**Nulmeting/omgeving**
- Rooktest leest geheimen en de back-upmap via een wegwerpcontainer (werkte alleen als root); test met verkeerde
  rechten deterministisch. Back-uptest kiest de nieuwste `pg_restore` (machines met meerdere PostgreSQL-clients).
- Integratietests maken de database ~50× sneller leeg (DELETE i.p.v. TRUNCATE).

**Review P1 (onafhankelijke QA, ADR-0009)**
- Eventtypen `sso.authentik.sync.failed`, `sso.authentik.upgrade_gate.evaluated` en
  `sso.authentik.restore_check.completed` hernoemd naar `sso.authentik_sync.failed`,
  `sso.authentik_upgrade_gate.evaluated` en `sso.authentik_restore_check.completed` (contract §7; de Hub-inbox weigerde
  vier segmenten). `events.emit` dwingt het patroon af; lange id's afgekapt, te grote payload ingekort.
- Least privilege van het Authentik-token nooit meer `ok`: `te_ruim` / `onbekend` / `deels_gecontroleerd`
  (systeemrechten gecontroleerd, rolrechten niet via de API te zien).
- `/sso/rights` wordt `verouderd` als Authentik niet meer volledig gelezen kan worden (velden `freshness`,
  `snapshot_taken_at`).
- Controle van een bestaande Hub-client: alleen actieve, niet-omgekeerde bindingen tellen; ontbrekende groepen →
  afwijking.
- Een gat in de Authentik-events wordt een blijvende afwijking `events_onvolledig`.

**Validatie:** Sim-getest (nep-Hub, nep-Authentik). NIET GEVALIDEERD met een echte Authentik, domeinnaam (D17) of NAS.

## 0.1.0 — P0 (nog niet uitgebracht)

**Nieuw**
- Integratiedienst `integrations` (FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 16) op poort 30420.
- Contract 1.1: foutformaat met `trace_id`, `Idempotency-Key` op alle mutaties, ETag/If-Match, cursor-paginering,
  `/healthz` + `/readyz`, connectorcontract (`discover`, `health`, `items`, `evidence`, `events`; `propose`, `apply`
  en `rollback` geven eerlijk `501 capability_unavailable`), outbox met event-envelope en push naar de Hub-inbox.
- Authenticatie: Hub-JWT (EdDSA, `iss=hub`, `aud=home-control-hub`, levensduur ≤ 120 s) via een JWKS-cache die
  fail-closed is; service-token uit de enrollment.
- Koppelen met de Hub: eenmalig token uit de omgeving (worker) of koppelcode op de statuspagina; zonder Hub eerlijk
  *niet gekoppeld*; ontkoppelen met de lokale ontkoppelcode uit de app-log.
- B13-001: herstelregister voor beheeraccounts zonder geheimen, herstelmethodes (minstens twee, waarvan één zonder
  SSO), noodtoegang alleen vanaf LAN/VPN-bereiken met sessieduur en herbevestiging, zelftest die werkt met Authentik
  offline, handmatige oefeningen, activaties met rotatieplicht, versleutelde herstelkit (scrypt + AES-256-GCM).
- B10/B11/B14: datamodellen met database-invarianten (geen malware zonder bewijs, meters altijd alleen-lezen, geen
  CPU-schatting zonder kalibratie, netwerkwijzigingen minimaal R2) en inventaris; SSO-dekkingsmatrix en
  energie-dekkingsmatrix met status *te verifiëren*/*onbekend*.
- Alles-in-één image met procesbewaker, first-start-init van `/appdata/secrets`, back-up vóór migraties en
  healthcheck; installatie-instructie voor het standaard TrueNAS Custom App-formulier; manifest; CI en release.

**Aangescherpt na de onafhankelijke P0-review** (ADR-0006)
- Geen migratie zonder geslaagde back-up vooraf (was: migratie ging door als `pg_dump` mislukte).
- Verzoeken > 1 MiB worden vóór de authenticatie geweigerd (`413 payload_too_large`).
- Herstelkit openen begrensd (geheugen van de sleutelafleiding, nonce, formaat); geen 500 meer bij vreemde kits.
- Statuspagina toont alleen het totaalniveau van het herstelregister.
- Ongebruikte instellingen `HCH_TRUSTED_PROXIES` en `HCH_EMERGENCY_ADMIN_MAX_DAYS` verwijderd.
- Extra tests: auth/rollen/Idempotency-Key op elke route, JWT-randgevallen, B13-003 (geen header-SSO), B10-002 in
  het datamodel, back-up vóór migratie; rooktest met minimale capabilities en controle op dataverlies.

**Validatie:** Unit-, integratie- (PostgreSQL) en dienst-E2E-tests met simulators; image-rooktest in Docker.
NIET GEVALIDEERD op een echte NAS, met echte Authentik of met echte accounts.
