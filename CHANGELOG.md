# Wijzigingen

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
