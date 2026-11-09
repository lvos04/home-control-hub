# ADR-0007 — B13-002…005: Authentik via de officiële API, voorstellen zonder toepassen, SSO-mapping, audit en back-up

Status: aanvaard · Datum: 2026-11-09 · Fase: P1 · Contract: 1.1 (verenigbaar gemaakt met de 1.2-punten, zie ADR-0008)

## Context
B13-002…005 vragen een OIDC-client voor de Hub, SSO-mapping per app, audit/rechten en back-up/upgrade van Authentik.
Authentik zelf wordt via de officiële TrueNAS-catalogusapp geïnstalleerd (niet door deze repo). Contract §8 eist dat
wijzigingen alleen worden uitgevoerd met een door de Hub ondertekend `ExecutionRequest`; die keten (policy-engine,
goedkeuring, executor) bestaat pas in fase P2. Er is geen echte Authentik, NAS of domeinnaam (D17) beschikbaar.

## Besluiten
1. **Alleen de officiële API (`/api/v3`), alleen lezen.** Client met contract-§5-tijdlimieten, max. 3 pogingen (alleen
   GET), geen redirects (token-lek), antwoorden ≤ 5 MiB, paginering met maximum → `onvolledig` i.p.v. stil afkappen.
   Token komt uit de vault (`vault://source/authentik`, ingevoerd via `PUT /integrations/v1/sources/authentik`) en
   wordt nooit teruggegeven of gelogd. In deze versie stuurt de dienst **nooit** een schrijfverzoek naar Authentik
   (getest: de nep-Authentik registreert elke niet-GET).
2. **Versiedetectie en geverifieerd API-oppervlak.** `GET /api/v3/admin/version/` bepaalt de versie. Elk gebruikt pad,
   elke queryparameter en elk veld (`compat.USED_API`) is gecontroleerd tegen de officiële `schema.yml` van elke
   release-lijn 2024.10 t/m 2026.8 (`tools/authentik_schema_check.py`; resultaat met sha256 per schema in
   `docs/b13/authentik-api-verificatie.json`). Versieafhankelijk: `grant_types` pas vanaf 2026.5, `?actions=` pas
   vanaf 2025.8 (oudere versies negeren die filter en zouden alles teruggeven → dan per actie vragen).
   Nieuwere lijnen: lezen met waarschuwing, geen voorstellen. Ouder dan 2024.10: niet ondersteund.
3. **Least privilege.** Detectie leest `/core/users/me/`; een superuser-token geeft status `degraded`
   (`token_te_ruim`). Aanbevolen: een Authentik-serviceaccount met alleen leesrechten (exacte RBAC-rechtnamen zijn
   **te verifiëren** op een echte installatie). Een ontbrekend recht maakt een onderdeel `onvolledig`, nooit "leeg".
4. **Schoning met een whitelist.** Wat uit Authentik bewaard of doorgegeven wordt bevat alleen genoemde velden: nooit
   `client_secret`, privésleutels, e-mail of vrije `attributes`. Flow-exports (blueprints) worden regel voor regel
   geredigeerd (`password|secret|token|private_key|api_key`) en alleen met sha256 van het origineel bewaard.
5. **B13-002 als R2-voorstel, toepassen nog niet.** `POST /connector/v1/propose` met `sso.oidc.hub.register` geeft
   diff, exacte API-verzoeken (zonder geheimen), `resource_etag` (hash van de te wijzigen objecten), `preview_hash`
   (canonieke JSON zoals §8, inclusief blast radius), rollbackrecept en `requires_backup=true`. `risk_claim` van de
   aanvrager wordt genegeerd (altijd R2; de database weigert R0/R1). `expected_version` ≠ huidige `resource_etag` →
   `409 resource_gewijzigd` (approval drift). `apply_status` is in de database vastgezet op `nog_niet_toepasbaar`;
   `/connector/v1/apply` geeft `501` met die reden. Keuzes in het voorstel: confidential client, Authorization Code
   (`grant_types=[authorization_code]` waar de versie dat kent), strikte https-redirect-URI's uit de Hub (D17; nooit
   een voorbeeldwaarde), asymmetrische ondertekening, `issuer_mode=per_provider`, `sub_mode=hashed_user_id`, scopes
   openid/email/profile (profile levert `groups`), code 1 min / token 5 min. PKCE (S256) dwingt de Hub af; Authentik
   ondersteunt het (docs) maar heeft er geen providerveld voor. Zonder groep→rol-koppeling geen voorstel (anders kan
   iedere Authentik-gebruiker de client gebruiken); bestaande applicaties/providers van iets anders worden nooit
   overgenomen. De OIDC-login zelf (redirect, PKCE, ID-token-validatie, sessiecookie) hoort in de Hub
   (`ai-server-manager`); `GET /integrations/v1/sso/oidc/hub/check` controleert een bestaande client alleen-lezen.
6. **B13-003 met bron per app.** De dekkingsmatrix noemt per app de bron (officiële docs-URL of broncode + commit),
   de datum en `geverifieerd_docs`/`geverifieerd_broncode` — expliciet **niet** "getest op een installatie". OIDC:
   Immich (docs, rolclaim `immich_role`), Node-RED (met voorwaarden: Passport-strategie in settings.js), Hub (gepland,
   B13-002). Niet: MediaGuard, MSO, my_house (broncode), Jellyfin/Jelly Leon, AdGuard Home, NetAlertX (docs),
   TrueNAS (middleware-broncode). Loginroute `oidc` alleen voor apps die het ondersteunen; een mislukte testlogin
   zet de app terug op de eigen login (database weigert `oidc` + `mislukt`). Groep→rol alleen met rollen uit de
   catalogus van die app; alleen `admin` mag koppelingen wijzigen. Vertrouwde-header-SSO is nooit toegestaan.
7. **B13-004 audit.** Events (login, login_failed, logout, model_*, impersonation_started, secret_view,
   suspicious_request, password_set) met een watermerk; minimale kopie, 30 dagen. Bij `login_failed` komt de
   geprobeerde naam uit `context.username` (authentik/events/signals.py). Afwijkingsregels (ontdubbeld, als event
   `sso.anomaly.detected`, classificatie *sensitive*): ≥ 5 mislukte logins per naam in 10 min, impersonatie, ingezien
   geheim, verdacht verzoek, login van een geregistreerd Authentik-noodaccount, wijziging van een aan een rol
   gekoppelde groep, beheerrecht toegekend, afwijking na herstel. De grenzen zijn een startpunt, niet geijkt op een
   echte installatie. De rechtenkaart wordt alleen bij een **volledig** gelezen toestand vergeleken (een half gelezen
   lijst mag nooit "toegang ingetrokken" opleveren) en alleen bij verandering opgeslagen. Ingetrokken toegang →
   `sso.access.revoked` zodat de Hub sessies kan beëindigen; worker synchroniseert elke 300 s
   (`HCH_AUTHENTIK_SYNC_INTERVAL_S`, 0 = uit).
8. **B13-005 back-up en upgrade.** De configuratie-export via API + flow-blueprints is een *controlebasis*, geen
   vervanging van de database-back-up (officiële docs: PostgreSQL is het belangrijkste). De pre-upgrade-gate volgt de
   officiële regels (geen downgrade; per release-lijn; eerst de nieuwste patch) en eist: Authentik gereed, volledige
   export < 24 u van de huidige versie, noodtoegang (B13-001) `ok`, back-upcheckpoint **door de Hub bevestigd** (een
   admin-opgave is geen bewijs), externe outposts mee-upgraden, en de catalogusversie blijft `onbekend` (treinen
   houden vaak alleen de nieuwste versie). Uitkomst `rood`/`onbekend`/`ok_lokaal` — nooit "groen"; de eindbeslissing
   ligt bij de Hub. De herstelcheck vergelijkt een volledige export met de huidige toestand: providers, applicaties,
   groepen en leden, gebruikers, sleutel-vingerafdrukken, flows, brands en de bevestigde MFA-apparaten van beheerders.
   `sso.sessions.revoke` (R2-voorstel) is het vervolg na herstel of een lek.
9. **Catalogusapp.** Op 2026-11-09: trein `community`, app `authentik`, versie 1.3.63 (app_version 2026.8.5). Optie
   *Mount Docker Socket* (standaard uit) moet uit blijven: geen Docker-socket in containers.

## Gevolgen
- Alles is Sim-getest tegen de in-repo nep-Authentik (`apps/api/tests/fakes/authentik_fake.py`, zelfde vorm als de
  officiële API). Echte Authentik, domein/HTTPS (D17) en de Hub-zijde zijn **NIET GEVALIDEERD**.
- P2 moet toevoegen: verificatie van het ondertekende `ExecutionRequest` (handtekening met de Hub-policy-sleutel uit de
  koppeling, vervaltijd, nonce, `preview_hash`/`resource_etag`-binding, risicoklasse), het schrijfpad, readback en
  overdracht van het `client_secret` naar de vault van de Hub.
