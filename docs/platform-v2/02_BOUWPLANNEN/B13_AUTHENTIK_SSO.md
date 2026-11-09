# Authentik en toegangsbeheer — volledige bouwspecificatie

**Type/eigenaar:** Integratie: Authentik  
**Doel:** Eén login waar apps OIDC/SAML/proxy ondersteunen, met veilige fallback waar niet.

**Afhankelijkheden:** Backups, Hub, LAN HTTPS.

**Bron:** https://github.com/goauthentik/authentik

## 1. Concrete schermen en gebruikersreizen
Gebruikers; Groepen; Applicaties; Sessions; Providers; Audit; MFA; Herstel

**Per scherm minimaal:** responsief (360/390/768/1440 px), status leeg/laden/storing/offline, gedocumenteerde navigatie, zoek/filter/paginering, rolcontrole, datum van laatste update, bronherkomst, fout in het Nederlands, toegankelijk toetsenbordgebruik en zichtbaar auditspoor voor wijzigingen.

## 2. Datamodel en levensduur
auth_user, auth_group, client_registration, app_access, session, auth_event, recovery_code

Dwing database-migraties met forward-schema-tests af; time-series met retentie/aggregatie; primaire gegevens alleen bij bron. Entiteiten krijgen stable ID, versie, eigenaar, timestamps en provenance waar toepasselijk. Secrets alleen als vault-reference.

## 3. API en integratie-contracten
OIDC Authorization Code + PKCE voor Hub; authentik outpost/proxy alleen voor apps die dat ondersteunen

Bij alle endpoints: authenticatie, rol, inputvalidatie, idempotency voor mutaties, paginering of cursors voor lijsten, rate limits, time-outs, versie/capability-detectie en machineleesbare foutcodes. De genoemde uitbreidingsroutes zijn ontwerpeisen, niet automatisch bestaande endpoints. API-contracten moet de bouwer in OpenAPI vastleggen en e2e verifiëren.

## 4. Bouwfasen (verplichte volgorde)

### F0 - Inventaris & onderzoek
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B13-001 — Accountrecovery en admin toegang
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** Maak twee beheerherstelmethodes en export versleuteld herstelmateriaal, geen SSO-only lock-out.
**Implementatie in code/diensten:** Local emergency admin scoped to LAN/VPN, expiry and audit, MFA setup.
**Schermen/bediening:** Auth status en health.
**Acceptatie / concrete toets:** Authenticator offline → break glass in Hub blijft testbaar.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F1 - Kern en contracten
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B13-002 — OIDC Hub
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** OIDC Authorization Code + PKCE, 2FA, groepen en rollen.
**Implementatie in code/diensten:** Provider/app registration, redirect URI, JWT validation, JWKS rotate, secure cookie.
**Schermen/bediening:** Login via SSO en sessieoverzicht.
**Acceptatie / concrete toets:** Wrong issuer/aud/replay rejected.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F2 - Functionaliteit
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B13-003 — SSO mapping per app
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** MediaGuard/MSO/my_house niet aannemen dat OIDC bestaat.
**Implementatie in code/diensten:** Capability survey first; proxy only if app supports trusted headers under controlled deployment, otherwise own login.
**Schermen/bediening:** SSO coverage matrix.
**Acceptatie / concrete toets:** Geen automatische toegang via onbeveiligde X-Forwarded-User header.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F3 - Integraties en veiligheid
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B13-004 — Audit en rechten
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Per rol admin/operator/viewer en per app scoped credential.
**Implementatie in code/diensten:** Group membership refresh, access revoke propagation and API least privilege.
**Schermen/bediening:** Accountrechtenkaart met verschillen.
**Acceptatie / concrete toets:** Viewer kan geen apps stoppen of credentials ophalen.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F4 - Automatisering
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B13-005 — Back-up en upgrade
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Auth database, tokens, recovery, keystore en app mappings persistent houden en testen.
**Implementatie in code/diensten:** Backup restore isolated, then staged upgrade, old sessions revoke.
**Schermen/bediening:** Recovery flow.
**Acceptatie / concrete toets:** Na herstel draaien correct mapped privileges en 2FA.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

## 5. Niet-regressie, randgevallen en verbodsbepalingen
Authentik mag geen single point of failure zonder noodaccount worden. Reserveer voldoende resources en controleer poortconflicten. Gebruik alleen echte support voor SSO per app.

## 6. Oplevering door bouwer
Opleveren: (1) broncode en tests, (2) migration scripts en versiecompatibiliteit, (3) Compose/TrueNAS app manifest met gepinde images, (4) .env.example zonder geheimen, (5) OpenAPI/connector schemas, (6) test- en auditrapport, (7) restore bewijs, (8) release notes, (9) gebruikershandleiding, (10) screenshots web/mobiel. Markeer niet-geteste hardware/echte accounts als `NIET GEVALIDEERD`.

## 7. Proof of Done
Alle acceptatiecriteria in Excel zijn gekoppeld aan testbewijs en codecommit; bij stroomonderbreking, uitval van afhankelijke app, NAS-herstart, gewijzigde credentials en incompatibele versie degradeert de service aantoonbaar veilig. Geen directe writes aan de database van een andere app.
