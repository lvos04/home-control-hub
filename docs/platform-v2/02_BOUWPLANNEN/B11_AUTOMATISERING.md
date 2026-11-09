# Node-RED automatisering — volledige bouwspecificatie

**Type/eigenaar:** Integratie: Node-RED met Hub-policy  
**Doel:** Gebruikers ontwerpen flows zonder code, maar alle acties die iets veranderen lopen via policy en audit.

**Afhankelijkheden:** Hub policy, eventbus, backup.

**Bron:** https://github.com/node-red/node-red

## 1. Concrete schermen en gebruikersreizen
Flow overzicht; Editor; Triggers; Acties; Templates; Testevents; Versies; Pauzeren; Uitvoeringshistorie

**Per scherm minimaal:** responsief (360/390/768/1440 px), status leeg/laden/storing/offline, gedocumenteerde navigatie, zoek/filter/paginering, rolcontrole, datum van laatste update, bronherkomst, fout in het Nederlands, toegankelijk toetsenbordgebruik en zichtbaar auditspoor voor wijzigingen.

## 2. Datamodel en levensduur
flow, flow_version, trigger, flow_run, action_request, replay_key, rate_limit, flow_owner

Dwing database-migraties met forward-schema-tests af; time-series met retentie/aggregatie; primaire gegevens alleen bij bron. Entiteiten krijgen stable ID, versie, eigenaar, timestamps en provenance waar toepasselijk. Secrets alleen als vault-reference.

## 3. API en integratie-contracten
Node-RED HTTP/admin API beveiligd op LAN; Hub /api/v1/events; Hub POST /api/v1/actions/preview

Bij alle endpoints: authenticatie, rol, inputvalidatie, idempotency voor mutaties, paginering of cursors voor lijsten, rate limits, time-outs, versie/capability-detectie en machineleesbare foutcodes. De genoemde uitbreidingsroutes zijn ontwerpeisen, niet automatisch bestaande endpoints. API-contracten moet de bouwer in OpenAPI vastleggen en e2e verifiëren.

## 4. Bouwfasen (verplichte volgorde)

### F0 - Inventaris & onderzoek
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B11-001 — Flow netwerkisolatie
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** Install Node-RED non-root, admin auth, credentialSecret, geen onbeperkte nodes/shell.
**Implementatie in code/diensten:** Private bridge network, allowlist plugins, no Docker socket; export encryption.
**Schermen/bediening:** Editor alleen achter SSO/proxy of eigen auth.
**Acceptatie / concrete toets:** Viewer kan editor niet bereiken en custom exec-node is geblokkeerd.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F1 - Kern en contracten
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B11-002 — Eventtypen catalogus
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** MediaGuard, MSO, my_house, ZFS, monitoring en netwerk publiceren gestandaardiseerde events.
**Implementatie in code/diensten:** Typed event schema, per-source retry queue, origin chain to prevent loops.
**Schermen/bediening:** Kies gebeurtenis dropdown met voorbeeldschema.
**Acceptatie / concrete toets:** Een event met onbekende schema-versie verdwijnt niet stil.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F2 - Functionaliteit
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B11-003 — Veilige acties
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** Restarts en kennisgevingen via Hub action requests; smart-home commands via my_house policy.
**Implementatie in code/diensten:** Scoped per-flow token, idempotency, owner labels, rate limit + risk preview.
**Schermen/bediening:** Nodes tonen goedkeuringsvereiste.
**Acceptatie / concrete toets:** Flow mag zonder admin geen dataset delete uitvoeren.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F3 - Integraties en veiligheid
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B11-004 — Simulatie en tests
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Replay events in testmodus, diff resultaten en impact.
**Implementatie in code/diensten:** Mock target plugins, immutable sample events, testfixtures in CI.
**Schermen/bediening:** Dry-run met runlog en exceptions.
**Acceptatie / concrete toets:** Geen echte apparaten gewijzigd tijdens test.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F4 - Automatisering
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B11-005 — Herstel en versiebeheer
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Exporteer flows versioned, git diffs, backup, rollback en incident tracing.
**Implementatie in code/diensten:** Snapshot before edit, scheduled export and restore to fresh Node-RED.
**Schermen/bediening:** Historie en herstellen.
**Acceptatie / concrete toets:** Undo herstelt oude flows inclusief credentials zonder secrets te loggen.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

## 5. Niet-regressie, randgevallen en verbodsbepalingen
Geen dubbele flow-builder in Hub bouwen: Hub embedt/beheert Node-RED editor en toont status. Native workflows behouden waar apps al eigen automatisering hebben.

## 6. Oplevering door bouwer
Opleveren: (1) broncode en tests, (2) migration scripts en versiecompatibiliteit, (3) Compose/TrueNAS app manifest met gepinde images, (4) .env.example zonder geheimen, (5) OpenAPI/connector schemas, (6) test- en auditrapport, (7) restore bewijs, (8) release notes, (9) gebruikershandleiding, (10) screenshots web/mobiel. Markeer niet-geteste hardware/echte accounts als `NIET GEVALIDEERD`.

## 7. Proof of Done
Alle acceptatiecriteria in Excel zijn gekoppeld aan testbewijs en codecommit; bij stroomonderbreking, uitval van afhankelijke app, NAS-herstart, gewijzigde credentials en incompatibele versie degradeert de service aantoonbaar veilig. Geen directe writes aan de database van een andere app.
