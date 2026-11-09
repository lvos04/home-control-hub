# Energie en resource manager — volledige bouwspecificatie

**Type/eigenaar:** Hub-module met my_house en hardwaremetrics  
**Doel:** Combineer woningverbruik met NAS-werkload, gericht op kosten en prestaties zonder onterechte precisie.

**Afhankelijkheden:** my_house, Hub, monitoring, workload planner.

**Bron:** https://github.com/lvos04/my_house

## 1. Concrete schermen en gebruikersreizen
Energie; Kosten; Verbruiksbronnen; GPU/CPU; Werkloadplanning; Vergelijk; Prognoses

**Per scherm minimaal:** responsief (360/390/768/1440 px), status leeg/laden/storing/offline, gedocumenteerde navigatie, zoek/filter/paginering, rolcontrole, datum van laatste update, bronherkomst, fout in het Nederlands, toegankelijk toetsenbordgebruik en zichtbaar auditspoor voor wijzigingen.

## 2. Datamodel en levensduur
energy_meter, meter_role, usage_interval, tariff, sample_quality, workload, workload_reservation, cost_model, estimate_provenance

Dwing database-migraties met forward-schema-tests af; time-series met retentie/aggregatie; primaire gegevens alleen bij bron. Entiteiten krijgen stable ID, versie, eigenaar, timestamps en provenance waar toepasselijk. Secrets alleen als vault-reference.

## 3. API en integratie-contracten
my_house energy GET; TrueNAS read-only metrics; MediaGuard encoding status; Hub /api/v1/resources/allocate

Bij alle endpoints: authenticatie, rol, inputvalidatie, idempotency voor mutaties, paginering of cursors voor lijsten, rate limits, time-outs, versie/capability-detectie en machineleesbare foutcodes. De genoemde uitbreidingsroutes zijn ontwerpeisen, niet automatisch bestaande endpoints. API-contracten moet de bouwer in OpenAPI vastleggen en e2e verifiëren.

## 4. Bouwfasen (verplichte volgorde)

### F0 - Inventaris & onderzoek
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B14-001 — Dekkingsmatrix
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** NAS-energie wordt alleen exact als losse meter aanwezig; anders schatting of onbekend label.
**Implementatie in code/diensten:** Map P1, boilerplug en airco-kWh uit my_house; NAS power measurement optional and clearly separate.
**Schermen/bediening:** Herkomst en kwaliteitslabel per getal.
**Acceptatie / concrete toets:** Geen wattage afleiden uit CPU% zonder calibratie.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F1 - Kern en contracten
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B14-002 — Energietijdreeks
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Consistente dag/maand verbruiksrapporten en dynamisch of vast tarief afhankelijk data.
**Implementatie in code/diensten:** Cumulative counter deltas; timezone DST, reset, meter replacement, import/export met bron.
**Schermen/bediening:** Kostenoverzicht en brutoverbruik.
**Acceptatie / concrete toets:** Dag met zomertijd 23/25h wordt goed verwerkt.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F2 - Functionaliteit
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B14-003 — Workload reservations
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** MediaGuard AV1, Jellyfin transcodes, zoekindex, backups, ZFS scrub delen CPU, RAM, GPU.
**Implementatie in code/diensten:** Queue with priority classes, time windows, throttle and preempt safe checkpoint, no interfering owner semantics.
**Schermen/bediening:** Dagplanner met waarom taak wacht.
**Acceptatie / concrete toets:** Live Jellyfin stream kan AV1 tijdelijk laten wachten zonder bestandsverlies.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F3 - Integraties en veiligheid
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B14-004 — AI advies voor kosten
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Voorstel om index en AV1 's nachts of bij lage load te doen; geen hardware power toggles zonder approval.
**Implementatie in code/diensten:** Correlate energy and workload with confidence and compare equivalent days.
**Schermen/bediening:** Aannames en besparingsrange, niet gegarandeerd.
**Acceptatie / concrete toets:** Zonder meter geen verzonnen €-besparing.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F4 - Automatisering
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B14-005 — Alert bij afwijkingen
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Meter offline, ongebruikelijk boilerverbruik, groeiende NAS belasting, gebroken budget.
**Implementatie in code/diensten:** Threshold baselines and stale metadata, no actuation from energy chart.
**Schermen/bediening:** Alarmen met bron.
**Acceptatie / concrete toets:** Boiler blijft in all cases alleen meten.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

## 5. Niet-regressie, randgevallen en verbodsbepalingen
Airco 1-fase kWh meter meet gedeelde buitenunit, niet afzonderlijke binnenunits. NAS-host energie kan niet per app exact zonder meting worden verdeeld. Maak schatting expliciet.

## 6. Oplevering door bouwer
Opleveren: (1) broncode en tests, (2) migration scripts en versiecompatibiliteit, (3) Compose/TrueNAS app manifest met gepinde images, (4) .env.example zonder geheimen, (5) OpenAPI/connector schemas, (6) test- en auditrapport, (7) restore bewijs, (8) release notes, (9) gebruikershandleiding, (10) screenshots web/mobiel. Markeer niet-geteste hardware/echte accounts als `NIET GEVALIDEERD`.

## 7. Proof of Done
Alle acceptatiecriteria in Excel zijn gekoppeld aan testbewijs en codecommit; bij stroomonderbreking, uitval van afhankelijke app, NAS-herstart, gewijzigde credentials en incompatibele versie degradeert de service aantoonbaar veilig. Geen directe writes aan de database van een andere app.
