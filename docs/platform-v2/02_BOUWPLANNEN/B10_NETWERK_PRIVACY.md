# Netwerk en privacy — volledige bouwspecificatie

**Type/eigenaar:** Integratie: NetAlertX + AdGuard Home + Tailscale + Cloudflared  
**Doel:** Ontdek apparaten, bescherm DNS, diagnoseer verkeer en bewaak VPN/tunnel zonder jezelf van het netwerk af te sluiten.

**Afhankelijkheden:** Back-ups, LAN topology, Hub, NetAlertX, AdGuard.

**Bron:** https://github.com/netalertx/NetAlertX

## 1. Concrete schermen en gebruikersreizen
Apparaten; DNS; Trackerblokkade; Netwerkprestatie; VPN/tunnel; Verdachte signalen; Firewall voorstel; Rechten

**Per scherm minimaal:** responsief (360/390/768/1440 px), status leeg/laden/storing/offline, gedocumenteerde navigatie, zoek/filter/paginering, rolcontrole, datum van laatste update, bronherkomst, fout in het Nederlands, toegankelijk toetsenbordgebruik en zichtbaar auditspoor voor wijzigingen.

## 2. Datamodel en levensduur
network_device, dhcp_lease, discovery_event, dns_query_aggregate, block_rule, vpn_peer, tunnel_health, security_finding, policy_change

Dwing database-migraties met forward-schema-tests af; time-series met retentie/aggregatie; primaire gegevens alleen bij bron. Entiteiten krijgen stable ID, versie, eigenaar, timestamps en provenance waar toepasselijk. Secrets alleen als vault-reference.

## 3. API en integratie-contracten
NetAlertX discovered devices; AdGuard Home control API; Tailscale status; Cloudflare Tunnel health; router API optioneel

Bij alle endpoints: authenticatie, rol, inputvalidatie, idempotency voor mutaties, paginering of cursors voor lijsten, rate limits, time-outs, versie/capability-detectie en machineleesbare foutcodes. De genoemde uitbreidingsroutes zijn ontwerpeisen, niet automatisch bestaande endpoints. API-contracten moet de bouwer in OpenAPI vastleggen en e2e verifiëren.

## 4. Bouwfasen (verplichte volgorde)

### F0 - Inventaris & onderzoek
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B10-001 — Netwerktopologie ontdekken
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Subnetten, IP-reserveringen, gateway, DNS en huidige LAN-firewall vastleggen.
**Implementatie in code/diensten:** Passive discovery first, permissions for ARP/ICMP and network namespaces audited; router capabilities probed.
**Schermen/bediening:** Topology view with last seen and unknown names.
**Acceptatie / concrete toets:** Geen onbekend apparaat als malware categoriseren zonder bewijs.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F1 - Kern en contracten
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B10-002 — Nieuwe apparaten en signalen
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** NetAlertX ingest met first_seen, last_seen, vendor/confidence, IP/MAC history.
**Implementatie in code/diensten:** Normalize MAC anonymization where required, dedupe on stable ID; tunable detection thresholds.
**Schermen/bediening:** Apparatenlijst en nieuw apparaat melding.
**Acceptatie / concrete toets:** DHCP-IP-wisseling geeft niet twee apparaten als MAC gelijk blijft.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F2 - Functionaliteit
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B10-003 — DNS-filtering met fail-safe
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** AdGuard Home stap voor stap en herstelmogelijkheid naar oude DNS.
**Implementatie in code/diensten:** Test pilot device, alternative resolver, export config, rollback TTL, parental scoped rules.
**Schermen/bediening:** DNS status, top blocked categories, uitzondering.
**Acceptatie / concrete toets:** DNS-storing → terugvallen binnen afgesproken venster en LAN blijft werken.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F3 - Integraties en veiligheid
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B10-004 — Netwerktrafiekdiagnose
**Status bij start:** Bouwen; **impact:** Middel.
**Gewenst gedrag en grenzen:** Per app uitgaande bestemmingen en bandwidth alleen als host/router dit feitelijk rapporteert.
**Implementatie in code/diensten:** Optional flow collector/ebpf limited in scope; do not equate DNS logs with all network packets.
**Schermen/bediening:** Bij app uitgaand verkeer geobserveerd/geschat/niet beschikbaar.
**Acceptatie / concrete toets:** Afwezigheid in DNS is niet presenteren als geen internetverkeer.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

#### B10-005 — VPN en tunnel monitoring
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** Behoud Tailscale/Cloudflared en valideer certificaat, verbinding en toegangsregels.
**Implementatie in code/diensten:** Read status; scope public apps separate from NAS admin; tunnel secrets vault.
**Schermen/bediening:** VPN sessies, tunnel health, renewal alerts.
**Acceptatie / concrete toets:** TrueNAS console alleen via LAN/VPN; internetprobe kan geen admin openen.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

### F4 - Automatisering
**Fase-entry:** voorafgaande kritieke gates geslaagd; bestaande gegevens en huidige release vastgelegd; rollback plan bekend.

#### B10-006 — AI-beveiligingsadvies
**Status bij start:** Bouwen; **impact:** Hoog.
**Gewenst gedrag en grenzen:** Koppel onbekende apparaten, loginpogingen, DNS anomalieën aan incident met suggesties.
**Implementatie in code/diensten:** Rule-based anomaly baseline and approval before block/firewall changes.
**Schermen/bediening:** Bewijs en risico per voorstel.
**Acceptatie / concrete toets:** Geen LAN-afsluiting of self-block zonder approval.
**Foutafhandeling en bewijs:** een externe storing mag niet als succes worden gelogd; leg testscenario, gebruikte app/image-versie, screenshots, redacted request/response, timestamps, audit/rollback en incidentlink vast.

**Fase-exit:** alle in deze fase genoemde checks aantoonbaar geslaagd, code review, back-up-/rollback-gate, een gebruikersreis op mobiel en een negatieve test voor permissions. Bij een blocker niets forceren: status `Geblokkeerd` + reden + eigenaar.

## 5. Niet-regressie, randgevallen en verbodsbepalingen
Voor apparaatdiscoveries kan bridge/host networking nodig zijn; isoleer en maak privacy/privilege impact expliciet. Firewall en router beheer alleen indien gateway API beschikbaar én veilig.

## 6. Oplevering door bouwer
Opleveren: (1) broncode en tests, (2) migration scripts en versiecompatibiliteit, (3) Compose/TrueNAS app manifest met gepinde images, (4) .env.example zonder geheimen, (5) OpenAPI/connector schemas, (6) test- en auditrapport, (7) restore bewijs, (8) release notes, (9) gebruikershandleiding, (10) screenshots web/mobiel. Markeer niet-geteste hardware/echte accounts als `NIET GEVALIDEERD`.

## 7. Proof of Done
Alle acceptatiecriteria in Excel zijn gekoppeld aan testbewijs en codecommit; bij stroomonderbreking, uitval van afhankelijke app, NAS-herstart, gewijzigde credentials en incompatibele versie degradeert de service aantoonbaar veilig. Geen directe writes aan de database van een andere app.
