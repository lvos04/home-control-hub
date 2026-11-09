# NetAlertX — installatie, update, test en herstel

**Rol:** LAN apparaatdetectie.  
**Aanpak:** Nieuw installeren.  
**Bron:** https://github.com/netalertx/NetAlertX.  
**Versiebeleid:** Officiële pinned release/image bij installatie controleren.

## 1. Vooraf controleren
Router/subnet, privacy en discovery rechten vooraf gekend.

**Toegang / netwerk:** Discovery vereist LAN toegang; autorisatie voor network namespace expliciet.

**Data / mounts:** Config en database persistent in apps/security/netalertx.

**Preflight-regels (niet overslaan):** TrueNAS-release en Docker-appconfig controleren; data-eigenaar bepalen; bestaande install herkennen; bezette ports en container netwerken vergelijken; herstelbare backup + exacte image pin eisen; secrets nooit in logs of screenshots; test op stille omgeving vóór productie.

## 2. Stappen in uitvoeringsvolgorde

### Stap 1. Passieve basis en scope
**Uitvoeren:** Kies subnetten, MAC/IP retention, privacy, expected devices.
**Verifiëren:** Nog geen ongeautoriseerde scan buiten LAN.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I11-11-01`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 2. Install en netwerk
**Uitvoeren:** Gebruik actuele NetAlertX compose instructies, benodigde host/bridge setup na beveiligingsreview.
**Verifiëren:** App leest echte LAN devices.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I11-11-02`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 3. Known devices baseline
**Uitvoeren:** Label router/NAS/IoT/telefoons en detectie van nieuwe apparaten.
**Verifiëren:** DHCP adreswissel leidt niet tot dubbele apparaten.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I11-11-03`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 4. Alert test
**Uitvoeren:** Voeg testapparaat toe of simuleer; meld nieuw apparaat met confidence.
**Verifiëren:** Geen false malware claim.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I11-11-04`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 5. Hub connector
**Uitvoeren:** Read-only device state and change events.
**Verifiëren:** Hub herkent identieke host.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I11-11-05`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 6. Privacy en backup
**Uitvoeren:** DB encrypt backup en retentiebeleid.
**Verifiëren:** Herstel en purging werken.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I11-11-06`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

## 3. Acceptatie en oplevering
Echte TrueNAS-app start, authenticatie, persistente data na herstart, firewall/poort, metrics, backup+restore en rolrechten controleren.

- **GO:** elke stap heeft bewijs en geen kritisch defect; health na herstart, functionaliteit in eigen UI en Hub, DB persistent, documenten geactualiseerd.
- **NO-GO:** geen restorepoint, onbekend secret ownership, ongeteste dataset/poort, falende health, incomplete migratie, onveilige WAN-exposure of datawijziging buiten eigenaar.

## 4. Terugdraaien / verwijderen
1. Schakel nieuwe automation/ingest uit. 2. Bewaar audit en logs. 3. Stop nieuwe container/route, herstel oude version-pinned image én passend databestand/snapshot waar schema is veranderd. 4. Controleer credentials, clients en content integrity. 5. Maak incidentrapport met wat wel/niet is teruggezet. 6. Bij decommission: data alleen na eigen, afzonderlijke bevestiging verwijderen.

## 5. Let op
NetAlertX is geen complete packet capture of firewall. DNS logs apart van NetAlertX.

## 6. Upstream documentatie en broncontrole
https://github.com/netalertx/NetAlertX

Re-run broncheck vlak vóór uitvoering: deze installatiebeschrijving is een plan en geen claim dat er reeds een live installatie is gevalideerd.