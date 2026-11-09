# AdGuard Home — installatie, update, test en herstel

**Rol:** DNS advertentie- en trackerfilter.  
**Aanpak:** Nieuw installeren met fail-safe.  
**Bron:** https://github.com/AdguardTeam/AdGuardHome/wiki/Docker.  
**Versiebeleid:** Pin actuele officiële release.

## 1. Vooraf controleren
Router DNS nu bekend en mogelijkheid om terug te schakelen.

**Toegang / netwerk:** DNS 53 UDP/TCP; dashboardport nader kiezen en poortconflict controleren.

**Data / mounts:** Config en work persistente datasets.

**Preflight-regels (niet overslaan):** TrueNAS-release en Docker-appconfig controleren; data-eigenaar bepalen; bestaande install herkennen; bezette ports en container netwerken vergelijken; herstelbare backup + exacte image pin eisen; secrets nooit in logs of screenshots; test op stille omgeving vóór productie.

## 2. Stappen in uitvoeringsvolgorde

### Stap 1. DNS baseline vastleggen
**Uitvoeren:** Noteer router DHCP DNS, fallback resolver, betrokken devices en poort 53 huidige eigenaar.
**Verifiëren:** Een testclient kan voor wijziging resolven.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I12-12-01`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 2. Install isolated
**Uitvoeren:** Installeer officiële AdGuard Home container/TrueNAS app, geen DHCP/DNS redirect netwerkbreed.
**Verifiëren:** Admin UI alleen LAN/VPN.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I12-12-02`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 3. Test op één apparaat
**Uitvoeren:** Stel DNS van één telefoon/pc handmatig in, controleer resolutie en blocklist.
**Verifiëren:** Normale sites en apps werken; filters bruikbaar.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I12-12-03`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 4. Filters en uitzonderingen
**Uitvoeren:** Zet conservatieve filters, logs/retention, whitelist voor kritische smart-home devices.
**Verifiëren:** Hue/Gree firmware en Tailscale blijven bereikbaar.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I12-12-04`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 5. Router omschakeling
**Uitvoeren:** Pas DHCP DNS pas aan na test en maak terugzetroute; geen geforceerde firewallredirect.
**Verifiëren:** Bij stop AdGuard werkt fallback binnen overeengekomen window.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I12-12-05`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 6. Hub monitoring en herstel
**Uitvoeren:** DNS status, blocked metrics, ZFS snapshot/backup.
**Verifiëren:** Alert bij uitval en DNS kan snel terug naar oude resolver.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I12-12-06`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

## 3. Acceptatie en oplevering
Echte TrueNAS-app start, authenticatie, persistente data na herstart, firewall/poort, metrics, backup+restore en rolrechten controleren.

- **GO:** elke stap heeft bewijs en geen kritisch defect; health na herstart, functionaliteit in eigen UI en Hub, DB persistent, documenten geactualiseerd.
- **NO-GO:** geen restorepoint, onbekend secret ownership, ongeteste dataset/poort, falende health, incomplete migratie, onveilige WAN-exposure of datawijziging buiten eigenaar.

## 4. Terugdraaien / verwijderen
1. Schakel nieuwe automation/ingest uit. 2. Bewaar audit en logs. 3. Stop nieuwe container/route, herstel oude version-pinned image én passend databestand/snapshot waar schema is veranderd. 4. Controleer credentials, clients en content integrity. 5. Maak incidentrapport met wat wel/niet is teruggezet. 6. Bij decommission: data alleen na eigen, afzonderlijke bevestiging verwijderen.

## 5. Let op
Poort 53 kan al bezet zijn; bewust niet automatisch router-DNS wijzigen. Als AdGuard op NAS draait en NAS platgaat, DNS-backup extern nodig.

## 6. Upstream documentatie en broncontrole
https://github.com/AdguardTeam/AdGuardHome/wiki/Docker

Re-run broncheck vlak vóór uitvoering: deze installatiebeschrijving is een plan en geen claim dat er reeds een live installatie is gevalideerd.