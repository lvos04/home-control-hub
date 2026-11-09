# Tailscale en Cloudflared — installatie, update, test en herstel

**Rol:** Bestaande externe toegang.  
**Aanpak:** Behouden en scope verstrengen.  
**Bron:** https://tailscale.com/kb/; https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/.  
**Versiebeleid:** Huidige versies en routes inventariseren.

## 1. Vooraf controleren
Routers en DNS updates mogen bereikbaarheid niet verbreken.

**Toegang / netwerk:** NAS admin alleen VPN, app tunnels met Access / HTTPS.

**Data / mounts:** Keys/config encrypted in apps datasets.

**Preflight-regels (niet overslaan):** TrueNAS-release en Docker-appconfig controleren; data-eigenaar bepalen; bestaande install herkennen; bezette ports en container netwerken vergelijken; herstelbare backup + exacte image pin eisen; secrets nooit in logs of screenshots; test op stille omgeving vóór productie.

## 2. Stappen in uitvoeringsvolgorde

### Stap 1. Huidige routekaart
**Uitvoeren:** Schrijf tunnels, hostnames, tailnet routes, ACL en toegang per app op.
**Verifiëren:** Welke app buiten huis bereikbaar is bekend.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I21-21-01`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 2. Niet-publiek admin
**Uitvoeren:** TrueNAS UI, Authentik admin, privileged Hub alleen LAN/Tailscale; geen algemene Cloudflare tunnel.
**Verifiëren:** Externe URL van NAS console werkt zonder VPN niet.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I21-21-02`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 3. App tunnels valideren
**Uitvoeren:** Bestaande externe MediaGuard/my_house viewer links en HTTPS correct (geen http QR code).
**Verifiëren:** Geen mixed content of tokenleak.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I21-21-03`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 4. Secret en MFA
**Uitvoeren:** Revoke oude tunnel keys en export encrypted credential inventory.
**Verifiëren:** Geen token in logs.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I21-21-04`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 5. DNS/Cert alert
**Uitvoeren:** Vervaldatums en tunnel health in Uptime Kuma/Hub.
**Verifiëren:** Storing meldt zich.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I21-21-05`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 6. Rollback
**Uitvoeren:** Documenteer offline lokale toegang bij DNS/Cloudflare/Tailscale storing.
**Verifiëren:** Beheerder kan alsnog NAS bereiken.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I21-21-06`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

## 3. Acceptatie en oplevering
Echte TrueNAS-app start, authenticatie, persistente data na herstart, firewall/poort, metrics, backup+restore en rolrechten controleren.

- **GO:** elke stap heeft bewijs en geen kritisch defect; health na herstart, functionaliteit in eigen UI en Hub, DB persistent, documenten geactualiseerd.
- **NO-GO:** geen restorepoint, onbekend secret ownership, ongeteste dataset/poort, falende health, incomplete migratie, onveilige WAN-exposure of datawijziging buiten eigenaar.

## 4. Terugdraaien / verwijderen
1. Schakel nieuwe automation/ingest uit. 2. Bewaar audit en logs. 3. Stop nieuwe container/route, herstel oude version-pinned image én passend databestand/snapshot waar schema is veranderd. 4. Controleer credentials, clients en content integrity. 5. Maak incidentrapport met wat wel/niet is teruggezet. 6. Bij decommission: data alleen na eigen, afzonderlijke bevestiging verwijderen.

## 5. Let op
Geen mini-pc inzetten als VPN egress of monitoringhost; behoud bestaande inrichting tenzij aantoonbaar nodig.

## 6. Upstream documentatie en broncontrole
https://tailscale.com/kb/; https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/

Re-run broncheck vlak vóór uitvoering: deze installatiebeschrijving is een plan en geen claim dat er reeds een live installatie is gevalideerd.