# Authentik — installatie, update, test en herstel

**Rol:** Centrale OIDC authenticatie.  
**Aanpak:** Nieuw installeren.  
**Bron:** https://docs.goauthentik.io/install-config/install/docker-compose/.  
**Versiebeleid:** Vastgeprikte huidige officiële compose release, geen onbeheerde latest.

## 1. Vooraf controleren
Backups, domeinnaam/TLS-route, lokale break-glass beheeraccount.

**Toegang / netwerk:** TLS achter private reverse proxy/VPN, geen admin direct publiek.

**Data / mounts:** Postgres database, secret key, media/templates, provider config persistent.

**Preflight-regels (niet overslaan):** TrueNAS-release en Docker-appconfig controleren; data-eigenaar bepalen; bestaande install herkennen; bezette ports en container netwerken vergelijken; herstelbare backup + exacte image pin eisen; secrets nooit in logs of screenshots; test op stille omgeving vóór productie.

## 2. Stappen in uitvoeringsvolgorde

### Stap 1. Official compose versie
**Uitvoeren:** Gebruik actuele Authentik doc en image, genereer unieke geheime sleutels via documentatie.
**Verifiëren:** Geen sample secret en image pin geregistreerd.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I09-09-01`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 2. Postgres/migraties
**Uitvoeren:** Dataset voor DB en app persistent, upgrades tegen clone testen.
**Verifiëren:** Login na restart.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I09-09-02`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 3. MFA en herstel
**Uitvoeren:** Maak admin + MFA, recovery procedure en break-glass account, backup credentials encrypted.
**Verifiëren:** Geen totale lockout bij Authentik storing.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I09-09-03`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 4. OIDC Hub
**Uitvoeren:** Registreer Hub callback/redirect, issuer, scopes en claims.
**Verifiëren:** Code+PKCE en rolmapping werken; JWT audience gevalideerd.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I09-09-04`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 5. SSO appcompat
**Uitvoeren:** Test bestaande apps per app, geen header-injectie-trucs zonder validatie.
**Verifiëren:** Unsupported apps blijven op bestaande login.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I09-09-05`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

### Stap 6. Restore en revocation
**Uitvoeren:** Backup en herstel Authentik data, keys, clients; revoke sessies en credentials.
**Verifiëren:** Gelekte sleutel kan ingetrokken worden.
**Bewijs:** noteer NAS-versie, appimage digest, datum, gemaskeerde output, eventuele screenshot en status in Excel (ID `I09-09-06`).
**Als dit mislukt:** stop hier; maak oorzaak en rollbackpad inzichtelijk. Geen volgende stap starten zolang deze test of de back-upgate rood is.

## 3. Acceptatie en oplevering
Echte TrueNAS-app start, authenticatie, persistente data na herstart, firewall/poort, metrics, backup+restore en rolrechten controleren.

- **GO:** elke stap heeft bewijs en geen kritisch defect; health na herstart, functionaliteit in eigen UI en Hub, DB persistent, documenten geactualiseerd.
- **NO-GO:** geen restorepoint, onbekend secret ownership, ongeteste dataset/poort, falende health, incomplete migratie, onveilige WAN-exposure of datawijziging buiten eigenaar.

## 4. Terugdraaien / verwijderen
1. Schakel nieuwe automation/ingest uit. 2. Bewaar audit en logs. 3. Stop nieuwe container/route, herstel oude version-pinned image én passend databestand/snapshot waar schema is veranderd. 4. Controleer credentials, clients en content integrity. 5. Maak incidentrapport met wat wel/niet is teruggezet. 6. Bij decommission: data alleen na eigen, afzonderlijke bevestiging verwijderen.

## 5. Let op
Authentik kan zwaarder zijn dan simpele auth. Eventueel later pas installeren nadat Hub basis-read-only draait, maar vóór privileged mutaties.

## 6. Upstream documentatie en broncontrole
https://docs.goauthentik.io/install-config/install/docker-compose/

Re-run broncheck vlak vóór uitvoering: deze installatiebeschrijving is een plan en geen claim dat er reeds een live installatie is gevalideerd.