# Open beslissingen en harde aannames

- **D01 TrueNAS versie:** Exact build en API schema uit System > General, https lokale API docs — *Verplicht vóór connector/bouw*.
- **D02 Poolnaam en datasetpaden:** Alle appdata en mediapaden uit TrueNAS Storage export — *Verplicht vóór mount/backup*.
- **D03 NAS IP en domeinen:** LAN IP, hostnames, VPN/tunnel en firewalled ports — *Verplicht vóór deployment*.
- **D04 OneDrive methode:** Welke taak/tool, encryptie, scope, retentie en restore credentials — *Verplicht vóór backup gate*.
- **D05 OneDrive restore bewijs:** Foto plus DB export geïsoleerd getest — *Verplicht vóór bestaande app updates*.
- **D06 ZFS pool gezondheid:** SMART, scrubs, free space, degraded errors, snapshot capaciteit — *Verplicht vóór data-mutaties*.
- **D07 Huidige appversies:** Image tags, current API, config backups, health, actief gebruik — *Verplicht vóór upgrade*.
- **D08 Intel GPU rendernodes:** /dev/dri mapping A310/UHD770 en QSV app support — *Verplicht vóór fork/transcode*.
- **D09 Claude API-credit claim:** Console org link, officieel inbegrepen maandbudget, hard stop en no-pay overage — *Verplicht vóór AI agent cloud tool*.
- **D10 Bestaande mini-pc doel:** Videoapp/andere projecten, geen Home Hub services — *Vast besluit*.
- **D11 Netwerk router DNS fallback:** Routermodel, huidige DNS, poort53 eigenaar, rollback access — *Verplicht vóór AdGuard DNS cutover*.
- **D12 Gree type en firmware:** Gree local UDP compatibility via echte bind/readback — *Verplicht vóór Gree actuation*.
- **D13 Zigbee hardwarestatus:** Dongle/adapter/serial-by-id en sensortype — *Verplicht vóór Zigbee installatie*.
- **D14 HomeWizard meterkoppeling:** P1, Energy Socket boiler alleen meten, airco 1fase meter aanwezig? — *Verplicht vóór energy dashboard exact*.
- **D15 Media clients/platforms:** Tv model(s), telefoons, Android TV/Apple TV, gewenste offline gedrag — *Verplicht vóór mediaserver cutover*.
- **D16 RPO/RTO:** Hoeveel historie/downtime maximaal toegestaan per app — *Verplicht vóór restore-policy*.
- **D17 OIDC bereikbaarheid:** Domeinnaam, HTTPS, recovery account, roles — *Verplicht vóór Authentik*.
- **D18 Optional Navidrome:** Meerwaarde boven Jellyfin na gebruikerstest — *Optioneel*.

Geen generieke IP/poolnaam als feit invullen; vervang eerst in installerconfigs en laat in Excel staan als onbekend totdat getest.
