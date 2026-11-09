# Projectcharter en doelarchitectuur

## Resultaat
Een thuisserverplatform waar de gebruiker vanaf één adres zijn TrueNAS-applicaties, mediaserver, downloads, Smart Home, netwerken, automatiseringen en AI-serverbeheer kan bedienen. Geen lock-in: apps en servers kunnen later worden verhuisd en nieuwe apparaten/adapters kunnen worden toegevoegd zonder datakoppelingen te verbreken.

## Onderdelen

```text
Telefoon / browser (HTTPS binnen trusted LAN/VPN)
  |
  v
[Home Control Hub: UI, sessie, API, catalogus, zoek, goedkeuring]
  |--> Authentik / OIDC (voor apps die OIDC werkelijk ondersteunen)
  |--> Event bus / workflow (Node-RED; centrale audit en policy buiten Node-RED)
  |--> AI Router / Agent Manager --> Claude Platform API (alleen inbegrepen credit) + lokale tools
  |--> Monitoring adapters --> Beszel / Uptime Kuma / ZFS / GPU / TrueNAS API
  |--> Backup Controller --> ZFS snapshots / bestaande OneDrive-back-up / herstelproeven
  |--> Netwerk adapters --> NetAlertX / AdGuard / Tailscale / Cloudflared
  |--> MediaGuard API --> 4 arr-forks / bibliotheek / AV1 / Seerr
  |--> MSO API --> SABnzbd / qBittorrent / Prowlarr / NZB / providerdiagnose
  |--> Jellyfin fork/extension --> clients / tv / muziek / zoekindex / MediaGuard
  |--> my_house API --> Hue / Gree / HomeWizard / Zigbee2MQTT
  |--> Immich metadata (read-only integratie; Immich blijft eigenaar)
  |
  +--[smalle privileged executor op TrueNAS: allowlisted, audit, credentials]
```

## Te implementeren kwaliteitsattributen
- Privacy: lokaal tenzij expliciet aangezet; geen upload van foto's, media of volledige logs naar cloudmodellen zonder opt-in per datatype.
- Beschikbaarheid: falende module degradeert afzonderlijk; dashboard blijft opstartbaar zonder internet, AI, MSO of my_house.
- Performance: geen storende co-scheduling tussen AV1 encode, back-up, scrub, indexing of transcode; fairness, reservering en tijdelijk pauzeren.
- Veiligheid: scheiding control plane/data plane, rollen, audit, policy engine, time-bound approval, geen privileges omhoog in Node-RED.
- Beheer: versiepinning, migraties, acceptatietests, terugzetplan, automatische dependency-check en gefaseerde canary.
- Gebruikservaring: NL als standaard, volledige mobiele navigatie, één problemen-inbox, uitleg van 'waarom', verse data timestamps, bereikbaarheid ook bij appstoring.
- Verhuisbaarheid: externe secrets-back-up, containerimages, datasets, portable exports, adapters op ID i.p.v. IP, restore op een tweede host.

## Uitdrukkelijk buiten scope
- Geen appcontainers op de mini-pc, geen verplicht Home Assistant, geen vervanging van Immich, geen nieuwe betaalde AI-overages, geen full rewrite van MediaGuard/MSO/my_house, geen massale automatische bestandsverwijdering.

## Definition of Done
- Iedere primaire gebruikersreis (app openen, incidentdiagnose, goedkeuren, herstel, backup verifiëren, media zoeken, apparaat lezen) heeft een E2E-test én op echte NAS een acceptatiebewijs.
- In de Excel zijn alle P0- en P1-taken `Gereed`, gekoppelde tests `Geslaagd` en de back-up-gates aantoonbaar groen; niet anders als afgerond presenteren.
