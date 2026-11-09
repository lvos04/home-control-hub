# Traceerbaarheid van al je gekozen functies

| Gewenst onderdeel | Primaire specificatie | Eigenaarschap / niet-dupliceren |
|---|---|---|
| Alle apps openen, installeren/updaten/verwijderen, 1 dashboard, mobiel/tablet/pc | B01, B08, I23 | Hub catalogus + versiebeheer; bestaande apps houden eigen DB |
| Live CPU/GPU/RAM/disk/netwerk, energie/kosten, meerdere servers later | B01, B09, B14, I07/I08 | Alleen TrueNAS in eerste deployment; mini-pc expliciet uitgesloten |
| Centrale meldingen, foutlogs, alerts, performance prognoses | B09, B02 | Beszel/Uptime gegevens, Hub incidenten; nooit stale=groen |
| AI herstel/updates/scripts/optimalisatie en beveiliging met risicoklassen | B02, 03_RISICO_AUTONOMIE, I23 | Specifieke allowlisted executor, geen universele shell; R3 approval |
| Film/series/anime/muziek, mobiel/tv, ondertitels, intro/recap, transcoding, profiles, watch sync, offline, liveTV/DVR, scene search | B03, I06/I24 | Jellyfin upstream/protocol als basis; MediaGuard owner downloads |
| Downloads fallback, kwaliteit, library AV1, missing episodes, Usenet/torrent optimalisatie | B04, B05, I03/I04/I16-I19 | MediaGuard bibliotheek, MSO provider/bronnen, Prowlarr indexers |
| Hue/Gree/Zigbee/HomeWizard, smart climate, energiesensors en verhuisbaarheid | B06, B14, I05 | my_house blijft controller; boiler uitsluitend meten |
| Netwerk discovery, privacy, AdBlock DNS, VPN, traffic en intrusion | B10, I11/I12/I21 | NetAlertX + AdGuard + Tailscale/Cloudflared |
| Eigen AI-assistent via tekst/spraak, eigen bestandzoeker, agents, automations | B02, B07, B11, B15, I10/I14/I25 | Hub+NodeRED+search, lokale privacy, Claude credits hard stop |
| Appstore, forks, release-tests, upgrades en portabiliteit | B08, B12, I23-I26 | Alleen approved manifests, snapshots en offsite restore |
| Eigen fotobeheer behouden, organizing, foto's doorzoeken | I15, B07 | Immich eigenaar; opt-in search metadata |
| Minder betaalde diensten, betrouwbare backups | B05, B12, I02 | MSO cost scenarios; OneDrive bestaand en hersteltests |
| SSO waar mogelijk, veilige externe toegang | B13, I09/I21 | Authentik OIDC waar app het ondersteunt, anders native auth |

Functionele traceerbaarheid is een blueprint. Ieder effect wordt pas als gerealiseerd gemarkeerd als een echte test het bevestigd heeft. Zie Excel `Werkpakketten`, `Testmatrix`, `Besluiten`.
