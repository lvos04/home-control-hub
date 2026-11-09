# Home Control Hub installeren als standaard TrueNAS Custom App

Home Control Hub is de integratiedienst van het TrueNAS Home Platform (netwerk/privacy, Node-RED, Authentik/SSO en
beheerherstel, energie/resources). Het is **één image** waarin alles zit: een eigen PostgreSQL 16 (alleen via een
unix-socket), de API met een kleine statuspagina en een worker. Je installeert hem met het **gewone Custom
App-formulier** van TrueNAS: geen YAML, geen *Install via YAML*, geen docker compose, geen terminal, geen wachtwoorden.

> **Normaal installeer je deze app niet zelf.** Na de eerste installatie van de Hub (`ai-server-manager`) en de
> executor installeert het platform deze app via de TrueNAS-API met precies dezelfde formulierwaarden, en geeft het
> `HUB_URL` en een eenmalig koppeltoken mee. Dit document is voor handmatige installatie en voor controle.

> **Verificatiestatus: NIET GEVALIDEERD (echte NAS).** De image is in een Linux/Docker-bouwomgeving gebouwd en gestart
> (zie `docs/platform-v2/EVIDENCE.json`). Het TrueNAS-formulier zelf is niet op echte TrueNAS-hardware doorlopen; de
> veldnamen volgen het standaard Custom App-formulier van TrueNAS SCALE 24.10/25.x en kunnen per versie iets afwijken.
> Jouw TrueNAS-versie (D01), poolnaam/dataset (D02) en NAS-adres (D03) zijn onbekend: vul je eigen waarden in.

## Wat je nodig hebt

| Wat | Waarde |
|---|---|
| Image | `ghcr.io/lvos04/home-control-hub` |
| Tag | de vaste versie uit de release, bv. `0.1.0` (**nooit** `latest`) |
| Poort | container `30420` → host `30420` (voorstel; de Hub controleert vooraf op conflicten) |
| Opslag | één dataset → `/appdata` |
| Omgevingsvariabelen | geen verplichte; zie hieronder voor optionele |

## 1. Dataset maken

**Datasets** → kies je pool → **Add Dataset**:

- Name: `home-control-hub` (bijvoorbeeld onder je apps-dataset; gebruik je eigen poolnaam)
- Dataset Preset: **Apps**

Rechten hoef je niet aan te passen: bij de eerste start maakt de app gebruiker `568` (apps) eigenaar van de dataset
en van zijn eigen submappen (`postgres`, `secrets`, `backups`).

## 2. Custom App aanmaken

**Apps** → **Discover Apps** → **Custom App**. Vul in:

| Sectie | Veld | Waarde |
|---|---|---|
| Application Name | | `home-control-hub` |
| Image Configuration | Repository | `ghcr.io/lvos04/home-control-hub` |
| | Tag | de releaseversie, bv. `0.1.0` |
| | Pull Policy | *Pull the image if it is not already present on host* |
| Container Configuration | Timezone | jouw tijdzone |
| | Restart Policy | *Unless Stopped* |
| | Environment Variables | leeg laten (zie *Optioneel*) |
| Security Context | Privileged | **uit** |
| | Capabilities | geen toevoegen |
| | Custom User | **uit** (de app start als root alleen om de rechten van `/appdata` te regelen en draait daarna als 568) |
| Network Configuration | Host Network | **uit** |
| | Ports → Add | Container Port `30420`, Host Port `30420`, Protocol TCP |
| Storage Configuration | Add → Type | **Host Path** (of ixVolume) |
| | Mount Path | `/appdata` |
| | Host Path | het pad van de dataset uit stap 1 |
| Resources (optioneel) | CPUs / Memory | 1 CPU / 512 MiB is ruim voor P0 (niet gemeten op een echte NAS) |
| GPU | | geen |

Kies **Install**. De eerste start duurt ongeveer 10–30 seconden (database aanmaken, migraties). Daarna staat de app op
*Running* en na de healthcheck (`/readyz`) op *Healthy*.

Niet doen: geen Docker-socket koppelen, geen extra host-paden zoals `/`, `/mnt`, `/etc` of `/var/run`, geen *Host
Network*, geen *Privileged*. Er is geen enkele reden voor in deze app.

## 3. Koppelen met de Hub

- **Geïnstalleerd door het platform:** de Hub geeft `HUB_URL` en een eenmalig koppeltoken mee; de app koppelt
  zichzelf bij de eerste start. Het token is daarna waardeloos.
- **Handmatig geïnstalleerd:** open `http://<NAS-adres>:30420`. De statuspagina toont *niet gekoppeld*. Maak in de
  Hub-UI een koppelcode voor `home-control-hub` en vul op de statuspagina het Hub-adres
  (`http://<NAS-adres>:<Hub-poort>`, geen `localhost`) en de koppelcode in.

Ontkoppelen (alleen nodig als de Hub opnieuw is geïnstalleerd): in de Hub, of op de statuspagina met de **lokale
ontkoppelcode** die bij elke start in de app-log staat (**Apps** → `home-control-hub` → **Logs**).

## Optioneel (omgevingsvariabelen)

| Variabele | Wanneer |
|---|---|
| `HUB_URL` | Hub-adres als je het koppeltoken handmatig meegeeft (normaal zet het platform dit) |
| `HUB_ENROLLMENT_TOKEN` | eenmalig koppeltoken uit de Hub (vervalt na 60 min of na gebruik; geen blijvend geheim) |
| `HCH_PUBLIC_URL` | adres waarop de Hub deze app bereikt, als dat afwijkt van wat de Hub zelf weet |

Zet hier **nooit** wachtwoorden of API-sleutels. Credentials van andere apps (bv. Authentik) voer je in de Hub-UI in;
de app bewaart ze versleuteld in `/appdata` (`vault.key` in `/appdata/secrets`).

## Updaten en terugdraaien

- **Updaten:** app → **Edit** → Tag naar de nieuwe versie → **Update**. Bij openstaande databasewijzigingen maakt de
  app eerst een back-up (`/appdata/backups/voor-upgrade-*.dump`, de nieuwste 3 blijven) en voert dan de migraties uit.
  **Mislukt de back-up, dan migreert de app niet** en stopt hij met een melding in de log (bijv. te weinig vrije
  ruimte op de dataset). Mislukt een migratie, dan blijft de oude database ongewijzigd en meldt de log dat ook. Een
  ZFS-snapshot vooraf blijft verstandig.
- **Terugdraaien:** zolang een release geen databasewijziging heeft (zie de releasenotes, veld
  `tag_only_rollback_safe`), kun je de Tag terugzetten. Bij een schemawijziging: zet de ZFS-snapshot van vóór de
  update terug, of gebruik de back-up uit `/appdata/backups`.

## Problemen

| Melding in de app-log | Oplossing |
|---|---|
| `FOUT: /appdata bestaat niet` | Opslagregel ontbreekt of Mount Path is niet precies `/appdata`. |
| `FOUT: geen schrijfrechten op /appdata/...` | *Custom User* staat aan met een andere gebruiker: zet het uit, of geef gebruiker 568 schrijfrechten. |
| `oude postmaster.pid ... verwijderd` | Geen fout: de vorige stop was onverwacht (stroom/kill). |
| `FOUT: back-up vóór de migratie mislukt` | Maak ruimte vrij op de dataset en start de app opnieuw, of zet de vorige Tag terug. Er is niets gewijzigd. |
| Poort bezet bij opslaan | Kies een andere vrije **Host Port**; de Container Port blijft `30420`. |
| Statuspagina: *Loopback-adressen ... wijzen naar deze container zelf* | Gebruik het LAN-adres van de NAS i.p.v. `localhost`. |
| Image kan niet worden opgehaald (`denied`) | Het GHCR-pakket staat nog op privé (eenmalig openbaar maken in GitHub → Packages). |
