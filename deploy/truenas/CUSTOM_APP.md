# Home Control Hub installeren als standaard TrueNAS Custom App

Home Control Hub is de integratiedienst van het TrueNAS Home Platform (netwerk/privacy, Node-RED, Authentik/SSO en
beheerherstel, energie/resources). Het is **één image** waarin alles zit: een eigen PostgreSQL 16 (alleen via een
unix-socket), de API met een kleine statuspagina en een worker. Je installeert hem met het **gewone Custom
App-formulier** van TrueNAS: geen YAML, geen *Install via YAML*, geen docker compose, geen terminal, geen wachtwoorden.

> **Normaal installeer je deze app niet zelf.** Na de eerste installatie van de Hub (`ai-server-manager`) en de
> executor installeert het platform deze app via de TrueNAS-API met precies dezelfde formulierwaarden, en geeft het
> `HUB_URL`, een eenmalig koppeltoken (`HUB_ENROLLMENT_TOKEN`) en de verwachte sleutelset-vingerafdruk
> (`HUB_KEY_FINGERPRINT`) mee (platformcontract 1.2 §3.2). Dit document is voor handmatige installatie en voor
> controle.

> **Verificatiestatus: NIET GEVALIDEERD (echte NAS).** De image is in een Linux/Docker-bouwomgeving gebouwd en gestart
> zoals het formulier hem start (standaard Docker-capabilities, **zonder** no-new-privileges en **zonder** cap-drop;
> `deploy/allinone/smoke-test.sh`): elk proces, ook PID 1, draait na de start als 568 zonder capabilities en met
> no-new-privileges, die de image zelf zet. Het TrueNAS-formulier zelf is niet op echte TrueNAS-hardware doorlopen;
> de veldnamen volgen het standaard Custom App-formulier (`ix-app`) van TrueNAS 24.10/25.x en kunnen per versie iets
> afwijken. Jouw TrueNAS-versie (D01), poolnaam/dataset (D02) en NAS-adres (D03) zijn onbekend: vul je eigen waarden in.

## Wat je nodig hebt

| Wat | Waarde |
|---|---|
| Image | `ghcr.io/lvos04/home-control-hub` (publiek pakket; registry-login alleen als terugval, zie stap 0) |
| Tag | `<versie>@sha256:<digest>` uit `release/digests.json` van de release, bv. `0.1.0@sha256:` + 64 hex (**nooit** `latest`) |
| Poort | container `30420` → host `30420` (voorstel; de Hub controleert vooraf op conflicten) |
| Opslag | één dataset → `/appdata` |
| Omgevingsvariabelen | geen verplichte; voor koppelen zonder wedloop `HUB_URL` + `HUB_ENROLLMENT_TOKEN` + `HUB_KEY_FINGERPRINT` |

## 0. Image ophalen (publiek; registry-login alleen als terugval)

- **Standaard:** het GHCR-pakket wordt publiek (besluit 3 van de gebruiker, pas na een scan van de volledige
  historie). TrueNAS haalt de image dan zonder registry-login op. Zolang het pakket nog privé is, mislukt ophalen
  (`denied`); installeren op een echte NAS is dan **Geblokkeerd / NIET GEVALIDEERD**.
- **Terugval:** *Apps → Configuration → Sign-in to a Docker registry* → *Other Registry*, URI `https://ghcr.io`, met een
  GitHub-token dat **alleen** pakketten mag lezen (`read:packages`). Dat token is jouw geheim in TrueNAS — nooit in een
  app-formulier, manifest, repo of log. Gedrag met GHCR-tokens: **NIET GEVALIDEERD (echte NAS)**.

## 1. Dataset maken

**Datasets** → kies je pool → **Add Dataset**:

- Name: `home-control-hub` (bijvoorbeeld onder je apps-dataset; gebruik je eigen poolnaam)
- Dataset Preset: **Apps**

Rechten hoef je niet aan te passen: bij de eerste start maakt de app gebruiker `568` (apps) eigenaar van de dataset
en van zijn eigen submappen (`postgres`, `secrets`, `backups`).

## 2. Custom App aanmaken

**Apps** → **Discover Apps** → knop **Custom App** (niet *Install via YAML*). Vul in:

| Sectie | Veld | Waarde |
|---|---|---|
| Application Name | | `home-control-hub` (een andere naam mag; de dienst meldt zich altijd als `home-control-hub`) |
| Image Configuration | Repository | `ghcr.io/lvos04/home-control-hub` |
| | Tag | `<versie>@sha256:<digest>` uit `release/digests.json` (trekt op digest). Weigert het formulier het `@`-teken, vul dan alleen de exacte versie in (bv. `0.1.0`); de Hub leest de digest na installatie terug en stopt bij een afwijking. **Of het formulier `@` accepteert en of TrueNAS daarmee updates ziet: NIET GEVALIDEERD (echte NAS).** |
| | Pull Policy | *Pull the image if it is not already present on host* |
| Container Configuration | Timezone | jouw tijdzone |
| | Restart Policy | *Unless Stopped* |
| | Environment Variables | leeg laten, of voor koppelen zonder wedloop (aanbevolen): `HUB_URL`, `HUB_ENROLLMENT_TOKEN`, `HUB_KEY_FINGERPRINT` (zie stap 3) |
| | Disable Builtin Healthcheck | **uit** (de image controleert zelf `/readyz`) |
| Security Context | Privileged | **uit** |
| | Capabilities | geen toevoegen |
| | Custom User | **uit** (de app start als root alleen om de rechten van `/appdata` te regelen; daarna draait alles, ook PID 1, als 568 zonder capabilities). Aan met 568:568 werkt ook, mits 568 op de dataset mag schrijven. |
| Network Configuration | Host Network | **uit** |
| | Ports → Add | Container Port `30420`, Host Port `30420`, Protocol TCP |
| Storage Configuration | Add → Type | **Host Path** (of ixVolume; laat bij verwijderen *Remove ixVolumes* uit) |
| | Mount Path | `/appdata` |
| | Host Path | het pad van de dataset uit stap 1 |
| Resources (optioneel) | CPUs / Memory | 1 CPU / 512 MiB is ruim voor deze fase (niet gemeten op een echte NAS) |
| GPU | | geen |

Kies **Install**. De eerste start duurt ongeveer 10–30 seconden (database aanmaken, migraties). Daarna staat de app op
*Running* en na de healthcheck (`/readyz`) op *Healthy*.

Niet doen: geen Docker-socket koppelen, geen extra host-paden zoals `/`, `/mnt`, `/etc` of `/var/run`, geen *Host
Network*, geen *Privileged*. Er is geen enkele reden voor in deze app.

## 3. Koppelen met de Hub

- **Geïnstalleerd door het platform:** de Hub geeft `HUB_URL`, een eenmalig koppeltoken en `HUB_KEY_FINGERPRINT` mee;
  de app koppelt zichzelf bij de eerste start, controleert de sleutelset-vingerafdruk en bevestigt de koppeling. Het
  token vervalt na 60 minuten of na het eerste gebruik.
- **Handmatig, zonder wedloop (aanbevolen):** maak in de Hub-UI (*Diensten*) een enrollment-token voor
  `home-control-hub` en vul in het formulier van stap 2 bij *Environment Variables* in:

  | Variabele | Waarde |
  |---|---|
  | `HUB_URL` | `http://<NAS-adres>:<Hub-poort>` — LAN-adres, geen `localhost`, geen pad |
  | `HUB_ENROLLMENT_TOKEN` | het token uit de Hub (`enr_…`; eenmalig, 60 min — daarna waardeloos) |
  | `HUB_KEY_FINGERPRINT` | de sleutelset-vingerafdruk die de Hub ernaast toont (`XXXX-XXXX-XXXX-XXXX`) |

  Zonder `HUB_KEY_FINGERPRINT` vertrouwt de app de Hub bij de eerste koppeling (*trust on first use*); vergelijk dan
  de vingerafdruk op de statuspagina met die in de Hub-UI.
- **Handmatig via de statuspagina:** open `http://<NAS-adres>:30420`. Zolang de dienst **nog nooit** gekoppeld is,
  staat daar een formulier: Hub-adres, koppelcode en de **Hub-vingerafdruk** (de Hub-UI toont koppelcode en
  vingerafdruk samen met een kopieerknop). Maximaal 5 pogingen per kwartier per apparaat.

Na de eerste koppeling verdwijnt het formulier: **ontkoppelen, opnieuw koppelen en intrekken gaan alleen via de Hub**.
Opnieuw koppelen = de Hub zet een nieuw `HUB_ENROLLMENT_TOKEN` (en `HUB_KEY_FINGERPRINT`) in het formulier, of jij doet
dat zelf via **Edit**. Een ingetrokken dienst weigert alle Hub-aanroepen tot hij opnieuw gekoppeld is.

## Optioneel (omgevingsvariabelen)

| Variabele | Wanneer |
|---|---|
| `HUB_URL` | Hub-adres bij koppelen met een token (normaal zet het platform dit) |
| `HUB_ENROLLMENT_TOKEN` | eenmalig koppeltoken uit de Hub (vervalt na 60 min of na gebruik; geen blijvend geheim) |
| `HUB_KEY_FINGERPRINT` | verwachte sleutelset-vingerafdruk van de Hub; staat hij er, dan moet hij kloppen |
| `HCH_PUBLIC_URL` | adres waarop de Hub deze app bereikt, alleen ter informatie bij het koppelen |
| `HCH_AUTHENTIK_SYNC_INTERVAL_S` | hoe vaak (seconden) logins en rechten uit Authentik gelezen worden; standaard `300`, `0` = uit |

De oude naam `ENROLLMENT_TOKEN` wordt in deze release nog gelezen (met een waarschuwing in de app-log) en vervalt
daarna; gebruik `HUB_ENROLLMENT_TOKEN`. Zet hier **nooit** wachtwoorden of API-sleutels. Credentials van andere apps
(bv. Authentik) voer je in de Hub-UI in; de app bewaart ze versleuteld in `/appdata` (`vault.key` in
`/appdata/secrets`). De koppeling met de Hub staat in `/appdata/secrets/hub-link.json` (alleen leesbaar voor 568);
maak externe kopieën van `/appdata/secrets` alleen versleuteld.

## Authentik koppelen (B13, optioneel)

Authentik zelf installeer je als **officiële TrueNAS-catalogusapp** `authentik` (niet met dit formulier); laat daar
**Mount Docker Socket uit**. Daarna in de Hub-UI bij de bron *Authentik*: het LAN-adres van Authentik en een
**API-token van een serviceaccount met alleen leesrechten** (geen superuser — de app meldt een superuser-token of
schrijvende systeemrechten als waarschuwing; de rolrechten van het serviceaccount kan de app niet zelf zien, die
controleer je in Authentik: alleen `view`-rechten). Deze app leest alleen; wijzigingen in Authentik zijn voorstellen
die pas met een door de Hub ondertekende opdracht kunnen worden uitgevoerd (nog niet beschikbaar). Back-up en
upgrade: zie `docs/runbooks/AUTHENTIK_BACKUP_UPGRADE.md`.

## Updaten en terugdraaien

- **Updaten:** app → **Edit** → Tag naar de nieuwe `<versie>@sha256:<digest>` → **Update**. Bij openstaande
  databasewijzigingen maakt de app eerst een back-up (`/appdata/backups/voor-upgrade-*.dump`, de nieuwste 3 blijven)
  en voert dan de migraties uit. **Mislukt de back-up, dan migreert de app niet** en stopt hij met een melding in de
  log (bijv. te weinig vrije ruimte op de dataset). Mislukt een migratie, dan blijft de oude database ongewijzigd en
  meldt de log dat ook. Een ZFS-snapshot vooraf blijft verstandig.
- **Contract 1.2 (deze versie):** de database kreeg migratie `0003` en de koppeling met de Hub verhuist bij de eerste
  start eenmalig uit de database naar `/appdata/secrets/hub-link.json`. Terug naar een oudere image kan alleen met de
  back-up of ZFS-snapshot van vóór de update.
- **Terugdraaien:** zolang een release geen databasewijziging heeft (zie de releasenotes, veld
  `tag_only_rollback_safe`), kun je de Tag terugzetten. Bij een schemawijziging: zet de ZFS-snapshot van vóór de
  update terug, of gebruik de back-up uit `/appdata/backups`. `app.rollback` van TrueNAS werkt niet voor een
  tagwijziging van een Custom App.

## Problemen

| Melding | Oplossing |
|---|---|
| App-log: `FOUT: /appdata bestaat niet` | Opslagregel ontbreekt of Mount Path is niet precies `/appdata`. |
| App-log: `FOUT: geen schrijfrechten op /appdata/...` | *Custom User* staat aan met een andere gebruiker: zet het uit, of geef gebruiker 568 schrijfrechten. |
| App-log: `FOUT: rechten verlagen mislukt` | De container mag niet naar 568 wisselen; controleer dat *Privileged* uit staat en er geen afwijkende securityinstellingen zijn. |
| App-log: `oude postmaster.pid ... verwijderd` | Geen fout: de vorige stop was onverwacht (stroom/kill). |
| App-log: `FOUT: back-up vóór de migratie mislukt` | Maak ruimte vrij op de dataset en start de app opnieuw, of zet de vorige Tag terug. Er is niets gewijzigd. |
| Poort bezet bij opslaan | Kies een andere vrije **Host Port**; de Container Port blijft `30420`. |
| Statuspagina: *sleutelset-vingerafdruk van de Hub klopt niet* | Vingerafdruk verkeerd overgenomen, of je praat niet met jouw Hub. Er is niets opgeslagen; maak in de Hub een nieuwe koppelcode of een nieuw token. |
| Statuspagina: *HUB_URL is ongeldig* | Gebruik `http://<NAS-adres>:<Hub-poort>`: geen `localhost`, geen pad, geen inloggegevens. |
| Statuspagina: *ingetrokken* | De Hub heeft de koppeling ingetrokken. Opnieuw koppelen gaat via de Hub (nieuw token). |
| Image kan niet worden opgehaald (`denied`) | Het GHCR-pakket is nog privé; zie stap 0 (terugval met registry-login). |
