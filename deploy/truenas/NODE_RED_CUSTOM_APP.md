# Node-RED en Home Control Hub (B11)

Node-RED is een **eigen standaard TrueNAS Custom App** met één container. De installatieweg van Node-RED is het
manifest van `jelly-leon-platform`: bestand `install/manifests/node-red.manifest.yaml` (installatiestap I10; de
keuzes staan daar in `docs/adr/ADR-0023-node-red-als-custom-app.md`). Dat manifest bepaalt de image en de digest,
de poort, de dataset, de gebruiker (**568:568**) en de beveiligingsinstellingen. Dit document beschrijft **geen
eigen formuliervelden** voor Node-RED: volg het manifest. Geen YAML, geen *Install via YAML*, geen docker compose,
geen terminal en geen eigen image.

Dit document beschrijft alleen wat je in **Home Control Hub** instelt om Node-RED te bewaken: de bron, de
optionele instellingen `HCH_NODE_RED_*` en de controles die alleen op de NAS te zien zijn. Home Control Hub start,
stopt of wijzigt de app Node-RED zelf niet.

> **NIET GEVALIDEERD (echte NAS): niet als Custom App op TrueNAS geïnstalleerd; zie STAPPEN_P6.md.** (Het plan
> staat in `ai-server-manager`, `docs/platform-v2/OVERDRACHT/UITVOERINGSPLAN/STAPPEN_P6.md`.) Wat wél is gemeten:
> de bewaking van Home Control Hub tegen een Node-RED-simulator, en de aannames over Node-RED tegen de gepinde image
> in lokale containers (`docs/b11/node-red-verificatie.json`). Die meting is gedaan met het eigen
> beveiligingsprofiel van Home Control Hub (gebruiker 1000, eigen argumenten), **niet** met het manifest van
> `jelly-leon-platform`. Jouw TrueNAS-versie (D01), poolnaam en dataset (D02) en NAS-adres (D03) zijn onbekend.

## Anonieme toegang (besluit C-11)

Er is **geen anonieme toegang** tot de editor van Node-RED: de editor is alleen bruikbaar via een beheerder. Home
Control Hub controleert dat met `anoniem_geweigerd`: een lezer zonder aanmelding moet `401` krijgen op `/flows`,
`/nodes` en `/settings`.

Het manifest van `jelly-leon-platform` doet dat pas na stap S-P2-410. Tot die commit staat er in het manifest nog
"anoniem alleen lezen" (aanmelden verplicht om te schrijven, lezen open op het vertrouwde netwerk). Tegen een
Node-RED die volgens dat manifest is geïnstalleerd geeft `anoniem_geweigerd` tot dan dus een **afwijking**. Dat is
bekend en wordt niet weggewerkt door de controle af te zwakken.

## Beheerder- en dienstaccount (besluit C-12)

Zonder beheerder is de editor van Node-RED niet bruikbaar. Het manifest levert nog **geen beheerder**: de
manifeststandaard kent nog geen manier om een account te maken zonder een geheim in het formulier te zetten. De
manifeststandaard (`appstore-en-fork`) krijgt daarvoor een **voorziening zonder geheim in het Custom App-formulier**
voor een beheerder en voor het dienstaccount waarmee Home Control Hub leest. Die voorziening wordt eerst ontworpen
(stap S-P2-510 in `appstore-en-fork`) en daarna, na fase P2, gebouwd.

Home Control Hub heeft een eigen beveiligingsprofiel (`POST /integrations/v1/automation/hardening-profile`). Dat is
**geen installatiestap**: zet geen argumenten, wachtwoord-hashes of sleutels uit dat profiel in het formulier van
Node-RED. Het profiel vervalt of wordt gelijkgetrokken met de voorziening zodra die er is.

Gevolg tot dan: Home Control Hub werkt alleen met een Node-RED die een aanmelding vraagt en een dienstaccount voor
Home Control Hub heeft: Home Control Hub meldt zich aan met dat account. Wat de isolatiemeting precies toont tegen
een Node-RED die volgens het manifest is geïnstalleerd, is nog niet gemeten.

## Wat je in Home Control Hub instelt

**Bron.** Vul in de Hub bij de bron **Node-RED** (`node_red`) het LAN-adres van Node-RED in
(`http://<NAS-adres>:<host-poort>`, de poort uit het manifest) en zet de bron aan. Een wachtwoord of token vul je
nergens in. Laat daarna de isolatie meten (*Isolatie meten*; API:
`POST /integrations/v1/automation/isolation/check`).

**Instellingen** (optioneel; omgevingsvariabelen in het formulier van de app **home-control-hub**, zie ook
`deploy/truenas/CUSTOM_APP.md` en `.env.example`):

| Variabele | Wat | Standaard |
|---|---|---|
| `HCH_NODE_RED_SYNC_INTERVAL_S` | hoe vaak (seconden) de flows uit Node-RED gelezen en gecontroleerd worden; `0` = uit | `60` |
| `HCH_NODE_RED_DATA_DIR` | pad in de container van home-control-hub waar de datamap van Node-RED **alleen-lezen** is gekoppeld; leeg = versies van flows zonder credentials | leeg |
| `HCH_NODE_RED_ALLOWED_MODULES` | extra toegestane Node-RED-modules, gescheiden door komma's; een flow met een node uit een andere module wordt geblokkeerd | leeg (alleen de kern `node-red`) |

**Optioneel: credentials meenemen in versies.** Zonder deze koppeling bewaart Home Control Hub versies van je flows
**zonder** credentials (de momentopname zegt dat eerlijk: `niet_gekoppeld`). Wil je dat een herstel ook de
credentials terugzet: open de app **home-control-hub** → **Edit** → *Storage Configuration* → **Add**: Type *Host
Path*, Host Path = de dataset van Node-RED (uit het manifest), Mount Path = `/node-red-data`, **Read Only aan**; en
zet `HCH_NODE_RED_DATA_DIR` op `/node-red-data`. Home Control Hub leest daar alleen `flows_cred.json`, en alleen als
Node-RED dat bestand zelf heeft versleuteld. Een onversleuteld bestand wordt nooit meegenomen. De app kan de
credentials niet ontsleutelen of tonen.

Flows voeren zelf niets uit: een flow vraagt een actie aan, de Hub beslist. De boiler schakelen, iets verwijderen en
opdrachten op het systeem worden altijd geweigerd. Een flow met een verboden node wordt geblokkeerd.

## Zelf controleren (kan Home Control Hub niet meten)

Drie dingen zijn alleen op de NAS zelf te zien. De isolatiemeting toont ze als **niet meetbaar**, nooit als in orde.
Loop ze na de installatie en na elke wijziging van het formulier van Node-RED na, en vergelijk met het manifest:

| Controle | Waar je kijkt | Goed als |
|---|---|---|
| `niet_root` | app Node-RED → **Edit** → *Security Context* | *Custom User* aan met `568:568` zoals het manifest, *Privileged* uit |
| `geen_docker_socket` | app Node-RED → **Edit** → *Storage Configuration* | alleen de opslag uit het manifest (`/data`); geen `/var/run/docker.sock` |
| `prive_netwerk` | app Node-RED → **Edit** → *Network Configuration*, en je router | *Host Network* uit; geen port-forward of publieke proxy naar deze poort |

## Updaten en terugdraaien

- **Node-RED updaten:** alleen naar de versie en digest die het manifest noemt; volg de upgradenotitie in het
  manifest. Maak eerst een momentopname in de Hub.
- **Terugdraaien van flows:** via de Hub (*Versies* → *Terugzetten*). Dat is een voorstel dat je goedkeurt; de
  huidige stand wordt eerst zelf als momentopname bewaard.
- **Terugdraaien van de app Node-RED:** zoals het manifest beschrijft (vorige Tag samen met de snapshot van de
  dataset van vóór de update).

## Problemen

| Melding | Oplossing |
|---|---|
| Hub: *Node-RED is nog niet als bron ingesteld* (`node_red_niet_ingesteld`) | Vul het adres in bij de bron en zet hem aan. |
| Hub: `niet_beveiligd` | Node-RED vraagt geen aanmelding. Controleer of de app volgens het manifest is geïnstalleerd; stop Node-RED tot dat zo is. |
| Hub: *Node-RED is niet bereikbaar* (`node_red_unavailable`) | App gestopt, verkeerde poort of verkeerd adres. De Hub probeert het zelf opnieuw. |
| Isolatie: afwijking bij `anoniem_geweigerd` | Verwacht tot het manifest besluit C-11 volgt (na S-P2-410); zie "Anonieme toegang". |
| Flow staat op *geblokkeerd* | De flow bevat een verboden node, een onbekend type of een module die niet is toegestaan. Haal die weg; hervat de flow daarna zelf. |
| Herstel: `credentials_niet_te_ontsleutelen` | De sleutel waarmee Node-RED de credentials versleutelt is een andere dan toen de momentopname werd gemaakt. Er is niets gewijzigd. |
