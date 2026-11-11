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
"anoniem alleen lezen" (aanmelden verplicht om te schrijven, lezen open op het vertrouwde netwerk). Home Control Hub
meet `anoniem_geweigerd` alleen als het zich bij Node-RED kan aanmelden, dus pas **zodra er een dienstaccount is**
(besluit C-12, hieronder). Is er dan nog "anoniem alleen lezen", dan geeft `anoniem_geweigerd` een **afwijking**. Dat
is bekend en wordt niet weggewerkt door de controle af te zwakken. Tot er een dienstaccount is, wordt
`anoniem_geweigerd` niet gemeten: de isolatie is dan `onbekend` (zie "Gevolg tot dan").

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
Home Control Hub heeft; het meldt zich aan met dat account. Een Node-RED volgens het manifest heeft nog geen
dienstaccount. Home Control Hub meet dan **niets**: de isolatie heet `onbekend` met de fout `geen_aanmelding`, de
lijst met controles is leeg (ook `anoniem_geweigerd` wordt niet gemeten), en het uitlezen van flows en het maken van
een momentopname geven `node_red_niet_ingesteld` met de reden `geen_aanmelding`. Dat is verwacht tot de voorziening
van besluit C-12 er is. De melding bij `geen_aanmelding` zegt "maak eerst het beveiligingsprofiel": doe dat **niet**
(het profiel is geen installatiestap, zie hierboven).

## Wat je in Home Control Hub instelt

**Bron (nog niet beschikbaar).** Het koppelen van Node-RED is voor jou nog niet uit te voeren: het scherm
*Automatisering* in de Hub, waar je het adres van Node-RED invult en de isolatie laat meten, is nog niet gebouwd, en
er is nog geen dienstaccount (besluit C-12). Zodra beide er zijn, vul je daar bij de bron **Node-RED** (`node_red`)
het LAN-adres in (`http://<NAS-adres>:<host-poort>`, de poort uit het manifest) en zet je de bron aan. Een wachtwoord
of sleutel zet je nooit in een formulier. Zonder dienstaccount geeft de meting `onbekend` met `geen_aanmelding` (zie
"Gevolg tot dan").

**Instellingen** (optioneel; omgevingsvariabelen in het formulier van de app **home-control-hub**, zie ook
`deploy/truenas/CUSTOM_APP.md` en `.env.example`). Deze variabelen staan **niet in het manifest** van
home-control-hub (`custom_app.env` is leeg): bij een installatie via de Hub worden ze niet gezet en gelden de
standaardwaarden hieronder. Je zet ze alleen met de hand (**Edit** van de app). Of een update via de Hub zulke met de
hand gezette waarden laat staan, is nog niet vastgesteld (NIET GEVALIDEERD).

| Variabele | Wat | Standaard |
|---|---|---|
| `HCH_NODE_RED_SYNC_INTERVAL_S` | hoe vaak (seconden) de flows uit Node-RED gelezen en gecontroleerd worden; `0` = uit | `60` |
| `HCH_NODE_RED_DATA_DIR` | pad in de container van home-control-hub waar de datamap van Node-RED **alleen-lezen** is gekoppeld; leeg = versies van flows zonder credentials. **Laat leeg** bij een Node-RED volgens het manifest (zie hieronder) | leeg |
| `HCH_NODE_RED_ALLOWED_MODULES` | extra toegestane Node-RED-modules, gescheiden door komma's; een flow met een node uit een andere module wordt geblokkeerd | leeg (alleen de kern `node-red`) |

**Credentials in versies (nog niet beschikbaar met het manifest).** Zonder koppeling van de datamap bewaart Home
Control Hub versies van je flows **zonder** credentials (de momentopname zegt dat eerlijk: `niet_gekoppeld`). De
code kan het door Node-RED versleutelde `flows_cred.json` meenemen als de datamap van Node-RED alleen-lezen is
gekoppeld (`HCH_NODE_RED_DATA_DIR`). Bij een Node-RED volgens het manifest staat in **dezelfde dataset** ook de
sleutel van die credentials (`.config.runtime.json`; het manifest zet geen eigen `credentialSecret`). Een koppeling
van die dataset geeft home-control-hub (ook gebruiker 568) dus leestoegang tot de sleutel én tot het versleutelde
bestand; met beide zijn de credentials te ontsleutelen. Dat de code alleen `flows_cred.json` leest, is geen
afscherming. Daarom: **koppel de dataset van Node-RED niet** aan home-control-hub en laat `HCH_NODE_RED_DATA_DIR`
leeg. Een koppeling zonder de sleutel kan de manifeststandaard nu niet beschrijven; die volgt pas na een besluit
(voorziening van besluit C-12, ontwerp S-P2-510).

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
  manifest. Een momentopname in de Hub vooraf is **nog niet beschikbaar** (het scherm ontbreekt en er is nog geen
  dienstaccount); maak een snapshot van de dataset zoals het manifest beschrijft.
- **Terugdraaien van flows:** **nog niet beschikbaar.** Het komt in de Hub (*Versies* → *Terugzetten*), als voorstel
  dat je goedkeurt; dat scherm is nog niet gebouwd en de Hub kent de actie nog niet.
- **Terugdraaien van de app Node-RED:** zoals het manifest beschrijft (vorige Tag samen met de snapshot van de
  dataset van vóór de update).

## Problemen

| Melding | Oplossing |
|---|---|
| Hub: *Node-RED is nog niet als bron ingesteld* (`node_red_niet_ingesteld`) | Kijk naar de reden. Ontbreekt het adres of staat de bron uit: vul het adres in en zet de bron aan (zodra het scherm er is). Reden `geen_aanmelding`: zie de volgende rij. |
| Isolatie `onbekend` met `geen_aanmelding` (*Er zijn geen aanmeldgegevens voor Node-RED opgeslagen*) | Verwacht bij een Node-RED volgens het manifest, tot de voorziening van besluit C-12 er is (er is nog geen dienstaccount). Maak **niet** het beveiligingsprofiel en zet geen wachtwoord in een formulier. |
| Hub: `niet_beveiligd` | Node-RED vraagt geen aanmelding. Controleer of de app volgens het manifest is geïnstalleerd; stop Node-RED tot dat zo is. |
| Hub: *Node-RED is niet bereikbaar* (`node_red_unavailable`) | App gestopt, verkeerde poort of verkeerd adres. De Hub probeert het zelf opnieuw. |
| Isolatie: afwijking bij `anoniem_geweigerd` | Alleen te zien zodra er een dienstaccount is. Verwacht tot het manifest besluit C-11 volgt (na S-P2-410); zie "Anonieme toegang". |
| Flow staat op *geblokkeerd* | De flow bevat een verboden node, een onbekend type of een module die niet is toegestaan. Haal die weg; hervat de flow daarna zelf. |
| Herstel: `credentials_niet_te_ontsleutelen` | De sleutel waarmee Node-RED de credentials versleutelt is een andere dan toen de momentopname werd gemaakt. Er is niets gewijzigd. |
