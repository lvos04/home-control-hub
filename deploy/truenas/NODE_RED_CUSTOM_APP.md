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

Het manifest van `jelly-leon-platform` volgt dit sinds stap S-P2-410: `adminAuth` in `FLOWS` zonder anonieme
rechten, dus ook geen anoniem lezen. Het manifest heeft zelf een controle na installatie `anoniem_geweigerd` met
dezelfde paden (elk `401`). Home Control Hub meet `anoniem_geweigerd` alleen als het zich bij Node-RED kan aanmelden,
dus pas **zodra er een dienstaccount is** (besluit C-12, hieronder). Geeft een Node-RED dan anoniem toch flows, nodes
of instellingen terug, dan geeft `anoniem_geweigerd` een **afwijking**; dat wordt niet weggewerkt door de controle af
te zwakken. Tot er een dienstaccount is, wordt `anoniem_geweigerd` niet gemeten: de isolatie is dan `onbekend` (zie
"Gevolg tot dan").

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
lijst met controles is leeg (ook `anoniem_geweigerd` wordt niet gemeten), het uitlezen van flows legt de reden
`geen_aanmelding` vast in de synchronisatietoestand, en het maken van een momentopname of een herstelvoorstel geeft
`node_red_niet_ingesteld` met de reden `geen_aanmelding`. Het adres van de editor, de lijst met flows en de stand van
de isolatie blijven gewoon zichtbaar. Dat is verwacht tot de voorziening
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
| `HCH_NODE_RED_DATA_DIR` | pad in de container van home-control-hub waar de datamap van Node-RED **alleen-lezen** is gekoppeld; leeg = versies van flows zonder credentials. Een beschrijfbare koppeling telt niet: de status blijft `niet_gekoppeld` (de synchronisatie noemt dan de reden `niet_alleen_lezen`). **Laat leeg** bij een Node-RED volgens het manifest (zie hieronder) | leeg |
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
| Hub: `niet_beveiligd` | Node-RED vraagt geen aanmelding. Controleer of de app volgens het manifest is geïnstalleerd; stop Node-RED tot dat zo is. Zolang zijn alle flows geblokkeerd met reden `synchronisatie_mislukt` (zie de rij daarover). |
| Hub: *Node-RED is niet bereikbaar* (`node_red_unavailable`) | App gestopt, verkeerde poort of verkeerd adres. De Hub probeert het zelf opnieuw. |
| Isolatie: afwijking bij `anoniem_geweigerd` | Alleen te zien zodra er een dienstaccount is. Het manifest heeft sinds stap S-P2-410 geen anoniem lezen meer (besluit C-11): controleer of Node-RED volgens het huidige manifest is geïnstalleerd; zie "Anonieme toegang". |
| Flow staat op *geblokkeerd* | Ergens in de configuratie van Node-RED staat een verboden node, een onbekend type, een module die niet is toegestaan, of iets wat deze app niet kan plaatsen (een vormfout, ook een id langer dan 120 tekens of een NUL of een ongeldig teken in een naam of label, een dubbele id, een node buiten elk tabblad, een draad of link naar een node die niet bestaat). Dan zijn **alle** flows geblokkeerd (besluit "grof blokkeren"); een flow zonder eigen fout heeft de reden `bron_geblokkeerd`, en zijn bevindingen noemen de oorzaak en waar die staat. Haal dat weg; hervat de flows daarna zelf. |
| Alle flows staan op *geblokkeerd* met reden `synchronisatie_mislukt` | Deze app kon de configuratie van Node-RED niet verwerken (de synchronisatie liep vast). Uit voorzorg zijn alle flows geblokkeerd en staat de check `automatisering` op *degraded*. Zoek in de editor van Node-RED wat er laatst is gewijzigd en haal dat weg. Slaagt een synchronisatie weer, dan staan de flows gepauzeerd; hervat ze daarna zelf. Dat gebeurt ook als Node-RED een antwoord geeft dat deze app niet kan gebruiken: te groot of ongeldig, geen aanmelding (`niet_beveiligd`), een geweigerde aanmelding of ontbrekende rechten van het dienstaccount, een onbekend pad of een doorverwijzing (de meting van de bron noemt de oorzaak). Antwoordt Node-RED niet (niet bereikbaar, time-out) of met een serverfout, dan blijft de stand van de flows nog staan; zie de rij *Node-RED is niet bereikbaar*. |
| Herstel: `credentials_niet_te_ontsleutelen` | De sleutel waarmee Node-RED de credentials versleutelt is een andere dan toen de momentopname werd gemaakt. Er is niets gewijzigd. |
