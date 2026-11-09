# TrueNAS Home Platform — uitvoeringspakket v2

**Peildatum: 9 november 2026.** Dit pakket vervangt het eerdere, te summiere plan. Het bevat fasegewijze technische specificaties en praktische installatie-/acceptatieplannen. De documenten zijn uitvoeringsspecificaties: **er is niets op je TrueNAS geïnstalleerd of getest door het maken van dit pakket**.

## Jouw vaste keuzes

- Productie draait **uitsluitend op TrueNAS SCALE op de i7-14700 (>64 GB RAM), Intel Arc A310 en UHD 770**. De mini-pc is *uitgesloten*: die blijft voor de videoapp/andere projecten, ook geen nieuwe thuisserveragents daarop.
- Één web/PWA-interface op telefoon/tablet/pc en optioneel eigen mobiele client; zelfstandig draaiende apps met één centrale beheerlaag, geen gedwongen samenvoeging van databases.
- De bestaande **MediaGuard Ultimate**, **Media Source Optimizer** en **my_house** blijven zelfstandige applicaties. MediaGuard blijft eigenaar van bibliotheek, selectie, import en AV1; MSO eigenaar van bron-, provider- en torrentoptimalisatie; my_house van woning/apparaatregelingen.
- AI mag binnen risicoklassen automatisch veilig beheer verrichten; destructieve, externe en kritieke systeem-/netwerkveranderingen hebben expliciete goedkeuring nodig. Geen allesomvattende root-token of onbeperkte shelltoegang.
- **Geen nieuwe betaalde abonnementen of API-kosten**. Claude Max kan inbegrepen Claude Platform API-credits beschikbaar stellen, maar controleer de actuele voorwaarden, koppel het juiste account en gebruik 'hard stop' zodra inbegrepen credits op zijn. ChatGPT Plus is geen vrij inzetbare OpenAI API.
- Fotos en appdatabases hebben al een off-site kopie bij OneDrive; geen bewijs dat álle datasets en configuraties herstelbaar zijn. Verificatie en proefherstel zijn verplichte eerste stap; ZFS-snapshots vullen OneDrive aan.

## Begin hier

1. Lees `01_ARCHITECTUUR/01_PROJECTCHARTER.md`, `02_DATA_EIGENAARSCHAP.md`, `03_RISICO_AUTONOMIE.md`.
2. Open `08_EXCEL/TrueNAS_V2_Uitvoering_en_Afvinken.xlsx` → tab **Besluiten**, **Preflight** en **Fasen**. Bij onbekende zaken: `Blokkade` totdat ze gemeten zijn.
3. Bouw de **Back-up & Restore** en **Monitoring** basis eerst. Pas daarna de **Home Control Hub**, AI-agents en uiteindelijk de mediaserverfork.
4. Voor iedere bestaande app: maak een release-/functie-inventaris, vergelijk met de GitHub HEAD en behandel nieuwe wensen als een delta; nooit blind over bestaande code heen schrijven.
5. Gebruik de applicatiespecifieke documenten `02_BOUWPLANNEN/Bxx_...` bij Claude Code/Codex, de `03_INSTALLATIE/Ixx_...` bij TrueNAS-deployment en de `05_TESTS` bij productieacceptatie.

## Belangrijke begrenzingen

- TrueNAS-versie, poolnaam, NAS-IP, routermodel, schijf-/VDEV-opzet, totale opslag, ZFS-datasets en huidige image-tags zijn niet bekend: **geen voorbeeldwaarden als echte waarden inzetten**.
- Bestaande installs en repositorytoestand zijn niet noodzakelijk gelijk: versie/release op GitHub ≠ bewezen draaiende versie op je NAS.
- Een oudere image-tag terugzetten na een database-migratie is **niet** vanzelf een veilige rollback; herstel ook de passende configuratie en database uit een getest herstelpunt.
- Geen `latest`-tags, geen publiek toegankelijk TrueNAS-beheer, geen Docker-socket in webcontainers, geen standaard rootrechten. Privilege scheiding via een kleine executor met strikt gecontroleerde acties.
- Een lokale snapshot op dezelfde pool is niet voldoende tegen poolverlies of ransomware; behoud OneDrive en zet belangrijke configs ook extern.

## Wat je ontvangt

- Architectuur, eigenaarschap, rollen, security, datamodel, eventcontracten en uitrol-/rollbackstrategie.
- Faseplannen voor centrale beheerapp, AI, mediaserver, MediaGuard, MSO, my_house, zoekmachine, automatisering, appstore, netwerk, monitoring, back-ups en SSO.
- Per bestaande/nieuwe app een installatie-, migratie-, test- en terugvaldocument.
- Excel met gekoppelde fasen, uitvoerbare subtaken, acceptatie, risico, prioriteit, afhankelijkheden, statussen, links en een dashboard.

**Status:** voorbereid/gespecificeerd. Uitvoering, live tests en architectuurkeuzes zijn zichtbaar en nog af te vinken in Excel.
