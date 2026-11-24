# Authentik: back-up, upgrade en herstelcontrole (B13-005)

> **Verificatiestatus: NIET GEVALIDEERD (echte NAS/account).** De simulatorproeven dekken detectie,
> configuratie-export, de controle op een door de Hub bevestigd back-upcheckpoint, de geblokkeerde upgradegate
> en de herstelcontrole. De Authentik-upgrade, het databaseherstel en de stappen in de Hub-UI en TrueNAS-web-UI
> moeten nog in de praktijk worden beproefd.

Authentik wordt geïnstalleerd als **officiële TrueNAS-catalogusapp** (`authentik`, trein *community*). Laat de optie
**Mount Docker Socket uit**. De echte back-up van Authentik is de **database** (in de datasets van die app); maak die
via de back-up/snapshotfunctie van het platform. Home Control Hub maakt daarnaast een geschoonde *configuratie-export*
om na een herstel of upgrade te controleren of rechten, 2FA en clients weer kloppen.

## Vóór een upgrade
1. **Hub → SSO → Authentik → Detecteren**: controleer de versie en dat het token geen superuser is en geen
   schrijvende systeemrechten heeft. De uitkomst is hooguit `deels_gecontroleerd`: kijk in Authentik zelf na dat
   de rollen van het serviceaccount alleen `view`-rechten geven.
2. **Configuratie-export maken**: moet *volledig* zijn (geen ontbrekende onderdelen).
3. **Back-up van de Authentik-database** maken via het platform. De gate accepteert alleen een door de Hub
   bevestigd back-upcheckpoint.
4. **Pre-upgrade-gate** met de exacte stabiele doelversie. Deze versie geeft geen upgrade vrij.
   Zolang de catalogusinterop met de Hub ontbreekt, blijft `catalogusversie` op `onbekend`. Daardoor blokkeert de
   gate de upgrade ook bij een volledige, verse export, een bevestigd back-upcheckpoint en een geldige
   registratie voor noodtoegang. De regels voor het upgradepad blijven gelden: **geen downgrade**,
   **geen release-lijn overslaan**, eerst de nieuwste patch van je huidige lijn. Externe outposts moeten tegelijk mee.

## Een export hoort bij één koppeling
Elke export legt een willekeurige *koppelrevisie* van de bron vast. Die revisie wordt nieuw bij elke wijziging van de
Authentik-bron in de Hub (opslaan van de bron, ander of verwijderd adres, nieuw token) en keert nooit terug. Gevolgen:

- De gate en de herstelcontrole gebruiken alleen een export van de **huidige** koppeling. Een export van vóór zo'n
  wijziging blijft leesbaar zolang die bewaard is (lijst en detail). Met alleen zo'n export geeft de gate `fout`
  zonder export-ID en de herstelcontrole geeft `onbekend`.
- Exports van vóór deze functie hebben geen revisie. Ook deze exports zijn leesbaar zolang ze bewaard zijn en vallen
  buiten de herstelbasis.
- `onbekend` bij de herstelcontrole met de deelcontrole *herkomst* betekent: deze export hoort niet aantoonbaar bij
  de huidige koppeling. Er is dan niets vergeleken en niets bevestigd; dit is geen afwijking en geen alarm.
- Maak daarom **vóór elke Authentik-wijziging die je wilt beoordelen** (upgrade, herstel, verhuizing, nieuw token of
  adres) een verse export, nadat de bron in de Hub goed staat. Een export die je pas ná de wijziging maakt, kan de
  toestand van vóór de wijziging niet bevestigen.
- Stel de bron daarna niet opnieuw in (ook niet met hetzelfde token): dat maakt de export onbruikbaar als bewijs en
  vraagt een nieuwe.
- Periodiek onderhoud bewaart de nieuwste 30 exports over alle koppelrevisies samen, ook die zonder revisie.
  Alleen de huidige koppeling krijgt extra bescherming: de laatste bruikbare export per Authentik-versie
  blijft ook buiten die 30 bewaard. Voor exports van vervallen revisies geldt geen vaste bewaartijd.
  Vervolgpunt: bepalen of de gezamenlijke aantalsgrens volstaat voor het terugzoeken van vervallen revisies.
- Een herhaalde exportaanvraag met dezelfde idempotentiesleutel geeft tijdens de bewaartermijn van die sleutel
  het oorspronkelijke antwoord. De detailroute toont of de export nu nog beschikbaar is en geeft na opruiming 404.

Bij een terugmigratie van de Hub-database over revisie `0008` archiveert `integrations migrate --down` de koppelrevisies
vóór de schemawijziging. De dump en de bijbehorende SHA-256 staan in de map van `--backup-dir` of in de map
`backups` onder de datamap. Mislukt de back-up, dan stopt de terugmigratie. Herstel de geverifieerde dump op
revisie `0008` om dezelfde koppelrevisie en herstelbasis terug te krijgen. Opnieuw upgraden maakt nieuwe koppelrevisies.

## Upgraden
Wacht met **Update** in de TrueNAS-web-UI totdat de catalogusinterop is getoetst en de gate de exacte doelversie
vrijgeeft. Catalogustreinen bieden vaak alleen de nieuwste versie aan. Beoordeel een andere doelversie opnieuw
met de gate.

## Na de upgrade of na een herstel
1. **Herstelcontrole** tegen de export van vóór de upgrade: providers, applicaties, groepen + leden, superusers,
   sleutels, flows en de 2FA-apparaten van beheerders. Een betrouwbaar vastgestelde providerafwijking blijft
   zichtbaar met een herstelalarm als andere providergegevens onvolledig zijn.
2. Bij **afwijking**: niet verder gaan. Herstel de database/snapshot van vóór de upgrade (downgraden van Authentik
   kan niet). **Sessies intrekken** levert in versie 1 een voorstel. De intrekking bij Authentik volgt in versie 2.
3. In het scenario van OIDC-overdracht en -rotatie is het lokale noodaccount van de Hub bij uitval van Authentik
   bedoeld voor toegang **uitsluitend via LAN**; dit pad verruimt de bestaande netwerkinstellingen niet.
   De simulator toetst de registratie en de voorwaarden voor noodtoegang. De gevulde migratieproef controleert
   het behoud van die registratie. De feitelijke noodlogin en de bronadrescontrole op de NAS moeten nog worden
   beproefd. De afstemming van de netwerkinstellingen ligt bij de eigenaar van de noodlogin (ADR-0033 O3).
