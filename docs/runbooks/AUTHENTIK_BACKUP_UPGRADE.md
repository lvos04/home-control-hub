# Authentik: back-up, upgrade en herstelcontrole (B13-005)

> **Verificatiestatus: NIET GEVALIDEERD (echte NAS/account).** Deze stappen zijn met een nep-Authentik getest
> (Sim-getest). Geen terminal nodig; alles via de Hub-UI en de TrueNAS-web-UI.

Authentik wordt geïnstalleerd als **officiële TrueNAS-catalogusapp** (`authentik`, trein *community*). Laat de optie
**Mount Docker Socket uit**. De echte back-up van Authentik is de **database** (in de datasets van die app); maak die
via de back-up/snapshotfunctie van het platform. Home Control Hub maakt daarnaast een geschoonde *configuratie-export*
om na een herstel of upgrade te controleren of rechten, 2FA en clients weer kloppen.

## Vóór een upgrade
1. **Hub → SSO → Authentik → Detecteren**: controleer de versie en dat het token geen superuser is en geen
   schrijvende systeemrechten heeft. De uitkomst is hooguit `deels_gecontroleerd`: kijk in Authentik zelf na dat
   de rollen van het serviceaccount alleen `view`-rechten geven.
2. **Configuratie-export maken**: moet *volledig* zijn (geen ontbrekende onderdelen).
3. **Back-up van de Authentik-database** maken via het platform (de Hub bevestigt het checkpoint).
4. **Pre-upgrade-gate** met de exacte doelversie (bv. de volgende release-lijn). Alleen doorgaan bij `ok_lokaal`
   én akkoord van de Hub. Regels uit de officiële docs: **geen downgrade**, **geen release-lijn overslaan**, eerst de
   nieuwste patch van je huidige lijn. Externe outposts moeten tegelijk mee.

## Een export hoort bij één koppeling
Elke export legt een willekeurige *koppelrevisie* van de bron vast. Die revisie wordt nieuw bij elke wijziging van de
Authentik-bron in de Hub (opslaan van de bron, ander of verwijderd adres, nieuw token) en keert nooit terug. Gevolgen:

- De gate en de herstelcontrole gebruiken alleen een export van de **huidige** koppeling. Een export van vóór zo'n
  wijziging blijft **leesbaar** (lijst en detail), maar geldt niet als bewijs: de gate geeft dan `fout` zonder
  export-ID en de herstelcontrole geeft `onbekend`.
- Exports van vóór deze functie hebben geen revisie. Ze blijven ook leesbaar en tellen op dezelfde manier niet als
  bewijs.
- `onbekend` bij de herstelcontrole met de deelcontrole *herkomst* betekent: deze export hoort niet aantoonbaar bij
  de huidige koppeling. Er is dan niets vergeleken en niets bevestigd; dit is geen afwijking en geen alarm.
- Maak daarom **vóór elke Authentik-wijziging die je wilt beoordelen** (upgrade, herstel, verhuizing, nieuw token of
  adres) een verse export, nadat de bron in de Hub goed staat. Een export die je pas ná de wijziging maakt, kan de
  toestand van vóór de wijziging niet bevestigen.
- Stel de bron daarna niet opnieuw in (ook niet met hetzelfde token): dat maakt de export onbruikbaar als bewijs en
  vraagt een nieuwe.

## Upgraden
In de TrueNAS-web-UI: **Apps** → `authentik` → **Update** naar de versie uit de gate. Let op: catalogustreinen
bieden vaak alleen de nieuwste versie aan; staat jouw doelversie er niet, upgrade dan niet "door" naar een verdere
versie zonder nieuwe gate.

## Na de upgrade of na een herstel
1. **Herstelcontrole** tegen de export van vóór de upgrade: providers, applicaties, groepen + leden, superusers,
   sleutels, flows en de 2FA-apparaten van beheerders.
2. Bij **afwijking**: niet verder gaan. Herstel de database/snapshot van vóór de upgrade (downgraden van Authentik
   kan niet). Overweeg daarna het voorstel **Sessies intrekken** (iedereen opnieuw inloggen).
3. Werkt Authentik helemaal niet: gebruik de **noodtoegang** (lokaal noodaccount via LAN/VPN, zie
   `NOODTOEGANG.md`); de Hub en deze dienst blijven bruikbaar zonder Authentik.
