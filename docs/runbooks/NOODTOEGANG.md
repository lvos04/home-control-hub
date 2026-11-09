# Noodtoegang en beheerherstel (B13-001) — handleiding

> Status: **NIET GEVALIDEERD (echte NAS/account).** De regels en de zelftest zijn met simulators getest; de echte
> noodlogin zit in de Hub en moet daar nog gebouwd en op de NAS geoefend worden.

## Waarom
Als Authentik (SSO) stuk is, mag je niet buitengesloten raken. Daarom heeft elk belangrijk beheeraccount minstens
**twee herstelmethodes**, waarvan minstens één **zonder SSO** werkt, en is er een **noodaccount** dat alleen vanaf je
thuisnetwerk (LAN) of de VPN mag inloggen.

## Eenmalig inrichten (in de Hub, scherm *Toegang → Herstel*)
1. Registreer je beheeraccounts: het lokale Hub-account, de Authentik-beheerder en de TrueNAS-beheerder. Je vult
   **nooit** een wachtwoord of code in — alleen de naam en het soort login.
2. Markeer één lokaal Hub-account als **noodaccount** (inloggen *lokaal*, nooit alleen SSO).
3. Voeg per account minstens twee herstelmethodes toe, bv. *lokaal wachtwoord via LAN* (bewaard in je
   wachtwoordmanager) en *verzegelde envelop* (in de kluis). Je kiest alleen wáár het staat.
4. Stel de **noodtoegang** in: de netwerkbereiken van je LAN en/of VPN (CIDR, bv. het bereik dat je router uitgeeft;
   gebruik je eigen waarden). Internetadressen worden geweigerd. Kies hoe lang een noodsessie mag duren (5–240 min).
5. Bevestig de MFA-status van elk account (alleen een vinkje + methode; geen codes).
6. Maak een **herstelkit**: kies een lange wachtwoordzin (min. 16 tekens). Bewaar het bestand offline (USB-stick in de
   kluis) en de wachtwoordzin apart. De kit bevat geen wachtwoorden, codes of sleutels; controleer hem met *Kit
   controleren*.

## Oefenen (minstens elke 90 dagen)
1. **Zelftest** (knop in de Hub): controleert de inrichting en het beleid. Dit werkt ook als Authentik uit staat — dat
   is juist de bedoeling. De zelftest is géén echte login.
2. **Echte oefening:** zet Authentik even uit (of doe alsof), log vanaf het LAN of de VPN in op de Hub met het
   noodaccount, en registreer daarna *handmatige oefening: gelukt*. Pas dan staat de herstelstatus op *ok*.

## In nood
Volg de stappen uit je herstelkit (ook hieronder):
1. Zorg dat je op het LAN of via de VPN verbonden bent.
2. Log in op de Hub met het lokale noodaccount (niet via SSO).
3. Gebruik de herstelmethode van de plek die in de kit staat.
4. Na echt gebruik: wijzig het wachtwoord van het noodaccount en registreer *rotatie bevestigd*.
5. Is de Hub zelf onbereikbaar: TrueNAS-web-UI → Apps → app → Logs, of de TrueNAS-console lokaal.

## Status lezen
- **ok** — alles op orde. **risico** — er ontbreekt iets (de reden staat erbij, bv. *minder dan twee
  herstelmethodes*). **onbekend** — nog niets geregistreerd of MFA niet bevestigd. Onbekend is nooit groen.
