# ADR-0003 — B13-001: noodtoegang en herstelregister zonder geheimen

Status: aanvaard · Datum: 2026-11-09 · Fase: P0 · Taak: B13-001

## Context
B13-001 vraagt: twee beheerherstelmethodes, versleuteld herstelmateriaal exporteren, geen SSO-only lock-out; een
lokaal noodaccount alleen via LAN/VPN, met verloop, audit en MFA. Acceptatie: *Authenticator offline → break glass in
de Hub blijft testbaar*. De gebruikersaccounts (en dus de echte noodlogin) zijn van de Hub (contract §4); Authentik is
nog niet geïnstalleerd (D17 onbekend). Er mogen geen geheimen worden opgeslagen.

## Besluit
1. **Herstelregister zonder geheimen:** beheeraccounts (systeem, gebruikersnaam, noodaccount ja/nee, login lokaal/SSO/
   beide), herstelmethodes (type uit een vaste lijst + waar het materiaal ligt, ook uit een vaste lijst), MFA-status
   als **attestatie**. Nooit wachtwoorden, herstelcodes, TOTP-seeds of sleutels — ook niet gehasht. Vrije tekst wordt
   geweigerd als die op een token/sleutel lijkt; extra velden (zoals `password`) worden geweigerd.
2. **SSO-onafhankelijkheid is afgeleid**, niet instelbaar (alleen `authentik_herstelsleutel` hangt van Authentik af).
   Een noodaccount kan in de database niet SSO-only zijn (CHECK-constraint).
3. **Noodtoegang:** alleen privé-bereiken (RFC 1918, 100.64/10 voor Tailscale, ULA fc00::/7); nooit internet.
   **Verloop** = elke activatie verloopt na `session_max_minutes` (5–240) en de registratie moet periodiek worden
   herbevestigd (`review_interval_days`). De noodtoegang zelf verloopt **niet**: dat zou precies bij nood een lock-out
   geven (veiligste interpretatie; gemeld als contract_issue — **gesloten** door contract 1.2 §4.1: "Het noodaccount
   zelf verloopt niet"). Echte activatie → rotatieplicht tot bevestigd.
4. **Beoordeling zonder Authentik:** `POST /sso/break-glass/evaluate` is deterministisch en raadpleegt Authentik nooit.
   De **zelftest** controleert account, lokale login, ≥ 2 methodes (≥ 1 zonder SSO), noodtoegang, en het beleid met een
   testadres binnen het bereik én een documentatie-adres (RFC 5737) buiten het bereik. Authentik wordt alleen ter
   informatie gepeild (online/offline/niet geconfigureerd) en kan de uitkomst niet beïnvloeden.
5. **Handmatige oefening** (na een echte login in de Hub) is een attestatie van een beheerder; de herstelstatus is pas
   `ok` met een geslaagde handmatige oefening ≤ 90 dagen.
6. **Herstelkit:** register + Nederlandse noodprocedure, versleuteld met scrypt + AES-256-GCM onder een wachtwoordzin
   die nooit wordt opgeslagen of gelogd (de Idempotency-hash is een HMAC met een vault-afgeleide sleutel). **Geen
   sleutels in de kit**: key-export is R3 en wordt niet aangeboden. `verify` controleert of een kit te openen is.
7. **Herstelstatus** `ok|risico|onbekend` (health `healthy|degraded|unknown`); een leeg register is `onbekend`, nooit
   groen. Wijzigingen emitteren `sso.recovery.readiness_changed` zodat de Hub het kan cachen.

## Gevolgen en grenzen
- Deze dienst is **register en adviseur**, geen poortwachter: de lokale noodlogin in de Hub mag niet van deze dienst
  afhangen (anders ontstaat een nieuw single point of failure). Contract 1.2 §4.1 legt dit vast: de noodlogin zit in
  de Hub (H6) en werkt zonder enige aanroep naar deze dienst; de Hub mag het beleid van deze dienst (bereiken,
  sessieduur, gemeld via `sso.recovery.readiness_changed`) alleen cachen om te **verscherpen** (ADR-0010 besluit 18).
- Echte MFA-inrichting en een echte noodlogin zijn hier niet te testen: NIET GEVALIDEERD (echte NAS/account).
