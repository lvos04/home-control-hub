# Delta-matrix home-control-hub (P0, 2026-11-09)

Nieuwe repo: vóór P0 bestond alleen documentatie. *Bestaand* = al aanwezig vóór deze fase; *P0 gebouwd* = in deze
fase gebouwd en met simulators getest; *ontbrekend* = nog te bouwen. Geen enkele regel is op een echte NAS gevalideerd.

| Onderdeel | Bestaand | P0 gebouwd | Ontbrekend |
|---|---|---|---|
| Kern: auth §4, enrollment §3, foutformaat, idempotency, healthz/readyz, connector §6, outbox §7 | — | ja | Hub-zijde (enroll-endpoint, inbox) in `ai-server-manager` |
| Alles-in-één image + Custom App-instructie + manifest + CI/release | — | ja | echte installatie op TrueNAS; GHCR-release met digest |
| B13-001 accountrecovery en admin-toegang | — | register, noodtoegang LAN/VPN, zelftest met Authentik offline, oefeningen, activaties, herstelkit | noodlogin in de Hub; schermen in de Hub-UI; echte oefening op de NAS |
| B13-002 OIDC Hub | — | alleen JWT-validatie van Hub-tokens (iss/aud/tijden, fail-closed) | OIDC-login in de Hub (ai-server-manager), replay-bescherming |
| B13-003 SSO-mapping per app | — | dekkingsmatrix-structuur (alles *te verifiëren*); deze dienst negeert X-Forwarded-User e.d. (getest) | capability-onderzoek per app (F2) |
| B13-004/005 | — | — | alles |
| B10-001 netwerktopologie | — | inventaris + datamodel (geen malware zonder bewijs) | NetAlertX-adapter, LAN-gegevens (D03) |
| B10-002…006 | — | alleen schema | alles |
| B11-001 flow-netwerkisolatie | — | inventaris, verbodslijst exec-node (te verifiëren), datamodel | Node-RED-installatie (I10), isolatie, editor-auth |
| B11-002…005 | — | alleen schema | alles |
| B14-001 dekkingsmatrix | — | structuur met status *onbekend*, kwaliteitslabels, DB-invarianten | D14, readback my_house |
| B14-002…005 | — | alleen schema | alles |

Review P0 (2026-11-09): aanscherpingen in ADR-0006; geen nieuwe functionaliteit, wel fail-closed gedrag en tests.
