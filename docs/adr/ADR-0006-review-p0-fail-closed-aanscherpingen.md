# ADR-0006 — Aanscherpingen na de onafhankelijke P0-review (fail-closed)

Status: aanvaard · Datum: 2026-11-09 · Fase: P0 (review/QA)

## Context
Een onafhankelijke review van de P0-oplevering (contracten 1.1 §1–§12, veiligheid volgens `03_RISICO_AUTONOMIE`,
eerlijkheid van het bewijs) vond enkele plekken waar de dienst bij een fout of misbruik niet de veiligste kant koos.
Het contract regelt deze details niet; hieronder staat de gekozen, veiligste interpretatie.

## Besluiten
1. **Geen migratie zonder geslaagde back-up vooraf.** Was: mislukt `pg_dump` vóór een openstaande migratie, dan ging
   de migratie toch door. Nu: `python -m integrations migrate --backup-dir …` stopt met code 3 en een Nederlandse
   melding; de database blijft ongewijzigd en de procesbewaker stopt de app met een melding in de app-log. Reden: de
   gate-matrix (`06_FASERING_EN_GATES`) eist een database-export vóór schemawijzigingen; "door bij fout" is open bij
   fout. Een verse database (nog geen schema) heeft geen back-up nodig. Zonder `--backup-dir` (ontwikkeling/CI)
   verandert er niets.
2. **Grens op de verzoekgrootte (1 MiB) vóór de authenticatie.** FastAPI leest en parseert de body vóórdat de
   auth-afhankelijkheden draaien; zonder grens kon iedereen op het LAN grote bodies laten inlezen. Een ASGI-laag
   weigert te grote verzoeken met `413 payload_too_large` (contractfoutformaat), ook bij chunked upload.
3. **Herstelkit van buiten begrensd.** `recovery/kit/verify` accepteerde scrypt-parameters tot ruim 2 GiB geheugen
   per verzoek en gaf bij een ongeldige nonce of een niet-macht-van-2 een 500. Nu: hooguit 128 MiB (`128·n·r`),
   `n` een macht van 2 tussen 2^14 en 2^17, `p ≤ 2`, nonce exact 12 bytes; anders `422 herstelkit_onleesbaar`.
4. **Statuspagina zonder hersteldetails.** De openbare statuspagina toonde het aantal beheeraccounts en de
   aandachtspunten (bv. "geen noodaccount"). Dat is beveiligingsinformatie voor wie niet is ingelogd; de pagina toont
   nu alleen het totaalniveau (ok/risico/onbekend). Details blijven achter de beheerdersrol in de Hub.
5. **Geen instellingen die niets doen.** `HCH_TRUSTED_PROXIES` en `HCH_EMERGENCY_ADMIN_MAX_DAYS` werden gelezen maar
   nergens gebruikt; een gebruiker kon denken dat ze iets regelden. Verwijderd. `X-Forwarded-*`-headers worden nooit
   gebruikt (uvicorn `proxy_headers=False`; B13-003).
6. **Tests vallen in CI nooit stil weg.** Zonder PostgreSQL werden integratie- en E2E-tests overgeslagen; in CI
   (`CI=true`) falen ze nu hard, zodat een groene CI niet kan betekenen dat 120+ tests niet draaiden.

## Gevolgen
- Een update kan nu stoppen als er te weinig ruimte is voor de back-up; dat is bedoeld (liever geen start dan een
  schemawijziging zonder terugweg). De melding noemt vrije ruimte en de vorige image-tag.
- Nieuwe routes worden automatisch gecontroleerd op auth, rollen en Idempotency-Key via de OpenAPI-export
  (`tests/integration/test_review_p0.py`).
