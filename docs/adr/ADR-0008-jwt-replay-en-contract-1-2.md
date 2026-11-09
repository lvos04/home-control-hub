# ADR-0008 — JWT-replaybescherming en verenigbaarheid met de (nog niet vastgestelde) contract 1.2-punten

Status: aanvaard · Datum: 2026-11-09 · Fase: P1

## Context
B13-002 eist "Wrong issuer/aud/replay rejected". Issuer/audience werden al geweigerd (ADR-0002); replay niet: een
Hub-JWT (max. 120 s) kon voor meerdere wijzigingen gebruikt worden. Contract 1.2 (nog niet vastgesteld, zie
`ai-server-manager/docs/platform-v2/OVERDRACHT/STATUS.md`) noemt o.a. "JWT-replay (jti + korte cache)",
`HUB_ENROLLMENT_TOKEN`, max. 1 MiB → 413, JWKS-pinning bij enrollment, koppelen via de statuspagina alleen vóór de
eerste koppeling met rate-limit, en noodlogin in de Hub.

## Besluit
1. **Eén JWT per wijziging.** Een mutatie (POST/PUT/PATCH/DELETE met geldige `Idempotency-Key`) legt de `jti` vast
   (`jwt_jti_use`, PostgreSQL, gedeeld door alle processen, vervalt na `exp` + speling). Hergebruik voor een andere
   wijziging → `401 unauthorized` (`token_hergebruikt`). Dezelfde wijziging opnieuw (zelfde token, methode, pad en
   `Idempotency-Key`) blijft mogen: de idempotency-laag geeft het opgeslagen resultaat (netwerk-retry). Een JWT
   zonder `jti` mag geen wijziging doen (`jti_ontbreekt`). Lezen (GET) mag binnen de levensduur vaker. Database weg
   → `503 replay_check_unavailable` (fail-closed).
   *Gevolg voor de Hub:* per wijziging een nieuwe JWT halen (`POST /api/v1/auth/service-jwt` doet dat al met een
   nieuwe `jti`). Gemeld als contract_issue.
2. Overige 1.2-punten: `HUB_ENROLLMENT_TOKEN` wordt al gelezen (met `ENROLLMENT_TOKEN` als terugval); verzoeken
   > 1 MiB → 413 vóór auth (ADR-0006); koppelen via de statuspagina kan alleen als de dienst niet gekoppeld is, met
   CSRF en throttle (ADR-0002; de throttle is per dienst, niet per bron-IP — afwijking gemeld); noodlogin hoort in
   de Hub (B13-001 levert hier het register en `break-glass/evaluate`). **JWKS-pinning bij enrollment is niet
   gebouwd**: de enroll-JWKS wordt nu gebruikt als startwaarde, latere verversing gaat via HTTP (afwijking gemeld;
   vraagt een door de Hub ondertekende sleutelrotatie, buiten B13-P1).

## Gevolgen
- Tests minten per mutatie een nieuwe JWT (`TokenHeaders` in de fixtures), zoals de Hub dat hoort te doen; aparte
  tests bewijzen weigering bij hergebruik, toegestane retry en weigering zonder `jti`.
