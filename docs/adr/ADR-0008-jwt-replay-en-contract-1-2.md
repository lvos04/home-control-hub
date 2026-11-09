# ADR-0008 — JWT-replaybescherming en verenigbaarheid met de (nog niet vastgestelde) contract 1.2-punten

Status: aanvaard, **bijgewerkt naar contract 1.2** (ADR-0010) · Datum: 2026-11-09 · Fase: P1

> **Contract 1.2 (vastgesteld):** §4.6 maakt de keuze hieronder contract: `jti` op **elke** Hub-JWT verplicht
> (`jti_missing`), een persistente replaycache op `(iss, jti)` (migratie `0003`) voor elke mutatie van gebruikers- én
> dienst-JWT's (`token_replayed`), exacte herhaling (zelfde `jti`, methode, pad en `Idempotency-Key`) toegestaan,
> fail-closed met 503 `replay_check_unavailable`. De Nederlandse `reason`-waarden (`token_hergebruikt`,
> `jti_ontbreekt`) zijn vervangen door de vaste Engelse lijst van §4.7. De throttle van de statuspagina is nu per
> bron-IP (5/15 min) plus 20/15 min voor de dienst (§3.7), en de JWKS-pinning is gebouwd (§4.5). De open punten
> hieronder zijn daarmee gesloten.

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
   nieuwe `jti`). Gemeld als contract_issue — **gesloten**: contract 1.2 §4.6 ("De Hub haalt dus per mutatie een
   nieuwe JWT").
2. Overige 1.2-punten: `HUB_ENROLLMENT_TOKEN` wordt al gelezen (met `ENROLLMENT_TOKEN` als terugval); verzoeken
   > 1 MiB → 413 vóór auth (ADR-0006); koppelen via de statuspagina kan alleen als de dienst niet gekoppeld is, met
   CSRF en throttle (ADR-0002; de throttle was per dienst, niet per bron-IP — **gesloten**: nu per bron-IP volgens
   §3.7); noodlogin hoort in de Hub (B13-001 levert hier het register en `break-glass/evaluate`; §4.1). JWKS-pinning
   bij enrollment was niet gebouwd — **gesloten**: nu gepind met ondertekende sleutelrotatie (§4.5, ADR-0010).

## Gevolgen
- Tests minten per mutatie een nieuwe JWT (`TokenHeaders` in de fixtures), zoals de Hub dat hoort te doen; aparte
  tests bewijzen weigering bij hergebruik, toegestane retry en weigering zonder `jti`.
