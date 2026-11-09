# ADR-0002 — Authenticatie, JWKS en koppelen met de Hub

Status: aanvaard (met open punten voor de Hub) · Datum: 2026-11-09 · Fase: P0

## Context
Contract §3/§4 beschrijft enrollment (`POST {HUB_URL}/api/v1/services/enroll`), service-tokens, Hub-JWT's en de JWKS
(`GET {HUB_URL}/api/v1/auth/jwks`), maar niet het exacte verzoek-/antwoordformaat, en niet hoe de Hub zich tegenover
een dienst authenticeert. De Hub-implementatie bestond nog niet toen deze dienst werd gebouwd.

## Besluit
1. **Enroll-verzoek (aanname):** `{"app_id","kind":"token"|"koppelcode","secret","version","base_url",
   "public_key_jwk","api_prefix","connector_prefix"}`. **Antwoord (aanname):** `201 {"service_token" (verplicht),
   "service_id"?, "jwks"?, "policy_public_key"?}`. 400/401/403/409/410/422 = definitief geweigerd (het token wordt
   niet opnieuw geprobeerd), 404 = endpoint ontbreekt, 5xx/429/netwerk = later opnieuw (backoff, max. 15 min).
   Past de Hub een ander formaat toe, dan wordt alleen `enrollment.py` aangepast.
2. **Service-token:** wordt versleuteld in de vault bewaard (`vault://hub/service-token`); in de status alleen
   SHA-256 + laatste 4 tekens. Inkomende `Bearer <service-token>` wordt in constante tijd vergeleken met die hash en
   geeft principal `service:hub` met rol `service` (alleen connector-lezen en noodtoegang melden/beoordelen).
   **Interpretatie:** de Hub roept deze dienst aan met het token dat hij zelf uitgaf. Gebruikerscontext gaat altijd
   via een Hub-JWT.
3. **Hub-JWT:** alleen `alg=EdDSA`; `iss=hub`, `aud=home-control-hub`, `exp`, `iat`, `sub` verplicht; `exp-iat ≤ 120 s`;
   30 s klokspeling; onbekende rollen worden genegeerd.
4. **JWKS-cache, fail-closed:** vers 300 s; daarna verversen; lukt dat niet, dan nog hooguit 900 s de oude set;
   daarna wordt elke JWT geweigerd (401 `jwks_niet_beschikbaar`). Onbekende `kid` → hooguit elke 30 s verversen.
   Zonder koppeling: elke authenticatie 401 (`niet_gekoppeld`). Nooit open toegang (EX16).
5. **Koppelcode via de statuspagina:** alleen mogelijk als de dienst niet gekoppeld is; formulier met CSRF
   (double-submit-cookie, SameSite=Strict) + Origin-controle, throttle (10 pogingen / 10 min), vaste meldingen.
   **Ontkoppelen** kan via de Hub (admin-API) of op de statuspagina met een **lokale ontkoppelcode** die bij elke start
   in de app-log staat (alleen zichtbaar voor wie TrueNAS beheert; zelfde patroon als de setupcode van de Hub).
6. Hub-adressen: alleen http(s), geen inloggegevens/query, geen loopback (in de container wijst die naar zichzelf;
   alleen met `HCH_ALLOW_LOOPBACK_HUB` voor ontwikkeling).

## Open punten (gemeld als contract_issue)
- Het enroll-formaat moet door de Hub (`ai-server-manager`) worden bevestigd of aangepast.
- JWKS over gewoon HTTP op het LAN kan worden vervalst door wie het LAN beheerst; het contract eist geen HTTPS of
  sleutel-pinning. Voorstel: HTTPS of een door de policy-sleutel ondertekende JWKS-rotatie.
- Vóór de eerste koppeling kan iemand op het LAN de dienst aan een eigen "Hub" koppelen. Mitigatie: de dienst heeft
  dan nog geen data of rechten, de statuspagina toont het Hub-adres, en herkoppelen vereist de lokale ontkoppelcode.
