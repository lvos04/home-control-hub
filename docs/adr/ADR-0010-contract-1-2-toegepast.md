# ADR-0010 — Platformcontract 1.2 toegepast (koppelen, inkomende auth, image)

Status: aanvaard · Datum: 2026-11-09 · Fase: contract 1.2 (`CONTRACT_1.2_CONFORMITEIT.md` §0 A2, A4–A7 en §2 HC1–HC10)

## Context
`contracts 1.2` (`docs/platform-v2/PLATFORM_CONTRACTEN.md`, byte-gelijk aan `ai-server-manager` bron-commit `8b54f39`)
legt het koppelen met de Hub exact vast (§3.3–§3.8), vervangt het service-token als inkomende Hub-authenticatie door
een dienst-JWT (§4.3), pint de Hub-sleutels (§4.5), maakt `jti` + replaycache verplicht (§4.6), geeft vaste
`reason`-waarden (§4.7), en eist dat **elk** proces van de image — ook PID 1 — als 568 zonder capabilities en met
no-new-privileges draait, ook als het TrueNAS-formulier die niet zet (§2.2). ADR-0002 (koppelen, P0) en ADR-0008
(replay, P1) waren aannames vóór 1.2; hun open punten worden hier gesloten. Waar 1.2 iets open laat, staat hieronder
de gekozen, veiligste interpretatie (gemeld als contract_issue).

## Besluiten

### Koppelen (HC1, HC2, HC6, HC8)
1. **Enroll-verzoek exact §3.3**: `{app_id, enrollment_token | pairing_code, version, base_url, public_key_jwk}` met
   `public_key_jwk` = `{kty, crv, x, kid}` (`kid` = RFC 7638-thumbprint, geen `use`/`alg`); `app_id` is de constante
   `home-control-hub`. Unit-test op de exacte veldenset; de Hub-simulator weigert al het andere met 422.
2. **Antwoord**: alle velden en typen van §3.3, `schema_version` major 1, `service_id` UUID, `svc_`-patroon, elke JWK
   Ed25519 met `use: sig`/`alg: EdDSA` en unieke `kid`, zelf berekende sleutelset-vingerafdruk gelijk aan het antwoord
   **en** aan `HUB_KEY_FINGERPRINT`/de statuspagina. Afwijking → niets opslaan, `last_error` en (env-token) de hash in
   `used_enrollment_token_sha256`.
3. **Foutgedrag**: 401/404/413/422 en ongeldig antwoord definitief; 429 opnieuw na `Retry-After`; 5xx, netwerk en
   3xx (nooit gevolgd) met backoff 5 s…15 min + jitter; stoppen 60 min na `pending.started_at`
   (`token_verlopen_na_60_min`). Alle uitgaande calls (Hub, Authentik, bronprobes) negeren proxy-omgevingsvariabelen.
4. **Opslag** `/appdata/secrets/hub-link.json` volgens §3.5 (0600, atomair via tijdelijk bestand + `fsync` + `rename`
   + `fsync` van de map, `flock` op `hub-link.lock`, opnieuw lezen bij een andere inode/mtime/grootte). Aanvullende
   velden (genegeerd door wie ze niet kent): `token_rotation_requested_at` (een rotatieverzoek overleeft een herstart)
   en `key_rotation_blocked_sequence` (een geweigerde sleutelrotatie blijft zichtbaar). Onleesbaar bestand →
   fail-closed (`not_linked`, geen koppelformulier).
5. **Eigen `last_error`-codes** naast die van §3.5: `hub_incompatibel` (413/422), `token_ongeldig` (env-token niet
   `enr_` + 43), `vingerafdruk_ongeldig` (`HUB_KEY_FINGERPRINT` onleesbaar), `hub_adres_ongeldig` (`HUB_URL` breekt de
   adresregels) en `overzetten_onvolledig`. Bij een onleesbare vingerafdruk of een ongeldig `HUB_URL` wordt de Hub
   **niet** aangesproken en het token niet als afgehandeld gemarkeerd (na herstel van het formulier kan het alsnog).
6. **Eenmalige overzetting** (§3.5): bij de eerste start van 1.2 zetten API en worker (wie eerst is, onder de
   bestandsvergrendeling) de oude koppeling uit `service_state` + vault over naar het bestand (pins met
   `source: overgezet`, `confirmed_at` leeg zodat de worker met `services/self` bevestigt) en verwijderen de oude rijen.
   Onvolledig (bv. geen policy-sleutel of token in het oude formaat) → `ontkoppeld` + `overzetten_onvolledig`. Bestaat
   het bestand al, dan wint het bestand en worden teruggekomen rijen (database-herstel) alleen verwijderd.
7. **Opnieuw koppelen** alleen via de Hub: een env-token waarvan de hash niet in `used_enrollment_token_sha256` staat,
   wordt geprobeerd, ook als de dienst gekoppeld, ontkoppeld of ingetrokken is; mislukt het, dan blijft een bestaande
   koppeling ongewijzigd. `ENROLLMENT_TOKEN` wordt nog één release gelezen, met een waarschuwing in de log.
8. **Bevestigen, intrekken, rotatie**: de worker bevestigt periodiek met `GET /api/v1/services/self`
   (`HCH_HUB_HEARTBEAT_S`, standaard 240 s, zodat een aangevraagde rotatie binnen 5 min gebeurt en een intrekking
   tijdig zichtbaar is). 401 op een aanroep met het service-token → eerst `services/self`; pas bij opnieuw 401
   `ingetrokken`. `Hub-Token-Rotation: required` → `self/rotate`, nieuw token atomair opslaan, bevestigen.
9. **Ontkoppelen**: `POST /connector/v1/hub-link/unlink` (dienst-JWT of gebruiker `admin`, `Idempotency-Key`, lege
   body of `{}`) → `ontkoppeld`, token gewist, pins naar `previous_pins`. `GET /connector/v1/hub-link` (dienst-JWT of
   `viewer`+) geeft de witte lijst + `pinned_kids` + `rotation_sequence`. De oude routes `/integrations/v1/enrollment`
   en `/integrations/v1/enrollment/unpair` zijn verwijderd. `/readyz` toont de witte lijst ter informatie (een
   niet-gekoppelde dienst is wel `ready`).

### Statuspagina (HC5)
10. Koppelformulier alleen zolang `first_linked_at` leeg is **en** er geen koppelpoging loopt; velden Hub-adres
    (zelfde regels als `HUB_URL`), koppelcode en verplichte Hub-vingerafdruk. Geen ontkoppelen, geen lokale
    ontkoppelcode, geen herkoppelen na intrekking. Rate-limit 5 per 15 min per bron-IP (TCP-adres; `X-Forwarded-For`
    nooit) en 20 per 15 min voor de dienst, in het geheugen (de image draait precies één API-proces). **Elke**
    formulierpoging na de CSRF-controle telt mee, ook ongeldige invoer (veiligste lezing van "pogingen").

### Inkomende auth (HC3, HC4)
11. Alleen Hub-JWT's tegen de **gepinde** sleutels (`pins.jwt`); de JWKS wordt niet meer via HTTP opgehaald.
    Controlevolgorde en `reason`-waarden precies §4.7. Niet in de tabel geregeld, gekozen: ontbrekende of
    niet-Bearer-header → `invalid_token`; JWT zonder `kid` → `unknown_key`; een gepinde `kid` met een andere sleutel
    (handtekening klopt niet) → `invalid_token`. Onbekende `kid` → direct 401 en hooguit 1× per 30 s een poll van
    `key-rotations` op de achtergrond; de worker pollt elke ≤ 15 min.
12. `token_use` verplicht: `user` (rollen ⊂ admin/operator/viewer/kind, `kind` wint, `service` → 401) of
    `hub_service` (`sub: hub`, `roles: ["service"]`, `service_id` als UUID gelijk aan de eigen) → principal
    `service:hub`. De rechten van `service` blijven die van ADR-0002/0007: connector lezen, voorstellen maken,
    noodtoegang melden/beoordelen en ontkoppelen; nooit `admin` of beheer van het herstelregister.
13. `jti` verplicht op elke JWT; de replaycache (`jwt_jti_use`, migratie `0003`: primaire sleutel `(iss, jti)`)
    geldt voor **elke** POST/PUT/PATCH/DELETE van gebruikers- én dienst-JWT's, ook zonder `Idempotency-Key` (dan is er
    geen exacte herhaling). Database weg → 503 `replay_check_unavailable`.
14. Sleutelset-vingerafdruk met meer dan één policy-sleutel (alleen tijdens een toekomstige policy-rotatie): de
    thumbprints worden net als bij `jwt` gesorteerd en met komma's verbonden — zelfde keuze als appstore-en-fork; met
    één policy-sleutel exact het contract (testvectoren `MEGG-8GFG-2E4Y-K2RQ`, `CYRC-JS8C-14AN-JR17`).
15. Valt de Hub weg, dan blijven de gepinde sleutels geldig (de dienst is niet strenger dan §4.5 vraagt): een
    storing bij de Hub mag geen lock-out van beheer geven. Wel: storing is nooit een intrekking.

### Image (HC7, A6)
16. `dumb-init` is weg; `supervisor.py` is PID 1, ruimt verweesde zombies op, laat de bounding set vallen, wisselt
    volledig naar 568 en zet `PR_SET_NO_NEW_PRIVS` vóór de eerste `execve`. Lukt dat niet, dan start de app niet.
    De rooktest draait zonder `--security-opt` en `--cap-drop` en controleert voor elk proces `Uid 568` (alle vier),
    `CapEff 0` en `NoNewPrivs 1`, plus zombie-opruiming. Docker voert de `HEALTHCHECK` uit als de gebruiker van de
    image (root, nodig voor de eigenaarschapsstap); `healthcheck.py` wisselt daarom als eerste naar 568 met
    no-new-privileges. De rooktest slaat dat kortlevende proces over en controleert de wissel apart.

### Manifest en documentatie (HC9, HC10)
17. Manifest volgens §9 en de validator van appstore-en-fork (geldig; alleen de verwachte waarschuwing
    `digest_pending_release`). `HUB_*` zijn geen manifestparameters: de Hub geeft ze bij `app.install`/`app.update` mee.
18. B13-001: de noodlogin zit in de Hub (§4.1, H6); deze dienst blijft register en adviseur, en
    `sso.recovery.readiness_changed` blijft de bron voor de Hub-cache (die alleen mag verscherpen).

## Gesloten open punten uit eerdere ADR's
- ADR-0002: enroll-formaat (nu §3.3), JWKS via HTTP (nu gepind, §4.5), koppelen vóór de eerste koppeling (restrisico
  in §3.7; de lokale ontkoppelcode is verwijderd), inkomend service-token (nu dienst-JWT, §4.3).
- ADR-0008: "Hub haalt per wijziging een nieuwe JWT" is nu contract (§4.6); de throttle is nu per bron-IP (§3.7);
  JWKS-pinning is gebouwd (§4.5).
- ADR-0003: "het noodaccount verloopt niet" en "de Hub dwingt zelf af met een gecachte kopie" staan nu in §4.1.

## Gevolgen
- Breaking voor wie de oude routes of het service-token inkomend gebruikte (nog niemand: de Hub belt deze dienst pas
  met dienst-JWT's vanaf 1.2). Een dienst die vóór 1.2 gekoppeld was, wordt na de update overgezet en bevestigd; is
  de oude koppeling onvolledig (geen policy-sleutel, token in het oude formaat) dan wordt hij `ontkoppeld`, en kent
  de Hub het token niet meer dan `ingetrokken`. In beide gevallen: opnieuw koppelen via de Hub.
- Alles is Sim-getest (Hub-simulator `tests/e2e/sim_hub.py`, die ook de nep-Hub van de integratietests is) en
  NIET GEVALIDEERD tegen een echte Hub op een echte NAS.
