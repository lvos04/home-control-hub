# ADR-0009 — Aanscherpingen na de onafhankelijke P1-review (eerlijke status, Authentik)

Status: aanvaard · Datum: 2026-11-09 · Fase: P1 (review/QA van B13-002…005)

## Context
Een onafhankelijke review van de P1-oplevering (B13-002…005) controleerde contracten 1.1 §1–§12, de veiligheid volgens
`03_RISICO_AUTONOMIE` en de eerlijkheid van statussen. Alle CI-stappen slaagden, maar op vier plekken gaf de dienst een
geruststellender beeld dan hij kon onderbouwen. Het contract regelt deze details niet; hieronder de gekozen, veiligste
interpretatie.

## Besluiten
1. **Least privilege van het Authentik-token nooit `ok`.** Was: elk token dat geen superuser was kreeg
   `least_privilege: "ok"`. `GET /api/v3/core/users/me/` toont echter alleen superuser en de systeemrechten
   (`system_permissions`, in Authentik alleen de `authentik_rbac`-rechten zoals `edit_system_settings`; bron:
   `authentik/core/api/users.py` en `authentik/rbac/models.py`, tag `version/2026.8.5`). Model-/objectrechten via
   rollen (bv. `change_user`) zijn daar niet te zien. Nu:
   - `te_ruim` bij superuser of een systeemrecht dat niet met `view_` begint (status `degraded`, `token_te_ruim`);
   - `onbekend` als Authentik geen systeemrechten teruggeeft (status `degraded`, `token_rechten_onbekend`);
   - anders `deels_gecontroleerd` met `rbac_object_permissions: "niet_gecontroleerd"` en een Nederlandse melding
     dat de beheerder de rollen van het serviceaccount op de echte installatie moet nagaan.
   Het veld `UserSelf.system_permissions` staat in `compat.USED_API` en is met `tools/authentik_schema_check.py`
   opnieuw gecontroleerd tegen de officiële `schema.yml` van alle 11 release-lijnen 2024.10–2026.8 (verplicht veld).
2. **Rechtenkaart nooit `ok` op oude gegevens.** Was: `GET /integrations/v1/sso/rights` gaf altijd `status: "ok"`
   met de laatste momentopname, ook als Authentik al dagen onbereikbaar was of het token was ingetrokken. Nu houdt de
   synchronisatie bij wanneer Authentik voor het laatst **volledig** gelezen is en de kaart bevestigde
   (`rights_verified`, ook als er niets veranderde en dus geen nieuwe momentopname kwam). Is dat ouder dan
   `max(15 min, 3 × HCH_AUTHENTIK_SYNC_INTERVAL_S)`, dan `status: "verouderd"` met de laatste synchronisatiestatus en
   -reden; de gegevens blijven zichtbaar maar heten "huidige rechten onbekend". `observed_at` is nu het moment van
   die laatste volledige lezing; `snapshot_taken_at` het moment van de momentopname.
3. **Controle van een bestaande Hub-client: zwakke bindingen zijn geen `ok`.** Was: elke binding telde als
   toegangsbeperking. In Authentik beperken uitgeschakelde bindingen niets en betekent een omgekeerde (`negate`)
   groepsbinding "iedereen behalve die groep". Ook gaf een aan een Hub-rol gekoppelde groep die in Authentik niet
   bestaat stilzwijgend `ok`. Nu: alleen ingeschakelde, niet-omgekeerde bindingen tellen; ontbrekende groepen →
   `afwijking` (met namen); geen groep→rol-koppeling → `onbekend`; groepen niet leesbaar → `onbekend`.
4. **Een gat in de Authentik-events wordt een blijvende afwijking.** Per synchronisatie worden per soort hooguit
   500 nieuwe events gelezen. Bij meer schuift het watermerk door (anders blijft elke volgende run steken) en
   ontbreken oudere events uit dat venster blijvend in de audit. Dat stond alleen in de status van die ene
   synchronisatie en was bij de volgende weer weg. Nu ook een afwijking `events_onvolledig` (ontdubbeld per
   watermerk, event `sso.anomaly.detected`).
5. **Eventtypen precies volgens contract §7.** Drie P1-eventtypen hadden vier segmenten
   (`sso.authentik.sync.failed`, `sso.authentik.upgrade_gate.evaluated`, `sso.authentik.restore_check.completed`).
   De inbox van de echte Hub (`ai-server-manager` `apps/api/src/hub/events/envelope.py`, patroon
   `^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$`) weigert die; ze zouden na 10 pogingen als dead-letter eindigen. De
   simulators accepteerden alles. Nu: hernoemd naar `sso.authentik_sync.failed`,
   `sso.authentik_upgrade_gate.evaluated` en `sso.authentik_restore_check.completed`; `events.emit` dwingt het
   Hub-patroon af; `entity_id`/`actor_id` worden op de kolom-/Hub-lengte afgekapt en een payload boven 16 KiB wordt
   ingekort met `_ingekort`; beide Hub-simulators valideren de envelope zoals de Hub (422 bij een fout).

## Getest (Sim-getest, geen echte Authentik)
- `apps/api/tests/integration/test_review_p1.py`: Authentik-token nooit in logs (DEBUG, tracebacks), API-antwoorden,
  headers, enige databasetabel (buiten de versleutelde vault), outbox of idempotency-opslag — ook als de nep-Authentik
  het token in foutantwoorden terugkaatst, bij time-outs, uitval en een geweigerd token, en via de worker; geen
  wijziging zonder door de Hub ondertekend verzoek (andere sleutel, HS256, `alg: none`, verkeerde `aud`/`iss` →
  401 en de database blijft byte-gelijk); `apply`/`rollback` voeren ook met een ExecutionRequest-achtige body niets
  uit; rechtenkaart `verouderd`; events-gat als afwijking; geen header-SSO op de P1-routes en elke
  "ondersteund"-bewering in de dekkingsmatrix heeft een bron.
- `apps/api/tests/unit/test_b13_authentik_unit.py`: `test_token_privileges_never_claims_full_least_privilege`,
  `test_check_hub_client_access_is_never_ok_on_weak_bindings`.
- `tests/e2e/test_service_e2e.py::test_08_no_tokens_in_process_logs`: de echte proceslogs van API en worker bevatten
  het Authentik-token en het koppeltoken niet.
- `test_review_p1.py::test_every_p1_event_is_accepted_by_the_hub_inbox`, `test_catalog_and_contracts.py::
  test_every_event_type_follows_contract_7` en `tests/e2e/test_service_e2e.py::test_05c_hub_accepted_every_event`.
- De lektest is met twee bewuste mutaties gecontroleerd (token in een DEBUG-log; foutbody in de API-fout): beide
  werden gevangen.

## Gevolgen
- De Hub (ai-server-manager) mag `least_privilege: "deels_gecontroleerd"` en `rights.status: "verouderd"` nooit als
  groen tonen. Waarden `ok` voor `least_privilege` bestaan niet meer.
- Wie de oude eventnamen al gebruikte (nog niemand: de Hub verwerkt ze nog niet) moet de nieuwe namen gebruiken.
- Het API-antwoord van `/sso/rights` kreeg de velden `freshness` en `snapshot_taken_at`; de route-omschrijving in de
  OpenAPI-export is bijgewerkt (het antwoord is daar een vrij object).
