# Data-eigenaarschap, integratie en anti-duplicatie

| Data/functie | Auteur van waarheid | Toegestane Hub-interactie | Niet doen |
|---|---|---|---|
| Films, episodes, kwaliteit, import, AV1, quarantine | MediaGuard | GET status/wanted/policy; acties alleen via gedocumenteerde routes en MediaGuard-audit | Geen dubbele wanted-engine, directe SQL, bestandsmutaties buiten MediaGuard |
| Prowlarr-indexers en Sonarr/Radarr sync | MediaGuard/Prowlarr | status en diagnose; expliciete configuratieverzoeken naar eigenaar | Geen tweede synchronisatie die tags door elkaar haalt |
| Usenet-providerhealth, torrentbeperkingen, zoekbronbeoordeling | MSO | Read-model en door MSO goedgekeurde change sets | Geen opschonen zonder bevestiging; geen directe torrent-delete uit Hub |
| qBittorrent/SABnzbd wachtrij | Downloadclients, door MediaGuard/MSO aangestuurd | status en relevante handelingen bij oorspronkelijke eigenaar | Geen third writer zonder conflictbeleid |
| Woning, scènes, climate, energy, apparaten | my_house | read-only telemetrie en guarded command delegation | Geen alternatieve klimaatregelaar in Hub; boiler schakelen blijft verboden |
| Kijkstatus, stream, gebruikerprofielen | Jellyfin fork | Player/client API, events, zoekindex | Geen mutaties direct op Jellyfin DB |
| Foto's, gezichts-/albumgegevens | Immich | read-only selectie, index opt-in | Geen re-implementatie fotobeheer, originele bestanden nooit aanpassen |
| TrueNAS pools, datasets, apps, snapshots | TrueNAS middleware | genormeerde read-only adapter; write via privileged executor | Geen directe shell vanuit chatbot of frontend |
| AI-plan, policy, approval en globale audit | Hub | enige bron van waarheid voor cross-app acties | Geen goedkeuring alleen in tekstprompt |

## Event contract
Gebruik JSON-envelope: `event_id` (UUID), `schema_version`, `source_app`, `source_event_id`, `event_type`, `entity_type`, `entity_id`, `timestamp_utc`, `trace_id`, `correlation_id`, `actor`, `payload_ref`, `sensitivity`. Metadata en secrets gescheiden. Event-id idempotent; outbox in bron en inbox in bestemming met dedupe, retry, dead-letter, backoff. Wanneer bron geen events levert: read-only polling met ETag en watermarks. Geen afhankelijkheid van exact-once netwerklevering.

## API contract
- Centrale Hub API `/api/v1/...`, JSON, UUID, ISO-8601 UTC, OpenAPI, error `{code,message,details,trace_id}`.
- Elke connector declareert capabilities (`read`, `propose`, `apply`, `rollback`, `stream`), limieten en versie; ontbreken van een functie resulteert in `unavailable`, niet in gesimuleerd succes.
- Connectorcredentials per app en per scope in versleutelde vault. Rotatie zonder complete herinstallatie; firewall-deny voor onbekende bestemmingen.
- Command request met `idempotency_key`, `expected_version`/ETag, preview hash, TTL en audit. Bij veranderd object moet opnieuw goedgekeurd worden.
- Integratietests tegen bestaande routes; placeholders zijn **ontwerpvoorstellen**, geen bewering dat huidige apps die routes al hebben.
