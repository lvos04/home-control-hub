# Wijzigingen

## 0.1.0 — P0 (nog niet uitgebracht)

**Nieuw**
- Integratiedienst `integrations` (FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 16) op poort 30420.
- Contract 1.1: foutformaat met `trace_id`, `Idempotency-Key` op alle mutaties, ETag/If-Match, cursor-paginering,
  `/healthz` + `/readyz`, connectorcontract (`discover`, `health`, `items`, `evidence`, `events`; `propose`, `apply`
  en `rollback` geven eerlijk `501 capability_unavailable`), outbox met event-envelope en push naar de Hub-inbox.
- Authenticatie: Hub-JWT (EdDSA, `iss=hub`, `aud=home-control-hub`, levensduur ≤ 120 s) via een JWKS-cache die
  fail-closed is; service-token uit de enrollment.
- Koppelen met de Hub: eenmalig token uit de omgeving (worker) of koppelcode op de statuspagina; zonder Hub eerlijk
  *niet gekoppeld*; ontkoppelen met de lokale ontkoppelcode uit de app-log.
- B13-001: herstelregister voor beheeraccounts zonder geheimen, herstelmethodes (minstens twee, waarvan één zonder
  SSO), noodtoegang alleen vanaf LAN/VPN-bereiken met sessieduur en herbevestiging, zelftest die werkt met Authentik
  offline, handmatige oefeningen, activaties met rotatieplicht, versleutelde herstelkit (scrypt + AES-256-GCM).
- B10/B11/B14: datamodellen met database-invarianten (geen malware zonder bewijs, meters altijd alleen-lezen, geen
  CPU-schatting zonder kalibratie, netwerkwijzigingen minimaal R2) en inventaris; SSO-dekkingsmatrix en
  energie-dekkingsmatrix met status *te verifiëren*/*onbekend*.
- Alles-in-één image met procesbewaker, first-start-init van `/appdata/secrets`, back-up vóór migraties en
  healthcheck; installatie-instructie voor het standaard TrueNAS Custom App-formulier; manifest; CI en release.

**Validatie:** Unit-, integratie- (PostgreSQL) en dienst-E2E-tests met simulators; image-rooktest in Docker.
NIET GEVALIDEERD op een echte NAS, met echte Authentik of met echte accounts.
