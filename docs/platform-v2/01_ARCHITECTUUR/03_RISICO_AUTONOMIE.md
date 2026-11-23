# AI-autonomie, risicoklassen en veiligheidsgrenzen

## Klassen

| Klasse | Actievoorbeelden | Uitvoering |
|---|---|---|
| R0 alleen lezen | metrics, logs, uitleg, inventaris, zoeken in eigen toegestane data | Automatisch |
| R1 omkeerbaar en beperkt | healthcheck, notificatie, tijdelijke pauze van nietkritieke job, beperkte service-restart na drempel | Automatisch bij allowlist, cooldown, anti-flap en rollback |
| R2 infrastructureel/impactvol | bestaande container-upgrade, netwerkservice herstarten, opslagquota aanpassen, secrets roteren | Expliciete approval of vooraf goedgekeurde playbook met aanvullende gates; standaard approval |
| R3 destructief/onomkeerbaar/privilege | datasets verwijderen, firewall WAN-regels, massale bestandswijzigingen, auto-purge, rootbeheer, key export, betaalde acties | Altijd uitdrukkelijke menselijke akkoord per gebonden diff; sommige acties bewust helemaal niet aanbieden |

## Technische handhaving
1. Agent produceert strikt gestructureerd **voorstel**, geen shellcode als privilegebasis. Behandel modeloutput als onbetrouwbaar.
2. Policy engine valideert gebruiker, scope, risico, target, precondities, onderhoudsvenster, active incident, back-up-staat, idempotency key en wijzigingshash.
3. Executor herkent uitsluitend geregistreerde `action_id`s (bijv. `app.restart`, `app.update`, `zfs.snapshot.create`, `nas.service.read`) met getypte argumenten en harde grenzen. Geen universeel `sh -c` of `sudo` endpoint.
4. De API/GUI toont preview, blast radius, verantwoordelijke, back-up-link, risico, benodigde downtime, rollbackrecept.
5. Approval is beperkt tot exact `action_id`, object, gewijzigde velden, versie, actor, vervaltijd; verouderde of gewijzigde diff vervalt automatisch.
6. Uitvoer legt before/after hashes en readback vast; onvoorziene verandering → stop en incident. Abortknop voorkomt nieuwe acties, maar kan bestaande OS-operatie niet altijd onderbreken.
7. Restore van media, my_house of netwerk gaat via de data-eigenaar. Backup-is-healthy is nooit alleen `bestand bestaat`: ook checksums, testrestore en recency.

## Speciale blokkades
- Een gestopte Custom App (ix-app of compose) toont in TrueNAS geen image; het platform kan dan niet uitsluiten dat het Emby, MediaGuard of de mediaserver is en weigert elke actie erop (`doel_niet_herkenbaar`), ook met goedkeuring. Daarom is `app.stop` op een Custom App altijd R2 (goedkeuring van een beheerder; nooit automatisch, ook niet op voorstel van de AI of een runbook) en zegt de preview dat weer starten daarna alleen in de TrueNAS-web-UI kan. Een catalogusapp blijft gestopt herkenbaar aan zijn catalogusnaam; stoppen en starten blijven daar R1 (besluit van de gebruiker, 2026-11-11; ai-server-manager ADR-0030, besluit 21).
- Bij gedegradeerde ZFS-pool, onbekende backupstatus, ontbrekende externe backup of schrijferrors: geen mutaties aan opslag of massale mediaoperaties.
- Geen wijzigingen in beveiligingsbeleid of privileges door de AI zelf; policyfiles worden buiten AI-runner onder aparte beheerder geversioneerd.
- Geen automatisch verwijderen van torrents, downloads, mediabestanden, foto's of datasets; MSO/MediaGuard eigen veiligheid blijft leidend.
- Smart Home: geen commando dat boiler schakelt; bij twijfel sensor-/adapterstatus `unknown` en geen aansturing.
- Netwerk: DNS/VPN/firewall-aanpassingen vereisen test vanaf onafhankelijke verbinding plus automatische timeout/rollback waar mogelijk, om lock-out te vermijden.
- Kosten: Claude API uitsluitend binnen inbegrepen credits en contractueel toegestane accountkoppeling; API-balance check, absolute bestedingslimiet 0 overage, geen automatisch opwaarderen. Local deterministic fallback.

## Faalproeven
Policy wijzigingshash mismatch; dubbele event delivery; reboot tijdens apply; verloren NAS-API; 401-revoked credentials; gemanipuleerde logs met prompt injection; valse 'admin' prompt; mislukte rollback. Allemaal moeten veilig stoppen, traceerbaar zijn en de webinterface bereikbaar houden.
