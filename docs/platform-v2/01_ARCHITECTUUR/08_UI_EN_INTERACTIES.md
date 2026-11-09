# UI-ontwerp, paginacontracten en gebruikersreizen

## Navigatie
Mobiel: ondernavigatie Home, Apps, Problemen, AI, Meer. Desktop: zijbalk Home, Server, Media, Huis, Netwerk, Automatisering, Backups, Kosten, Instellingen. Bestaande gespecialiseerde apps blijven met deep-link bereikbaar; centrale kaarten zijn bruikbaar zonder elke losse UI te openen.

## Home
Toon bovenaan: totale systeemstatus + wat actie nodig heeft; 1 overzichtskaart voor downloads/bibliotheek, GPU/AV1, apps/uptime, huiscomfort/energie, veiligheid/backups, nieuwste acties. Elke kaart bevat getal + eenheid + bron + **laatst bijgewerkt** en een duidelijke vervolghandeling. Geen fictief ‘alles groen’ bij onbekende status.

## Appbeheer
Lijst met status, uptime, build digest, data-dataset, resourcegrenzen en veilige beheeracties. Appdetail heeft vijf tabs: Status, Metrieken, Logs, Versies, Acties. Voor iedere actie: preview, risico, benodigde backup en readback. Bij nieuwe installatie toon alle hostpaths, netwerk- en GPU-permissies vóór bevestiging.

## Problemen en AI
Eén inbox met severity, bron, eerste/laatste gebeurtenis, onderliggende events, rootcause-hypothese met zekerheid en ‘toon bewijs’. AI chat mag logs uitleggen; ‘repareer’ leidt naar actie-preview, niet direct een terminal. ‘Ik weet het niet’ is geldige uitkomst. Attributen tijd/bron/actor in detail.

## Media
Vijf hoofdtabs film, serie, anime, muziek, Live TV; watch continuation, media quality, downloads, verzoekstatus. Ontbrekende episode gaat naar MediaGuard context en MSO-broncontext; playback uit Jellyfin. Staging mediaserverfork moet vooraf dezelfde of hogere clientcompat hebben.

## Huis
Per kamer verlichting, actuele temperatuur, humidity, temperatuurdoel, bediening, energy, sensor freshness, waarschuwingen. Boiler Energy Socket **alleen lezen**. Bij Gree shared outdoor-unit conflicterende heat/cool tonen als expliciet geblokkeerd; handmatige afstandsbediening en offline-status overriden AI.

## Backups
Dekking per app/dataset: lokaal snapshot, externe OneDrive, consistent DB-export en laatste testrestore. Een succesvolle synchronisatie is niet automatisch een herstelgarantie. R2/R3 actions niet beschikbaar zolang de gate rood is.

## Toegankelijkheid en UX tests
360/390/768/1440, dark/light, toetsenbord en screenreader, touch targets, echte foutstates en offline/reconnect, NL talen, kopieerbare geschoonde incidentgegevens. Testen met een Android-telefoon en een gebruikte TV/player vóór afmelding.
