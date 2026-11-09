# Ontwerptaal Peil — versie-gepinde kopie (O-14)

Deze map bevat **kopieën**, geen eigen ontwerp. Bron van waarheid: `lvos04/ai-server-manager`
(`docs/platform-v2/ONTWERPTAAL.md` + `design/ontwerptaal/`). Versie, bron-commit en sha256 staan in `HERKOMST.json` en
in de herkomstkop (de eerste regel) van elk bestand; alles na die regel is byte-gelijk aan de bron.

| Bestand | Gebruik |
|---|---|
| `statuspagina.html` | Sjabloon van `GET /` (geen JavaScript; CSS en lucide-iconen inline). Gerenderd door `apps/api/src/integrations/peil.py` en `status_page.py`; in de image staat het in `/usr/local/lib/hch/ontwerptaal/`. |
| `statuspagina.css` | Dezelfde CSS als de `<style>` in het sjabloon; alleen voor de driftcontrole. |
| `HERKOMST.json` | Versie, bron-repo, gepinde commit, bronbranch en sha256 per bestand. |

**Niet met de hand wijzigen.** Controleren en bijwerken:

```sh
python3 tools/peil_kopie.py controleer                       # offline (CI en unit-tests)
python3 tools/peil_kopie.py vergelijk --online               # tegen GitHub (CI): drift = fout, nieuwere versie = waarschuwing
python3 tools/peil_kopie.py vergelijk --bron ../ai-server-manager
python3 tools/peil_kopie.py bijwerken --bron ../ai-server-manager --commit <40 hex> --ref <branch>
```

Na bijwerken: `make test e2e test-ui schermafdrukken` en de afdrukken in `docs/screenshots/peil/statuspagina/`
vervangen. Besluit en ontwerpstap: `docs/adr/ADR-0011-statuspagina-peil.md`.
