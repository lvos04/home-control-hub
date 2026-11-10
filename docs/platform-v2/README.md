# TrueNAS Home Platform V2 — documentatie voor `home-control-hub`

Bron: uitvoeringspakket `TrueNAS_Home_Platform_V2_VOLLEDIG_2026-11-09.zip` (peildatum 9 november 2026).

**Rol van deze repo (vast besluit):** Integraties: B10 netwerk/privacy, B11 Node-RED, B13 Authentik/SSO, B14 energie/resources.

Hier staan alleen de eigen B-, I-, A- en promptdocumenten plus de gedeelde architectuur (`00_START`, `01_ARCHITECTUUR`, `05_TESTS`). Het volledige pakket en de Excel staan in `lvos04/ai-server-manager` onder `docs/platform-v2/`.

Onbekende NAS-gegevens (D01–D18) worden nooit met voorbeeldwaarden ingevuld; ze worden via de onboarding-wizard in de web-UI vastgelegd.

## Bestanden

- `00_START/BESLUITEN_EN_ONBEKENDEN.md`
- `00_START/INHOUDSOPGAVE.md`
- `00_START/INHOUD_CONTROLE.json`
- `00_START/LEES_MIJ_EERST.md`
- `00_START/SHA256SUMS.txt`
- `01_ARCHITECTUUR/01_PROJECTCHARTER.md`
- `01_ARCHITECTUUR/02_DATA_EIGENAARSCHAP.md`
- `01_ARCHITECTUUR/03_RISICO_AUTONOMIE.md`
- `01_ARCHITECTUUR/04_GEGEVENS_EN_STORAGE.md`
- `01_ARCHITECTUUR/05_OPERATIES_EN_UPDATES.md`
- `01_ARCHITECTUUR/06_FASERING_EN_GATES.md`
- `01_ARCHITECTUUR/07_API_EN_EVENTSCHEMA.md`
- `01_ARCHITECTUUR/08_UI_EN_INTERACTIES.md`
- `02_BOUWPLANNEN/B10_NETWERK_PRIVACY.md`
- `02_BOUWPLANNEN/B11_AUTOMATISERING.md`
- `02_BOUWPLANNEN/B13_AUTHENTIK_SSO.md`
- `02_BOUWPLANNEN/B14_ENERGIE_RESOURCE_MANAGER.md`
- `03_INSTALLATIE/I09_AUTHENTIK.md`
- `03_INSTALLATIE/I10_NODE_RED.md`
- `03_INSTALLATIE/I11_NETALERTX.md`
- `03_INSTALLATIE/I12_ADGUARD_HOME.md`
- `03_INSTALLATIE/I21_TAILSCALE_CLOUDFLARED.md`
- `04_BESTAANDE_APPS/A15_TAILSCALE.md`
- `04_BESTAANDE_APPS/A16_CLOUDFLARED.md`
- `05_TESTS/GEBRUIKERSWENSEN_TRACEERBAARHEID.md`
- `05_TESTS/INTEGRALE_E2E_TESTMATRIX.md`
- `06_TEMPLATES/PROMPTS_PER_APP/PROMPT_B10_NETWERK_PRIVACY.md`
- `06_TEMPLATES/PROMPTS_PER_APP/PROMPT_B11_AUTOMATISERING.md`
- `06_TEMPLATES/PROMPTS_PER_APP/PROMPT_B13_AUTHENTIK_SSO.md`
- `06_TEMPLATES/PROMPTS_PER_APP/PROMPT_B14_ENERGIE_RESOURCE_MANAGER.md`

## Platformcontract (kopieën)

- `PLATFORM_CONTRACTEN.md` — byte-gelijke kopie van `contracts 1.3` uit `lvos04/ai-server-manager`
- `CONTRACT_1.3_CONFORMITEIT.md` — wat elke repo voor 1.3 moet veranderen (deze repo: hoofdstuk 2, C1.3-HCH-01…15)
- `CONTRACT_1.2_CONFORMITEIT.md` — historie
- `CONTRACT_HERKOMST.json` — bron-commit en sha256 van de kopieën; controle met `tools/contract_kopie.py` en
  `apps/api/tests/unit/test_contract_docs.py` (nooit lokaal aanpassen; een nieuwe kopie overnemen is een stap van de
  orkestratie)
- `EVIDENCE.json` — bewijs per Excel-ID en per contractpunt (`C1.3-HCH-<nn>`, contract 1.3 §11)
- `DELTA_MATRIX.md` — wat bestond, wat gebouwd is en wat ontbreekt
