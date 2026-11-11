"""Nep-Node-RED als echte HTTP-dienst voor de dienst-E2E. ALLEEN voor tests; geen productiecode.

Gebruikt dezelfde nep-Node-RED als de unit- en integratietests (``apps/api/tests/fakes/node_red_fake.py``), met de vorm
van de admin-API van de vastgezette image (gemeten met ``tools/node_red_verify.py``); bediening via ``/sim/*``:
``POST /sim/arguments`` (herstart met de argumenten uit het formulier), ``POST /sim/deploy`` (een wijziging in de
editor), ``GET``/``POST /sim/state``. De datamap (``SIM_NODE_RED_DATA_DIR``) is de map die de dienst alleen-lezen
koppelt: daar schrijft de nep het door "Node-RED" versleutelde ``flows_cred.json``.

Resultaten hiermee heten "Sim-getest"; een echte Node-RED op de NAS is NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "api" / "tests" / "fakes"))

from node_red_fake import NodeRedFake, asgi_app

_DATA = os.environ.get("SIM_NODE_RED_DATA_DIR")
FAKE = NodeRedFake(host="nodered.sim", data_dir=Path(_DATA) if _DATA else None)
app = asgi_app(FAKE)
