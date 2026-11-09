"""Nep-Authentik als echte HTTP-dienst voor de dienst-E2E. ALLEEN voor tests; geen productiecode.

Gebruikt dezelfde nep-Authentik als de unit- en integratietests (``apps/api/tests/fakes/authentik_fake.py``), met de
vorm van de officiële Authentik-API; bediening via ``/sim/*``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps" / "api" / "tests" / "fakes"))

from authentik_fake import AuthentikFake, asgi_app

FAKE = AuthentikFake(version=os.environ.get("SIM_AUTHENTIK_VERSION", "2026.8.5"), host="authentik.sim")
app = asgi_app(FAKE)
