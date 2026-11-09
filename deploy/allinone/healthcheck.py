"""Healthcheck van de alles-in-één image: /readyz moet 200 geven (database, migraties en geheimen in orde).

Docker start de healthcheck met de gebruiker van de image (root, want de bewaker moet als root kunnen starten voor
het eigenaarschap van /appdata). Daarom wisselt dit script als eerste naar 568:568 zonder capabilities en met
no-new-privileges, zodat ook dit kortlevende proces niet als root draait (contract 1.2 §2.2, ADR-0010).
"""

import ctypes
import os
import sys
import urllib.request

UID = GID = 568
if os.getuid() == 0:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        for cap in range(64):
            if libc.prctl(24, cap, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
                break
        os.setgroups([])
        os.setgid(GID)
        os.setuid(UID)
        libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    except OSError:
        sys.exit(1)

port = os.environ.get("HCH_PORT", "30420")
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # nooit via een proxy
    with opener.open(f"http://127.0.0.1:{port}/readyz", timeout=6) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception:
    sys.exit(1)
