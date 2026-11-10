"""Healthcheck van de alles-in-één image: /readyz moet 200 geven (database, migraties en geheimen in orde).

Docker start de healthcheck met de gebruiker van de image (root, want de bewaker moet als root kunnen starten voor
het eigenaarschap van /appdata), buiten de procesboom van PID 1. Daarom is de **eerste** handeling (contract 1.3 §2.2):
bij root eerst de bounding set legen, dan ``setgroups([])``, ``setgid(568)``, ``setuid(568)`` en daarna
``PR_SET_NO_NEW_PRIVS`` (ook als de container al als 568 start). Mislukt de wissel, dan exit 1 (rood).

Controlevlag (rooktest, C1.3-HCH-12): ``python healthcheck.py --controle`` doet precies dezelfde wissel en meldt
daarna ``Uid``, ``CapEff``, ``CapPrm``, ``CapAmb``, ``CapBnd`` en ``NoNewPrivs`` van dit proces op één regel, zonder
/readyz aan te spreken. Exit 0 alleen als Uid 568, CapEff/CapPrm/CapAmb 0 en NoNewPrivs 1.
"""

import ctypes
import os
import sys
import urllib.request

UID = GID = 568
PR_CAPBSET_DROP = 24
PR_SET_NO_NEW_PRIVS = 38
NUL = "0" * 16


def wissel() -> None:
    """Eerst de wissel naar 568 (zie moduledoc); elke fout → exit 1."""
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if os.getuid() == 0:
            for cap in range(64):
                if libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0:
                    break  # EINVAL na de laatste bestaande capability
            os.setgroups([])
            os.setgid(GID)
            os.setuid(UID)
        # ook als de container al als 568 start ("Custom User"): no-new-privileges voor dit proces (§2.2)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 or 0 in (os.getuid(), os.geteuid()):
            sys.exit(1)
    except OSError:
        sys.exit(1)


def controle() -> int:
    with open("/proc/self/status", encoding="utf-8") as fh:
        st = dict(line.split(":", 1) for line in fh.read().splitlines() if ":" in line)
    waarden = {
        k: st.get(k, "?").split()[0] if k == "Uid" else st.get(k, "?").strip()
        for k in ("Uid", "CapEff", "CapPrm", "CapAmb", "CapBnd", "NoNewPrivs")
    }
    print(" ".join(f"{k}={v}" for k, v in waarden.items()))
    goed = waarden["Uid"] == str(UID) and waarden["NoNewPrivs"] == "1"
    goed = goed and all(waarden[k] == NUL for k in ("CapEff", "CapPrm", "CapAmb"))
    return 0 if goed else 1


def main() -> int:
    wissel()
    if "--controle" in sys.argv[1:]:
        return controle()
    port = os.environ.get("HCH_PORT", "30420")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # nooit via een proxy
        with opener.open(f"http://127.0.0.1:{port}/readyz", timeout=6) as resp:
            return 0 if resp.status == 200 else 1
    except Exception:
        return 1


if __name__ == "__main__":
    sys.exit(main())
