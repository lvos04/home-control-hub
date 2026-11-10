#!/usr/bin/env python3
"""Toestanden van de statuspagina uit de **echte app** vastleggen voor de UI-tests (HC11, ONTWERPTAAL §12/§13.2).

Per toestand draait de echte FastAPI-app (PostgreSQL, eigen ``/appdata`` in een tijdelijke map) tegen de Hub-simulator
van de dienst-E2E (``tests/e2e/sim_hub.py``, via de nep-Hub uit ``apps/api/tests/conftest.py``). Vastgelegd worden de
body en de headers (o.a. de CSP) van ``GET /`` of ``POST /koppelen``; ``statuspagina.spec.ts`` geeft ze met dezelfde
headers aan Chromium. Uitkomst: **Sim-getest** (geen echte Hub, geen echte NAS).

    python tests/ui/genereer_toestanden.py [--uit tests/ui/uit]

Database: ``HCH_TEST_ADMIN_URL`` (standaard de lokale ontwikkel-PostgreSQL), database ``hch_ui_toestanden``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

# vaste tijdzone (zoals CI) en vaste trace-ID's: de afdrukken zijn dan vergelijkbaar tussen runs
os.environ["TZ"] = "UTC"
time.tzset()

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "apps" / "api"))

from fastapi.testclient import TestClient  # noqa: E402
from tests.conftest import (  # noqa: E402
    BROWSER_HEADERS,
    HUB_URL,
    PAIR_CODE,
    FakeHub,
    HubKeys,
    idem,
    recreate_database,
)

from integrations.app import create_app  # noqa: E402
from integrations.config import Settings  # noqa: E402
from integrations.hublink_store import LinkState, Pending  # noqa: E402
from integrations.migrations import upgrade  # noqa: E402

DB_NAAM = "hch_ui_toestanden"
TRACE = {
    "niet-gekoppeld": "0b5c2d6e-1f3a-4c8b-9d7e-2a6f4b1c3e01",
    "koppelen-mislukt": "3d8a1f4e-6b2c-4e95-a7d0-91c5b8e2f364",
    "invoer-ongeldig": "6a1e9c3b-7d24-4f58-8b0a-5c2d9e1f4a02",
    "te-veel-pogingen": "9e4b7a2c-3f61-4d85-a2c9-0b7e6d5f1a03",
    "gekoppeld": "c7f2a9d1-5e38-4b6c-8a4f-1d9e3b7c2a04",
    "ingetrokken": "e2a6c8f4-9b13-4d7a-b5e1-3c8f0a2d6b05",
    "ontkoppeld": "f1d3b5a7-2c49-4e6b-9a8d-7e0c2f4b1d06",
    "niet-gereed": "a8c1e3f5-6d27-4b9a-8c4e-0f2b5d7a9c07",
    "onleesbaar": "b4d6f8a1-3e5c-4a7b-9d2f-8c1e0a3b5d08",
    "koppelen-bezig": "c2e4a6b8-1d3f-4a5c-8e7b-9f0a1b2c3d09",
    "herkomst-geweigerd": "d5f7b9c1-2e4a-4b6d-9f8c-0a1b2c3d4e10",
    "domeinnaam": "e6a8c0d2-3f5b-4c7e-8a9d-1b2c3d4e5f11",
}


class Toestanden:
    def __init__(self, uit: Path) -> None:
        self.uit = uit
        self.url = recreate_database(DB_NAAM)
        upgrade(Settings(database_url=self.url))
        self.tmp = Path(tempfile.mkdtemp(prefix="hch-ui-"))

    def app(self, naam: str, hub: FakeHub, **settings: Any) -> TestClient:
        data = self.tmp / naam
        data.mkdir()
        base: dict[str, Any] = {"data_dir": data, "database_url": self.url, "allow_loopback_hub": False}
        base.update(settings)
        # Origin/Sec-Fetch-Site zoals een browser bij een formulier-POST van de eigen pagina (contract 1.3 §3.7)
        client = TestClient(
            create_app(Settings(**base), transport=hub.transport), client=("192.0.2.40", 50000), headers=BROWSER_HEADERS
        )
        client.__enter__()
        return client

    def bewaar(self, naam: str, r: Any, beschrijving: str, moet: list[str]) -> None:
        tekst = r.text
        for stuk in moet:
            if stuk not in tekst:
                raise SystemExit(f"{naam}: verwacht '{stuk}' niet gevonden (status {r.status_code})")
        if r.headers.get("x-trace-id") != TRACE[naam]:
            raise SystemExit(f"{naam}: trace-ID {r.headers.get('x-trace-id')} ≠ {TRACE[naam]}")
        headers = {k.lower(): v for k, v in r.headers.items() if k.lower() != "set-cookie"}
        meta = {"toestand": naam, "beschrijving": beschrijving, "status": r.status_code, "headers": headers}
        (self.uit / f"{naam}.html").write_text(tekst, encoding="utf-8")
        (self.uit / f"{naam}.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"{naam:18} HTTP {r.status_code}  {beschrijving}")


def _csrf(client: TestClient) -> str:
    m = re.search(r'name="csrf" value="([^"]+)"', client.get("/").text)
    if m is None:
        raise SystemExit("geen koppelformulier")
    return m.group(1)


def _koppel(client: TestClient, naam: str, **velden: str) -> Any:
    data = {"csrf": _csrf(client), "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": "", **velden}
    return client.post("/koppelen", data=data, headers={"X-Trace-Id": TRACE[naam]}, follow_redirects=False)


def _get(client: TestClient, naam: str, pad: str = "/") -> Any:
    return client.get(pad, headers={"X-Trace-Id": TRACE[naam]})


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--uit", type=Path, default=Path(__file__).resolve().parent / "uit")
    args = p.parse_args()
    args.uit.mkdir(parents=True, exist_ok=True)
    for oud in args.uit.glob("*.*"):
        oud.unlink()
    t = Toestanden(args.uit)
    stappen: list[Callable[[Toestanden], None]] = [
        niet_gekoppeld,
        koppelen_mislukt,
        invoer_ongeldig,
        te_veel_pogingen,
        gekoppeld,
        ingetrokken,
        ontkoppeld,
        niet_gereed,
        onleesbaar,
        koppelen_bezig,
        herkomst_geweigerd,
        domeinnaam,
    ]
    for stap in stappen:
        stap(t)
    return 0


def niet_gekoppeld(t: Toestanden) -> None:
    c = t.app("niet-gekoppeld", FakeHub(HubKeys()))
    r = _get(c, "niet-gekoppeld")
    t.bewaar("niet-gekoppeld", r, "nog nooit gekoppeld: koppelformulier", ["Niet gereed", 'action="/koppelen"'])


def koppelen_mislukt(t: Toestanden) -> None:
    hub = FakeHub(HubKeys())
    c = t.app("koppelen-mislukt", hub)
    r = _koppel(c, "koppelen-mislukt", koppelcode="AAAA-BBBB-CCCC", hub_vingerafdruk=hub.fingerprint())
    t.bewaar(
        "koppelen-mislukt",
        r,
        "de Hub weigert de koppelcode: 400, code hub_weigerde, veldfout en trace-ID",
        ["Code <code>hub_weigerde</code>", TRACE["koppelen-mislukt"], 'aria-invalid="true"'],
    )


def invoer_ongeldig(t: Toestanden) -> None:
    hub = FakeHub(HubKeys())
    c = t.app("invoer-ongeldig", hub)
    r = _koppel(c, "invoer-ongeldig", hub_adres="http://localhost:30400", hub_vingerafdruk=hub.fingerprint())
    t.bewaar(
        "invoer-ongeldig", r, "ongeldig Hub-adres: 422, niets naar de Hub", ["Code <code>ongeldig_hub_adres</code>"]
    )


def te_veel_pogingen(t: Toestanden) -> None:
    hub = FakeHub(HubKeys())
    hub.sim.max_failures = 1000
    c = t.app("te-veel-pogingen", hub)
    for _ in range(5):
        _koppel(c, "te-veel-pogingen", koppelcode="AAAA-BBBB-CCCC", hub_vingerafdruk="0000-0000-0000-0000")
    r = _koppel(c, "te-veel-pogingen", koppelcode="AAAA-BBBB-CCCC", hub_vingerafdruk="0000-0000-0000-0000")
    t.bewaar("te-veel-pogingen", r, "rate-limit van de dienst: 429", ["Code <code>te_veel_pogingen</code>"])


def gekoppeld(t: Toestanden) -> None:
    hub = FakeHub(HubKeys())
    c = t.app("gekoppeld", hub)
    r = _koppel(c, "gekoppeld", hub_vingerafdruk=hub.fingerprint())
    if r.status_code != 303:
        raise SystemExit(f"gekoppeld: koppelen mislukte ({r.status_code})")
    r = _get(c, "gekoppeld", r.headers["location"])
    t.bewaar(
        "gekoppeld",
        r,
        "gekoppeld en door de Hub bevestigd, met de succesmelding na het koppelen",
        ["Gekoppeld met de Hub</strong>", "pil-neutraal", hub.fingerprint()],
    )


def _gekoppelde_app(t: Toestanden, naam: str) -> tuple[TestClient, FakeHub]:
    hub = FakeHub(HubKeys())
    c = t.app(naam, hub)
    if _koppel(c, naam, hub_vingerafdruk=hub.fingerprint()).status_code != 303:
        raise SystemExit(f"{naam}: koppelen mislukte")
    return c, hub


def ingetrokken(t: Toestanden) -> None:
    c, hub = _gekoppelde_app(t, "ingetrokken")
    hub.sim.revoke()
    if c.app.state.hublink.confirm(trace_id=TRACE["ingetrokken"]) is not False:
        raise SystemExit("ingetrokken: intrekking niet gezien")
    r = _get(c, "ingetrokken")
    t.bewaar("ingetrokken", r, "de Hub trok de koppeling in (services/self 401)", ["Ingetrokken</span>"])


def ontkoppeld(t: Toestanden) -> None:
    c, hub = _gekoppelde_app(t, "ontkoppeld")
    if c.post("/connector/v1/hub-link/unlink", headers=idem(hub.service_auth())).status_code != 200:
        raise SystemExit("ontkoppeld: unlink mislukte")
    r = _get(c, "ontkoppeld")
    t.bewaar("ontkoppeld", r, "ontkoppeld door de Hub", ["Ontkoppeld</span>"])


def niet_gereed(t: Toestanden) -> None:
    c = t.app(
        "niet-gereed",
        FakeHub(HubKeys()),
        database_url="postgresql+psycopg://postgres@127.0.0.1:1/hch_onbereikbaar?connect_timeout=2",
    )
    r = _get(c, "niet-gereed")
    t.bewaar("niet-gereed", r, "eigen database onbereikbaar: niet gereed (storing)", ["Nee — de eigen database"])


def onleesbaar(t: Toestanden) -> None:
    c = t.app("onleesbaar", FakeHub(HubKeys()))
    (t.tmp / "onleesbaar" / "secrets" / "hub-link.json").write_text("geen json", encoding="utf-8")
    r = _get(c, "onleesbaar")
    t.bewaar("onleesbaar", r, "koppelbestand onleesbaar: fail-closed", ["Code <code>koppelstatus_onleesbaar</code>"])


def koppelen_bezig(t: Toestanden) -> None:
    c = t.app("koppelen-bezig", FakeHub(HubKeys()))

    def bezig(st: LinkState) -> LinkState:
        st.pending = Pending(
            kind="token", secret_sha256="f" * 64, hub_url=HUB_URL, started_at="2026-11-10T11:54:00Z", attempts=2
        )
        return st

    c.app.state.hublink_store.update(bezig)
    r = _get(c, "koppelen-bezig")
    t.bewaar(
        "koppelen-bezig",
        r,
        "nog nooit gekoppeld, er loopt een koppelpoging (env-token): geen formulier (Peil 1.1.1, E02)",
        ["Koppelen bezig</span>", "Niet gekoppeld</span>"],
    )
    if 'action="/koppelen"' in r.text:
        raise SystemExit("koppelen-bezig: het formulier hoort weg te zijn")


def herkomst_geweigerd(t: Toestanden) -> None:
    hub = FakeHub(HubKeys())
    c = t.app("herkomst-geweigerd", hub)
    data = {"csrf": _csrf(c), "hub_adres": HUB_URL, "koppelcode": PAIR_CODE, "hub_vingerafdruk": hub.fingerprint()}
    r = c.post(
        "/koppelen",
        data=data,
        headers={"X-Trace-Id": TRACE["herkomst-geweigerd"], "Origin": "null"},
        follow_redirects=False,
    )
    t.bewaar(
        "herkomst-geweigerd",
        r,
        "formulier-POST met Origin: null: 403 herkomst_onjuist, niets naar de Hub (contract 1.3 §3.7)",
        ["Code <code>herkomst_onjuist</code>"],
    )


def domeinnaam(t: Toestanden) -> None:
    c = t.app("domeinnaam", FakeHub(HubKeys()))
    r = c.get("/", headers={"X-Trace-Id": TRACE["domeinnaam"], "Host": "nas.voorbeeld.nl:30420"})
    t.bewaar(
        "domeinnaam",
        r,
        "pagina geopend via een publieke domeinnaam: melding dat koppelen hier niet kan (contract 1.3 §3.7 punt 4)",
        ["Code <code>host_niet_toegestaan</code>"],
    )


if __name__ == "__main__":
    sys.exit(main())
