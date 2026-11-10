#!/usr/bin/env python3
"""Onafhankelijke ontwerpreview van de statuspagina tegen de **draaiende dienst** (contract §13; ONTWERPTAAL §12).

Anders dan ``genereer_toestanden.py`` (de app in-proces via TestClient) draait hier alles als echt proces, zoals in de
dienst-E2E: de Hub-simulator (``tests/e2e/sim_hub.py``) via uvicorn en per toestand een eigen API (en waar nodig de
worker) van home-control-hub met een eigen PostgreSQL-database en een eigen ``/appdata``. De browser (Chromium via
``ontwerpreview.mjs``) bezoekt de echte dienst en vult zelf het koppelformulier in (CSRF-cookie, Origin, 303). Per
toestand × thema × breedte meet ``ontwerpreview.mjs`` axe-core (WCAG 2.2 AA), contrast in de gerenderde pagina
(tekst, UI-randen, iconen, focusring), aanraakdoelen, overloop, focus en de Peil-statusregels, en maakt een
schermafdruk. Uitkomst: **Sim-getest** (geen echte Hub, geen echte NAS, geen echte telefoon of schermlezer).

    python tests/ui/ontwerpreview.py [--uit tests/ui/review-uit] [--breedtes 320,360,390,768,1440] [--alleen naam,...]

Testdata: bronnen met verse en oude metingen (gezond, beperkt, storing, nooit gemeten, verouderd) in de database van
de toestand ``gekoppeld-met-bronnen``; de koppelstatus via de echte flows (formulier, intrekking door de Hub,
ontkoppelen via de connector-API) of, waar geen flow bestaat, via ``hub-link.json`` (niet bevestigd, geweigerde
sleutelrotatie, onleesbaar). Databases: ``hch_review_<n>`` op ``HCH_TEST_ADMIN_URL`` (standaard de lokale PostgreSQL).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import create_engine, text

REPO = Path(__file__).resolve().parents[2]
HIER = Path(__file__).resolve().parent
E2E = REPO / "tests" / "e2e"
ADMIN_DB_URL = os.environ.get("HCH_TEST_ADMIN_URL", "postgresql+psycopg://postgres@127.0.0.1:5432/postgres")
PY = sys.executable
SIM_POORT = 39400  # vaste poort (als hij vrij is): het Hub-adres op de afdrukken blijft gelijk tussen runs


def vrije_poort(voorkeur: int | None = None) -> int:
    for poort in ([voorkeur] if voorkeur else []) + [0]:
        s = socket.socket()
        try:
            s.bind(("127.0.0.1", poort))
            return int(s.getsockname()[1])
        except OSError:
            continue
        finally:
            s.close()
    raise RuntimeError("geen vrije poort")


def wacht_http(url: str, timeout: float = 30) -> None:
    eind = time.monotonic() + timeout
    while time.monotonic() < eind:
        with contextlib.suppress(httpx.HTTPError):
            if httpx.get(url, timeout=2).status_code < 500:
                return
        time.sleep(0.3)
    raise RuntimeError(f"{url} kwam niet op")


def maak_database(naam: str) -> str:
    eng = create_engine(ADMIN_DB_URL, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{naam}" WITH (FORCE)'))
        c.execute(text(f'CREATE DATABASE "{naam}"'))
    eng.dispose()
    return ADMIN_DB_URL.rsplit("/", 1)[0] + "/" + naam


def verwijder_database(naam: str) -> None:
    eng = create_engine(ADMIN_DB_URL, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{naam}" WITH (FORCE)'))
    eng.dispose()


@dataclass
class Dienst:
    """Eén draaiende home-control-hub (API, optioneel worker) met eigen database en ``/appdata``."""

    naam: str
    url: str
    data: Path
    db_url: str
    env: dict[str, str]
    procs: list[subprocess.Popen[bytes]] = field(default_factory=list)

    def link(self) -> dict[str, Any]:
        return dict(json.loads((self.data / "secrets" / "hub-link.json").read_text(encoding="utf-8")))

    def schrijf_link(self, data: dict[str, Any]) -> None:
        pad = self.data / "secrets" / "hub-link.json"
        tmp = pad.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, pad)

    def pagina(self) -> str:
        return httpx.get(self.url + "/", timeout=10).text


#: thema's die ontwerpreview.mjs per toestand en breedte meet (licht en donker)
THEMAS = 2


class Review:
    def __init__(self, uit: Path, breedtes: str) -> None:
        # absoluut: ontwerpreview.mjs draait met cwd tests/ui; een relatief pad (zoals in CI) kwam anders op een andere
        # plek terecht dan waar beoordeel() leest, en dan werd er 0 gemeten en toch "geslaagd" gemeld (review 1.2)
        self.uit, self.breedtes = uit.resolve(), breedtes
        self.verwacht = 0  # aantal metingen dat beoordeel() moet terugvinden
        self.tmp = Path(tempfile.mkdtemp(prefix="hch-review-"))
        self.logs = self.tmp / "logs"
        self.logs.mkdir()
        self.basis_env = {k: v for k, v in os.environ.items() if not k.startswith(("HCH_", "HUB_", "ENROLLMENT_"))}
        self.basis_env["TZ"] = "UTC"
        self.databases: list[str] = []
        poort = vrije_poort(SIM_POORT)
        self.hub = f"http://127.0.0.1:{poort}"
        self.hub_proc = subprocess.Popen(
            [PY, "-m", "uvicorn", "sim_hub:app", "--host", "127.0.0.1", "--port", str(poort), "--log-level", "warning"],
            env={**self.basis_env, "PYTHONPATH": str(E2E)},
            cwd=E2E,
            stdout=open(self.logs / "hub.log", "wb"),  # blijft open zolang het proces leeft
            stderr=subprocess.STDOUT,
        )
        wacht_http(f"{self.hub}/sim/state")

    # ------------------------------------------------------------------ Hub-simulator (wat een beheerder in de Hub doet)
    def koppelcode(self) -> tuple[str, str]:
        g = httpx.post(f"{self.hub}/sim/grant", json={"kind": "code"}, timeout=5).json()
        return str(g["secret"]), str(g["fingerprint"])

    def token(self) -> tuple[str, str]:
        g = httpx.post(f"{self.hub}/sim/grant", json={"kind": "token"}, timeout=5).json()
        return str(g["secret"]), str(g["fingerprint"])

    def storing(self, aan: bool) -> None:
        httpx.post(f"{self.hub}/sim/outage", json={"on": aan}, timeout=5)

    # ------------------------------------------------------------------ dienst
    @contextlib.contextmanager
    def dienst(
        self, naam: str, *, worker: bool = False, db_bereikbaar: bool = True, **extra_env: str
    ) -> Iterator[Dienst]:
        db_naam = f"hch_review_{len(self.databases) + 1}"
        if db_bereikbaar:
            db_url = maak_database(db_naam)
            self.databases.append(db_naam)
        else:
            db_url = "postgresql+psycopg://postgres@127.0.0.1:1/hch_onbereikbaar?connect_timeout=2"
        data = self.tmp / naam
        data.mkdir()
        poort = vrije_poort()
        env = {
            **self.basis_env,
            "HCH_DATA_DIR": str(data),
            "HCH_DATABASE_URL": db_url,
            "HCH_ALLOW_LOOPBACK_HUB": "1",  # de Hub-simulator draait op 127.0.0.1
            "HCH_WORKER_INTERVAL_S": "1",
            "HCH_HUB_HEARTBEAT_S": "1",
            "HCH_HUB_KEY_POLL_S": "1",
            **extra_env,
        }
        subprocess.run([PY, "-m", "integrations", "init"], env=env, check=True, capture_output=True)
        if db_bereikbaar:
            subprocess.run([PY, "-m", "integrations", "migrate"], env=env, check=True, capture_output=True)
        d = Dienst(naam, f"http://127.0.0.1:{poort}", data, db_url, env)
        log = open(self.logs / f"{naam}.log", "wb")
        d.procs.append(
            subprocess.Popen(
                [PY, "-m", "integrations", "api", "--host", "127.0.0.1", "--port", str(poort)],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        )
        if worker:
            d.procs.append(
                subprocess.Popen([PY, "-m", "integrations", "worker"], env=env, stdout=log, stderr=subprocess.STDOUT)
            )
        try:
            wacht_http(f"{d.url}/healthz")
            yield d
        finally:
            for p in d.procs:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(10)
                    except subprocess.TimeoutExpired:
                        p.kill()
            log.close()

    def koppel_via_http(self, d: Dienst) -> None:
        """Koppelen zoals een browser het formulier verstuurt (cookie + CSRF + Origin), voor de vervolgtoestanden."""
        code, vinger = self.koppelcode()
        with httpx.Client(base_url=d.url, timeout=15) as c:
            m = re.search(r'name="csrf" value="([^"]+)"', c.get("/").text)
            if m is None:
                raise SystemExit(f"{d.naam}: geen koppelformulier")
            r = c.post(
                "/koppelen",
                data={"csrf": m[1], "hub_adres": self.hub, "koppelcode": code, "hub_vingerafdruk": vinger},
                headers={"Origin": d.url},
            )
        if r.status_code != 303:
            raise SystemExit(f"{d.naam}: koppelen mislukte (HTTP {r.status_code})")

    def wacht_op(self, d: Dienst, tekst: str, timeout: float = 30) -> None:
        eind = time.monotonic() + timeout
        while time.monotonic() < eind:
            if tekst in d.pagina():
                return
            time.sleep(0.5)
        raise SystemExit(f"{d.naam}: '{tekst}' verscheen niet op de statuspagina")

    # ------------------------------------------------------------------ browser
    def bekijk(self, d: Dienst, beschrijving: str, stappen: list[dict[str, Any]], verwacht: list[str]) -> None:
        plan = {
            "toestand": d.naam,
            "beschrijving": beschrijving,
            "url": d.url,
            "stappen": stappen,
            "verwacht": verwacht,
            "breedtes": [int(b) for b in self.breedtes.split(",")],
            "uit": str(self.uit),
        }
        pad = self.tmp / f"{d.naam}.plan.json"
        pad.write_text(json.dumps(plan, ensure_ascii=False), encoding="utf-8")
        r = subprocess.run(["node", str(HIER / "ontwerpreview.mjs"), str(pad)], cwd=HIER)
        if r.returncode != 0:
            raise SystemExit(f"{d.naam}: browserstap mislukt (exit {r.returncode}); logs in {self.logs}")
        self.verwacht += len(plan["breedtes"]) * THEMAS

    def opruimen(self) -> None:
        if self.hub_proc.poll() is None:
            self.hub_proc.terminate()
            self.hub_proc.wait(10)
        for naam in self.databases:
            with contextlib.suppress(Exception):
                verwijder_database(naam)
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------------------------- toestanden
GET = [{"soort": "goto", "pad": "/"}]


def formulier(hub: str, code: str, vinger: str, keer: int = 1) -> list[dict[str, Any]]:
    return [*GET, {"soort": "formulier", "hub": hub, "koppelcode": code, "vingerafdruk": vinger, "keer": keer}]


def niet_gekoppeld(r: Review) -> None:
    with r.dienst("niet-gekoppeld") as d:
        r.bekijk(d, "nog nooit gekoppeld: koppelformulier", GET, ["Niet gereed", "Koppelen met de Hub"])


def koppelen_mislukt(r: Review) -> None:
    _, vinger = r.koppelcode()
    with r.dienst("koppelen-mislukt") as d:
        r.bekijk(
            d,
            "browser verstuurt een onbekende koppelcode: de Hub weigert (400 hub_weigerde)",
            formulier(r.hub, "AAAA-BBBB-CCCC", vinger),
            ["hub_weigerde", "Koppelen is mislukt"],
        )


def vingerafdruk_onjuist(r: Review) -> None:
    code, _ = r.koppelcode()
    with r.dienst("vingerafdruk-onjuist") as d:
        r.bekijk(
            d,
            "geldige koppelcode met een vingerafdruk van een andere Hub (400 hub_vingerafdruk_onjuist)",
            formulier(r.hub, code, "0000-0000-0000-0000"),
            ["hub_vingerafdruk_onjuist"],
        )


def invoer_ongeldig(r: Review) -> None:
    code, vinger = r.koppelcode()
    with r.dienst("invoer-ongeldig") as d:
        r.bekijk(
            d,
            "Hub-adres met een pad (422 ongeldig_hub_adres, niets naar de Hub)",
            formulier("http://192.0.2.10:30400/hub", code, vinger),
            ["ongeldig_hub_adres"],
        )


def te_veel_pogingen(r: Review) -> None:
    _, vinger = r.koppelcode()
    with r.dienst("te-veel-pogingen") as d:
        r.bekijk(
            d,
            "zes pogingen achter elkaar vanaf één adres (429 te_veel_pogingen)",
            formulier(r.hub, "AAAA-BBBB-CCCC", vinger, keer=6),
            ["te_veel_pogingen"],
        )


def koppelen_bezig(r: Review) -> None:
    token, vinger = r.token()
    r.storing(True)
    try:
        with r.dienst(
            "koppelen-bezig", worker=True, HUB_URL=r.hub, HUB_ENROLLMENT_TOKEN=token, HUB_KEY_FINGERPRINT=vinger
        ) as d:
            r.wacht_op(d, "Koppelen bezig")
            r.bekijk(d, "token uit het Custom App-formulier, de Hub antwoordt niet: koppelen bezig", GET, [])
    finally:
        r.storing(False)


def gekoppeld(r: Review) -> None:
    code, vinger = r.koppelcode()
    with r.dienst("gekoppeld") as d:
        r.bekijk(
            d,
            "browser koppelt met een geldige koppelcode en vingerafdruk (303 → melding 'Gekoppeld met de Hub')",
            formulier(r.hub, code, vinger),
            ["Gekoppeld met de Hub", "pil-neutraal", vinger],
        )


def gekoppeld_met_bronnen(r: Review) -> None:
    with r.dienst("gekoppeld-met-bronnen") as d:
        r.koppel_via_http(d)
        _bronnen(d.db_url)
        r.bekijk(d, "gekoppeld en bevestigd; testdata: bronnen gezond/beperkt/storing/nooit gemeten/verouderd", GET, [])


def niet_bevestigd(r: Review) -> None:
    with r.dienst("niet-bevestigd") as d:
        r.koppel_via_http(d)
        link = d.link()
        link["confirmed_at"] = None
        d.schrijf_link(link)
        r.bekijk(d, "gekoppeld, maar de Hub heeft de koppeling (nog) niet bevestigd", GET, ["Niet bevestigd"])


def sleutelrotatie_geweigerd(r: Review) -> None:
    with r.dienst("sleutelrotatie-geweigerd") as d:
        r.koppel_via_http(d)
        link = d.link()
        link["key_rotation_blocked_sequence"] = 2
        d.schrijf_link(link)
        r.bekijk(d, "gekoppeld; een sleutelrotatie van de Hub is geweigerd (Beperkt)", GET, ["Sleutels van de Hub"])


def ingetrokken(r: Review) -> None:
    with r.dienst("ingetrokken", worker=True) as d:
        r.koppel_via_http(d)
        httpx.post(f"{r.hub}/sim/revoke", timeout=5)
        r.wacht_op(d, "Ingetrokken</span>")
        r.bekijk(d, "de Hub trok de koppeling in; de worker zag 401 op services/self", GET, [])


def ontkoppeld(r: Review) -> None:
    with r.dienst("ontkoppeld") as d:
        r.koppel_via_http(d)
        jwt = httpx.post(f"{r.hub}/sim/service-jwt", timeout=5).json()["token"]
        resp = httpx.post(
            f"{d.url}/connector/v1/hub-link/unlink",
            headers={"Authorization": f"Bearer {jwt}", "Idempotency-Key": str(uuid.uuid4())},
            timeout=10,
        )
        if resp.status_code != 200:
            raise SystemExit(f"ontkoppeld: unlink gaf HTTP {resp.status_code}")
        r.bekijk(d, "de Hub ontkoppelde de dienst via de connector-API", GET, ["Ontkoppeld</span>"])


def niet_gereed(r: Review) -> None:
    with r.dienst("niet-gereed", db_bereikbaar=False) as d:
        r.bekijk(d, "eigen database onbereikbaar: niet gereed (Storing)", GET, ["Nee — de eigen database"])


def herkomst(r: Review) -> None:
    """Contract 1.3 §3.7 punt 6 (C1.3-HCH-01): Chromium verstuurt het ECHTE formulier tegen de ECHTE dienst. Eerst de
    negatieve gevallen (Origin null, vreemde Origin, Sec-Fetch-Site same-site en cross-site, geen cookie, een
    niet-toegestane Host): elk 403 met de vaste code, en de Hub-simulator mag daarna geen enkel enroll-verzoek hebben
    gezien en de koppelstatus is ongewijzigd. Daarna koppelt hetzelfde formulier wél (303)."""
    code, vinger = r.koppelcode()
    uit = r.uit / "herkomst"
    with r.dienst("herkomst") as d:
        poort = int(d.url.rsplit(":", 1)[1])
        pad = r.tmp / "herkomst.plan.json"
        plan = {"url": d.url, "poort": poort, "hub": r.hub, "code": code, "vinger": vinger, "uit": str(uit)}
        pad.write_text(json.dumps(plan), encoding="utf-8")
        voor = len(httpx.get(f"{r.hub}/sim/state", timeout=5).json()["enroll_requests"])
        for fase in ("negatief", "positief"):
            res = subprocess.run(
                ["node", str(HIER / "herkomst.mjs"), str(pad)], cwd=HIER, env={**os.environ, "HERKOMST_FASE": fase}
            )
            if res.returncode != 0:
                raise SystemExit(f"herkomst ({fase}): browsertest mislukt; zie {uit}")
            if fase == "negatief":
                na = len(httpx.get(f"{r.hub}/sim/state", timeout=5).json()["enroll_requests"])
                link = httpx.get(f"{d.url}/readyz", timeout=10).json()["hub_link"]
                if na != voor or link["state"] != "nooit_gekoppeld" or link["koppelen_bezig"]:
                    raise SystemExit(
                        f"herkomst: een geweigerd formulier bereikte de Hub of wijzigde de koppeling: {link}"
                    )
        if httpx.get(f"{d.url}/readyz", timeout=10).json()["hub_link"]["state"] != "gekoppeld":
            raise SystemExit("herkomst: het echte formulier koppelde niet")


def onleesbaar(r: Review) -> None:
    with r.dienst("onleesbaar") as d:
        (d.data / "secrets" / "hub-link.json").write_text("geen json", encoding="utf-8")
        r.bekijk(d, "koppelbestand onleesbaar: fail-closed", GET, ["koppelstatus_onleesbaar"])


def _bronnen(db_url: str) -> None:
    """Testdata in de inventaris: verse en oude metingen (de catalogus bepaalt welke bronnen er kunnen zijn)."""
    from integrations.db import Database
    from integrations.models import IntegrationSource

    nu = datetime.now(UTC)
    rijen = [
        # bron, domein, status, gemeten (None = nooit gemeten)
        ("adguard_home", "network", "healthy", nu - timedelta(minutes=2)),
        ("netalertx", "network", "degraded", nu - timedelta(minutes=3)),
        ("node_red", "automation", "healthy", nu - timedelta(minutes=1)),
        ("authentik", "sso", "healthy", nu - timedelta(days=3)),  # laatste meting is oud: nooit groen tonen
        ("my_house", "energy", "down", nu - timedelta(minutes=4)),
        ("truenas_metrics", "energy", "unknown", None),
    ]
    db = Database(db_url)
    try:
        with db.sessions() as s:
            for bron, domein, status, gemeten in rijen:
                s.add(
                    IntegrationSource(
                        source_id=bron,
                        domain=domein,
                        base_url=f"http://bron-{bron.replace('_', '-')}.test:8080",
                        enabled=True,
                        last_probe_at=gemeten,
                        last_probe_status=status,
                        updated_by="ontwerpreview",
                    )
                )
            s.commit()
    finally:
        db.dispose()


TOESTANDEN: list[Callable[[Review], None]] = [
    niet_gekoppeld,
    koppelen_mislukt,
    vingerafdruk_onjuist,
    invoer_ongeldig,
    te_veel_pogingen,
    koppelen_bezig,
    gekoppeld,
    gekoppeld_met_bronnen,
    niet_bevestigd,
    sleutelrotatie_geweigerd,
    ingetrokken,
    ontkoppeld,
    niet_gereed,
    onleesbaar,
    herkomst,
]


#: rijen waarvan de laatste meting oud is (testdata): die mogen nooit groen zijn (Peil §4.1/§4.4, 05_OPERATIES)
VEROUDERD = {"gekoppeld-met-bronnen": ["Authentik en toegangsbeheer (B13)"]}
NOOIT_GROEN = re.compile(r"^(Onbekend|Verouderd|Niet |Ontkoppeld|Ingetrokken|Koppelen bezig|Onleesbaar|Onvolledig)")
#: groen mag alleen met het vaste Peil-woord: "Gezond" in een rij, "Alles gezond" in de totaalpil (Peil §11.1)
GROENE_WOORDEN = {"Gezond", "Alles gezond"}


def beoordeel(uit: Path, verwacht: int | None = None) -> int:
    """Harde eisen over alle metingen; schrijft ``samenvatting.json`` en geeft het aantal overtredingen terug.

    ``verwacht`` = het aantal metingen dat de browser heeft gedaan. Wijkt het gevonden aantal af (of is het 0), dan is
    dat zelf een overtreding: een review die niets meet, mag nooit slagen."""
    fouten: list[str] = []
    rijen: list[dict[str, Any]] = []
    for pad in sorted(uit.glob("*.json")):
        if pad.name == "samenvatting.json":
            continue
        res = json.loads(pad.read_text(encoding="utf-8"))
        naam = res["toestand"]
        if res["csp_overtredingen"] or res["paginafouten"]:
            fouten.append(f"{naam}: CSP-overtredingen of paginafouten")
        if not (res["csp"] or "").startswith("default-src 'none'"):
            fouten.append(f"{naam}: CSP ontbreekt")
        afstand = res.get("tekstafstand") or {}
        if afstand.get("overloop", 1) > 0 or afstand.get("afgekapt"):
            fouten.append(f"{naam}: tekstafstand (WCAG 1.4.12) geeft overloop of afgekapte tekst: {afstand}")
        for run in res["runs"]:
            plek = f"{naam} · {run['thema']} · {run['breedte']}"
            checks = {
                "axe": len(run["axe"]),
                "tekst<4,5": len(run["tekst"]["fouten"]),
                "tekst<14px": len(run["tekst"]["klein"]),
                "ellips": len(run["tekst"]["ellips"]),
                "rand<3": len(run["randen"]["fouten"]),
                "icoon<3": len(run["iconen"]["fouten"]),
                "doel<44": len(run["doelen"]["fouten"]),
                "focus": len(run["focus"]["fouten"]),
                "overloop": max(0, run["overloop"]),
                "h1≠1": int(run["structuur"]["h1"] != 1),
                "kopsprong": run["structuur"]["sprongen"],
                "ids/aria": len(run["structuur"]["dubbeleIds"]) + len(run["structuur"]["kapotteVerwijzingen"]),
            }
            peil: list[str] = []
            for pil in run["pillen"]:
                if not pil["icoon"] or not pil["woord"]:
                    peil.append(f"pil zonder icoon of woord: {pil}")
                woord_ok = pil["woord"] in GROENE_WOORDEN and (
                    pil["woord"] != "Alles gezond" or pil is run["pillen"][0]
                )
                if pil["klasse"] == "pil-gezond" and (not woord_ok or NOOIT_GROEN.match(pil["woord"])):
                    peil.append(f"groen voor '{pil['woord']}'")
                if pil["klasse"] == "pil-gezond" and pil["rij"] in VEROUDERD.get(naam, []):
                    peil.append(f"verouderde meting groen: {pil['rij']}")
                # onbekend altijd met reden; het koppelblok legt zijn pil uit in de alinea eronder
                zonder_reden = pil["klasse"] == "pil-onbekend" and not pil["reden"]
                if zonder_reden and pil is not run["pillen"][0] and pil["rij"] != "Koppeling met de Hub":
                    peil.append(f"onbekend zonder reden: {pil['rij']}")
            totaal = run["pillen"][0] if run["pillen"] else None
            if totaal and run["gereed"].startswith("Nee") and totaal["klasse"] == "pil-gezond":
                peil.append("totaal groen terwijl de dienst niet gereed is")
            checks["peil"] = len(peil)
            for k, v in checks.items():
                if v:
                    fouten.append(f"{plek}: {k} = {v}")
            fouten.extend(f"{plek}: {p}" for p in peil)
            rijen.append(
                {
                    "plek": plek,
                    "http": res["status"],
                    "axe": checks["axe"],
                    "best_practice": len(run["bestPractice"]),
                    "tekst_min": run["tekst"]["min"],
                    "tekst_onder_7": len(run["tekst"]["onderPeil7"]),
                    "rand_min": run["randen"]["betekenisMin"],
                    "icoon_min": run["iconen"]["min"],
                    "focus_min": run["focus"]["min"],
                    "focus_stops": run["focus"]["aantal"],
                    "overloop": run["overloop"],
                }
            )
    if not rijen or (verwacht is not None and len(rijen) != verwacht):
        fouten.insert(0, f"aantal metingen klopt niet: verwacht {verwacht}, gevonden {len(rijen)} in {uit}")
    samenvatting = {
        "metingen": len(rijen),
        "verwacht": verwacht,
        "overtredingen": fouten,
        "laagste": {
            k: min((r[k] for r in rijen), default=None) for k in ("tekst_min", "rand_min", "icoon_min", "focus_min")
        },
        "rijen": rijen,
    }
    (uit / "samenvatting.json").write_text(json.dumps(samenvatting, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"{len(rijen)} metingen; laagste: {samenvatting['laagste']}; overtredingen: {len(fouten)}")
    for f in fouten[:60]:
        print("  - " + f)
    return len(fouten)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--uit", type=Path, default=HIER / "review-uit")
    p.add_argument("--breedtes", default="320,360,390,768,1024,1440")  # contract 1.3 §13 = ONTWERPTAAL §12
    p.add_argument("--alleen", default="", help="komma-gescheiden namen (zoals niet-gekoppeld)")
    args = p.parse_args()
    args.uit = args.uit.resolve()
    if args.uit.exists():
        shutil.rmtree(args.uit)
    (args.uit / "afdrukken").mkdir(parents=True)
    alleen = {n for n in args.alleen.split(",") if n}
    r = Review(args.uit, args.breedtes)
    try:
        for stap in TOESTANDEN:
            naam = stap.__name__.replace("_", "-")
            if alleen and naam not in alleen:
                continue
            print(f"== {naam}", flush=True)
            stap(r)
    finally:
        r.opruimen()
    return 1 if beoordeel(args.uit, r.verwacht) else 0


if __name__ == "__main__":
    sys.exit(main())
