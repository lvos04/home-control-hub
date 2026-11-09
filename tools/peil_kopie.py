#!/usr/bin/env python3
"""Versie-gepinde kopie van het Peil-statuspaginasjabloon bewaken (ONTWERPTAAL §13.2 en §14, O-14).

``design/ontwerptaal/statuspagina.html`` en ``statuspagina.css`` zijn byte-gelijk aan de bron in
``lvos04/ai-server-manager`` (``design/ontwerptaal/``), met één extra eerste regel: de **herkomstkop**::

    <!-- Herkomst: Peil 1.1.0 · sha256:<64 hex> · bron lvos04/ai-server-manager@<commit> design/ontwerptaal/… · … -->
    /*! Herkomst: Peil 1.1.0 · sha256:<64 hex> · bron lvos04/ai-server-manager@<commit> design/ontwerptaal/… · … */

De sha256 in de kop is die van het bronbestand (= alles na de eerste regel). ``HERKOMST.json`` pint dezelfde waarden.
Hetzelfde kopformaat gebruiken de andere diensten van het platform.

Opdrachten (alleen de standaardbibliotheek; werkt zonder het pakket te installeren):

``controleer``
    Offline: kop, inhoud, ``HERKOMST.json`` en de in het sjabloon ingebedde CSS kloppen met elkaar (CI, elke run;
    ook in de unit-tests).
``vergelijk --bron <map van ai-server-manager>`` en/of ``vergelijk --online``
    Tegen de bron. De gepinde commit moet exact deze inhoud hebben. Op de bronbranch geldt: dezelfde versie met
    andere inhoud = **drift** (fout); een nieuwere versie = waarschuwing (bewust bijwerken, niet stil meenemen).
``bijwerken --bron <map> --commit <40 hex> [--ref <branch>]``
    Kopieën en ``HERKOMST.json`` opnieuw schrijven vanuit een checkout op die commit.

Uitgang 0 = in orde, 1 = drift of fout, 2 = verkeerd gebruik.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MAP = REPO_ROOT / "design" / "ontwerptaal"
HERKOMST = MAP / "HERKOMST.json"
BESTANDEN = ("statuspagina.html", "statuspagina.css")
BRON_REPO = "lvos04/ai-server-manager"
BRON_MAP = "design/ontwerptaal"
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{pad}"
STAART = "versie-gepinde kopie, niet met de hand wijzigen (tools/peil_kopie.py)"

KOP = re.compile(
    r"^(?:<!--|/\*!) Herkomst: Peil (?P<versie>\d+\.\d+\.\d+) · sha256:(?P<sha>[0-9a-f]{64}) · "
    r"bron (?P<repo>[\w.-]+/[\w.-]+)@(?P<commit>[0-9a-f]{40}) (?P<pad>\S+) · [^\n]*?(?:-->|\*/)$"
)
#: de versie zoals de bron hem zelf noemt (eerste commentaar van het sjabloon, eerste regel van de CSS)
BRONVERSIE = {
    "statuspagina.html": re.compile(r"<!-- Peil statuspagina-sjabloon (\d+\.\d+\.\d+) · "),
    "statuspagina.css": re.compile(r"^/\*! Peil statuspagina\.css (\d+\.\d+\.\d+) · "),
}
STYLE = re.compile(rb"<style>(/\*!.*?)</style>", re.S)  # het eerste commentaar noemt <style> ook


@dataclass(frozen=True)
class Kop:
    versie: str
    sha: str
    repo: str
    commit: str
    pad: str


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def splits(data: bytes) -> tuple[Kop | None, bytes]:
    """Herkomstkop en bronbytes van een kopie (de kop is precies de eerste regel)."""
    eerste, _, rest = data.partition(b"\n")
    m = KOP.match(eerste.decode("utf-8", "replace"))
    if not m:
        return None, data
    return Kop(**m.groupdict()), rest


def bronversie(naam: str, bron: bytes) -> str | None:
    m = BRONVERSIE[naam].search(bron.decode("utf-8", "replace")[:800])
    return m.group(1) if m else None


def maak_kop(naam: str, versie: str, digest: str, commit: str) -> str:
    tekst = f"Herkomst: Peil {versie} · sha256:{digest} · bron {BRON_REPO}@{commit} {BRON_MAP}/{naam} · {STAART}"
    return f"<!-- {tekst} -->" if naam.endswith(".html") else f"/*! {tekst} */"


def semver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in v.split("."))


def lees_herkomst() -> dict[str, object]:
    return json.loads(HERKOMST.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


# ------------------------------------------------------------------------------------------------ controleer
def controleer() -> list[str]:
    """Offline controle; geeft de lijst met fouten (leeg = in orde)."""
    fouten: list[str] = []
    try:
        herkomst = lees_herkomst()
    except (OSError, ValueError) as exc:
        return [f"HERKOMST.json onleesbaar: {exc}"]
    versie = herkomst.get("versie")
    commit = herkomst.get("bron_commit")
    bestanden = herkomst.get("bestanden")
    if not isinstance(bestanden, dict) or set(bestanden) != set(BESTANDEN):
        return [f"HERKOMST.json: 'bestanden' moet precies {', '.join(BESTANDEN)} bevatten"]
    if herkomst.get("bron_repo") != BRON_REPO:
        fouten.append(f"HERKOMST.json: bron_repo moet {BRON_REPO} zijn")
    bron: dict[str, bytes] = {}
    for naam in BESTANDEN:
        pad = MAP / naam
        try:
            data = pad.read_bytes()
        except OSError as exc:
            fouten.append(f"{naam}: ontbreekt ({exc.strerror})")
            continue
        kop, rest = splits(data)
        if kop is None:
            fouten.append(f"{naam}: de eerste regel is geen geldige herkomstkop")
            continue
        werkelijk = sha256(rest)
        pin = bestanden[naam]
        if not isinstance(pin, dict):
            fouten.append(f"HERKOMST.json: {naam} is geen object")
            continue
        if werkelijk != kop.sha:
            fouten.append(f"{naam}: inhoud gewijzigd (sha256 {werkelijk[:16]}… ≠ kop {kop.sha[:16]}…)")
        if kop.sha != pin.get("sha256"):
            fouten.append(f"{naam}: sha256 in de kop wijkt af van HERKOMST.json")
        if kop.versie != versie or bronversie(naam, rest) != versie:
            fouten.append(f"{naam}: versie in kop/bron ({kop.versie}/{bronversie(naam, rest)}) ≠ HERKOMST {versie}")
        if kop.commit != commit or kop.repo != BRON_REPO:
            fouten.append(f"{naam}: bron in de kop ({kop.repo}@{kop.commit[:7]}) ≠ HERKOMST.json")
        if kop.pad != f"{BRON_MAP}/{naam}" or pin.get("bron_pad") != kop.pad:
            fouten.append(f"{naam}: bronpad {kop.pad} klopt niet")
        bron[naam] = rest
    if len(bron) == len(BESTANDEN):
        m = STYLE.search(bron["statuspagina.html"])
        if m is None or m.group(1) != bron["statuspagina.css"].strip():
            fouten.append("statuspagina.html: de ingebedde <style> is niet gelijk aan statuspagina.css")
    return fouten


# ------------------------------------------------------------------------------------------------ vergelijk
def haal_online(pad: str, ref: str) -> bytes:
    """Bronbestand van GitHub (publieke repo, geen token); 4 herhalingen na 2/4/8/16 s bij netwerkfouten."""
    url = RAW.format(repo=BRON_REPO, ref=ref, pad=pad)
    laatste: Exception | None = None
    for wacht in (0, 2, 4, 8, 16):
        if wacht:
            time.sleep(wacht)
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 - vaste https-URL naar GitHub
                return bytes(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise FileNotFoundError(f"{url}: 404") from exc
            laatste = exc
        except (urllib.error.URLError, TimeoutError) as exc:
            laatste = exc
    raise ConnectionError(f"{url}: niet op te halen ({laatste})")


def haal_lokaal(bron_map: Path, pad: str, ref: str | None) -> bytes:
    """Bronbestand uit een lokale checkout: op ``ref`` (commit of branch) via git, anders de werkmap."""
    if ref is None:
        return (bron_map / pad).read_bytes()
    out = subprocess.run(  # noqa: S603 - vaste opdracht, geen shell
        ["git", "-C", str(bron_map), "show", f"{ref}:{pad}"],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if out.returncode != 0:
        raise FileNotFoundError(f"{bron_map}: {ref}:{pad} niet gevonden")
    return out.stdout


def vergelijk(bron_map: Path | None, online: bool) -> tuple[list[str], list[str]]:
    """Vergelijk met de bron; geeft (fouten, waarschuwingen)."""
    fouten = controleer()
    waarschuwingen: list[str] = []
    if fouten:
        return fouten, waarschuwingen
    herkomst = lees_herkomst()
    commit, ref, versie = str(herkomst["bron_commit"]), str(herkomst.get("bron_ref") or ""), str(herkomst["versie"])
    bronnen: list[tuple[str, object]] = []
    if bron_map is not None:
        bronnen.append(("lokaal", bron_map))
    if online:
        bronnen.append(("online", None))
    for soort, waar in bronnen:
        for naam in BESTANDEN:
            pad = f"{BRON_MAP}/{naam}"
            _, kopie = splits((MAP / naam).read_bytes())

            def haal(r: str | None, soort: str = soort, waar: object = waar, pad: str = pad) -> bytes:
                if soort == "online" or not isinstance(waar, Path):
                    return haal_online(pad, r or commit)
                return haal_lokaal(waar, pad, r)

            try:
                gepind = haal(commit)
            except (FileNotFoundError, ConnectionError, OSError) as exc:
                fouten.append(f"{soort} {naam}: gepinde commit {commit[:7]} niet te lezen ({exc})")
                continue
            if gepind != kopie:
                fouten.append(f"{soort} {naam}: kopie ≠ bron op de gepinde commit {commit[:7]} (drift)")
            # de huidige stand van de bron: online de bronbranch, lokaal de werkmap
            try:
                nu = haal(ref if soort == "online" and ref else None)
            except (FileNotFoundError, ConnectionError, OSError) as exc:
                fouten.append(f"{soort} {naam}: huidige bron niet te lezen ({exc})")
                continue
            nu_versie = bronversie(naam, nu)
            if nu == kopie:
                continue
            if nu_versie is None:
                fouten.append(f"{soort} {naam}: de bron heeft geen leesbare versie meer (drift)")
            elif semver(nu_versie) > semver(versie):
                waarschuwingen.append(
                    f"{soort} {naam}: de bron heeft Peil {nu_versie} (kopie {versie}); bewust bijwerken met "
                    "'tools/peil_kopie.py bijwerken'"
                )
            else:
                fouten.append(f"{soort} {naam}: Peil {nu_versie} in de bron heeft andere inhoud dan de kopie (drift)")
    return fouten, waarschuwingen


# ------------------------------------------------------------------------------------------------ bijwerken
def bijwerken(bron_map: Path, commit: str, ref: str | None) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        return ["--commit moet een volledige commit-hash (40 hex) zijn"]
    pins: dict[str, dict[str, str]] = {}
    versies: set[str] = set()
    inhoud: dict[str, bytes] = {}
    for naam in BESTANDEN:
        pad = f"{BRON_MAP}/{naam}"
        try:
            data = haal_lokaal(bron_map, pad, commit)
        except FileNotFoundError as exc:
            return [str(exc)]
        v = bronversie(naam, data)
        if v is None:
            return [f"{naam}: geen versie in de bron gevonden"]
        versies.add(v)
        inhoud[naam] = data
        pins[naam] = {"bron_pad": pad, "sha256": sha256(data)}
    if len(versies) != 1:
        return [f"sjabloon en CSS hebben verschillende versies: {sorted(versies)}"]
    versie = versies.pop()
    MAP.mkdir(parents=True, exist_ok=True)
    for naam, data in inhoud.items():
        kop = maak_kop(naam, versie, pins[naam]["sha256"], commit)
        (MAP / naam).write_bytes(kop.encode("utf-8") + b"\n" + data)
    herkomst = {
        "ontwerptaal": "Peil",
        "versie": versie,
        "bron_repo": BRON_REPO,
        "bron_commit": commit,
        "bron_ref": ref or "",
        "bestanden": pins,
        "toelichting": "Versie-gepinde kopie (ONTWERPTAAL §13.2/§14, O-14). Bijwerken alleen met "
        "'python3 tools/peil_kopie.py bijwerken'; daarna tests, UI-tests en schermafdrukken opnieuw.",
    }
    HERKOMST.write_text(json.dumps(herkomst, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return controleer()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Versie-gepinde Peil-kopie bewaken (O-14).")
    sub = p.add_subparsers(dest="opdracht", required=True)
    sub.add_parser("controleer", help="offline: kop, inhoud, HERKOMST.json en ingebedde CSS")
    v = sub.add_parser("vergelijk", help="tegen de bron (lokale checkout en/of GitHub)")
    v.add_argument("--bron", type=Path, help="map van een checkout van ai-server-manager")
    v.add_argument("--online", action="store_true", help="tegen GitHub: gepinde commit en bronbranch")
    b = sub.add_parser("bijwerken", help="kopieën opnieuw schrijven vanuit een checkout")
    b.add_argument("--bron", type=Path, required=True)
    b.add_argument("--commit", required=True)
    b.add_argument("--ref")
    args = p.parse_args(argv)
    waarschuwingen: list[str] = []
    if args.opdracht == "controleer":
        fouten = controleer()
    elif args.opdracht == "vergelijk":
        if args.bron is None and not args.online:
            p.error("geef --bron en/of --online")
        fouten, waarschuwingen = vergelijk(args.bron, args.online)
    else:
        fouten = bijwerken(args.bron, args.commit, args.ref)
    for w in waarschuwingen:
        print(f"::warning::Peil: {w}" if _ci() else f"waarschuwing: {w}")
    for f in fouten:
        print(f"::error::Peil: {f}" if _ci() else f"fout: {f}", file=sys.stderr)
    if not fouten:
        print(f"Peil-kopie in orde ({args.opdracht}).")
    return 1 if fouten else 0


def _ci() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true"


if __name__ == "__main__":
    sys.exit(main())
