#!/usr/bin/env python3
"""Byte-gelijke kopieën van het platformcontract bewaken (contract 1.3, kop en §10; C1.3-ALG-01, C1.3-HCH-14).

``docs/platform-v2/PLATFORM_CONTRACTEN.md``, ``CONTRACT_1.3_CONFORMITEIT.md`` (en de 1.2-lijst als historie) zijn
byte-gelijk aan ``lvos04/ai-server-manager`` op de vaste bron-commit uit ``docs/platform-v2/CONTRACT_HERKOMST.json``.

``controleer``            offline: sha256 van elke kopie = de pin (CI, elke run; ook in de unit-tests).
``vergelijk --online``    de bron op GitHub op de gepinde commit moet exact deze inhoud hebben (fout bij drift); de
                          bronbranch met andere inhoud geeft alleen een waarschuwing (een nieuwe kopie overnemen is
                          een stap van de orkestratie, geen rode CI).
``vergelijk --bron <map>`` hetzelfde tegen een lokale checkout.
``bijwerken --bron <map> --commit <40 hex>``  kopieën en pins opnieuw schrijven vanuit die checkout.

Alleen de standaardbibliotheek. Uitgang 0 = in orde, 1 = drift of fout, 2 = verkeerd gebruik.
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
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PV2 = REPO_ROOT / "docs" / "platform-v2"
HERKOMST = PV2 / "CONTRACT_HERKOMST.json"
BRON_PAD = "docs/platform-v2"
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{pad}"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lees() -> dict[str, object]:
    return json.loads(HERKOMST.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def controleer() -> list[str]:
    try:
        h = lees()
    except (OSError, ValueError) as exc:
        return [f"CONTRACT_HERKOMST.json onleesbaar: {exc}"]
    bestanden = h.get("bestanden")
    if not isinstance(bestanden, dict) or not bestanden:
        return ["CONTRACT_HERKOMST.json: 'bestanden' ontbreekt"]
    if not re.fullmatch(r"[0-9a-f]{40}", str(h.get("bron_commit"))):
        return ["CONTRACT_HERKOMST.json: bron_commit moet een volledige commit-hash zijn"]
    fouten = []
    for naam, pin in bestanden.items():
        pad = PV2 / naam
        if not pad.is_file():
            fouten.append(f"{naam}: ontbreekt")
        elif sha256(pad.read_bytes()) != pin:
            fouten.append(f"{naam}: inhoud wijkt af van de pin (lokaal aangepast?)")
    return fouten


def haal_online(repo: str, ref: str, pad: str) -> bytes:
    url = RAW.format(repo=repo, ref=ref, pad=pad)
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


def haal_lokaal(bron: Path, ref: str | None, pad: str) -> bytes:
    if ref is None:
        return (bron / pad).read_bytes()
    out = subprocess.run(  # noqa: S603 - vaste opdracht, geen shell
        ["git", "-C", str(bron), "show", f"{ref}:{pad}"],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if out.returncode != 0:
        raise FileNotFoundError(f"{bron}: {ref}:{pad} niet gevonden")
    return out.stdout


def vergelijk(bron: Path | None, online: bool) -> tuple[list[str], list[str]]:
    fouten = controleer()
    waarschuwingen: list[str] = []
    if fouten:
        return fouten, waarschuwingen
    h = lees()
    repo, commit, tak = str(h["bron_repo"]), str(h["bron_commit"]), str(h.get("bron_ref") or "")
    bestanden = h["bestanden"]
    if not isinstance(bestanden, dict):  # pragma: no cover - controleer() heeft dit al gemeld
        return ["CONTRACT_HERKOMST.json: 'bestanden' ontbreekt"], waarschuwingen
    for naam, pin in bestanden.items():
        pad = f"{BRON_PAD}/{naam}"
        bronnen: list[tuple[str, bytes | Exception, bytes | Exception]] = []
        if online:
            gepind = _probeer(lambda p=pad: haal_online(repo, commit, p))
            nu = _probeer(lambda p=pad: haal_online(repo, tak or commit, p))
            bronnen.append(("online", gepind, nu))
        if bron is not None:
            gepind = _probeer(lambda p=pad: haal_lokaal(bron, commit, p))
            nu = _probeer(lambda p=pad: haal_lokaal(bron, None, p))
            bronnen.append(("lokaal", gepind, nu))
        for soort, gepind, nu in bronnen:
            if isinstance(gepind, Exception):
                fouten.append(f"{soort} {naam}: gepinde commit {commit[:7]} niet te lezen ({gepind})")
            elif sha256(gepind) != pin:
                fouten.append(f"{soort} {naam}: kopie ≠ bron op de gepinde commit {commit[:7]} (drift)")
            if isinstance(nu, Exception):
                waarschuwingen.append(f"{soort} {naam}: huidige bron niet te lezen ({nu})")
            elif sha256(nu) != pin:
                waarschuwingen.append(
                    f"{soort} {naam}: de bron is gewijzigd sinds {commit[:7]}; een nieuwe kopie overnemen is een stap "
                    "van de orkestratie (tools/contract_kopie.py bijwerken)"
                )
    return fouten, waarschuwingen


def _probeer(f: object) -> bytes | Exception:
    try:
        return f()  # type: ignore[operator, no-any-return]
    except (OSError, ConnectionError) as exc:
        return exc


def bijwerken(bron: Path, commit: str, ref: str | None) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        return ["--commit moet een volledige commit-hash (40 hex) zijn"]
    h = lees()
    bestanden = h["bestanden"]
    if not isinstance(bestanden, dict):
        return ["CONTRACT_HERKOMST.json: 'bestanden' ontbreekt"]
    nieuw: dict[str, str] = {}
    for naam in bestanden:
        try:
            data = haal_lokaal(bron, commit, f"{BRON_PAD}/{naam}")
        except FileNotFoundError as exc:
            return [str(exc)]
        (PV2 / naam).write_bytes(data)
        nieuw[naam] = sha256(data)
    h.update({"bron_commit": commit, "bron_ref": ref or h.get("bron_ref", ""), "bestanden": nieuw})
    HERKOMST.write_text(json.dumps(h, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return controleer()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Byte-gelijke contractkopieën bewaken (C1.3-ALG-01).")
    sub = p.add_subparsers(dest="opdracht", required=True)
    sub.add_parser("controleer")
    v = sub.add_parser("vergelijk")
    v.add_argument("--bron", type=Path)
    v.add_argument("--online", action="store_true")
    b = sub.add_parser("bijwerken")
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
    ci = os.environ.get("GITHUB_ACTIONS") == "true"
    for w in waarschuwingen:
        print(f"::warning::Contract: {w}" if ci else f"waarschuwing: {w}")
    for f in fouten:
        print(f"::error::Contract: {f}" if ci else f"fout: {f}", file=sys.stderr)
    if not fouten:
        print(f"Contractkopieën in orde ({args.opdracht}).")
    return 1 if fouten else 0


if __name__ == "__main__":
    sys.exit(main())
