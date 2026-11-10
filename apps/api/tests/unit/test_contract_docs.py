"""Contract 1.3 (kop, §10, §11; C1.3-HCH-14, C1.3-ALG-01/-02): de kopieën van het platformcontract en van de
conformiteitslijst zijn byte-gelijk aan de bron (``ai-server-manager``, ``contracts 1.3``, vaste bron-commit) en
``docs/platform-v2/EVIDENCE.json`` volgt §11 van 1.3 (vaste statussen en validatiewaarden, nooit
``Gereed``/``Geslaagd``, nooit een lege ``validatie``, ``Niet getest`` alleen bij ``Niet gestart``, een
``NIET GEVALIDEERD (…)`` in ``blokkade`` staat ook in ``validatie``; contractpunten ``C1.3-HCH-<nn>`` en reviews
``REVIEW-home-control-hub-…`` mogen een eigen regel hebben)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any

import pytest

from tests.conftest import REPO_ROOT

PV2 = REPO_ROOT / "docs" / "platform-v2"
#: vaste bron-commit van ai-server-manager (branch ccr-c133d7a0-kuz1cv) waarop de kopieën zijn gemaakt
BRON_COMMIT = "0a7143bc0a94ed5317a9655fa785e73a1fb07ba1"
#: sha256 van de bronbestanden op die commit; een nieuwe kopie overnemen is een stap van de orkestratie (nooit lokaal
#: aanpassen, ook niet om een link te repareren)
KOPIEEN = {
    "PLATFORM_CONTRACTEN.md": "15b30cf17f91b606451ef9c41f02327076ef76ce655ee94e40e3538106962310",
    "CONTRACT_1.3_CONFORMITEIT.md": "f0a2352ddb27088ae668013501c62a1eaaf879efe742a2d4422ffe8d33b43466",
    # historie (contract 1.3 C1.3-ALG-01: "mag als historie blijven staan"), zelfde bron-commit
    "CONTRACT_1.2_CONFORMITEIT.md": "634941340afd2d9a55846076ab468ea4aacddb32dd8be6a7b92dd113661d39a4",
}
#: naast elkaar uitgecheckt (zoals in de bouwomgeving): dan ook rechtstreeks met de werkmap van de bron vergelijken
SOURCE = REPO_ROOT.parent / "ai-server-manager" / "docs" / "platform-v2"

STATUS_WORK = {"Niet gestart", "Bezig", "Geblokkeerd", "N.v.t."}  # 'Gereed' nooit in deze bouwomgeving
STATUS_TEST = {"Niet gestart", "Bezig", "Mislukt", "Geblokkeerd", "N.v.t."}  # 'Geslaagd' nooit
STATUS_DECISION = {"Open", "Ingevuld", "Getest", "Geblokkeerd", "N.v.t."}
NIET_GEVALIDEERD_WAARDEN = {
    "NIET GEVALIDEERD (echte NAS)",
    "NIET GEVALIDEERD (hardware)",
    "NIET GEVALIDEERD (account)",
    "NIET GEVALIDEERD (Mac/Xcode)",
}
VALIDATION = {
    "Sim-getest",
    "Unit-getest",
    "Intel-iGPU-getest (ontwikkelmachine)",  # nieuw in 1.3
    "Niet getest",  # nieuw in 1.3: alleen bij status 'Niet gestart'
    *NIET_GEVALIDEERD_WAARDEN,
}
VALIDATION_TEST = {"Sim-geslaagd", "Sim-mislukt"}  # alleen Testmatrix-ID's (EX.., JLT-..)
FIELDS = {"id", "status", "validatie", "bewijs", "blokkade", "opmerking", "repo", "bijgewerkt"}
TESTMATRIX = re.compile(r"EX\d{2}|JLT-\d{2}")
BESLUIT = re.compile(r"D\d{2}")
CONTRACTPUNT = re.compile(r"C1\.3-HCH-\d{2}|C1\.3-ALG-\d{2}|C1\.2-[A-Z]+\d+")
REVIEW = re.compile(r"REVIEW-home-control-hub-[a-z0-9][a-z0-9.-]*")
NIET_GEVALIDEERD = re.compile(r"NIET GEVALIDEERD \([^)]*\)")


@pytest.mark.parametrize(("name", "digest"), sorted(KOPIEEN.items()))
def test_contract_copy_is_byte_equal_to_the_source(name: str, digest: str) -> None:
    data = (PV2 / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, f"{name} wijkt af van de bron op {BRON_COMMIT[:7]}"
    if name == "PLATFORM_CONTRACTEN.md":
        assert b"Versie: `contracts 1.3`" in data
    source = SOURCE / name
    if source.is_file() and not os.environ.get("HCH_SKIP_SOURCE_COMPARE"):
        # wijzigt de bron later, dan faalt deze test lokaal: de kopie (en de hash hierboven) moet dan mee
        assert source.read_bytes() == data, f"{name}: de bron in ai-server-manager is gewijzigd; kopieer opnieuw"


def test_contract_copy_has_no_relative_links_to_the_source_repo() -> None:
    """Kop van het contract: verwijzingen naar de bronrepo staan als tekst ``ai-server-manager:<pad>``; een relatieve
    link zou in deze kopie kapot zijn (A35)."""
    text = (PV2 / "PLATFORM_CONTRACTEN.md").read_text(encoding="utf-8")
    links = re.findall(r"\[[^\]\n]{2,}\]\((?!https?://|#)([^)\s]*(?:\.md|/)[^)\s]*)\)", text)
    assert not links, f"relatieve link(s) in de contractkopie: {links}"


def _items() -> list[dict[str, Any]]:
    data = json.loads((PV2 / "EVIDENCE.json").read_text(encoding="utf-8"))
    assert isinstance(data, list) and data
    return data


def _kind(ident: str) -> str:
    if TESTMATRIX.fullmatch(ident):
        return "test"
    if BESLUIT.fullmatch(ident):
        return "besluit"
    if ident.startswith("C1."):
        assert CONTRACTPUNT.fullmatch(ident), f"{ident}: contractpunt heeft niet de vorm C1.3-HCH-<nn>"
        return "werk"
    if ident.startswith("REVIEW-"):
        assert REVIEW.fullmatch(ident), f"{ident}: review heeft niet de vorm REVIEW-home-control-hub-<onderwerp>"
        return "werk"
    assert re.fullmatch(r"B\d{2}-\d{3}|I\d{2}-\d{2}-\d{2}|APP-\d{2}", ident), f"{ident}: geen Excel-ID"
    return "werk"


def test_evidence_follows_section_11() -> None:
    items = _items()
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids))
    for item in items:
        ident = item["id"]
        assert set(item) == FIELDS, ident
        assert item["repo"] == "home-control-hub" and re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["bijgewerkt"])
        kind = _kind(ident)
        statuses = {"test": STATUS_TEST, "besluit": STATUS_DECISION}.get(kind, STATUS_WORK)
        values = VALIDATION | VALIDATION_TEST if kind == "test" else VALIDATION
        assert item["status"] in statuses, (ident, item["status"])
        assert item["status"] not in ("Gereed", "Geslaagd")
        assert item["validatie"].strip(), f"{ident}: een lege validatie is nooit toegestaan (1.3 §11)"
        parts = item["validatie"].split("; ")
        assert all(p in values for p in parts), (ident, item["validatie"])
        assert len(parts) == len(set(parts)), ident
        if "Niet getest" in parts:
            assert item["status"] == "Niet gestart", f"{ident}: 'Niet getest' alleen bij 'Niet gestart'"
            assert parts == ["Niet getest"] or set(parts) - {"Niet getest"} <= NIET_GEVALIDEERD_WAARDEN, ident


def test_niet_gevalideerd_in_blokkade_staat_ook_in_validatie() -> None:
    """1.3 §11: elke ``NIET GEVALIDEERD (…)`` uit ``blokkade`` is een waarde uit de vaste lijst en staat ook in
    ``validatie``."""
    problems = []
    for item in _items():
        parts = item["validatie"].split("; ")
        for found in NIET_GEVALIDEERD.findall(item["blokkade"]):
            if found not in NIET_GEVALIDEERD_WAARDEN:
                problems.append(f"{item['id']}: {found!r} is geen waarde uit de vaste lijst")
            elif found not in parts:
                problems.append(f"{item['id']}: {found!r} staat in blokkade maar niet in validatie")
    assert not problems, "\n".join(problems)


_TEST_REF = re.compile(r"((?:apps/api/tests|tests)/[\w/.-]+\.(?:py|ts|mjs|sh))|(?<![\w/])::(\w+)|(?<=\.py)::(\w+)")


def test_evidence_references_existing_tests() -> None:
    """§11/EERLIJKHEID: elk bewijs moet controleerbaar zijn. Elk genoemd testbestand bestaat en elke genoemde testfunctie
    (``pad::naam``, of ``::naam`` na het vorige pad) staat in dat bestand; geen sjabloonresten zoals ``{T}``. Zo blijft
    EVIDENCE.json niet wijzen naar tests die bij een contractwijziging zijn vervallen (review contract 1.2)."""
    problems: list[str] = []
    for item in _items():
        text = item["bewijs"]
        if re.search(r"\{[A-Za-z_]*\}", text):
            problems.append(f"{item['id']}: sjabloonrest in bewijs")
        last: str | None = None
        for m in _TEST_REF.finditer(text):
            if m.group(1):
                last = m.group(1)
                if not (REPO_ROOT / last).is_file():
                    problems.append(f"{item['id']}: {last} bestaat niet")
                continue
            name = m.group(2) or m.group(3)
            if last is None or not (REPO_ROOT / last).is_file():
                continue
            source = (REPO_ROOT / last).read_text(encoding="utf-8")
            if not re.search(rf"(def |test\(`?'?){re.escape(name)}\b", source):
                problems.append(f"{item['id']}: {last}::{name} bestaat niet")
    assert not problems, "\n".join(problems)


def test_no_session_links_in_docs() -> None:
    """§12 / A2: geen vaste sessielink meer in de eigen docs (de contractkopieën zelf tellen niet mee)."""
    own = [
        p
        for p in (REPO_ROOT / "docs").rglob("*.md")
        if "platform-v2" not in p.parts or p.name in ("README.md", "DELTA_MATRIX.md")
    ]
    own += [REPO_ROOT / "README.md", REPO_ROOT / "CHANGELOG.md", REPO_ROOT / "deploy" / "truenas" / "CUSTOM_APP.md"]
    for p in own:
        text = p.read_text(encoding="utf-8")
        assert "Claude-Session" not in text and "claude.ai/code/session" not in text, p
