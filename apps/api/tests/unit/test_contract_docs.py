"""A1 + A4: de kopie van het platformcontract is byte-gelijk aan de bron (``ai-server-manager``, ``contracts 1.2``) en
``docs/platform-v2/EVIDENCE.json`` gebruikt alleen de vaste Excel-statussen en validatiewaarden van §11 (nooit
``Gereed``/``Geslaagd``; toelichting in ``opmerking``)."""

from __future__ import annotations

import hashlib
import json
import os
import re

import pytest

from tests.conftest import REPO_ROOT

PV2 = REPO_ROOT / "docs" / "platform-v2"
#: sha256 van ai-server-manager ``docs/platform-v2/PLATFORM_CONTRACTEN.md`` (contracts 1.2, bron-commit 8b54f39)
CONTRACT_SHA256 = "6a9d29bd94fd991ac5d7876c1a5e51455d471c8bb2833dbed5c52c915b7df424"
#: sha256 van ai-server-manager ``docs/platform-v2/CONTRACT_1.2_CONFORMITEIT.md`` op dezelfde bron-commit
CONFORMITY_SHA256 = "6daedffb44a9506f97c7b9135f65393191a4b6247e96661a64c7a6fed5297f59"
#: naast elkaar uitgecheckt (zoals in de bouwomgeving): dan ook rechtstreeks met de bron vergelijken
SOURCE = REPO_ROOT.parent / "ai-server-manager" / "docs" / "platform-v2"

STATUS_WORK = {"Niet gestart", "Bezig", "Geblokkeerd", "N.v.t."}  # 'Gereed' nooit in deze bouwomgeving
STATUS_TEST = {"Niet gestart", "Bezig", "Mislukt", "Geblokkeerd", "N.v.t."}  # 'Geslaagd' nooit
STATUS_DECISION = {"Open", "Ingevuld", "Getest", "Geblokkeerd", "N.v.t."}
VALIDATION = {
    "Sim-getest",
    "Unit-getest",
    "NIET GEVALIDEERD (echte NAS)",
    "NIET GEVALIDEERD (hardware)",
    "NIET GEVALIDEERD (account)",
    "NIET GEVALIDEERD (Mac/Xcode)",
}
VALIDATION_TEST = {"Sim-geslaagd", "Sim-mislukt"}
FIELDS = {"id", "status", "validatie", "bewijs", "blokkade", "opmerking", "repo", "bijgewerkt"}


@pytest.mark.parametrize(
    ("name", "digest"),
    [("PLATFORM_CONTRACTEN.md", CONTRACT_SHA256), ("CONTRACT_1.2_CONFORMITEIT.md", CONFORMITY_SHA256)],
)
def test_contract_copy_is_byte_equal_to_the_source(name: str, digest: str) -> None:
    data = (PV2 / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == digest, f"{name} wijkt af van contracts 1.2 (bron-commit 8b54f39)"
    if name == "PLATFORM_CONTRACTEN.md":
        assert b"Versie: `contracts 1.2`" in data
    source = SOURCE / name
    if source.is_file() and not os.environ.get("HCH_SKIP_SOURCE_COMPARE"):
        # wijzigt de bron later, dan faalt deze test lokaal: de kopie (en de hash hierboven) moet dan mee
        assert source.read_bytes() == data, f"{name}: de bron in ai-server-manager is gewijzigd; kopieer opnieuw"


def test_evidence_follows_section_11() -> None:
    items = json.loads((PV2 / "EVIDENCE.json").read_text(encoding="utf-8"))
    assert isinstance(items, list) and items
    ids = [i["id"] for i in items]
    assert len(ids) == len(set(ids))
    for item in items:
        ident = item["id"]
        assert set(item) == FIELDS, ident
        assert item["repo"] == "home-control-hub" and re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["bijgewerkt"])
        if re.fullmatch(r"EX\d{2}", ident):
            statuses, values = STATUS_TEST, VALIDATION | VALIDATION_TEST
        elif re.fullmatch(r"D\d{2}", ident):
            statuses, values = STATUS_DECISION, VALIDATION
        else:
            statuses, values = STATUS_WORK, VALIDATION
        assert item["status"] in statuses, (ident, item["status"])
        assert item["status"] not in ("Gereed", "Geslaagd")
        if item["validatie"]:
            parts = item["validatie"].split("; ")
            assert all(p in values for p in parts), (ident, item["validatie"])
            assert len(parts) == len(set(parts)), ident
        else:
            assert item["status"] == "Niet gestart", (ident, "lege validatie alleen bij 'Niet gestart'")


def test_no_session_links_in_docs() -> None:
    """§12 / A2: geen vaste sessielink meer in de eigen docs (de contractkopie zelf telt niet mee)."""
    own = [
        p
        for p in (REPO_ROOT / "docs").rglob("*.md")
        if "platform-v2" not in p.parts or p.name in ("README.md", "DELTA_MATRIX.md")
    ]
    own += [REPO_ROOT / "README.md", REPO_ROOT / "CHANGELOG.md", REPO_ROOT / "deploy" / "truenas" / "CUSTOM_APP.md"]
    for p in own:
        text = p.read_text(encoding="utf-8")
        assert "Claude-Session" not in text and "claude.ai/code/session" not in text, p
