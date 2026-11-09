"""Peil-statuspaginasjabloon laden en invullen (ONTWERPTAAL §13.2; ADR-0011).

Het sjabloon is een **versie-gepinde kopie** (O-14) in ``design/ontwerptaal/statuspagina.html``. De eerste regel is
de herkomstkop ``<!-- Herkomst: Peil x.y.z · sha256:… · bron lvos04/ai-server-manager@<commit> … -->``; alles daarna is
byte-gelijk aan de bron. In de image staat dezelfde kopie in ``/usr/local/lib/hch/ontwerptaal/`` (``HCH_PEIL_DIR``;
de Dockerfile controleert de sha256 bij het bouwen). De kop wordt vóór het invullen weggelaten, zodat de pagina met
``<!doctype html>`` begint; het ontwikkelaarscommentaar van het sjabloon wordt één korte herkomstregel. Drift
bewaakt ``tools/peil_kopie.py`` (CI); hier alleen een foutregel in de log.

Plekken (gelijk aan de referentie-renderer ``bouw/sjabloon.mjs`` van de bron): ``{{x}}`` = tekst, altijd HTML-escaped;
``<!--ALS:x-->…<!--/ALS:x-->`` tonen als ``x`` waar is; ``<!--NIET:x-->…`` tonen als ``x`` onwaar is;
``<!--ELK:lijst-->…<!--/ELK:lijst-->`` per item herhalen (itemvelden over de paginavelden heen).
**Bewust strenger dan de referentie:** één doorgang. Een ingevulde waarde wordt nooit opnieuw als sjabloon gelezen, dus
een tekst als ``{{csrf_token}}`` in een waarde blijft letterlijk tekst.
"""

from __future__ import annotations

import functools
import hashlib
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger("integrations.peil")

SJABLOON = "statuspagina.html"
#: toonwaarden van pillen (vaste lijst van het sjabloon); de iconen ``#i-<toon>`` bestaan alleen hiervoor
TONEN = frozenset({"gezond", "beperkt", "storing", "onbekend", "gate"})
#: toon van een melding → icoon
MELDING_ICOON = {"fout": "storing", "info": "info"}

_KOP = re.compile(
    r"^<!-- Herkomst: Peil (?P<versie>\d+\.\d+\.\d+) · sha256:(?P<sha>[0-9a-f]{64}) · "
    r"bron (?P<repo>[\w.-]+/[\w.-]+)@(?P<commit>[0-9a-f]{40}) (?P<pad>\S+) · [^\n]*-->$"
)
#: het ontwikkelaarscommentaar bovenaan het sjabloon (regels voor bouwers) gaat niet mee naar de pagina; er komt een
#: korte herkomstregel voor in de plaats. Het commentaar bevat zelf plekken, dus het eindigt vlak vóór ``<html``.
_TOELICHTING = re.compile(r"<!-- Peil statuspagina-sjabloon (?P<versie>\S+) · .*?-->\n(?=<html)", re.S)
_PLEK = re.compile(r"<!--(ELK|ALS|NIET):(\w+)-->(.*?)<!--/\1:\2-->|\{\{(\w+)\}\}", re.S)
_ESC = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})


class SjabloonOntbreekt(RuntimeError):
    """Het sjabloon ontbreekt of heeft geen geldige herkomstkop."""


@dataclass(frozen=True)
class Sjabloon:
    versie: str
    sha256: str
    bron: str  # repo@commit
    tekst: str  # zonder herkomstkop en zonder het ontwikkelaarscommentaar
    intact: bool  # sha256 van de tekst gelijk aan de kop


def kandidaten(peil_dir: Path | None) -> list[Path]:
    """Waar de kopie staat: ``HCH_PEIL_DIR`` (image), anders ``design/ontwerptaal`` in de broncode."""
    paden = [peil_dir / SJABLOON] if peil_dir is not None else []
    repo = Path(__file__).resolve().parents[4]  # apps/api/src/integrations/peil.py → repo
    return [*paden, repo / "design" / "ontwerptaal" / SJABLOON]


@functools.cache
def lees(pad: Path) -> Sjabloon:
    data = pad.read_bytes()
    eerste, _, rest = data.partition(b"\n")
    m = _KOP.match(eerste.decode("utf-8", "replace"))
    if not m:
        raise SjabloonOntbreekt(f"{pad}: herkomstkop ontbreekt")
    intact = hashlib.sha256(rest).hexdigest() == m["sha"]
    if not intact:
        log.error("Peil-sjabloon %s wijkt af van de herkomstkop (sha256): de kopie is gewijzigd", pad)
    tekst = _TOELICHTING.sub(
        lambda t: f"<!-- Peil statuspagina-sjabloon {t['versie']} · sha256:{m['sha'][:16]} -->\n",
        rest.decode("utf-8"),
        count=1,
    )
    return Sjabloon(m["versie"], m["sha"], f"{m['repo']}@{m['commit']}", tekst, intact)


def sjabloon(peil_dir: Path | None = None) -> Sjabloon:
    for pad in kandidaten(peil_dir):
        if pad.is_file():
            return lees(pad)
    raise SjabloonOntbreekt("Peil-statuspaginasjabloon niet gevonden: " + ", ".join(map(str, kandidaten(peil_dir))))


def escape(waarde: object) -> str:
    return ("" if waarde is None else str(waarde)).translate(_ESC)


def render(tpl: str, data: Mapping[str, Any]) -> str:
    """Sjabloon invullen in één doorgang (zie moduledoc)."""

    def vervang(m: re.Match[str]) -> str:
        soort, sleutel, inhoud, veld = m.groups()
        if veld is not None:
            return escape(data.get(veld))
        if soort == "ELK":
            return "".join(render(inhoud, {**data, **item}) for item in data.get(sleutel) or [])
        if soort == "ALS":
            return render(inhoud, data) if data.get(sleutel) else ""
        return "" if data.get(sleutel) else render(inhoud, data)

    return _PLEK.sub(vervang, tpl)
