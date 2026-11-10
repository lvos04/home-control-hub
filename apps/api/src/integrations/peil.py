"""Peil-statuspaginasjabloon laden en invullen (ONTWERPTAAL §13.2; ADR-0011).

Het sjabloon is een **versie-gepinde kopie** (O-14) in ``design/ontwerptaal/statuspagina.html``. De eerste regel is
de herkomstkop ``<!-- Herkomst: Peil x.y.z · sha256:… · bron lvos04/ai-server-manager@<commit> … -->``; alles daarna is
byte-gelijk aan de bron. In de image staat dezelfde kopie in ``/usr/local/lib/hch/ontwerptaal/`` (``HCH_PEIL_DIR``;
de Dockerfile controleert de sha256 bij het bouwen). De kop wordt vóór het invullen weggelaten, zodat de pagina met
``<!doctype html>`` begint; het ontwikkelaarscommentaar van het sjabloon wordt één korte herkomstregel. Drift
bewaakt ``tools/peil_kopie.py`` (CI); hier alleen een foutregel in de log.

Plekken (Peil 1.1.1, ONTWERPTAAL §13.2 en COMPONENTEN §29.1): ``{{x}}`` = tekst, altijd HTML-escaped;
``<!--ALS:x-->…<!--/ALS:x-->`` tonen als ``x`` waar is; ``<!--NIET:x-->…`` tonen als ``x`` onwaar is;
``<!--ELK:lijst-->…<!--/ELK:lijst-->`` per item herhalen (itemvelden over de paginavelden heen). Blokken mogen genest
zijn (ook ``NIET`` binnen ``ALS``). **Renderer in één doorgang** (E07), gelijk aan de referentie ``bouw/sjabloon.py``
van de bron: het sjabloon wordt eerst in een boom gelezen en daarna ingevuld; een ingevulde waarde wordt nooit opnieuw
als sjabloon gelezen, dus een tekst als ``{{csrf_token}}`` in een waarde blijft letterlijk tekst. Waar = niet leeg
(``False``, ``None``, leeg, 0 en een lege lijst zijn onwaar). Een niet-gesloten of verkeerd genest blok is een fout
(``SjabloonOntbreekt``), nooit een half ingevulde pagina.
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
#: toonwaarden van pillen (vaste lijst van het sjabloon 1.1.1, E03/E04); het symbool heet altijd ``#i-<toon>``
TONEN = frozenset(
    {
        "gezond",
        "beperkt",
        "storing",
        "onbekend",
        "verouderd",
        "niet-beschikbaar",
        "nog-niet",
        "niet-gekoppeld",
        "gate",
        "beleid",
        "feit",
    }
)
#: het totaal (``totaal_toon``) is alleen een van deze vier
TOTAAL_TONEN = frozenset({"gezond", "beperkt", "storing", "onbekend"})
#: toon van een melding → icoon
MELDING_ICOON = {"fout": "storing", "info": "info"}

_KOP = re.compile(
    r"^<!-- Herkomst: Peil (?P<versie>\d+\.\d+\.\d+) · sha256:(?P<sha>[0-9a-f]{64}) · "
    r"bron (?P<repo>[\w.-]+/[\w.-]+)@(?P<commit>[0-9a-f]{40}) (?P<pad>\S+) · [^\n]*-->$"
)
#: het ontwikkelaarscommentaar bovenaan het sjabloon (regels voor bouwers) gaat niet mee naar de pagina; er komt een
#: korte herkomstregel voor in de plaats. Het commentaar bevat zelf plekken, dus het eindigt vlak vóór ``<html``.
_TOELICHTING = re.compile(r"<!-- Peil statuspagina-sjabloon (?P<versie>\S+) · .*?-->\n(?=<html)", re.S)
_TOKEN = re.compile(r"<!--(/?)(ELK|ALS|NIET):(\w+)-->|\{\{(\w+)\}\}")
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
    """Tekst voor in de pagina; ``True``/``False`` worden ``true``/``false`` zoals in de referentie-renderer."""
    if waarde is None:
        tekst = ""
    elif isinstance(waarde, bool):
        tekst = "true" if waarde else "false"
    else:
        tekst = str(waarde)
    return tekst.translate(_ESC)


@dataclass
class _Blok:
    soort: str
    naam: str
    kids: list[str | _Blok | _Plek]


@dataclass(frozen=True)
class _Plek:
    naam: str


def lees_boom(tpl: str) -> list[str | _Blok | _Plek]:
    """Het sjabloon als boom (referentie ``bouw/sjabloon.py``: ``lees``); ``ValueError`` bij een niet-gesloten of
    verkeerd genest blok."""
    wortel = _Blok("", "", [])
    stapel = [wortel]
    pos = 0
    for m in _TOKEN.finditer(tpl):
        top = stapel[-1]
        if m.start() > pos:
            top.kids.append(tpl[pos : m.start()])
        pos = m.end()
        if m.group(4):
            top.kids.append(_Plek(m.group(4)))
        elif not m.group(1):
            blok = _Blok(m.group(2), m.group(3), [])
            top.kids.append(blok)
            stapel.append(blok)
        else:
            if len(stapel) == 1 or top.soort != m.group(2) or top.naam != m.group(3):
                raise ValueError(f"sjabloon: onverwachte sluiting {m.group(0)}")
            stapel.pop()
    if len(stapel) != 1:
        raise ValueError(f"sjabloon: blok niet gesloten: {stapel[-1].soort}:{stapel[-1].naam}")
    if pos < len(tpl):
        wortel.kids.append(tpl[pos:])
    return wortel.kids


def _schrijf(knopen: list[str | _Blok | _Plek], data: Mapping[str, Any]) -> str:
    uit: list[str] = []
    for k in knopen:
        if isinstance(k, str):
            uit.append(k)
        elif isinstance(k, _Plek):
            uit.append(escape(data.get(k.naam)))
        elif k.soort == "ELK":
            for item in data.get(k.naam) or []:
                uit.append(_schrijf(k.kids, {**data, **item}))
        elif k.soort == "ALS":
            if data.get(k.naam):
                uit.append(_schrijf(k.kids, data))
        elif not data.get(k.naam):  # NIET
            uit.append(_schrijf(k.kids, data))
    return "".join(uit)


@functools.lru_cache(maxsize=8)
def _boom(tpl: str) -> list[str | _Blok | _Plek]:
    return lees_boom(tpl)


def render(tpl: str, data: Mapping[str, Any]) -> str:
    """Sjabloon invullen in één doorgang (zie moduledoc); de boom van een sjabloon wordt één keer gelezen."""
    try:
        boom = _boom(tpl)
    except ValueError as exc:
        raise SjabloonOntbreekt(str(exc)) from exc
    return _schrijf(boom, data)
