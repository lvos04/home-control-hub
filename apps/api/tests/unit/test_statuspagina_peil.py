"""Unit (HC11, ONTWERPTAAL §13.2 en §14, Peil 1.1.1, contract 1.3 §3.5/§3.7): de versie-gepinde Peil-kopie is intact en
gelijk aan de bron, de renderer vult in één doorgang (gelijk aan de referentie ``bouw/sjabloon.py``) en escapet alles,
en het paginamodel geeft per toestand precies één koppeltoestand, de juiste tonen en meldingsrol, en een totaal dat
nooit groen is als de dienst niet gereed is. Geen database nodig."""

from __future__ import annotations

import importlib.util
import itertools
import re
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from integrations import peil
from integrations.hublink_store import LastError, LinkState, Pending, Pin, Pins, PublicJwk
from integrations.status_page import (
    BRON_MAX_LEEFTIJD,
    FOUTEN,
    OPNIEUW_INVULLEN_NL,
    BronStand,
    Fout,
    Meldingen,
    Meting,
    bouw_model,
    host_toegestaan,
    koppeltoestand,
    nl_datumtijd,
)
from tests.conftest import REPO_ROOT

NU = datetime(2026, 11, 9, 11, 56, tzinfo=UTC)
FP = "MEGG-8GFG-2E4Y-K2RQ"  # testvector uit contract 1.3 §4.5
TRACE = "3d8a1f4e-6b2c-4e95-a7d0-91c5b8e2f364"
BRON_MAP = REPO_ROOT.parent / "ai-server-manager" / "design" / "ontwerptaal"


def _tool() -> ModuleType:
    name = "hch_peil_kopie"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / "tools" / "peil_kopie.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _pins() -> Pins:
    pin = Pin(kid="k1", jwk=PublicJwk(x="eA"), thumbprint="k1", pinned_at="2026-11-08T19:14:00Z")
    return Pins(jwt=[pin], policy=[pin], keyset_fingerprint=FP)


def _link(soort: str) -> LinkState:
    gekoppeld = {
        "state": "gekoppeld",
        "hub_url": "http://hub.test:30400",
        "service_id": "svc-1",
        "via": "koppelcode",
        "first_linked_at": "2026-11-08T19:14:00Z",
        "linked_at": "2026-11-08T19:14:00Z",
        "confirmed_at": "2026-11-08T19:14:01Z",
        "service_token": "svc_" + "a" * 43,
        "service_token_last4": "aaaa",
        "pins": _pins(),
    }
    if soort == "nooit":
        return LinkState()
    if soort == "nooit_mislukt":
        return LinkState(last_error=LastError(code="hub_weigerde", at="2026-11-09T11:50:00Z"))
    if soort == "bezig":
        return LinkState(
            pending=Pending(
                kind="token", secret_sha256="f" * 64, hub_url="http://hub.test:30400", started_at="2026-11-09T11:54:00Z"
            )
        )
    if soort == "gekoppeld_bezig":
        return LinkState(
            **gekoppeld,
            pending=Pending(
                kind="token", secret_sha256="e" * 64, hub_url="http://hub.test:30400", started_at="2026-11-09T11:54:00Z"
            ),
        )
    if soort == "gekoppeld":
        return LinkState(**gekoppeld)
    if soort == "onbevestigd":
        return LinkState(**{**gekoppeld, "confirmed_at": None})
    if soort == "rotatie_geweigerd":
        return LinkState(**{**gekoppeld, "key_rotation_blocked_sequence": 3})
    if soort in ("ontkoppeld", "ingetrokken"):
        return LinkState(
            **{**gekoppeld, "state": soort, "service_token": None, "pins": None, "previous_pins": _pins()},
            last_error=LastError(code="ingetrokken_door_hub", at="2026-11-09T10:00:00Z")
            if soort == "ingetrokken"
            else None,
        )
    if soort == "onleesbaar":
        st = LinkState()
        st._corrupt = True
        return st
    raise AssertionError(soort)


def _meting(link: LinkState, *, db_ok: bool = True, schema: str | None = "0003", **kw: Any) -> Meting:
    bronnen = kw.pop(
        "bronnen", (BronStand("network", True, "healthy", NU - timedelta(minutes=1)), BronStand("energy", False))
    )
    return Meting(
        nu=NU,
        db_ok=db_ok,
        schema_huidig=schema if db_ok else None,
        schema_verwacht="0003",
        geheimen=kw.pop("geheimen", {"vault.key": True, "identity.ed25519": True}),
        link=link,
        herstel_niveau=kw.pop("herstel", "ok") if db_ok else None,
        bronnen=bronnen if db_ok else (),
        herstel_accounts=kw.pop("accounts", 2) if db_ok else None,
        host_ok=kw.pop("host_ok", True),
    )


def _html(data: dict[str, Any]) -> str:
    return peil.render(peil.sjabloon().tekst, data)


FLAGS = ("koppelformulier", "gekoppeld", "ontkoppeld", "ingetrokken", "koppelstatus_onleesbaar")
ALLE = ["nooit", "nooit_mislukt", "bezig", "gekoppeld", "gekoppeld_bezig", "onbevestigd", "rotatie_geweigerd"]
ALLE += ["ontkoppeld", "ingetrokken", "onleesbaar"]


def _referentie() -> ModuleType | None:
    """De referentie-renderer van Peil 1.1.1 (``bouw/sjabloon.py`` in de bron), als die naast deze repo staat."""
    pad = BRON_MAP / "bouw" / "sjabloon.py"
    if not pad.is_file():
        return None
    spec = importlib.util.spec_from_file_location("peil_sjabloon_referentie", pad)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------ versie-gepinde kopie (O-14, E08)
def test_pinned_copy_is_intact_and_consistent() -> None:
    assert _tool().controleer() == []
    tpl = peil.sjabloon()
    assert tpl.intact and tpl.versie == "1.1.1" and tpl.bron.startswith("lvos04/ai-server-manager@")
    assert tpl.tekst.startswith("<!doctype html>\n<!-- Peil statuspagina-sjabloon 1.1.1 · sha256:")
    # het ontwikkelaarscommentaar (met plekken en woorden als 'ontkoppelcode') gaat niet mee naar de pagina
    assert "ontkoppelcode" not in tpl.tekst.split("<html", 1)[0]


def test_pinned_copy_detects_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    tool = _tool()
    kopie = tmp_path / "ontwerptaal"
    shutil.copytree(tool.MAP, kopie)
    monkeypatch.setattr(tool, "MAP", kopie)
    monkeypatch.setattr(tool, "HERKOMST", kopie / "HERKOMST.json")
    assert tool.controleer() == []
    css = kopie / "statuspagina.css"
    css.write_bytes(css.read_bytes().replace(b"--down:#B3141B", b"--down:#B3141C"))
    fouten = tool.controleer()
    assert any("statuspagina.css: inhoud gewijzigd" in f for f in fouten)
    assert any("ingebedde <style>" in f for f in fouten)
    # ook een gewijzigd sjabloon met een aangepaste kop valt op (HERKOMST.json pint de sha256)
    html = kopie / "statuspagina.html"
    kop, _, rest = html.read_bytes().partition(b"\n")
    rest = rest.replace(b"Koppelen met de Hub</button>", b"Koppelen</button>")
    nieuw = re.sub(rb"sha256:[0-9a-f]{64}", b"sha256:" + tool.sha256(rest).encode(), kop)
    html.write_bytes(nieuw + b"\n" + rest)
    assert any("statuspagina.html: sha256 in de kop wijkt af van HERKOMST.json" in f for f in tool.controleer())


def test_compare_with_source_drift_versus_newer_version(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin- en driftregel (Peil 1.1.1, E08) met ``vergelijk --online`` zonder netwerk: de bron wordt gesimuleerd (de
    echte online-stap draait in CI). Drift en dezelfde versie met andere inhoud = fout; een nieuwere versie = alleen een
    waarschuwing."""
    tool = _tool()
    herkomst = tool.lees_herkomst()
    kopie = {n: tool.splits((tool.MAP / n).read_bytes())[1] for n in tool.BESTANDEN}
    bron: dict[str, dict[str, bytes]] = {}

    def online(pad: str, ref: str) -> bytes:
        return bron[ref][pad.rsplit("/", 1)[1]]

    monkeypatch.setattr(tool, "haal_online", online)
    gepind, tak = str(herkomst["bron_commit"]), str(herkomst["bron_ref"])
    bron[gepind] = dict(kopie)
    bron[tak] = dict(kopie)
    assert tool.vergelijk(None, online=True) == ([], [])
    # zelfde versie, andere inhoud op de bronbranch = drift (fout)
    bron[tak] = {**kopie, "statuspagina.css": kopie["statuspagina.css"].replace(b"--down:#B3141B", b"--down:#B3141C")}
    fouten, _ = tool.vergelijk(None, online=True)
    assert fouten == ["online statuspagina.css: Peil 1.1.1 in de bron heeft andere inhoud dan de kopie (drift)"]
    # een nieuwere versie in de bron = waarschuwing (bewust bijwerken), geen fout
    bron[tak] = {n: d.replace(b"1.1.1", b"1.2.0", 2) for n, d in kopie.items()}
    fouten, waarschuwingen = tool.vergelijk(None, online=True)
    assert fouten == [] and len(waarschuwingen) == 2 and "Peil 1.2.0" in waarschuwingen[0]
    # de gepinde commit zelf wijkt af van de kopie = drift
    bron[gepind] = {**kopie, "statuspagina.html": kopie["statuspagina.html"] + b" "}
    fouten, _ = tool.vergelijk(None, online=True)
    assert any("kopie ≠ bron op de gepinde commit" in f for f in fouten)


@pytest.mark.skipif(not BRON_MAP.is_dir(), reason="geen lokale checkout van ai-server-manager (CI vergelijkt online)")
def test_pinned_copy_equals_local_source() -> None:
    fouten, waarschuwingen = _tool().vergelijk(BRON_MAP.parents[1], online=False)
    assert fouten == [], fouten
    print(*waarschuwingen, sep="\n")


def test_template_load_flags_tampering(tmp_path: Path) -> None:
    bron = peil.kandidaten(None)[-1].read_bytes()
    pad = tmp_path / "statuspagina.html"
    pad.write_bytes(bron.replace(b"Koppelen met de Hub</button>", b"Koppelen</button>"))
    assert peil.lees(pad).intact is False
    zonder = tmp_path / "zonder" / "statuspagina.html"
    zonder.parent.mkdir()
    zonder.write_bytes(bron.partition(b"\n")[2])
    with pytest.raises(peil.SjabloonOntbreekt):
        peil.lees(zonder)


# ------------------------------------------------------------------ renderer in één doorgang (E07)
def test_render_blocks_escape_and_single_pass() -> None:
    tpl = "<!--ALS:a-->A{{x}}<!--/ALS:a--><!--NIET:a-->N<!--/NIET:a--><!--ELK:l-->[{{n}}<!--ALS:r-->:{{r}}<!--/ALS:r-->]<!--/ELK:l-->"
    assert peil.render(tpl, {"a": True, "x": "<b>&'\"", "l": [{"n": 1}, {"n": 2, "r": "z"}]}) == (
        "A&lt;b&gt;&amp;&#39;&quot;[1][2:z]"
    )
    assert peil.render(tpl, {"a": False, "l": []}) == "N"
    # een waarde wordt nooit opnieuw als sjabloon gelezen (1.1.0 vulde een bronnaam '{{csrf_token}}' wél in)
    assert peil.render("{{x}}|{{y}}", {"x": "{{y}}", "y": "geheim"}) == "{{y}}|geheim"
    assert peil.render("{{x}}", {"x": "<!--ALS:y-->"}) == "&lt;!--ALS:y--&gt;"
    assert peil.render("<!--ELK:l-->{{n}}<!--/ELK:l-->", {"l": [{"n": "{{csrf_token}}"}], "csrf_token": "s"}) == (
        "{{csrf_token}}"
    )


def test_render_nested_blocks_and_truthiness() -> None:
    """Genest (ook NIET binnen ALS, en hetzelfde blok genest); onwaar = False, None, leeg, 0 en een lege lijst."""
    tpl = "<!--ALS:a--><!--NIET:b-->x<!--/NIET:b--><!--ALS:a-->y<!--/ALS:a--><!--/ALS:a-->"
    assert peil.render(tpl, {"a": "1", "b": ""}) == "xy"
    assert peil.render(tpl, {"a": "1", "b": "1"}) == "y"
    for onwaar in (False, None, "", 0, []):
        assert peil.render("<!--ALS:a-->j<!--/ALS:a--><!--NIET:a-->n<!--/NIET:a-->", {"a": onwaar}) == "n"
    assert peil.render("{{t}}|{{f}}", {"t": True, "f": False}) == "true|false"  # zoals de referentie (JavaScript)


@pytest.mark.parametrize(
    "kapot", ["<!--ALS:a-->x", "x<!--/ALS:a-->", "<!--ALS:a--><!--NIET:b--><!--/ALS:a--><!--/NIET:b-->"]
)
def test_render_refuses_broken_templates(kapot: str) -> None:
    with pytest.raises(peil.SjabloonOntbreekt):
        peil.render(kapot, {"a": True, "b": True})


@pytest.mark.skipif(_referentie() is None, reason="geen lokale checkout van ai-server-manager (bouw/sjabloon.py)")
@pytest.mark.parametrize("soort", ALLE)
def test_renderer_equals_the_reference_byte_for_byte(soort: str) -> None:
    """Peil 1.1.1 (E07): de Python-renderers van de diensten nemen ``bouw/sjabloon.py`` over; voor elke toestand van deze
    pagina is de uitvoer byte-gelijk aan die van de referentie."""
    ref = _referentie()
    assert ref is not None
    tekst = peil.sjabloon().tekst
    for fout in (None, Fout("hub_weigerde", TRACE)):
        data = bouw_model(_meting(_link(soort)), csrf="c" * 32, fout=fout)
        assert peil.render(tekst, data) == ref.render(tekst, data), soort


# ------------------------------------------------------------------ paginamodel per toestand (§3.5/§3.7)
@pytest.mark.parametrize(
    ("soort", "toestand"),
    [
        ("nooit", "koppelformulier"),
        ("nooit_mislukt", "koppelformulier"),
        ("bezig", "koppelformulier"),
        ("gekoppeld", "gekoppeld"),
        ("gekoppeld_bezig", "gekoppeld"),
        ("onbevestigd", "gekoppeld"),
        ("rotatie_geweigerd", "gekoppeld"),
        ("ontkoppeld", "ontkoppeld"),
        ("ingetrokken", "ingetrokken"),
        ("onleesbaar", "koppelstatus_onleesbaar"),
    ],
)
def test_exactly_one_link_state(soort: str, toestand: str) -> None:
    link = _link(soort)
    assert koppeltoestand(link) == toestand
    data = bouw_model(_meting(link), csrf="c" * 32)
    assert [f for f in FLAGS if data[f]] == [toestand]
    html = _html(data)
    # het formulier alleen bij nooit gekoppeld, leesbaar en zonder lopende poging
    assert ('action="/koppelen"' in html) == (toestand == "koppelformulier" and link.pending is None)
    assert ("novalidate" in html) == ('action="/koppelen"' in html)  # E09: server-side validatie met NL-teksten
    for verboden in ("ontkoppelcode", 'action="/ontkoppelen"', 'action="/beheer"', 'action="/schrijfsleutel"'):
        assert verboden not in html


def test_not_linked_is_never_green_and_shows_last_error() -> None:
    data = bouw_model(_meting(_link("nooit_mislukt")), csrf="c" * 32)
    assert (data["totaal_toon"], data["totaal_label"]) == ("onbekend", "Niet gereed")
    assert data["totaal_toelichting"] == "Deels onbekend — wacht op koppeling met de Hub."
    assert data["gereed"] == "Nee — wacht op koppeling met de Hub"
    assert data["titel_toestand"] == "niet gekoppeld, niet gereed"
    rij = next(r for r in data["checks"] if r["naam"] == "Koppeling met de Hub")
    # Peil 1.1.1 (E03/E04): toon niet-gekoppeld (link-2-off, telt als Onbekend) met het vaste woord
    assert (rij["toon"], rij["label"]) == ("niet-gekoppeld", "Niet gekoppeld")
    assert "Laatste melding, 9 nov 2026, 11:50 UTC (code hub_weigerde)" in rij["reden"]
    assert not data.get("melding")  # een opgeslagen fout is geen melding met trace-ID van dit verzoek
    html = _html(data)
    assert '<span class="pil pil-onbekend"><svg aria-hidden="true"><use href="#i-onbekend"/></svg>Niet gereed' in html
    assert '<use href="#i-niet-gekoppeld"/></svg>Niet gekoppeld</span>' in html
    assert "<title>Home Control Hub — niet gekoppeld, niet gereed</title>" in html
    assert "(verplicht)" in html and 'class="spring"' in html


def test_linked_and_confirmed_is_all_healthy_with_neutral_link_pill() -> None:
    data = bouw_model(_meting(_link("gekoppeld"), herstel="ok"), csrf="c" * 32, gekoppeld_melding=True)
    assert (data["totaal_toon"], data["totaal_label"], data["gereed"]) == ("gezond", "Alles gezond", "Ja")
    # niet ingesteld (gate) en beleid tellen niet mee (E10); dat staat erbij
    assert data["totaal_toelichting"] == (
        "Gereed. Alle controles en gemeten onderdelen zijn gezond. 3 onderdelen wachten op instelling of een verse "
        "meting."
    )
    assert all(r["naam"] != "Koppeling met de Hub" for r in data["checks"])  # alleen als er iets ontbreekt
    assert data["hub_adres"] == "http://hub.test:30400" and data["hub_vingerafdruk"] == FP
    assert data["gekoppeld_sinds"] == "8 nov 2026, 19:14 UTC"
    assert (data["melding_toon"], data["melding_rol"], data["melding_titel"]) == (
        "info",
        "status",
        "Gekoppeld met de Hub",
    )
    assert not data.get("trace_id")
    html = _html(data)
    assert (
        '<span class="pil pil-neutraal"><svg aria-hidden="true"><use href="#i-gekoppeld"/></svg>Gekoppeld</span>'
        in html
    )
    assert '<a class="knop knop-secundair" href="http://hub.test:30400">Hub openen</a>' in html and "svc_" not in html
    assert 'role="status" aria-labelledby="melding-titel"' in html


def test_success_notice_only_when_really_linked() -> None:
    for soort in ("nooit", "ontkoppeld", "ingetrokken", "onleesbaar"):
        data = bouw_model(_meting(_link(soort)), csrf="c" * 32, gekoppeld_melding=True)
        assert data.get("melding_titel") != "Gekoppeld met de Hub", soort


@pytest.mark.parametrize(
    ("soort", "toon", "label", "reden"),
    [
        ("onbevestigd", "onbekend", "Onbekend", "wacht op bevestiging door de Hub"),
        ("ingetrokken", "niet-gekoppeld", "Ingetrokken", "de Hub heeft de koppeling ingetrokken"),
        ("ontkoppeld", "niet-gekoppeld", "Ontkoppeld", "ontkoppeld door de Hub"),
        ("bezig", "niet-gekoppeld", "Niet gekoppeld", "er loopt een koppelpoging"),
    ],
)
def test_link_problems_make_the_service_not_ready(soort: str, toon: str, label: str, reden: str) -> None:
    data = bouw_model(_meting(_link(soort)), csrf="c" * 32)
    rij = next(r for r in data["checks"] if r["naam"] == "Koppeling met de Hub")
    assert (rij["toon"], rij["label"]) == (toon, label)
    assert "Ontkoppelen" not in rij["reden"]  # na intrekken/ontkoppelen kan alleen opnieuw koppelen
    assert data["totaal_toon"] == "onbekend" and data["totaal_label"] == "Niet gereed"
    assert data["gereed"] == f"Nee — {reden}"


def test_pairing_in_progress_hides_the_form_and_keeps_the_state() -> None:
    """Peil 1.1.1 (E02; contract 1.3 §3.7): ``koppelen_bezig`` verbergt formulier en stappen; de stabiele toestand
    blijft erboven staan, met de starttijd."""
    data = bouw_model(_meting(_link("bezig")), csrf="c" * 32)
    assert data["koppelformulier"] and data["koppelen_bezig"]
    assert (data["koppelen_bezig_sinds"], data["koppelen_bezig_iso"]) == ("11:54", "2026-11-09T11:54:00+00:00")
    rij = next(r for r in data["checks"] if r["naam"] == "Koppeling met de Hub")
    assert rij["reden"] == "Er loopt een koppelpoging sinds 11:54 (met het token uit de Custom App)."
    html = _html(data)
    assert 'action="/koppelen"' not in html and '<ol class="stappen">' not in html
    assert '<use href="#i-nog-niet"/></svg>Koppelen bezig</span>' in html
    assert '(gestart om <time datetime="2026-11-09T11:54:00+00:00">11:54</time>)' in html
    # ook een gekoppelde dienst met een nieuw env-token toont "Koppelen bezig" onder "Gekoppeld"
    html = _html(bouw_model(_meting(_link("gekoppeld_bezig")), csrf="c" * 32))
    assert html.index("</svg>Gekoppeld</span>") < html.index("</svg>Koppelen bezig</span>")


def test_orphaned_pairing_code_attempt_does_not_block_the_form() -> None:
    """Een verweesde koppelcodepoging (afgebroken verzoek, > 2 min) is geen 'Koppelen bezig': het formulier mag weer."""
    oud = LinkState(
        pending=Pending(
            kind="koppelcode",
            secret_sha256="c" * 64,
            hub_url="http://hub.test:30400",
            started_at="2026-01-01T00:00:00Z",
        )
    )
    data = bouw_model(_meting(oud), csrf="c" * 32)
    assert not data["koppelen_bezig"] and 'action="/koppelen"' in _html(data)


def test_unreadable_link_file_is_storing_without_form_and_without_live_region() -> None:
    """Peil 1.1.1 (E01/E05/E06; contract 1.3 §3.5): Storing · Niet gereed; melding met code en pad, zonder rol en
    zonder trace-ID (een toestand die bij het laden al bestond); geen formulier."""
    data = bouw_model(_meting(_link("onleesbaar")), csrf="c" * 32)
    assert (data["totaal_toon"], data["totaal_label"]) == ("storing", "Niet gereed")
    assert data["totaal_toelichting"] == "Storing — koppelstatus onleesbaar."
    assert data["gereed"] == "Nee — koppelstatus onleesbaar"
    assert (data["melding_code"], data["melding_toon"], data["melding_rol"]) == ("koppelstatus_onleesbaar", "fout", "")
    assert data["melding_pad"] == "/appdata/secrets/hub-link.json" and not data.get("trace_id")
    rij = next(r for r in data["checks"] if r["naam"] == "Koppeling met de Hub")
    assert (rij["toon"], rij["label"], rij["reden_code"]) == ("storing", "Onleesbaar", "koppelstatus_onleesbaar")
    html = _html(data)
    assert "Code <code>koppelstatus_onleesbaar</code>" in html and 'class="selecteer"' not in html
    assert 'role="alert"' not in html and 'action="/koppelen"' not in html
    assert "Hier staat bewust geen formulier." in html and "(code <code>koppelstatus_onleesbaar</code>)" in html


def test_database_down_is_storing_and_nothing_is_guessed() -> None:
    data = bouw_model(_meting(_link("gekoppeld"), db_ok=False), csrf="c" * 32)
    assert (data["totaal_toon"], data["totaal_label"]) == ("storing", "Niet gereed")
    assert data["gereed"] == "Nee — de eigen database antwoordt niet"
    schema = next(r for r in data["checks"] if r["naam"] == "Databaseschema")
    assert schema["toon"] == "onbekend" and schema["reden"] == "Niet te meten zonder database."
    tonen = {r["naam"]: r["toon"] for r in data["dienst_blok"]}
    assert tonen.pop("Boiler") == "beleid" and set(tonen.values()) == {"onbekend"}


def test_schema_and_secrets_failures() -> None:
    data = bouw_model(_meting(_link("gekoppeld"), schema="0002"), csrf="c" * 32)
    assert data["totaal_toon"] == "storing" and "het databaseschema klopt niet" in data["gereed"]
    data = bouw_model(_meting(_link("gekoppeld"), geheimen={"vault.key": False, "identity.ed25519": True}), csrf="c")
    rij = next(r for r in data["checks"] if r["naam"] == "Sleutels van de dienst")
    assert rij["toon"] == "storing" and "vault.key" in rij["reden"] and data["totaal_toon"] == "storing"


def test_refused_key_rotation_is_limited_but_ready() -> None:
    data = bouw_model(_meting(_link("rotatie_geweigerd"), herstel="ok"), csrf="c" * 32)
    assert (data["totaal_toon"], data["totaal_label"], data["gereed"]) == ("beperkt", "Beperkt", "Ja")
    assert data["totaal_toelichting"] == "Gereed, maar beperkt: Sleutels van de Hub."
    rij = next(r for r in data["checks"] if r["naam"] == "Sleutels van de Hub")
    assert rij["reden_code"] == "sleutelrotatie_geweigerd"


def test_total_rule_service_block_counts_at_most_limited() -> None:
    """Peil 1.1.1 (E10): een verse Storing in het dienstblok maakt het totaal hooguit Beperkt; gate, beleid en verouderd
    tellen niet mee; Onbekend in het dienstblok maakt het totaal Deels onbekend (nooit groen)."""
    bronnen = (
        BronStand("network", True, "healthy", NU - timedelta(minutes=3)),
        BronStand("network", True, "down", NU - timedelta(minutes=1)),
        BronStand("automation", True, "unknown", None),
    )
    data = bouw_model(_meting(_link("gekoppeld"), bronnen=bronnen, herstel="ok"), csrf="c")
    rijen = {r["naam"]: r for r in data["dienst_blok"]}
    assert rijen["Netwerk en privacy (B10)"]["toon"] == "storing"
    assert (
        rijen["Netwerk en privacy (B10)"]["reden"]
        == "2 van 5 bronnen ingesteld: 1 storing, 1 gezond. Laatst gemeten 9 nov 2026, 11:55 UTC."
    )
    assert rijen["Node-RED-automatisering (B11)"]["toon"] == "onbekend"
    assert rijen["Node-RED-automatisering (B11)"]["reden"] == "1 van 1 bron ingesteld: 1 nog nooit gemeten."
    assert (rijen["Energie en resources (B14)"]["toon"], rijen["Energie en resources (B14)"]["label"]) == (
        "gate",
        "Niet ingesteld",
    )
    assert rijen["Energie en resources (B14)"]["reden"].startswith("Nog geen bron ingesteld")
    assert rijen["Beheerherstel (B13-001)"]["toon"] == "gezond"
    assert rijen["Boiler"]["label"] == "Alleen meten" and rijen["Boiler"]["toon"] == "beleid"
    # een uitgevallen bron maakt de dienst zelf niet 'storing': hooguit Beperkt
    assert (data["totaal_toon"], data["totaal_label"]) == ("beperkt", "Beperkt")
    assert data["totaal_toelichting"] == "Gereed, maar beperkt: Netwerk en privacy (B10)."
    # alleen een onbekende meting in het dienstblok: Deels onbekend
    alleen = (BronStand("automation", True, "unknown", None),)
    data = bouw_model(_meting(_link("gekoppeld"), bronnen=alleen, herstel="ok"), csrf="c")
    assert (data["totaal_toon"], data["totaal_label"]) == ("onbekend", "Deels onbekend")
    assert data["totaal_toelichting"] == "Gereed, maar deels onbekend: Node-RED-automatisering (B11)."


def test_not_ready_with_a_limited_service_block_says_why() -> None:
    """Niet gereed + een beperkt onderdeel in het dienstblok: de pil wordt Beperkt (E10) en de toelichting noemt de
    reden van niet gereed én het onderdeel; nooit groen."""
    data = bouw_model(_meting(_link("nooit"), herstel="risico"), csrf="c")
    assert (data["totaal_toon"], data["totaal_label"]) == ("beperkt", "Niet gereed")
    assert data["totaal_toelichting"] == (
        "Deels onbekend — wacht op koppeling met de Hub. Daarnaast beperkt: Beheerherstel (B13-001)."
    )


def test_empty_recovery_register_waits_and_does_not_count() -> None:
    data = bouw_model(_meting(_link("gekoppeld"), herstel="onbekend", accounts=0), csrf="c")
    rij = next(r for r in data["dienst_blok"] if r["naam"] == "Beheerherstel (B13-001)")
    assert (rij["toon"], rij["label"]) == ("gate", "Niet ingevuld")
    assert data["totaal_toon"] == "gezond"


# ------------------------------------------------------------------ verouderd (Peil §4.4, E15; contract §6.2)
def test_stale_measurement_is_never_green() -> None:
    """Een oude meting is nooit de laatst bekende stand als actueel: alleen oude metingen → Verouderd met de tijd van
    de laatste meting (telt niet mee); een verse en een oude meting → de verse telt, de oude staat erbij."""
    oud = NU - BRON_MAX_LEEFTIJD - timedelta(seconds=1)
    bronnen = (
        BronStand("sso", True, "healthy", oud),
        BronStand("network", True, "healthy", NU - timedelta(minutes=2)),
        BronStand("network", True, "healthy", NU - timedelta(days=3)),
        BronStand("energy", True, "down", oud),
    )
    data = bouw_model(_meting(_link("gekoppeld"), bronnen=bronnen, herstel="ok"), csrf="c")
    rijen = {r["naam"]: r for r in data["dienst_blok"]}
    sso = rijen["Authentik en toegangsbeheer (B13)"]
    assert (sso["toon"], sso["label"]) == ("verouderd", "Verouderd · laatst bekend 11:40")
    assert sso["reden"] == (
        "1 van 1 bron ingesteld: 1 verouderd (laatst bekend 9 nov 2026, 11:40 UTC). Metingen ouder dan 15 minuten "
        "tonen we niet als actueel."
    )
    net = rijen["Netwerk en privacy (B10)"]
    assert (net["toon"], net["reden_code"]) == ("gezond", "meting_verouderd") and net["reden"] == (
        "2 van 5 bronnen ingesteld: 1 verouderd (laatst bekend 6 nov 2026, 11:56 UTC), 1 gezond. Laatst gemeten "
        "9 nov 2026, 11:54 UTC. Metingen ouder dan 15 minuten tonen we niet als actueel."
    )
    # ook een oude storing is geen actuele storing
    assert rijen["Energie en resources (B14)"]["toon"] == "verouderd"
    assert data["totaal_toon"] == "gezond"  # verouderd telt niet mee (E10); de pagina zegt wel dat iets wacht
    # precies op de grens is nog vers
    grens = (BronStand("sso", True, "healthy", NU - BRON_MAX_LEEFTIJD),)
    data = bouw_model(_meting(_link("gekoppeld"), bronnen=grens), csrf="c")
    assert {r["naam"]: r["toon"] for r in data["dienst_blok"]}["Authentik en toegangsbeheer (B13)"] == "gezond"


@pytest.mark.parametrize(
    ("niveau", "toon", "begin"),
    [
        ("ok", "gezond", "Alleen het totaalniveau staat hier"),
        ("risico", "beperkt", "Het herstelregister heeft aandachtspunten."),
        ("onbekend", "onbekend", "Het herstelregister is nog niet volledig ingevuld of getest."),
    ],
)
def test_recovery_level_always_has_a_reason(niveau: str, toon: str, begin: str) -> None:
    data = bouw_model(_meting(_link("gekoppeld"), herstel=niveau), csrf="c")
    rij = next(r for r in data["dienst_blok"] if r["naam"] == "Beheerherstel (B13-001)")
    assert (
        rij["toon"] == toon
        and rij["reden"].startswith(begin)
        and "details en oefeningen staan in de Hub" in rij["reden"]
    )


def test_pill_words_follow_the_tone() -> None:
    """Elke pil draagt het vaste Peil-woord bij zijn toon (ONTWERPTAAL §7, §11.1, 1.1.1)."""
    woorden = {
        "gezond": {"Gezond"},
        "beperkt": {"Beperkt"},
        "storing": {"Storing", "Onleesbaar"},
        "onbekend": {"Onbekend"},
        "niet-gekoppeld": {"Niet gekoppeld", "Ontkoppeld", "Ingetrokken"},
        "gate": {"Niet ingesteld", "Niet ingevuld"},
        "beleid": {"Alleen meten"},
    }
    for soort in ALLE:
        for db_ok in (True, False):
            data = bouw_model(_meting(_link(soort), db_ok=db_ok), csrf="c")
            for r in [*data["checks"], *data["dienst_blok"]]:
                assert r["label"] in woorden[r["toon"]], (soort, r)
                assert r["toon"] in peil.TONEN


def test_failed_attempt_says_fields_must_be_filled_in_again() -> None:
    """Ingevulde waarden worden nooit teruggezet (veiligheid, WCAG 3.3.7-uitzondering); de melding zegt dat."""
    for code in ("hub_weigerde", "ongeldige_koppelcode", "hub_onbereikbaar"):
        data = bouw_model(_meting(_link("nooit")), csrf="c", fout=Fout(code, TRACE))
        assert data["melding_tekst"].endswith(OPNIEUW_INVULLEN_NL), code
        assert data["melding_tekst"].count("opnieuw in") == 1, code
    for code in ("te_veel_pogingen", "koppelen_bezig", "rate_limited", "ongeldig_formulier", "herkomst_onjuist"):
        data = bouw_model(_meting(_link("nooit")), csrf="c", fout=Fout(code, TRACE))
        assert OPNIEUW_INVULLEN_NL not in data["melding_tekst"], code
    data = bouw_model(_meting(_link("gekoppeld")), csrf="c", fout=Fout("al_gekoppeld", TRACE))
    assert OPNIEUW_INVULLEN_NL not in data["melding_tekst"]


def test_header_copy_is_short_and_not_repeated() -> None:
    data = bouw_model(_meting(_link("nooit")), csrf="c")
    html = _html(data)
    # "Alle schermen staan in de Hub" staat al in de voet van het sjabloon; niet nog eens in de kop
    assert html.count("Alle schermen staan in de Hub") == 1
    assert "TrueNAS Home Platform" not in data["dienst_omschrijving"]


@pytest.mark.parametrize("code", sorted(FOUTEN))
def test_every_failure_has_status_code_trace_id_role_and_field(code: str) -> None:
    soort = FOUTEN[code]
    link = _link("gekoppeld") if code == "al_gekoppeld" else _link("onleesbaar" if "onleesbaar" in code else "nooit")
    data = bouw_model(_meting(link), csrf="c" * 32, fout=Fout(code, TRACE))
    assert 400 <= soort.status <= 599
    assert data["melding_code"] == code and data["trace_id"] == TRACE and data["melding_toon"] == "fout"
    assert data["melding_rol"] == "alert"  # de fout van dít verzoek (E05)
    assert data["titel_toestand"].endswith("(koppelen mislukt)")
    html = _html(data)
    assert f"Code <code>{code}</code>" in html and f'<code class="selecteer">{TRACE}</code>' in html
    assert 'role="alert"' in html
    if soort.veld is not None and data["koppelformulier"]:
        veld_id = {"hub_adres": "hub", "koppelcode": "koppelcode", "vingerafdruk": "vingerafdruk"}[soort.veld]
        assert data["spring_doel"] == veld_id and data["melding_link_doel"] == veld_id
        assert re.search(rf'<input id="{veld_id}"[^>]*aria-invalid="true"', html)
        assert html.count('aria-invalid="true"') == 1
    else:
        assert 'aria-invalid="true"' not in html


def test_unsafe_hub_address_is_never_a_link() -> None:
    link = _link("gekoppeld")
    for slecht in ("javascript:alert(1)", 'http://x"><script>alert(1)</script>', "ftp://hub.test"):
        link.hub_url = slecht
        data = bouw_model(_meting(link), csrf="c")
        assert data["hub_adres"] == ""
        assert "<script" not in _html(data) and "javascript:" not in _html(data)


def test_host_notice_before_filling_in_the_form() -> None:
    """§3.7 punt 4: via een domeinnaam kan niet gekoppeld worden; dat staat er vóór iemand het formulier invult (een
    toestand bij het laden: geen live-regio)."""
    data = bouw_model(_meting(_link("nooit"), host_ok=False), csrf="c")
    assert (data["melding_code"], data["melding_toon"], data["melding_rol"]) == ("host_niet_toegestaan", "info", "")
    assert "IP-adres van de NAS" in data["melding_tekst"]
    assert not bouw_model(_meting(_link("gekoppeld"), host_ok=False), csrf="c").get("melding")


def test_invariants_over_all_combinations() -> None:
    for soort, db_ok, schema, fout, host_ok in itertools.product(
        ALLE, (True, False), ("0003", "0002"), (None, "hub_weigerde"), (True, False)
    ):
        data = bouw_model(
            _meting(_link(soort), db_ok=db_ok, schema=schema, host_ok=host_ok),
            csrf="c" * 32,
            fout=Fout(fout, TRACE) if fout else None,
        )
        plek = f"{soort}/{db_ok}/{schema}/{fout}/{host_ok}"
        if data["gereed"] != "Ja":
            assert data["totaal_toon"] != "gezond" and data["totaal_label"] == "Niet gereed", plek
        assert data["totaal_toon"] in peil.TOTAAL_TONEN, plek
        tonen = [r["toon"] for r in data["checks"]] + [r["toon"] for r in data["dienst_blok"]]
        assert all(t in peil.TONEN for t in tonen), plek
        assert sum(bool(data[f]) for f in FLAGS) == 1, plek
        if data.get("melding"):
            assert data["melding_rol"] == ("alert" if fout else data["melding_rol"]), plek
            assert data["melding_rol"] in ("alert", "status", ""), plek
        html = _html(data)
        assert "{{" not in html and "<!--ALS" not in html and "<!--ELK" not in html, plek
        assert html.count("<h1>") == 1 and "<script" not in html, plek
        ids = re.findall(r' id="([^"]+)"', html)
        assert len(ids) == len(set(ids)), plek


# ------------------------------------------------------------------ herkomst en meldingen (contract 1.3 §3.7)
@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("192.168.1.10:30420", True),
        ("192.168.1.10", True),
        ("[fd00::10]:30420", True),
        ("[::1]", True),
        ("nas:30420", True),
        ("localhost:30420", True),
        ("nas.local:30420", True),
        ("NAS.Lan", True),
        ("truenas.internal", True),
        ("nas.home.arpa:30420", True),
        ("nas.local.:30420", True),  # één punt aan het eind telt niet mee
        ("testserver", True),
        ("evil.example:30420", False),  # publieke domeinnaam (DNS-rebinding)
        ("nas.fritz.box", False),  # .box is een publieke TLD (K1)
        ("local", True),
        ("x.local.evil.example", False),
        ("127.1", False),  # afwijkende IPv4-vormen (§3.2)
        ("2130706433", False),
        ("0x7f000001", False),
        ("010.0.0.1", False),
        ("fd00::10", False),  # IPv6 zonder []
        ("[fd00::10", False),
        ("[nietip]:80", False),
        ("nas:poort", False),
        ("nas..local", False),
        ("", False),
        (None, False),
        ("nas local", False),
    ],
)
def test_host_restriction(host: str | None, ok: bool) -> None:
    assert host_toegestaan(host) is ok


def test_notices_belong_to_this_browser_and_expire() -> None:
    m = Meldingen(geldig_s=60)
    sleutel = m.maak("gekoppeld", "cookie-a" * 4)
    assert m.lees(sleutel, "cookie-a" * 4) == "gekoppeld"
    assert m.lees(sleutel, "cookie-b" * 4) is None  # een andere browser
    assert m.lees(sleutel, None) is None and m.lees("gekoppeld", "cookie-a" * 4) is None  # alleen een parameter
    verlopen = Meldingen(geldig_s=-1)
    oud = verlopen.maak("gekoppeld", "c" * 32)
    assert verlopen.lees(oud, "c" * 32) is None


def test_nl_datetime() -> None:
    assert nl_datumtijd(datetime(2026, 3, 1, 7, 5, tzinfo=UTC)) == "1 mrt 2026, 07:05 UTC"
