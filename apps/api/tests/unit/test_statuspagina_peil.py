"""Unit (HC11, ONTWERPTAAL §13.2, O-14): de versie-gepinde Peil-kopie is intact en gelijk aan de bron, de renderer
vult in één doorgang en escapet alles, en het paginamodel geeft per toestand precies één koppeltoestand en een eerste
signaal dat nooit groen is als de dienst niet gereed is. Geen database nodig."""

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
from integrations.status_page import FOUTEN, BronStand, Fout, Meting, bouw_model, koppeltoestand, nl_datumtijd
from tests.conftest import REPO_ROOT

NU = datetime(2026, 11, 9, 11, 56, tzinfo=UTC)
FP = "MEGG-8GFG-2E4Y-K2RQ"  # testvector uit contract 1.2 §4.5
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
            pending=Pending(kind="token", secret_sha256="f" * 64, hub_url="http://hub.test:30400", started_at="x")
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
        herstel_niveau=kw.pop("herstel", "risico") if db_ok else None,
        bronnen=bronnen if db_ok else (),
    )


def _html(data: dict[str, Any]) -> str:
    return peil.render(peil.sjabloon().tekst, data)


FLAGS = ("koppelformulier", "gekoppeld", "ontkoppeld", "ingetrokken")


# ------------------------------------------------------------------ versie-gepinde kopie (O-14)
def test_pinned_copy_is_intact_and_consistent() -> None:
    assert _tool().controleer() == []
    tpl = peil.sjabloon()
    assert tpl.intact and tpl.versie == "1.1.0" and tpl.bron.startswith("lvos04/ai-server-manager@")
    assert tpl.tekst.startswith("<!doctype html>\n<!-- Peil statuspagina-sjabloon 1.1.0 · sha256:")
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
    """``vergelijk --online`` zonder netwerk: de bron wordt gesimuleerd (de echte online-stap draait in CI)."""
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
    assert fouten == ["online statuspagina.css: Peil 1.1.0 in de bron heeft andere inhoud dan de kopie (drift)"]
    # een nieuwere versie in de bron = waarschuwing (bewust bijwerken), geen fout
    bron[tak] = {n: d.replace(b"1.1.0", b"1.2.0", 2) for n, d in kopie.items()}
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


# ------------------------------------------------------------------ renderer
def test_render_blocks_escape_and_single_pass() -> None:
    tpl = "<!--ALS:a-->A{{x}}<!--/ALS:a--><!--NIET:a-->N<!--/NIET:a--><!--ELK:l-->[{{n}}<!--ALS:r-->:{{r}}<!--/ALS:r-->]<!--/ELK:l-->"
    assert peil.render(tpl, {"a": True, "x": "<b>&'\"", "l": [{"n": 1}, {"n": 2, "r": "z"}]}) == (
        "A&lt;b&gt;&amp;&#39;&quot;[1][2:z]"
    )
    assert peil.render(tpl, {"a": False, "l": []}) == "N"
    # een waarde wordt nooit opnieuw als sjabloon gelezen
    assert peil.render("{{x}}|{{y}}", {"x": "{{y}}", "y": "geheim"}) == "{{y}}|geheim"
    assert peil.render("{{x}}", {"x": "<!--ALS:y-->"}) == "&lt;!--ALS:y--&gt;"


# ------------------------------------------------------------------ paginamodel per toestand
@pytest.mark.parametrize(
    ("soort", "toestand"),
    [
        ("nooit", "koppelformulier"),
        ("nooit_mislukt", "koppelformulier"),
        ("bezig", "koppelformulier"),
        ("gekoppeld", "gekoppeld"),
        ("onbevestigd", "gekoppeld"),
        ("rotatie_geweigerd", "gekoppeld"),
        ("ontkoppeld", "ontkoppeld"),
        ("ingetrokken", "ingetrokken"),
        ("onleesbaar", None),
    ],
)
def test_exactly_one_link_state(soort: str, toestand: str | None) -> None:
    link = _link(soort)
    assert koppeltoestand(link) == toestand
    data = bouw_model(_meting(link), csrf="c" * 32, melding_trace_id=TRACE)
    assert [f for f in FLAGS if data[f]] == ([toestand] if toestand else [])
    html = _html(data)
    assert ('action="/koppelen"' in html) == (toestand == "koppelformulier")
    for verboden in ("ontkoppelcode", 'action="/ontkoppelen"', 'action="/beheer"', 'action="/schrijfsleutel"'):
        assert verboden not in html


def test_not_linked_is_never_green_and_shows_last_error() -> None:
    data = bouw_model(_meting(_link("nooit_mislukt")), csrf="c" * 32)
    assert (data["totaal_toon"], data["totaal_label"]) == ("onbekend", "Niet gereed")
    assert data["totaal_toelichting"] == "Deels onbekend — wacht op koppeling met de Hub."
    assert data["gereed"] == "Nee — wacht op koppeling met de Hub"
    assert data["titel_toestand"] == "niet gekoppeld, niet gereed"
    rij = next(r for r in data["checks"] if r["naam"] == "Koppeling met de Hub")
    assert rij["toon"] == "onbekend" and rij["label"] == "Niet gekoppeld"
    assert "code hub_weigerde" in rij["reden"] and "9 nov 2026, 11:50 UTC" in rij["reden"]
    assert not data.get("melding")  # een opgeslagen fout is geen melding met trace-ID van dit verzoek
    html = _html(data)
    assert '<span class="pil pil-onbekend"><svg aria-hidden="true"><use href="#i-onbekend"/></svg>Niet gereed' in html
    assert "<title>Home Control Hub — niet gekoppeld, niet gereed</title>" in html


def test_linked_and_confirmed_is_healthy_with_neutral_link_pill() -> None:
    data = bouw_model(_meting(_link("gekoppeld")), csrf="c" * 32, gekoppeld_melding=True)
    assert (data["totaal_toon"], data["totaal_label"], data["gereed"]) == ("gezond", "Gezond", "Ja")
    assert data["totaal_toelichting"] == "Gereed; onderdelen hieronder: 1 beperkt · 3 onbekend."
    assert all(r["naam"] != "Koppeling met de Hub" for r in data["checks"])  # alleen als er iets ontbreekt
    assert data["hub_adres"] == "http://hub.test:30400" and data["hub_vingerafdruk"] == FP
    assert data["gekoppeld_sinds"] == "8 nov 2026, 19:14 UTC"
    assert (
        data["melding_toon"] == "info" and data["melding_titel"] == "Gekoppeld met de Hub" and not data.get("trace_id")
    )
    html = _html(data)
    assert (
        '<span class="pil pil-neutraal"><svg aria-hidden="true"><use href="#i-gekoppeld"/></svg>Gekoppeld</span>'
        in html
    )
    assert '<a href="http://hub.test:30400">Hub openen</a>' in html and "svc_" not in html


def test_success_notice_only_when_really_linked() -> None:
    for soort in ("nooit", "ontkoppeld", "ingetrokken"):
        data = bouw_model(_meting(_link(soort)), csrf="c" * 32, gekoppeld_melding=True)
        assert not data.get("melding"), soort


@pytest.mark.parametrize(
    ("soort", "label", "reden"),
    [
        ("onbevestigd", "Niet bevestigd", "wacht op bevestiging door de Hub"),
        ("ingetrokken", "Ingetrokken", "de Hub heeft de koppeling ingetrokken"),
        ("ontkoppeld", "Ontkoppeld", "ontkoppeld door de Hub"),
        ("bezig", "Koppelen bezig", "koppelen is bezig"),
    ],
)
def test_link_problems_make_the_service_not_ready(soort: str, label: str, reden: str) -> None:
    data = bouw_model(_meting(_link(soort)), csrf="c" * 32)
    rij = next(r for r in data["checks"] if r["naam"] == "Koppeling met de Hub")
    assert (rij["toon"], rij["label"]) == ("onbekend", label)
    assert data["totaal_toon"] == "onbekend" and data["totaal_label"] == "Niet gereed"
    assert data["gereed"] == f"Nee — {reden}"


def test_unreadable_link_file_shows_error_with_code_and_trace_id() -> None:
    data = bouw_model(_meting(_link("onleesbaar")), csrf="c" * 32, melding_trace_id=TRACE)
    assert data["totaal_toon"] == "storing" and data["gereed"] == "Nee — koppelstatus onleesbaar"
    assert (data["melding_code"], data["trace_id"], data["melding_toon"]) == ("koppelstatus_onleesbaar", TRACE, "fout")
    html = _html(data)
    assert f'<code class="selecteer">{TRACE}</code>' in html and "Code <code>koppelstatus_onleesbaar</code>" in html


def test_database_down_is_storing_and_nothing_is_guessed() -> None:
    data = bouw_model(_meting(_link("gekoppeld"), db_ok=False), csrf="c" * 32)
    assert (data["totaal_toon"], data["totaal_label"]) == ("storing", "Storing")
    assert data["gereed"] == "Nee — de eigen database antwoordt niet"
    schema = next(r for r in data["checks"] if r["naam"] == "Databaseschema")
    assert schema["toon"] == "onbekend" and schema["reden"] == "Niet te meten zonder database."
    tonen = {r["naam"]: r["toon"] for r in data["dienst_blok"]}
    assert tonen.pop("Boiler") == "gate" and set(tonen.values()) == {"onbekend"}


def test_schema_and_secrets_failures() -> None:
    data = bouw_model(_meting(_link("gekoppeld"), schema="0002"), csrf="c" * 32)
    assert data["totaal_toon"] == "storing" and "het databaseschema klopt niet" in data["gereed"]
    data = bouw_model(_meting(_link("gekoppeld"), geheimen={"vault.key": False, "identity.ed25519": True}), csrf="c")
    rij = next(r for r in data["checks"] if r["naam"] == "Sleutels van de dienst")
    assert rij["toon"] == "storing" and "vault.key" in rij["reden"] and data["totaal_toon"] == "storing"


def test_refused_key_rotation_is_limited_but_ready() -> None:
    data = bouw_model(_meting(_link("rotatie_geweigerd")), csrf="c" * 32)
    assert (data["totaal_toon"], data["totaal_label"], data["gereed"]) == ("beperkt", "Beperkt", "Ja")
    assert data["totaal_toelichting"] == "Gereed; beperkt: sleutels van de hub."


def test_sources_and_recovery_level_in_service_block() -> None:
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
        == "2 van 5 bronnen ingesteld · laatst gemeten 9 nov 2026, 11:55 UTC."
    )
    assert rijen["Node-RED-automatisering (B11)"]["toon"] == "onbekend"
    assert "nog niet gemeten" in rijen["Node-RED-automatisering (B11)"]["reden"]
    assert rijen["Energie en resources (B14)"]["reden"].startswith("Nog geen bron ingesteld")
    assert rijen["Beheerherstel (B13-001)"]["toon"] == "gezond"
    assert rijen["Boiler"]["label"] == "Alleen meten" and rijen["Boiler"]["toon"] == "gate"
    # een uitgevallen bron maakt de dienst zelf niet 'storing', maar de telling staat wel bij het totaal
    assert data["totaal_toon"] == "gezond" and "1 storing" in data["totaal_toelichting"]


@pytest.mark.parametrize("code", sorted(FOUTEN))
def test_every_failure_has_status_code_trace_id_and_field(code: str) -> None:
    soort = FOUTEN[code]
    link = _link("gekoppeld") if code == "al_gekoppeld" else _link("nooit")
    data = bouw_model(_meting(link), csrf="c" * 32, fout=Fout(code, TRACE))
    assert 400 <= soort.status <= 599
    assert data["melding_code"] == code and data["trace_id"] == TRACE and data["melding_toon"] == "fout"
    assert data["titel_toestand"].endswith("(koppelen mislukt)")
    html = _html(data)
    assert f"Code <code>{code}</code>" in html and f'<code class="selecteer">{TRACE}</code>' in html
    if soort.veld is not None:
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


def test_invariants_over_all_combinations() -> None:
    soorten = ["nooit", "nooit_mislukt", "bezig", "gekoppeld", "onbevestigd", "rotatie_geweigerd", "ontkoppeld"]
    soorten += ["ingetrokken", "onleesbaar"]
    for soort, db_ok, schema, fout in itertools.product(
        soorten, (True, False), ("0003", "0002"), (None, "hub_weigerde")
    ):
        data = bouw_model(
            _meting(_link(soort), db_ok=db_ok, schema=schema),
            csrf="c" * 32,
            fout=Fout(fout, TRACE) if fout else None,
            melding_trace_id=TRACE,
        )
        plek = f"{soort}/{db_ok}/{schema}/{fout}"
        if data["gereed"] != "Ja":
            assert data["totaal_toon"] != "gezond", plek
        tonen = [r["toon"] for r in data["checks"]] + [r["toon"] for r in data["dienst_blok"]]
        assert all(t in peil.TONEN for t in [*tonen, data["totaal_toon"]]), plek
        html = _html(data)
        assert "{{" not in html and "<!--ALS" not in html and "<!--ELK" not in html, plek
        assert html.count("<h1>") == 1 and "<script" not in html, plek
        ids = re.findall(r' id="([^"]+)"', html)
        assert len(ids) == len(set(ids)), plek


def test_nl_datetime() -> None:
    assert nl_datumtijd(datetime(2026, 3, 1, 7, 5, tzinfo=UTC)) == "1 mrt 2026, 07:05 UTC"
