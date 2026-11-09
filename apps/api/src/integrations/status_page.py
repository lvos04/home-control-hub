"""Nederlandse statuspagina op ``GET /`` in Peil (ONTWERPTAAL §13.2) + koppelen met koppelcode (contract 1.2 §3.7).

Uiterlijk: het framework-vrije Peil-sjabloon (``peil.py``; versie-gepinde kopie in ``design/ontwerptaal``). Geen
JavaScript, geen externe bron; strikte CSP ``default-src 'none'``. Ontwerpstap en keuzes: ADR-0011.

Inhoud en veiligheid:
- **Eerste signaal nooit groen als de dienst niet gereed is:** de totaalpil is de slechtste van de controles, en
  "gereed" vraagt database, schema, sleutels én een door de Hub bevestigde koppeling. "Gekoppeld" is een neutrale pil.
- Geen geheimen, accountnamen of aandachtspunten van het herstelregister; van de koppeling alleen de witte lijst (§3.5).
- Precies één koppeltoestand: ``koppelformulier`` (alleen zolang de dienst **nog nooit** gekoppeld is,
  ``first_linked_at`` leeg) · ``gekoppeld`` · ``ontkoppeld`` · ``ingetrokken``. Geen ontkoppelen, geen lokale
  ontkoppelcode en geen herkoppelen na intrekking op deze pagina; dat gaat via de Hub (§3.8).
- Formulier: Hub-adres (zelfde regels als ``HUB_URL``), koppelcode en de verplichte Hub-vingerafdruk. CSRF-token
  (double-submit-cookie, ``SameSite=Strict``, HttpOnly) + ``Origin``-controle. Rate-limit: max. 5 pogingen per 15 min
  per bron-IP (adres van de TCP-verbinding; ``X-Forwarded-For`` wordt nooit gebruikt) én 20 per 15 min voor de hele
  dienst; overschrijding → vaste melding, geen verzoek naar de Hub. De teller staat in het geheugen: de image draait
  precies één API-proces.
- Een **mislukte** poging geeft direct de pagina terug met een passende HTTP-status, een vaste Nederlandse melding,
  de vaste code en de trace-ID van dát verzoek (selecteerbaar; ook in de log en de auditregel). Ingevulde waarden
  worden nooit teruggetoond of bewaard. Een geslaagde poging → ``303`` naar ``/?melding=gekoppeld``; die melding
  verschijnt alleen als de dienst echt gekoppeld is (nooit in strijd met de koppelstatus).
"""

from __future__ import annotations

import hmac
import logging
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from . import __version__, audit
from .domains import DOMAIN_TITLES_NL, DOMAINS
from .domains.sso import service as sso_service
from .errors import trace_id_for
from .hublink_store import ERROR_MESSAGES, LinkState
from .peil import MELDING_ICOON, TONEN, SjabloonOntbreekt, render, sjabloon
from .security.secrets import secrets_present
from .sources import ALL_SOURCES

log = logging.getLogger("integrations.statuspagina")
router = APIRouter(include_in_schema=False)

CSRF_COOKIE = "hch_csrf"
DIENST_NAAM = "Home Control Hub"
DIENST_OMSCHRIJVING = (
    "Integratiedienst van het TrueNAS Home Platform: netwerk en privacy, Node-RED-automatisering, Authentik en "
    "toegangsbeheer, energie en resources. Alle schermen staan in de Hub; dit is alleen de statuspagina."
)
KOPPELCODE_GELDIG = "60 minuten"
VIA_HUB_NL = "Ontkoppelen of opnieuw koppelen gaat via de Hub."

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}

#: ernst voor de totaalstatus (Peil §4.3: Storing > Beperkt > Onbekend > Gezond); een gate verslechtert niets
_ERNST = {"storing": 3, "beperkt": 2, "onbekend": 1, "gezond": 0, "gate": -1}
_WOORD = {"gezond": "Gezond", "beperkt": "Beperkt", "storing": "Storing", "onbekend": "Onbekend"}
_BRON_TOON = {"healthy": "gezond", "degraded": "beperkt", "down": "storing", "unknown": "onbekend"}
_HERSTEL_TOON = {"ok": "gezond", "risico": "beperkt", "onbekend": "onbekend"}
_MAANDEN = ("jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec")
_HTTP_ADRES = re.compile(r"^https?://[^\s\"'<>]+$")

# ------------------------------------------------------------------------------------------------ vaste meldingen


@dataclass(frozen=True)
class FoutSoort:
    """Vaste melding bij een mislukte koppelpoging: HTTP-status, titel, tekst en (optioneel) het veld met de fout."""

    status: int
    tekst: str
    veld: str | None = None  # hub_adres | koppelcode | vingerafdruk
    veldtekst: str | None = None
    titel: str = "Koppelen is mislukt"


_VELD_ID = {"hub_adres": "hub", "koppelcode": "koppelcode", "vingerafdruk": "vingerafdruk"}
_VELD_NAAM = {"hub_adres": "Adres van de Hub", "koppelcode": "Koppelcode", "vingerafdruk": "Vingerafdruk van de Hub"}
_NIETS_NAAR_HUB = "Er is niets naar de Hub gestuurd."

FOUTEN: dict[str, FoutSoort] = {
    "ongeldig_formulier": FoutSoort(
        403,
        "Het formulier is verlopen of komt niet van deze pagina. Vul het opnieuw in. " + _NIETS_NAAR_HUB,
        titel="Koppelen is niet gestart",
    ),
    "al_gekoppeld": FoutSoort(
        409,
        "Koppelen via deze pagina kan alleen zolang de dienst nog nooit gekoppeld is. " + VIA_HUB_NL,
        titel="Koppelen is niet gestart",
    ),
    "koppelen_bezig": FoutSoort(
        409,
        "Er loopt al een koppelpoging. Wacht een minuut en laad de pagina opnieuw.",
        titel="Koppelen is niet gestart",
    ),
    "te_veel_pogingen": FoutSoort(
        429,
        "Te veel pogingen in korte tijd. Wacht een kwartier en probeer het opnieuw. " + _NIETS_NAAR_HUB,
        titel="Koppelen is niet gestart",
    ),
    "ongeldig_hub_adres": FoutSoort(
        422,
        "Het adres van de Hub heeft niet de juiste vorm. " + _NIETS_NAAR_HUB,
        "hub_adres",
        "Gebruik http(s)://<NAS-adres>:<poort> zonder pad. Geen localhost.",
        titel="Koppelen is niet gestart",
    ),
    "ongeldige_koppelcode": FoutSoort(
        422,
        "De koppelcode heeft niet de juiste vorm. " + _NIETS_NAAR_HUB,
        "koppelcode",
        "De koppelcode is 12 tekens in groepen van 4 (XXXX-XXXX-XXXX), zoals de Hub hem toont.",
        titel="Koppelen is niet gestart",
    ),
    "ongeldige_vingerafdruk": FoutSoort(
        422,
        "De vingerafdruk van de Hub ontbreekt of heeft niet de juiste vorm. " + _NIETS_NAAR_HUB,
        "vingerafdruk",
        "De vingerafdruk is 16 tekens in groepen van 4 (XXXX-XXXX-XXXX-XXXX). Hij staat in de Hub naast de koppelcode.",
        titel="Koppelen is niet gestart",
    ),
    "database_onbereikbaar": FoutSoort(
        503,
        "De eigen database van deze dienst antwoordt nu niet. Probeer het over een minuut opnieuw. " + _NIETS_NAAR_HUB,
        titel="Koppelen is niet gestart",
    ),
    "hub_weigerde": FoutSoort(
        400,
        "De Hub weigerde de koppelcode: verlopen, al gebruikt of onbekend. Maak in de Hub een nieuwe koppelcode en "
        "probeer het opnieuw.",
        "koppelcode",
        "Deze koppelcode is verlopen, al gebruikt of onbekend. Maak een nieuwe in de Hub.",
    ),
    "hub_vingerafdruk_onjuist": FoutSoort(
        400,
        "De vingerafdruk hoort niet bij de Hub op dit adres. Er is niets opgeslagen. Controleer het adres en de "
        "vingerafdruk in de Hub en probeer het opnieuw.",
        "vingerafdruk",
        "Deze vingerafdruk hoort niet bij de Hub op dit adres.",
    ),
    "rate_limited": FoutSoort(429, ERROR_MESSAGES["rate_limited"] + " Probeer het over een kwartier opnieuw."),
    "hub_onbereikbaar": FoutSoort(
        502,
        "De Hub was niet bereikbaar (netwerkfout, time-out, doorverwijzing of storing bij de Hub). Controleer het "
        "adres en de poort van de Hub en probeer het opnieuw.",
    ),
    "hub_incompatibel": FoutSoort(502, ERROR_MESSAGES["hub_incompatibel"]),
    "hub_antwoord_ongeldig": FoutSoort(502, ERROR_MESSAGES["hub_antwoord_ongeldig"]),
    "enroll_endpoint_ontbreekt": FoutSoort(502, ERROR_MESSAGES["enroll_endpoint_ontbreekt"]),
}
ONBEKENDE_FOUT = FoutSoort(502, "Koppelen is niet gelukt. Er is niets opgeslagen. Probeer het opnieuw.")


@dataclass(frozen=True)
class Fout:
    """Een mislukte koppelpoging van dít verzoek (code + trace-ID)."""

    code: str
    trace_id: str

    @property
    def soort(self) -> FoutSoort:
        return FOUTEN.get(self.code, ONBEKENDE_FOUT)


# ------------------------------------------------------------------------------------------------ rate-limit


class PairThrottle:
    """Max. ``per_ip`` pogingen per bron-IP en ``total`` pogingen voor de hele dienst per ``window_s`` (§3.7)."""

    def __init__(self, per_ip: int = 5, total: int = 20, window_s: float = 900) -> None:
        self.per_ip, self.total, self.window_s = per_ip, total, window_s
        self.hits: deque[tuple[float, str]] = deque()
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            while self.hits and now - self.hits[0][0] > self.window_s:
                self.hits.popleft()
            if len(self.hits) >= self.total or sum(1 for _, h in self.hits if h == ip) >= self.per_ip:
                return False
            self.hits.append((now, ip))
            return True


# ------------------------------------------------------------------------------------------------ meting


@dataclass(frozen=True)
class BronStand:
    """Stand van één bron uit de inventaris (``integration_source``; geen rij = niet ingesteld)."""

    domein: str
    ingesteld: bool
    status: str = "unknown"  # healthy | degraded | down | unknown
    gemeten: datetime | None = None


@dataclass(frozen=True)
class Meting:
    """Alles wat de pagina toont, gemeten bij het laden (zonder geheimen)."""

    nu: datetime
    db_ok: bool
    schema_huidig: str | None
    schema_verwacht: str | None
    geheimen: Mapping[str, bool]
    link: LinkState
    herstel_niveau: str | None = None  # ok | risico | onbekend; None = niet te meten
    bronnen: tuple[BronStand, ...] = field(default_factory=tuple)


def meet(request: Request) -> Meting:
    state = request.app.state
    nu = datetime.now().astimezone()
    db_ok = state.db.ping()
    huidig = state.db.current_revision() if db_ok else None
    niveau: str | None = None
    bronnen: list[BronStand] = []
    rijen: dict[str, Any] | None = None
    if db_ok:
        from .models import IntegrationSource

        try:
            with state.db.sessions() as s:
                niveau = str(sso_service.overall(s, state.settings.break_glass_test_max_age_days)["level"])
                rijen = {r.source_id: r for r in s.query(IntegrationSource).all()}
        except Exception as exc:  # een half gemigreerde database mag de statuspagina nooit laten crashen
            log.warning("statuspagina: stand van herstelregister/bronnen niet te lezen (%s)", type(exc).__name__)
            niveau, rijen = None, None
        if rijen is not None:
            for sid, spec in ALL_SOURCES.items():
                rij = rijen.get(sid)
                ingesteld = rij is not None and rij.enabled and bool(rij.base_url)
                bronnen.append(
                    BronStand(
                        spec.domain,
                        ingesteld,
                        rij.last_probe_status if rij is not None and ingesteld else "unknown",
                        rij.last_probe_at if rij is not None and ingesteld else None,
                    )
                )
    return Meting(
        nu=nu,
        db_ok=db_ok,
        schema_huidig=huidig,
        schema_verwacht=state.alembic_head,
        geheimen=secrets_present(state.settings.secrets_dir),
        link=state.hublink.state(),
        herstel_niveau=niveau,
        bronnen=tuple(bronnen),
    )


# ------------------------------------------------------------------------------------------------ opmaak


def nl_datumtijd(dt: datetime) -> str:
    """``9 nov 2026, 11:56 UTC`` (Peil §11.2, 24-uurs tijd; de tijdzone erbij, want die van de NAS is onbekend)."""
    zone = dt.tzname() or dt.strftime("%z")
    return f"{dt.day} {_MAANDEN[dt.month - 1]} {dt.year}, {dt:%H:%M}" + (f" {zone}" if zone else "")


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(waarde: str | None) -> datetime | None:
    if not waarde:
        return None
    try:
        return datetime.fromisoformat(waarde.replace("Z", "+00:00"))
    except ValueError:
        return None


def _toon(toon: str) -> str:
    if toon not in TONEN:  # vaste lijst van het sjabloon; iets anders is een programmeerfout
        raise ValueError(f"onbekende toon {toon!r}")
    return toon


def _rij(naam: str, toon: str, nu: datetime, reden: str | None = None, label: str | None = None) -> dict[str, Any]:
    return {
        "naam": naam,
        "toon": _toon(toon),
        "label": label or _WOORD[toon],
        "tijd": f"{nu:%H:%M}",
        "iso": _iso(nu),
        "reden": reden,
    }


def _laatste_fout(link: LinkState, nu: datetime) -> str | None:
    if link.last_error is None:
        return None
    wanneer = _parse(link.last_error.at)
    tijd = nl_datumtijd(wanneer.astimezone(nu.tzinfo)) if wanneer else "tijd onbekend"
    tekst = ERROR_MESSAGES.get(link.last_error.code, "Koppelen is niet gelukt.")
    return f"Laatste melding ({tijd}, code {link.last_error.code}): {tekst}"


# ------------------------------------------------------------------------------------------------ model


def koppeltoestand(link: LinkState) -> str | None:
    """Precies één van ``koppelformulier`` · ``gekoppeld`` · ``ontkoppeld`` · ``ingetrokken`` (§3.7); ``None`` als de
    koppelstatus onleesbaar is (dan geen formulier en niets vertrouwd)."""
    if link.corrupt:
        return None
    if not link.ever_linked:
        return "koppelformulier"
    if link.state == "gekoppeld":
        return "gekoppeld"
    if link.state == "ingetrokken":
        return "ingetrokken"
    return "ontkoppeld"


def _koppel_controle(m: Meting, met_laatste_fout: bool) -> tuple[dict[str, Any] | None, str | None]:
    """Controle 'Koppeling met de Hub' (alleen als er iets ontbreekt) en de reden waarom de dienst niet gereed is."""
    link, nu, naam = m.link, m.nu, "Koppeling met de Hub"
    laatste = _laatste_fout(link, nu) if met_laatste_fout else None
    if link.corrupt:
        reden = (
            "Het koppelbestand in /appdata/secrets is onleesbaar; de dienst vertrouwt niets van de Hub. Herstel: zet "
            "in het formulier van de Custom App een nieuw eenmalig token van de Hub (HUB_ENROLLMENT_TOKEN)."
        )
        return _rij(naam, "storing", nu, reden, "Onleesbaar"), "koppelstatus onleesbaar"
    toestand = koppeltoestand(link)
    if toestand == "koppelformulier":
        if link.pending is not None:
            reden = "Er loopt een koppelpoging. Laad de pagina over een minuut opnieuw."
            return _rij(naam, "onbekend", nu, reden, "Koppelen bezig"), "koppelen is bezig"
        reden = " ".join(
            x for x in ("Zonder koppeling voert de dienst niets uit voor de Hub.", laatste) if x is not None
        )
        return _rij(naam, "onbekend", nu, reden, "Niet gekoppeld"), "wacht op koppeling met de Hub"
    if toestand == "ingetrokken":
        reden = "De Hub heeft de koppeling ingetrokken; de dienst weigert elke opdracht. " + VIA_HUB_NL
        return _rij(naam, "onbekend", nu, reden, "Ingetrokken"), "de Hub heeft de koppeling ingetrokken"
    if toestand == "ontkoppeld":
        reden = "De Hub heeft deze dienst ontkoppeld; de dienst voert niets uit. " + VIA_HUB_NL
        return _rij(naam, "onbekend", nu, reden, "Ontkoppeld"), "ontkoppeld door de Hub"
    if not link.linked:
        reden = "De koppeling is onvolledig opgeslagen; de dienst vertrouwt niets van de Hub. " + VIA_HUB_NL
        return _rij(naam, "storing", nu, reden, "Onvolledig"), "koppeling onvolledig"
    if link.confirmed_at is None:
        reden = "Gekoppeld, maar de Hub heeft de koppeling nog niet bevestigd. De dienst probeert het opnieuw."
        return _rij(naam, "onbekend", nu, reden, "Niet bevestigd"), "wacht op bevestiging door de Hub"
    return None, None


def bouw_model(
    m: Meting,
    *,
    csrf: str,
    fout: Fout | None = None,
    gekoppeld_melding: bool = False,
    melding_trace_id: str | None = None,
) -> dict[str, Any]:
    """Alle plekken van het Peil-sjabloon (pure functie; unit-getest per toestand)."""
    nu = m.nu
    toestand = koppeltoestand(m.link)
    rijen: list[dict[str, Any]] = [_rij("Proces", "gezond", nu)]
    niet_gereed: list[str] = []

    if m.db_ok:
        rijen.append(_rij("Eigen database", "gezond", nu))
    else:
        reden = "De ingebouwde PostgreSQL antwoordt niet. Blijft dit zo, bekijk dan de logs van de app in TrueNAS."
        rijen.append(_rij("Eigen database", "storing", nu, reden))
        niet_gereed.append("de eigen database antwoordt niet")
    if not m.db_ok:
        rijen.append(_rij("Databaseschema", "onbekend", nu, "Niet te meten zonder database."))
    elif m.schema_huidig is not None and m.schema_huidig == m.schema_verwacht:
        rijen.append(_rij("Databaseschema", "gezond", nu))
    else:
        reden = (
            f"Revisie {m.schema_huidig or 'geen'}; deze versie verwacht {m.schema_verwacht or 'onbekend'}. "
            "De dienst neemt geen verkeer aan tot dit klopt."
        )
        rijen.append(_rij("Databaseschema", "storing", nu, reden))
        niet_gereed.append("het databaseschema klopt niet")
    ontbreekt = [naam for naam, er in m.geheimen.items() if not er]
    if ontbreekt:
        reden = f"Ontbreekt in /appdata/secrets: {', '.join(sorted(ontbreekt))}. Zet de opslag terug uit de back-up."
        rijen.append(_rij("Sleutels van de dienst", "storing", nu, reden))
        niet_gereed.append("sleutels van de dienst ontbreken")
    else:
        rijen.append(_rij("Sleutels van de dienst", "gezond", nu))

    koppel_rij, koppel_reden = _koppel_controle(m, met_laatste_fout=fout is None)
    if koppel_rij is not None:
        rijen.append(koppel_rij)
    if koppel_reden is not None:
        niet_gereed.append(koppel_reden)
    if m.link.linked and m.link.key_rotation_blocked_sequence is not None:
        reden = (
            "Een sleutelrotatie van de Hub is geweigerd; de dienst vertrouwt alleen de gepinde sleutels. Opnieuw "
            "koppelen via de Hub lost dit op."
        )
        rijen.append(_rij("Sleutels van de Hub", "beperkt", nu, reden))

    gereed = not niet_gereed
    dienst_blok = _dienst_blok(m)
    totaal_toon, totaal_label, toelichting = _totaal(rijen, gereed, niet_gereed, dienst_blok)

    data: dict[str, Any] = {
        "voorbeeld": False,
        "dienst_naam": DIENST_NAAM,
        "dienst_omschrijving": DIENST_OMSCHRIJVING,
        "spring_doel": "inhoud",
        "spring_tekst": "Naar inhoud",
        "totaal_toon": totaal_toon,
        "totaal_label": totaal_label,
        "totaal_toelichting": toelichting,
        "checks": rijen,
        "gereed": "Ja" if gereed else "Nee — " + "; ".join(niet_gereed),
        "versie": __version__,
        "bijgewerkt": nl_datumtijd(nu),
        "bijgewerkt_iso": _iso(nu),
        "koppelformulier": toestand == "koppelformulier",
        "gekoppeld": toestand == "gekoppeld",
        "ontkoppeld": toestand == "ontkoppeld",
        "ingetrokken": toestand == "ingetrokken",
        "koppelcode_geldig": KOPPELCODE_GELDIG,
        "csrf_token": csrf,
        "dienst_blok_titel": "Wat deze dienst doet",
        "dienst_blok": dienst_blok,
    }
    if toestand == "gekoppeld":
        sinds = _parse(m.link.linked_at)
        adres = m.link.hub_url or ""
        data.update(
            gekoppeld_sinds=nl_datumtijd(sinds.astimezone(nu.tzinfo)) if sinds else "onbekend",
            # alleen een http(s)-adres uit de opgeslagen koppeling (gecontroleerd bij het koppelen) wordt een link
            hub_adres=adres if _HTTP_ADRES.match(adres) else "",
            hub_vingerafdruk=m.link.pins.keyset_fingerprint if m.link.pins else "onbekend",
        )
    if fout is not None:
        soort = fout.soort
        data.update(
            melding=True,
            melding_toon="fout",
            melding_icoon=MELDING_ICOON["fout"],
            melding_titel=soort.titel,
            melding_tekst=soort.tekst,
            melding_code=fout.code,
            trace_id=fout.trace_id,
        )
        if soort.veld is not None and toestand == "koppelformulier":
            doel = _VELD_ID[soort.veld]
            data.update(
                {
                    f"fout_{soort.veld}": soort.veldtekst,
                    "melding_link": True,
                    "melding_link_doel": doel,
                    "melding_link_tekst": f"Naar het veld {_VELD_NAAM[soort.veld]}",
                    "spring_doel": doel,
                    "spring_tekst": f"Naar het veld {_VELD_NAAM[soort.veld]} (fout)",
                }
            )
    elif m.link.corrupt:
        data.update(
            melding=True,
            melding_toon="fout",
            melding_icoon=MELDING_ICOON["fout"],
            melding_titel="Koppelstatus onleesbaar",
            melding_tekst=(
                "Het koppelbestand van deze dienst kon niet worden gelezen. De dienst vertrouwt daarom niets van de "
                "Hub en biedt geen koppelformulier. Herstel: zet in het formulier van de Custom App een nieuw "
                "eenmalig token van de Hub (HUB_ENROLLMENT_TOKEN)."
            ),
            melding_code="koppelstatus_onleesbaar",
            trace_id=melding_trace_id,
        )
    elif gekoppeld_melding and toestand == "gekoppeld":
        data.update(
            melding=True,
            melding_toon="info",
            melding_icoon=MELDING_ICOON["info"],
            melding_titel="Gekoppeld met de Hub",
            melding_tekst="Vergelijk de vingerafdruk hieronder met die in de Hub.",
        )
    data["titel_toestand"] = _titel(toestand, fout, totaal_label)
    return data


def _dienst_blok(m: Meting) -> list[dict[str, Any]]:
    def rij(naam: str, toon: str, reden: str, label: str | None = None) -> dict[str, Any]:
        return {"naam": naam, "toon": _toon(toon), "label": label or _WOORD[toon], "reden": reden}

    blok: list[dict[str, Any]] = []
    for domein in DOMAINS:
        naam = DOMAIN_TITLES_NL[domein]
        totaal = sum(1 for s in ALL_SOURCES.values() if s.domain == domein)
        if not m.db_ok or not m.bronnen:
            blok.append(rij(naam, "onbekend", "Niet te meten: de eigen database antwoordt niet."))
            continue
        ingesteld = [b for b in m.bronnen if b.domein == domein and b.ingesteld]
        if not ingesteld:
            reden = (
                f"Nog geen bron ingesteld ({totaal} in de inventaris). Instellen gaat via de Hub; tot dan tonen we "
                "geen stand."
            )
            blok.append(rij(naam, "onbekend", reden))
            continue
        toon = max((_BRON_TOON.get(b.status, "onbekend") for b in ingesteld), key=lambda t: _ERNST[t])
        tijden = [b.gemeten for b in ingesteld if b.gemeten is not None]
        meting = f"laatst gemeten {nl_datumtijd(max(tijden).astimezone(m.nu.tzinfo))}" if tijden else "nog niet gemeten"
        blok.append(rij(naam, toon, f"{len(ingesteld)} van {totaal} bronnen ingesteld · {meting}."))
    niveau = m.herstel_niveau if m.db_ok else None
    blok.append(
        rij(
            "Beheerherstel (B13-001)",
            _HERSTEL_TOON.get(niveau or "", "onbekend"),
            (
                "Alleen het totaalniveau; details en oefeningen staan in de Hub (alleen voor beheerders). De "
                "noodlogin zit in de Hub en hangt niet van deze dienst of van Authentik af."
                if niveau is not None
                else "Niet te meten: de eigen database antwoordt niet."
            ),
        )
    )
    blok.append(
        rij(
            "Boiler",
            "gate",
            "Schakelen is altijd uitgeschakeld (beleid). Er is bewust geen schakelaar; deze dienst meet alleen.",
            "Alleen meten",
        )
    )
    return blok


def _totaal(
    rijen: list[dict[str, Any]], gereed: bool, niet_gereed: list[str], dienst_blok: list[dict[str, Any]]
) -> tuple[str, str, str]:
    toon = max((r["toon"] for r in rijen), key=lambda t: _ERNST[t])
    if not gereed and toon == "gezond":  # vangnet: het eerste signaal is nooit groen als de dienst niet gereed is
        toon = "onbekend"
    waarom = "; ".join(niet_gereed)
    if toon == "storing":
        return toon, "Storing", f"Niet gereed — {waarom}."
    if toon == "beperkt":
        beperkt = ", ".join(r["naam"].lower() for r in rijen if r["toon"] == "beperkt")
        return toon, "Beperkt", (f"Niet gereed — {waarom}." if not gereed else f"Gereed; beperkt: {beperkt}.")
    if toon == "onbekend":
        return toon, "Niet gereed", f"Deels onbekend — {waarom}."
    telling = {t: sum(1 for r in dienst_blok if r["toon"] == t) for t in ("storing", "beperkt", "onbekend")}
    onder = " · ".join(f"{n} {t}" for t, n in telling.items() if n)
    # kort: deze regel staat vet naast de pil; de controles zelf staan eronder
    return (
        "gezond",
        "Gezond",
        (f"Gereed; onderdelen hieronder: {onder}." if onder else "Gereed; alle controles en onderdelen zijn gezond."),
    )


def _titel(toestand: str | None, fout: Fout | None, totaal_label: str) -> str:
    woord = {
        "koppelformulier": "niet gekoppeld",
        "gekoppeld": "gekoppeld",
        "ontkoppeld": "ontkoppeld",
        "ingetrokken": "ingetrokken",
        None: "koppelstatus onleesbaar",
    }[toestand]
    if fout is not None:
        return f"{woord} (koppelen mislukt)"
    return f"{woord}, {totaal_label.lower()}"


# ------------------------------------------------------------------------------------------------ HTTP


def _csrf_token(request: Request) -> str:
    tok = request.cookies.get(CSRF_COOKIE)
    if tok and 20 <= len(tok) <= 100 and tok.isascii() and all(c.isalnum() or c in "-_" for c in tok):
        return tok
    return secrets.token_urlsafe(24)


def _with_headers(resp: Response, csrf: str | None = None) -> Response:
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    if csrf is not None:
        resp.set_cookie(CSRF_COOKIE, csrf, httponly=True, samesite="strict", path="/", max_age=3600)
    return resp


def _form_ok(request: Request, token: str) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    if not cookie or not token or not hmac.compare_digest(cookie.encode(), token.encode()):
        return False
    origin = request.headers.get("origin")
    if origin and origin != "null":
        host = request.headers.get("host", "")
        if urlsplit(origin).netloc != host:
            return False
    return True


def _pagina(
    request: Request, *, status: int = 200, fout: Fout | None = None, gekoppeld_melding: bool = False
) -> Response:
    csrf = _csrf_token(request)
    tid = trace_id_for(request)
    try:
        tpl = sjabloon(request.app.state.settings.peil_dir)
    except SjabloonOntbreekt as exc:
        log.error("statuspagina: %s (trace_id=%s)", exc, tid)
        tekst = (
            "Statuspagina niet beschikbaar: het Peil-sjabloon ontbreekt in deze installatie.\n"
            f"Code statuspagina_sjabloon_ontbreekt · Trace-ID {tid}\n"
        )
        return _with_headers(PlainTextResponse(tekst, status_code=503))
    m = meet(request)
    if m.link.corrupt and fout is None:
        log.warning("statuspagina: koppelstatus onleesbaar; niets van de Hub wordt vertrouwd (trace_id=%s)", tid)
    data = bouw_model(m, csrf=csrf, fout=fout, gekoppeld_melding=gekoppeld_melding, melding_trace_id=tid)
    resp = HTMLResponse(render(tpl.tekst, data), status_code=status)
    if status == 429:
        resp.headers["Retry-After"] = "900"
    return _with_headers(resp, csrf)


@router.get("/", response_class=HTMLResponse)
def status_page(request: Request, melding: str | None = None) -> Response:
    # alleen de vaste succesmelding uit de URL; die verschijnt alleen als de dienst echt gekoppeld is
    return _pagina(request, gekoppeld_melding=melding == "gekoppeld")


def _mislukt(request: Request, code: str, tid: str) -> Response:
    fout = Fout(code, tid)
    log.warning("statuspagina: koppelen mislukt of geweigerd: %s (trace_id=%s)", code, tid)
    return _pagina(request, status=fout.soort.status, fout=fout)


@router.post("/koppelen")
def pair(
    request: Request,
    csrf: str = Form(""),
    hub_adres: str = Form(""),
    koppelcode: str = Form(""),
    hub_vingerafdruk: str = Form(""),
) -> Response:
    state = request.app.state
    tid = trace_id_for(request)
    if not _form_ok(request, csrf):
        return _mislukt(request, "ongeldig_formulier", tid)
    if state.hublink.state().ever_linked:
        return _mislukt(request, "al_gekoppeld", tid)  # geen poging, telt niet mee
    ip = request.client.host if request.client else "onbekend"  # TCP-bron; nooit X-Forwarded-For (§3.7)
    if not state.pair_throttle.allow(ip):
        return _mislukt(request, "te_veel_pogingen", tid)
    outcome = state.hublink.pair_with_code(
        hub_url=hub_adres[:500], pairing_code=koppelcode[:64], fingerprint=hub_vingerafdruk[:64], trace_id=tid
    )
    if outcome.ok:
        return _with_headers(RedirectResponse("/?melding=gekoppeld", status_code=303))
    code = str(outcome.code or "onbekend")
    if state.db.ping():
        with state.db.sessions() as s:
            audit.record(
                s,
                domain="hub_link",
                action="hub.pair_failed",
                entity_type="hub_link",
                entity_id="hub",
                principal=None,
                trace_id=tid,
                actor_override=("user", "statuspagina"),
                message_nl="Koppelen via de statuspagina mislukt.",
                details={"code": code},
            )
            s.commit()
    return _mislukt(request, code, tid)
