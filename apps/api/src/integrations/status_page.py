"""Nederlandse statuspagina op ``GET /`` in Peil 1.1.1 (ONTWERPTAAL §13.2) + koppelen met koppelcode (contract 1.3
§3.7).

Uiterlijk: het framework-vrije Peil-sjabloon (``peil.py``; versie-gepinde kopie in ``design/ontwerptaal``). Geen
JavaScript, geen externe bron; strikte CSP ``default-src 'none'``. Ontwerpstap en keuzes: ADR-0011, ADR-0014.

Inhoud en veiligheid:
- **Eerste signaal nooit groen als de dienst niet gereed is:** "Gereed" = ``/readyz`` in orde (database, schema,
  sleutels) **én** een door de Hub bevestigde koppeling (§3.7). Het totaal is het slechtste van de eigen controles en de
  **verse** metingen in het dienstblok; een Storing of Beperkt in het dienstblok maakt het totaal hooguit Beperkt; niet
  ingestelde, beleids- en verouderde rijen tellen niet mee (Peil 1.1.1, E10).
- Geen geheimen, accountnamen of aandachtspunten van het herstelregister; van de koppeling alleen de witte lijst (§3.5).
- Precies één koppeltoestand (§3.5/§3.7): ``koppelformulier`` (alleen zolang de dienst **nog nooit** gekoppeld is en
  het koppelbestand leesbaar is) · ``gekoppeld`` · ``ontkoppeld`` · ``ingetrokken`` · ``koppelstatus_onleesbaar``
  (fail-closed, geen formulier). Daarnaast de vlag ``koppelen_bezig`` (``pending`` ≠ ``null``): het formulier
  verdwijnt, de stabiele toestand blijft staan. Geen ontkoppelen of herkoppelen op deze pagina (§3.8).
- **Herkomst van de formulier-POST** (§3.7, A13/A14), vóór alles en zonder iets naar de Hub te sturen of te tellen:
  ``Host`` alleen een IP-adres (vorm van §3.2), een naam zonder punt of een naam onder ``.local``, ``.lan``,
  ``.internal`` of ``.home.arpa`` (DNS-rebinding; 403 ``host_niet_toegestaan``); ``Sec-Fetch-Site`` (als de browser hem
  stuurt) alleen ``same-origin`` of ``none``; ``Origin`` exact ``<schema>://<Host>`` (ontbreekt of ``null`` → 403);
  double-submit-cookie (``SameSite=Strict``, HttpOnly) met formuliertoken. De pagina stuurt ``Referrer-Policy:
  same-origin`` (met ``no-referrer`` stuurt elke browser ``Origin: null``).
- **Pogingen:** elke POST die de herkomstcontrole doorstaat telt mee (max. 5 per 15 min per bron-IP van de
  TCP-verbinding — nooit ``X-Forwarded-For`` — en 20 per 15 min voor de hele dienst), ook bij ongeldige invoer, een
  lopende poging, een onleesbaar koppelbestand of een al gekoppelde dienst (409 ``al_gekoppeld``, RV7). De teller staat
  in het geheugen: de image draait precies één API-proces.
- **Invoer** als geheel controleren, nooit eerst afkappen (Hub-adres ≤ 512, koppelcode ≤ 32, vingerafdruk ≤ 64 tekens;
  langer → veldfout). Ingevulde waarden worden nooit teruggetoond of bewaard.
- **Log:** elke formulier-POST geeft precies één regel in de app-log met code en trace-ID, zonder het ingevulde
  Hub-adres van een mislukte poging en zonder geheimen.
- **Meldingen** horen bij een echte, recente poging van deze browser: een fout staat direct in het antwoord op de POST
  (``role="alert"``); na een geslaagde poging verwijst de ``303`` naar ``/?melding=<sleutel>``, en die sleutel staat
  hooguit 15 minuten in het geheugen, gekoppeld aan het formuliercookie van deze browser. Een query-parameter alleen
  toont nooit iets; een melding spreekt de koppelstatus nooit tegen.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import ipaddress
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

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from . import __version__, audit
from .domains import DOMAIN_TITLES_NL, DOMAINS
from .domains.sso import service as sso_service
from .errors import trace_id_for
from .hublink_store import ERROR_MESSAGES, LINK_FILE, LinkState
from .peil import MELDING_ICOON, TONEN, TOTAAL_TONEN, SjabloonOntbreekt, render, sjabloon
from .security.secrets import secrets_present
from .sources import ALL_SOURCES, PROBE_MAX_AGE

log = logging.getLogger("integrations.statuspagina")
router = APIRouter(include_in_schema=False)

CSRF_COOKIE = "hch_csrf"
DIENST_NAAM = "Home Control Hub"
# kort: "Onderdeel van TrueNAS Home Platform" staat erboven en "Alle schermen staan in de Hub" in de voet (sjabloon)
DIENST_OMSCHRIJVING = (
    "Integratiedienst voor netwerk en privacy, Node-RED-automatisering, Authentik en toegangsbeheer, en energie en "
    "resources. Dit is alleen de statuspagina."
)
KOPPELCODE_GELDIG = "60 minuten"
VIA_HUB_NL = "Ontkoppelen of opnieuw koppelen gaat via de Hub."
OPNIEUW_VIA_HUB_NL = "Opnieuw koppelen gaat via de Hub."
BRON_NL = (
    "Eigen controles (/readyz, /healthz), de koppeling met de Hub en de laatste metingen van de ingestelde bronnen."
)
#: een meting van een bron die ouder is, is verouderd: nooit de laatst bekende stand als actueel (Peil §4.4; contract
#: 1.3 §6.2, standaard max_age 900 s). Dezelfde grens als in de API en de connector-health (sources.PROBE_MAX_AGE).
BRON_MAX_LEEFTIJD = PROBE_MAX_AGE
#: wie na een mislukte poging het formulier opnieuw ziet: de velden zijn leeg (ingevulde waarden worden nooit
#: teruggezet, ADR-0011 besluit 6); dat zeggen we erbij (WCAG 3.3.7, uitzondering voor veiligheid)
OPNIEUW_INVULLEN_NL = "Ingevulde waarden bewaren we bewust niet: vul alle velden opnieuw in."
#: §3.7: invoer als geheel controleren, nooit eerst afkappen; langer → veldfout
MAX_HUB_ADRES = 512
MAX_KOPPELCODE = 32
MAX_VINGERAFDRUK = 64
#: §3.7 punt 4 (DNS-rebinding): namen onder deze achtervoegsels mogen; publieke domeinnamen niet
LAN_ACHTERVOEGSELS = (".local", ".lan", ".internal", ".home.arpa")
#: §3.7 punt 3: alleen deze waarden van ``Sec-Fetch-Site`` (ontbreekt de header, dan beslissen Origin en Host)
SEC_FETCH_SITE_OK = frozenset({"same-origin", "none"})
#: §3.7: een melding hoort bij een echte, recente poging van deze browser (hooguit 15 min)
MELDING_GELDIG_S = 15 * 60
MELDING_MAX = 256

SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    # contract 1.3 §3.7 punt 1: same-origin (nooit no-referrer: dan stuurt elke browser Origin: null)
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
}

#: ernst voor het totaal (Peil §4.3: Storing > Beperkt > Onbekend > Gezond). ``niet-gekoppeld`` en
#: ``niet-beschikbaar`` tellen als Onbekend; ``gate``, ``nog-niet``, ``beleid``, ``feit`` en ``verouderd`` tellen niet
#: mee (Peil 1.1.1, E03/E10)
_ERNST = {
    "storing": 3,
    "beperkt": 2,
    "onbekend": 1,
    "niet-gekoppeld": 1,
    "niet-beschikbaar": 1,
    "gezond": 0,
}
_TOTAAL_TOON = {3: "storing", 2: "beperkt", 1: "onbekend", 0: "gezond"}
_WOORD = {"gezond": "Gezond", "beperkt": "Beperkt", "storing": "Storing", "onbekend": "Onbekend"}
_BRON_TOON = {"healthy": "gezond", "degraded": "beperkt", "down": "storing", "unknown": "onbekend"}
_HERSTEL_TOON = {"ok": "gezond", "risico": "beperkt", "onbekend": "onbekend"}
_MAANDEN = ("jan", "feb", "mrt", "apr", "mei", "jun", "jul", "aug", "sep", "okt", "nov", "dec")
_HTTP_ADRES = re.compile(r"^https?://[^\s\"'<>]+$")
_NUMERIEK = re.compile(r"(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+))*")
_NAAM = re.compile(r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*")

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
_NIET_GESTART = "Koppelen is niet gestart"
HOST_NIET_TOEGESTAAN_NL = "Open deze pagina via het IP-adres van de NAS, of koppel via de Hub."

FOUTEN: dict[str, FoutSoort] = {
    # herkomst (§3.7): telt niet als poging, gaat niet naar de Hub
    "host_niet_toegestaan": FoutSoort(
        403,
        f"Koppelen via deze pagina kan alleen als je hem opent via het IP-adres van de NAS of een lokale naam (zoals "
        f"nas.local). {HOST_NIET_TOEGESTAAN_NL} {_NIETS_NAAR_HUB}",
        titel=_NIET_GESTART,
    ),
    "herkomst_onjuist": FoutSoort(
        403,
        "Het formulier kwam niet van deze pagina (of de browser gaf niet aan waar het vandaan kwam). Laad de pagina "
        f"opnieuw en vul het formulier hier in. {_NIETS_NAAR_HUB}",
        titel=_NIET_GESTART,
    ),
    "ongeldig_formulier": FoutSoort(
        403,
        f"Het formulier is verlopen of komt niet van deze pagina. Laad de pagina opnieuw. {_NIETS_NAAR_HUB}",
        titel=_NIET_GESTART,
    ),
    # toestand (§3.5/§3.7): telt als poging, gaat niet naar de Hub
    "te_veel_pogingen": FoutSoort(
        429,
        f"Te veel pogingen in korte tijd. Wacht een kwartier en probeer het opnieuw. {_NIETS_NAAR_HUB}",
        titel=_NIET_GESTART,
    ),
    "koppelstatus_onleesbaar": FoutSoort(
        409,
        "De koppelstatus van deze dienst is onleesbaar; daarom kan hier niet gekoppeld worden. Herstel gaat alleen met "
        f"een nieuw koppeltoken van de Hub. {_NIETS_NAAR_HUB}",
        titel=_NIET_GESTART,
    ),
    "al_gekoppeld": FoutSoort(
        409,
        f"Koppelen via deze pagina kan alleen zolang de dienst nog nooit gekoppeld is. {VIA_HUB_NL} {_NIETS_NAAR_HUB}",
        titel=_NIET_GESTART,
    ),
    "koppelen_bezig": FoutSoort(
        409,
        f"Er loopt al een koppelpoging. {_NIETS_NAAR_HUB} Hoe die poging ervoor staat, zie je hieronder bij Koppeling "
        "met de Hub.",
        titel=_NIET_GESTART,
    ),
    # invoer (§3.7): telt als poging, gaat niet naar de Hub
    "ongeldig_hub_adres": FoutSoort(
        422,
        f"Het adres van de Hub heeft niet de juiste vorm. {_NIETS_NAAR_HUB}",
        "hub_adres",
        "Gebruik http(s)://<NAS-adres>:<poort> zonder pad, hooguit 512 tekens. Geen localhost.",
        titel=_NIET_GESTART,
    ),
    "ongeldige_koppelcode": FoutSoort(
        422,
        f"De koppelcode heeft niet de juiste vorm. {_NIETS_NAAR_HUB}",
        "koppelcode",
        "De koppelcode is 12 tekens in groepen van 4 (XXXX-XXXX-XXXX), zoals de Hub hem toont.",
        titel=_NIET_GESTART,
    ),
    "ongeldige_vingerafdruk": FoutSoort(
        422,
        f"De vingerafdruk van de Hub ontbreekt of heeft niet de juiste vorm. {_NIETS_NAAR_HUB}",
        "vingerafdruk",
        "De vingerafdruk is 16 tekens in groepen van 4 (XXXX-XXXX-XXXX-XXXX). Hij staat in de Hub naast de koppelcode.",
        titel=_NIET_GESTART,
    ),
    "database_onbereikbaar": FoutSoort(
        503,
        f"De eigen database van deze dienst antwoordt nu niet. Probeer het over een minuut opnieuw. {_NIETS_NAAR_HUB}",
        titel=_NIET_GESTART,
    ),
    # antwoord van de Hub
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
#: fouten waarbij opnieuw invullen nu niet helpt (wachten, de pagina opnieuw laden of via de Hub)
_GEEN_INVOER = frozenset(
    {
        "al_gekoppeld",
        "koppelen_bezig",
        "te_veel_pogingen",
        "rate_limited",
        "koppelstatus_onleesbaar",
        "host_niet_toegestaan",
        "herkomst_onjuist",
        "ongeldig_formulier",
    }
)
ONBEKENDE_FOUT = FoutSoort(502, "Koppelen is niet gelukt. Er is niets opgeslagen. Probeer het opnieuw.")


@dataclass(frozen=True)
class Fout:
    """Een mislukte koppelpoging van dít verzoek (code + trace-ID)."""

    code: str
    trace_id: str

    @property
    def soort(self) -> FoutSoort:
        return FOUTEN.get(self.code, ONBEKENDE_FOUT)


# ------------------------------------------------------------------------------------------------ herkomst (§3.7)


def host_toegestaan(host_header: str | None) -> bool:
    """§3.7 punt 4: ``Host`` (zonder poort) is een IP-adres in de vorm van §3.2 (IPv4 ``a.b.c.d``, IPv6 tussen ``[]``),
    een naam zonder punt, of een naam onder ``.local``, ``.lan``, ``.internal`` of ``.home.arpa``. Eén punt aan het
    eind van een naam telt niet mee. Alles anders (publieke domeinnaam, afwijkende IP-vorm, rommel) → ``False``."""
    host = (host_header or "").strip().lower()
    if not host or len(host) > 260:
        return False
    if host.startswith("["):
        einde = host.find("]")
        if einde < 0:
            return False
        rest = host[einde + 1 :]
        if rest and not re.fullmatch(r":[0-9]{1,5}", rest):
            return False
        try:
            ipaddress.IPv6Address(host[1:einde])
        except ValueError:
            return False
        return True
    if host.count(":") > 1:
        return False  # IPv6 zonder [] is geen geldige Host-header
    naam, scheiding, poort = host.partition(":")
    if scheiding and not re.fullmatch(r"[0-9]{1,5}", poort):
        return False
    if naam.endswith("."):
        naam = naam[:-1]
    if not naam or not _NAAM.fullmatch(naam):
        return False
    if _NUMERIEK.fullmatch(naam):
        try:
            ipaddress.IPv4Address(naam)  # weigert verkorte, decimale, octale en hexadecimale vormen
        except ValueError:
            return False
        return True
    if "." not in naam:
        return True
    return naam.endswith(LAN_ACHTERVOEGSELS)


def herkomst_fout(request: Request) -> str | None:
    """De herkomstcontrole van §3.7 (punt 2–4) zonder het formuliertoken; ``None`` = in orde, anders de vaste code."""
    host = request.headers.get("host")
    if not host_toegestaan(host):
        return "host_niet_toegestaan"
    site = request.headers.get("sec-fetch-site")
    if site is not None and site.strip().lower() not in SEC_FETCH_SITE_OK:
        return "herkomst_onjuist"  # same-site (andere app op hetzelfde NAS-adres) of cross-site
    origin = (request.headers.get("origin") or "").strip()
    if not origin or origin == "null":
        return "herkomst_onjuist"  # fail-closed: zonder Origin weten we niet waar het formulier vandaan kwam
    verwacht = f"{request.url.scheme}://{(host or '').strip()}"
    if origin.lower() != verwacht.lower():
        return "herkomst_onjuist"
    return None


def _formuliertoken_ok(request: Request, token: str) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE, "")
    return bool(cookie) and bool(token) and hmac.compare_digest(cookie.encode(), token.encode())


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


class Meldingen:
    """Meldingen na een geslaagde poging (§3.7): sleutel in het geheugen, hooguit 15 min geldig, alleen voor de browser
    met hetzelfde formuliercookie. Zonder geldige sleutel toont de pagina niets (nooit op alleen een query-parameter)."""

    def __init__(self, geldig_s: float = MELDING_GELDIG_S, maximum: int = MELDING_MAX) -> None:
        self.geldig_s, self.maximum = geldig_s, maximum
        self._items: dict[str, tuple[float, str, str]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _browser(cookie: str) -> str:
        return hashlib.sha256(cookie.encode()).hexdigest()

    def maak(self, soort: str, cookie: str) -> str:
        sleutel = secrets.token_urlsafe(16)
        nu = time.monotonic()
        with self._lock:
            self._opruimen(nu)
            while len(self._items) >= self.maximum:
                self._items.pop(next(iter(self._items)))
            self._items[sleutel] = (nu, self._browser(cookie), soort)
        return sleutel

    def lees(self, sleutel: str | None, cookie: str | None) -> str | None:
        if not sleutel or not cookie or len(sleutel) > 64:
            return None
        with self._lock:
            self._opruimen(time.monotonic())
            item = self._items.get(sleutel)
        if item is None or not hmac.compare_digest(item[1], self._browser(cookie)):
            return None
        return item[2]

    def _opruimen(self, nu: float) -> None:
        for k in [k for k, (t, _, _) in self._items.items() if nu - t > self.geldig_s]:
            del self._items[k]


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
    herstel_accounts: int | None = None  # aantal actieve accounts in het herstelregister; None = niet te meten
    host_ok: bool = True  # §3.7 punt 4: mag deze pagina via dit adres koppelen?


def meet(request: Request) -> Meting:
    state = request.app.state
    nu = datetime.now().astimezone()
    db_ok = state.db.ping()
    huidig = state.db.current_revision() if db_ok else None
    niveau: str | None = None
    accounts: int | None = None
    bronnen: list[BronStand] = []
    rijen: dict[str, Any] | None = None
    if db_ok:
        from .models import IntegrationSource

        try:
            with state.db.sessions() as s:
                overall = sso_service.overall(s, state.settings.break_glass_test_max_age_days)
                niveau = str(overall["level"])
                accounts = int(overall["counts"]["accounts"])
                rijen = {r.source_id: r for r in s.query(IntegrationSource).all()}
        except Exception as exc:  # een half gemigreerde database mag de statuspagina nooit laten crashen
            log.warning("statuspagina: stand van herstelregister/bronnen niet te lezen (%s)", type(exc).__name__)
            niveau, accounts, rijen = None, None, None
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
        herstel_accounts=accounts,
        host_ok=host_toegestaan(request.headers.get("host")),
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


def _rij(
    naam: str,
    toon: str,
    nu: datetime,
    reden: str | None = None,
    label: str | None = None,
    reden_code: str | None = None,
) -> dict[str, Any]:
    return {
        "naam": naam,
        "toon": _toon(toon),
        "label": label or _WOORD[toon],
        "tijd": f"{nu:%H:%M}",
        "iso": _iso(nu),
        "reden": reden,
        "reden_code": reden_code if reden else None,
    }


def _laatste_fout(link: LinkState, nu: datetime) -> str | None:
    if link.last_error is None:
        return None
    wanneer = _parse(link.last_error.at)
    tijd = nl_datumtijd(wanneer.astimezone(nu.tzinfo)) if wanneer else "tijd onbekend"
    tekst = ERROR_MESSAGES.get(link.last_error.code, "Koppelen is niet gelukt.")
    return f"Laatste melding, {tijd} (code {link.last_error.code}): {tekst}"


# ------------------------------------------------------------------------------------------------ model


def koppeltoestand(link: LinkState) -> str:
    """Precies één van ``koppelformulier`` · ``gekoppeld`` · ``ontkoppeld`` · ``ingetrokken`` ·
    ``koppelstatus_onleesbaar`` (§3.5/§3.7)."""
    if link.corrupt:
        return "koppelstatus_onleesbaar"
    if not link.ever_linked:
        return "koppelformulier"
    if link.state == "gekoppeld":
        return "gekoppeld"
    if link.state == "ingetrokken":
        return "ingetrokken"
    return "ontkoppeld"


def _bezig_sinds(link: LinkState, nu: datetime) -> datetime | None:
    if link.pending is None:
        return None
    start = _parse(link.pending.started_at)
    return start.astimezone(nu.tzinfo) if start else None


def _koppel_controle(m: Meting, met_laatste_fout: bool) -> tuple[dict[str, Any] | None, str | None]:
    """Controle 'Koppeling met de Hub' (alleen als er iets ontbreekt) en de reden waarom de dienst niet gereed is.

    Peil 1.1.1 (E03/E04): niet gekoppeld, ontkoppeld en ingetrokken krijgen de toon ``niet-gekoppeld`` (``link-2-off``,
    telt als Onbekend) met het vaste woord uit §11.1; een onleesbaar koppelbestand is Storing ("Onleesbaar")."""
    link, nu, naam = m.link, m.nu, "Koppeling met de Hub"
    laatste = _laatste_fout(link, nu) if met_laatste_fout else None
    toestand = koppeltoestand(link)

    def rij(toon: str, label: str, *delen: str | None, code: str | None = None) -> dict[str, Any]:
        return _rij(naam, toon, nu, " ".join(d for d in delen if d), label, code)

    if toestand == "koppelstatus_onleesbaar":
        reden = "Het koppelbestand is geen geldig bestand van deze dienst. Herstel staat hieronder bij Koppeling met de Hub."
        return rij("storing", "Onleesbaar", reden, code="koppelstatus_onleesbaar"), "koppelstatus onleesbaar"
    if toestand == "koppelformulier":
        sinds = _bezig_sinds(link, nu)
        if link.pending is not None:
            via = "met het token uit de Custom App" if link.pending.kind == "token" else "met een koppelcode"
            wanneer = f" sinds {sinds:%H:%M}" if sinds else ""
            reden = f"Er loopt een koppelpoging{wanneer} ({via})."
            return rij("niet-gekoppeld", "Niet gekoppeld", reden, laatste), "er loopt een koppelpoging"
        reden = "Zonder koppeling voert de dienst niets uit voor de Hub."
        return rij("niet-gekoppeld", "Niet gekoppeld", reden, laatste), "wacht op koppeling met de Hub"
    if toestand == "ingetrokken":
        reden = f"De Hub heeft de koppeling ingetrokken; de dienst weigert elke opdracht. {OPNIEUW_VIA_HUB_NL}"
        return rij("niet-gekoppeld", "Ingetrokken", reden), "de Hub heeft de koppeling ingetrokken"
    if toestand == "ontkoppeld":
        reden = f"De Hub heeft deze dienst ontkoppeld; de dienst voert niets uit. {OPNIEUW_VIA_HUB_NL}"
        return rij("niet-gekoppeld", "Ontkoppeld", reden), "ontkoppeld door de Hub"
    if not link.linked:
        reden = f"De koppeling is onvolledig opgeslagen; de dienst vertrouwt niets van de Hub. {OPNIEUW_VIA_HUB_NL}"
        return rij("storing", "Storing", reden), "koppeling onvolledig"
    if link.confirmed_at is None:
        reden = "Niet bevestigd: gekoppeld, maar de Hub heeft de koppeling nog niet bevestigd. De dienst probeert het opnieuw."
        return rij("onbekend", "Onbekend", reden), "wacht op bevestiging door de Hub"
    return None, None


def bouw_model(
    m: Meting,
    *,
    csrf: str,
    fout: Fout | None = None,
    gekoppeld_melding: bool = False,
) -> dict[str, Any]:
    """Alle plekken van het Peil-sjabloon 1.1.1 (pure functie; unit-getest per toestand)."""
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
        rijen.append(_rij("Sleutels van de Hub", "beperkt", nu, reden, reden_code="sleutelrotatie_geweigerd"))

    gereed = not niet_gereed
    dienst_blok = _dienst_blok(m)
    totaal_toon, totaal_label, toelichting = _totaal(rijen, gereed, niet_gereed, dienst_blok)
    bezig = m.link.pending is not None and toestand != "koppelstatus_onleesbaar"
    sinds = _bezig_sinds(m.link, nu) if bezig else None

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
        "bron": BRON_NL,
        "bijgewerkt": nl_datumtijd(nu),
        "bijgewerkt_iso": _iso(nu),
        "koppelformulier": toestand == "koppelformulier",
        "gekoppeld": toestand == "gekoppeld",
        "ontkoppeld": toestand == "ontkoppeld",
        "ingetrokken": toestand == "ingetrokken",
        "koppelstatus_onleesbaar": toestand == "koppelstatus_onleesbaar",
        "koppelen_bezig": bezig,
        "koppelen_bezig_sinds": f"{sinds:%H:%M}" if sinds else None,
        "koppelen_bezig_iso": _iso(sinds) if sinds else None,
        "koppelcode_geldig": KOPPELCODE_GELDIG,
        "csrf_token": csrf,
        "dienst_blok_titel": "Wat deze dienst doet",
        "dienst_blok": dienst_blok,
    }
    if toestand == "gekoppeld":
        linked_at = _parse(m.link.linked_at)
        adres = m.link.hub_url or ""
        data.update(
            gekoppeld_sinds=nl_datumtijd(linked_at.astimezone(nu.tzinfo)) if linked_at else "onbekend",
            # alleen een http(s)-adres uit de opgeslagen koppeling (gecontroleerd bij het koppelen) wordt een link
            hub_adres=adres if _HTTP_ADRES.match(adres) else "",
            hub_vingerafdruk=m.link.pins.keyset_fingerprint if m.link.pins else "onbekend",
        )
    if fout is not None:
        # de fout van dít verzoek: rol alert, code + trace-ID (Peil 1.1.1, E05/E06)
        soort = fout.soort
        data.update(
            melding=True,
            melding_toon="fout",
            melding_rol="alert",
            melding_icoon=MELDING_ICOON["fout"],
            melding_titel=soort.titel,
            melding_tekst=soort.tekst,
            melding_code=fout.code,
            trace_id=fout.trace_id,
        )
        if data["koppelformulier"] and not bezig and fout.code not in _GEEN_INVOER:
            data["melding_tekst"] = f"{soort.tekst} {OPNIEUW_INVULLEN_NL}"
        if soort.veld is not None and data["koppelformulier"] and not bezig:
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
    elif toestand == "koppelstatus_onleesbaar":
        # een toestand die bij het laden al bestond: geen live-regio en geen trace-ID, wel de code en het pad
        data.update(
            melding=True,
            melding_toon="fout",
            melding_rol="",
            melding_icoon=MELDING_ICOON["fout"],
            melding_titel="De koppelstatus is onleesbaar",
            melding_tekst="Deze dienst kon zijn koppelbestand niet lezen en voert daarom niets uit. Het bestand:",
            melding_pad=f"/appdata/secrets/{LINK_FILE}",
            melding_code="koppelstatus_onleesbaar",
        )
    elif gekoppeld_melding and toestand == "gekoppeld":
        data.update(
            melding=True,
            melding_toon="info",
            melding_rol="status",
            melding_icoon=MELDING_ICOON["info"],
            melding_titel="Gekoppeld met de Hub",
            melding_tekst="Vergelijk de vingerafdruk hieronder met die in de Hub.",
        )
    elif data["koppelformulier"] and not bezig and not m.host_ok:
        # §3.7 punt 4: via dit adres kan niet gekoppeld worden; dat zeggen we vóór iemand het formulier invult
        data.update(
            melding=True,
            melding_toon="info",
            melding_rol="",
            melding_icoon=MELDING_ICOON["info"],
            melding_titel="Koppelen kan niet via dit adres",
            melding_tekst="Deze pagina is geopend via een domeinnaam. Koppelen via deze pagina kan alleen via het "
            f"IP-adres van de NAS of een lokale naam (zoals nas.local). {HOST_NIET_TOEGESTAAN_NL}",
            melding_code="host_niet_toegestaan",
        )
    data["titel_toestand"] = _titel(toestand, fout, totaal_label)
    return data


def _dienst_blok(m: Meting) -> list[dict[str, Any]]:
    def rij(naam: str, toon: str, reden: str, label: str | None = None, code: str | None = None) -> dict[str, Any]:
        return {"naam": naam, "toon": _toon(toon), "label": label or _WOORD[toon], "reden": reden, "reden_code": code}

    blok: list[dict[str, Any]] = []
    for domein in DOMAINS:
        naam = DOMAIN_TITLES_NL[domein]
        totaal = sum(1 for s in ALL_SOURCES.values() if s.domain == domein)
        if not m.db_ok or not m.bronnen:
            blok.append(rij(naam, "onbekend", "Niet te meten: de eigen database antwoordt niet."))
            continue
        ingesteld = [b for b in m.bronnen if b.domein == domein and b.ingesteld]
        if not ingesteld:
            woord = "bron" if totaal == 1 else "bronnen"
            reden = (
                f"Nog geen bron ingesteld ({totaal} {woord} in de inventaris). Instellen gaat via de Hub. Dit is geen "
                "storing; er wacht een voorwaarde."
            )
            blok.append(rij(naam, "gate", reden, "Niet ingesteld"))
            continue
        blok.append(_domein_rij(naam, totaal, ingesteld, m.nu))
    niveau = m.herstel_niveau if m.db_ok else None
    if niveau is not None and m.herstel_accounts == 0:
        reden = (
            "Er staan nog geen beheeraccounts in het herstelregister. Invullen gaat via de Hub (alleen beheerders). "
            "Dit is geen storing; er wacht een voorwaarde."
        )
        blok.append(rij("Beheerherstel (B13-001)", "gate", reden, "Niet ingevuld"))
    else:
        blok.append(
            rij(
                "Beheerherstel (B13-001)",
                _HERSTEL_TOON.get(niveau or "", "onbekend"),
                _HERSTEL_REDEN.get(niveau or "", "Niet te meten: de eigen database antwoordt niet."),
            )
        )
    blok.append(
        rij(
            "Boiler",
            "beleid",
            "Schakelen is altijd uitgeschakeld (beleid). Er is bewust geen schakelaar; deze dienst meet alleen.",
            "Alleen meten",
        )
    )
    return blok


_HERSTEL_DETAILS = "Alleen het totaalniveau staat hier; details en oefeningen staan in de Hub (alleen voor beheerders)."
#: Onbekend en Beperkt altijd met een reden, zonder aandachtspunten of accountnamen van het herstelregister
_HERSTEL_REDEN = {
    "ok": f"{_HERSTEL_DETAILS} De noodlogin zit in de Hub en hangt niet van deze dienst of van Authentik af.",
    "risico": f"Het herstelregister heeft aandachtspunten. {_HERSTEL_DETAILS}",
    "onbekend": f"Het herstelregister is nog niet volledig ingevuld of getest. {_HERSTEL_DETAILS}",
}


def _domein_rij(naam: str, totaal: int, ingesteld: list[BronStand], nu: datetime) -> dict[str, Any]:
    """Stand van een domein: de slechtste van de **verse** metingen. Een verouderde meting is nooit de laatst bekende
    stand als actueel (Peil §4.4, E15): zijn er alleen verouderde metingen, dan toon ``verouderd`` met de tijd van de
    laatste meting (telt niet mee in het totaal); een nooit gedane meting telt als Onbekend."""
    soorten: dict[str, int] = {}
    tonen: list[str] = []
    verse: list[datetime] = []
    oud: list[datetime] = []
    for b in ingesteld:
        if b.gemeten is None:
            soort, toon = "nog nooit gemeten", "onbekend"
            tonen.append(toon)
        elif nu - b.gemeten > BRON_MAX_LEEFTIJD:
            soort = "verouderd"
            oud.append(b.gemeten)
        else:
            toon = _BRON_TOON.get(b.status, "onbekend")
            soort = {"gezond": "gezond", "beperkt": "beperkt", "storing": "storing"}.get(toon, "onbekend")
            tonen.append(toon)
            verse.append(b.gemeten)
        soorten[soort] = soorten.get(soort, 0) + 1
    volgorde = ("storing", "beperkt", "onbekend", "verouderd", "nog nooit gemeten", "gezond")
    laatst_oud = max(oud).astimezone(nu.tzinfo) if oud else None
    soorten_tekst = {"verouderd": f"verouderd (laatst bekend {nl_datumtijd(laatst_oud)})"} if laatst_oud else {}
    telling = ", ".join(f"{soorten[s]} {soorten_tekst.get(s, s)}" for s in volgorde if soorten.get(s))
    woord = "bron" if totaal == 1 else "bronnen"
    delen = [f"{len(ingesteld)} van {totaal} {woord} ingesteld: {telling}."]
    if verse:
        delen.append(f"Laatst gemeten {nl_datumtijd(max(verse).astimezone(nu.tzinfo))}.")
    if oud:
        minuten = int(BRON_MAX_LEEFTIJD.total_seconds() // 60)
        delen.append(f"Metingen ouder dan {minuten} minuten tonen we niet als actueel.")
    if not tonen and laatst_oud is not None:
        label = f"Verouderd · laatst bekend {laatst_oud:%H:%M}"
        return {"naam": naam, "toon": "verouderd", "label": label, "reden": " ".join(delen), "reden_code": None}
    toon = max(tonen, key=lambda t: _ERNST[t])
    code = "meting_verouderd" if oud else None
    return {"naam": naam, "toon": _toon(toon), "label": _WOORD[toon], "reden": " ".join(delen), "reden_code": code}


def _totaal(
    rijen: list[dict[str, Any]], gereed: bool, niet_gereed: list[str], dienst_blok: list[dict[str, Any]]
) -> tuple[str, str, str]:
    """Totaal (Peil 1.1.1, E10): het slechtste van de eigen controles en de verse metingen in het dienstblok. Het
    dienstblok maakt het totaal hooguit Beperkt; ``gate``, ``nog-niet``, ``beleid``, ``feit`` en ``verouderd`` tellen
    niet mee. Nooit groen zonder Gereed (contract 1.3 §3.7/§13)."""
    eigen = max((_ERNST.get(r["toon"], 0) for r in rijen), default=0)
    blok = max((min(_ERNST.get(r["toon"], 0), _ERNST["beperkt"]) for r in dienst_blok), default=0)
    ernst = max(eigen, blok)
    if not gereed:
        eigen = max(
            eigen, _ERNST["onbekend"]
        )  # vangnet: het eerste signaal is nooit groen als de dienst niet gereed is
        ernst = max(eigen, blok)
        aanloop = {"storing": "Storing", "beperkt": "Beperkt", "onbekend": "Deels onbekend"}[_TOTAAL_TOON[eigen]]
        toelichting = f"{aanloop} — {'; '.join(niet_gereed)}."
        if blok > eigen:  # het dienstblok maakt het erger dan de eigen controles: zeg waardoor
            oorzaak = ", ".join(r["naam"] for r in dienst_blok if _ERNST.get(r["toon"], 0) >= blok)
            toelichting += f" Daarnaast beperkt: {oorzaak}."
        return _TOTAAL_TOON[ernst], "Niet gereed", toelichting
    toon = _TOTAAL_TOON[ernst]
    if toon not in TOTAAL_TONEN:  # pragma: no cover - programmeerfout
        raise ValueError(toon)
    if toon == "gezond":
        overig = sum(1 for r in dienst_blok if r["toon"] in ("gate", "nog-niet", "verouderd"))
        wacht = "onderdeel wacht" if overig == 1 else "onderdelen wachten"
        extra = f" {overig} {wacht} op instelling of een verse meting." if overig else ""
        return "gezond", "Alles gezond", f"Gereed. Alle controles en gemeten onderdelen zijn gezond.{extra}"
    namen = [r["naam"] for r in [*rijen, *dienst_blok] if _ERNST.get(r["toon"], -1) >= 1]
    lijst = ", ".join(namen)
    if toon == "onbekend":
        return "onbekend", "Deels onbekend", f"Gereed, maar deels onbekend: {lijst}."
    beperkt = ", ".join(r["naam"] for r in [*rijen, *dienst_blok] if _ERNST.get(r["toon"], -1) >= 2)
    return "beperkt", "Beperkt", f"Gereed, maar beperkt: {beperkt}."


def _titel(toestand: str, fout: Fout | None, totaal_label: str) -> str:
    woord = {
        "koppelformulier": "niet gekoppeld",
        "gekoppeld": "gekoppeld",
        "ontkoppeld": "ontkoppeld",
        "ingetrokken": "ingetrokken",
        "koppelstatus_onleesbaar": "koppelstatus onleesbaar",
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
    data = bouw_model(m, csrf=csrf, fout=fout, gekoppeld_melding=gekoppeld_melding)
    try:
        html = render(tpl.tekst, data)
    except SjabloonOntbreekt as exc:  # pragma: no cover - de gepinde kopie is getest; alleen bij een kapotte kopie
        log.error("statuspagina: sjabloon onleesbaar: %s (trace_id=%s)", exc, tid)
        return _with_headers(PlainTextResponse(f"Statuspagina niet beschikbaar. Trace-ID {tid}\n", status_code=503))
    resp = HTMLResponse(html, status_code=status)
    if status == 429:
        resp.headers["Retry-After"] = "900"
    return _with_headers(resp, csrf)


@router.get("/", response_class=HTMLResponse)
def status_page(request: Request, melding: str | None = None) -> Response:
    # alleen een melding van een echte, recente poging van deze browser (sleutel in het geheugen, §3.7)
    soort = request.app.state.meldingen.lees(melding, request.cookies.get(CSRF_COOKIE))
    return _pagina(request, gekoppeld_melding=soort == "gekoppeld")


def _afgehandeld(request: Request, code: str, tid: str, *, telt: bool) -> Response:
    """Precies één logregel per formulier-POST (§3.7): code en trace-ID, geen Hub-adres en geen geheimen."""
    fout = Fout(code, tid)
    soort = "geweigerd (herkomst, telt niet mee)" if not telt else "mislukt of geweigerd"
    log.warning("statuspagina: koppelpoging %s: code=%s trace_id=%s", soort, code, tid)
    return _pagina(request, status=fout.soort.status, fout=fout)


def _invoer_fout(hub_adres: str, koppelcode: str, vingerafdruk: str) -> str | None:
    """§3.7: invoer als geheel controleren, nooit eerst afkappen; de vorm controleert ``pair_with_code``."""
    if len(hub_adres) > MAX_HUB_ADRES:
        return "ongeldig_hub_adres"
    if len(koppelcode) > MAX_KOPPELCODE:
        return "ongeldige_koppelcode"
    if len(vingerafdruk) > MAX_VINGERAFDRUK:
        return "ongeldige_vingerafdruk"
    return None


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
    # 1. herkomst (§3.7 punt 2–5): telt niet mee, gaat niet naar de Hub, verandert niets
    code = herkomst_fout(request)
    if code is None and not _formuliertoken_ok(request, csrf):
        code = "ongeldig_formulier"
    if code is not None:
        return _afgehandeld(request, code, tid, telt=False)
    # 2. vanaf hier telt elke POST als poging (§3.7, RV7)
    ip = request.client.host if request.client else "onbekend"  # TCP-bron; nooit X-Forwarded-For (§3.7)
    if not state.pair_throttle.allow(ip):
        return _afgehandeld(request, "te_veel_pogingen", tid, telt=True)
    link = state.hublink.state()
    if link.corrupt:
        code = "koppelstatus_onleesbaar"  # een POST uit een oud tabblad gaat niet naar de Hub (§3.7)
    elif link.ever_linked:
        code = "al_gekoppeld"
    elif link.pending is not None and not state.hublink.pending_is_stale(link.pending):
        code = "koppelen_bezig"
    else:
        code = _invoer_fout(hub_adres, koppelcode, hub_vingerafdruk)
    if code is not None:
        return _afgehandeld(request, code, tid, telt=True)
    # 3. één poging naar de Hub (enrollment.pair_with_code controleert de vorm en claimt de poging atomair)
    outcome = state.hublink.pair_with_code(
        hub_url=hub_adres, pairing_code=koppelcode, fingerprint=hub_vingerafdruk, trace_id=tid
    )
    if outcome.ok:
        log.info("statuspagina: koppelpoging geslaagd: code=gekoppeld trace_id=%s", tid)
        sleutel = state.meldingen.maak("gekoppeld", request.cookies.get(CSRF_COOKIE, ""))
        return _with_headers(RedirectResponse(f"/?melding={sleutel}", status_code=303))
    code = str(outcome.code or "onbekend")
    if state.db.ping():
        with contextlib.suppress(Exception), state.db.sessions() as s:
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
    return _afgehandeld(request, code, tid, telt=True)
