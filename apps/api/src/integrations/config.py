"""Configuratie uit omgevingsvariabelen.

De standaard TrueNAS Custom App heeft **geen verplichte variabelen**: alles heeft een veilige standaard.
Geheimen staan nooit in de omgeving; die maakt de app zelf aan in ``<data>/secrets`` (zie security.secrets).
Uitzondering (contract 1.2 §3.1/§3.2): het eenmalige ``HUB_ENROLLMENT_TOKEN`` (60 min, na gebruik waardeloos), samen
met ``HUB_URL`` en optioneel ``HUB_KEY_FINGERPRINT``. De oude naam ``ENROLLMENT_TOKEN`` wordt in deze release nog
gelezen, met een waarschuwing in de log; daarna vervalt hij.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PORT = 30420
DEFAULT_DATA_DIR = "/appdata"
DEFAULT_DB_URL = "postgresql+psycopg://hch@/hch?host=/tmp/hch-pg"


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} moet een geheel getal zijn, niet {raw!r}") from exc


def _bool(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "ja", "yes")


def _opt(name: str) -> str | None:
    raw = os.environ.get(name, "").strip()
    return raw or None


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path(DEFAULT_DATA_DIR)
    database_url: str = DEFAULT_DB_URL
    port: int = DEFAULT_PORT
    hub_url: str | None = None
    enrollment_token: str | None = None
    hub_key_fingerprint: str | None = None
    # True als het token alleen onder de verouderde naam ENROLLMENT_TOKEN stond (waarschuwing in de log)
    enrollment_token_legacy_name: bool = False
    public_url: str | None = None
    alembic_dir: Path | None = None
    # map met de versie-gepinde kopie van het Peil-statuspaginasjabloon (image: /usr/local/lib/hch/ontwerptaal);
    # leeg = ``design/ontwerptaal`` in de broncode (ontwikkeling en tests)
    peil_dir: Path | None = None
    # Hub-JWT (contract 1.2 §4): iss=hub, aud=home-control-hub, exp - iat <= 120 s, 30 s klokspeling. Vertrouwd worden
    # alleen de bij het koppelen gepinde sleutels uit hub-link.json (§4.5); er is geen JWKS-cache via HTTP meer.
    jwt_issuer: str = "hub"
    jwt_audience: str = "home-control-hub"
    jwt_max_lifetime_s: int = 120
    jwt_leeway_s: int = 30
    # Koppeling (§3.8, §4.5): periodieke bevestiging met services/self (zodat een aangevraagde rotatie binnen 5 min
    # gebeurt en een intrekking tijdig zichtbaar is) en het pollen van ondertekende sleutelrotaties (<= 15 min).
    hub_heartbeat_interval_s: float = 240.0
    hub_key_poll_interval_s: float = 900.0
    # uitgaande calls (contract §5): 5 s connect / 15 s read, max 3 pogingen
    http_connect_timeout_s: float = 5.0
    http_read_timeout_s: float = 15.0
    http_max_attempts: int = 3
    # B13-001
    break_glass_test_max_age_days: int = 90
    # B13-004: hoe vaak de worker events en de rechtenkaart uit Authentik leest (0 = uit)
    authentik_sync_interval_s: int = 300
    # B11: hoe vaak de worker de flows van Node-RED leest en bij een wijziging een momentopname maakt (0 = uit)
    node_red_sync_interval_s: int = 60
    # B11-005: alleen-lezen gekoppelde datamap van Node-RED (voor het door Node-RED zélf versleutelde
    # ``flows_cred.json``); leeg = credentials horen niet bij een momentopname (eerlijk gemeld, nooit verzonnen)
    node_red_data_dir: Path | None = None
    # B11-001: toegestane Node-RED-modules (allowlist voor plugins); alles daarbuiten blokkeert de flow
    node_red_allowed_modules: tuple[str, ...] = ("node-red",)
    # Bewust GEEN instelling voor vertrouwde proxies: X-Forwarded-*-headers worden nooit gebruikt (uvicorn met
    # proxy_headers=False; B13-003: geen toegang via X-Forwarded-User of vergelijkbare headers).
    worker_interval_s: float = 10.0
    # alleen voor ontwikkeling/tests: een Hub op 127.0.0.1 toestaan (in de container wijst loopback naar zichzelf)
    allow_loopback_hub: bool = False

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @classmethod
    def from_env(cls) -> Settings:
        alembic_dir = _opt("HCH_ALEMBIC_DIR")
        token = _opt("HUB_ENROLLMENT_TOKEN")
        legacy = _opt("ENROLLMENT_TOKEN")
        return cls(
            data_dir=Path(os.environ.get("HCH_DATA_DIR", DEFAULT_DATA_DIR)),
            database_url=os.environ.get("HCH_DATABASE_URL", DEFAULT_DB_URL),
            port=_int("HCH_PORT", DEFAULT_PORT),
            hub_url=_opt("HUB_URL"),  # gecontroleerd bij het koppelen (hubclient.validate_hub_url)
            enrollment_token=token or legacy,
            enrollment_token_legacy_name=token is None and legacy is not None,
            hub_key_fingerprint=_opt("HUB_KEY_FINGERPRINT"),
            public_url=_normalize_url(_opt("HCH_PUBLIC_URL")),
            alembic_dir=Path(alembic_dir) if alembic_dir else None,
            peil_dir=Path(peil_dir) if (peil_dir := _opt("HCH_PEIL_DIR")) else None,
            hub_heartbeat_interval_s=float(_int("HCH_HUB_HEARTBEAT_S", 240)),
            hub_key_poll_interval_s=float(min(900, max(1, _int("HCH_HUB_KEY_POLL_S", 900)))),
            break_glass_test_max_age_days=_int("HCH_BREAK_GLASS_MAX_AGE_DAYS", 90),
            authentik_sync_interval_s=_int("HCH_AUTHENTIK_SYNC_INTERVAL_S", 300),
            node_red_sync_interval_s=_int("HCH_NODE_RED_SYNC_INTERVAL_S", 60),
            node_red_data_dir=Path(nr_dir) if (nr_dir := _opt("HCH_NODE_RED_DATA_DIR")) else None,
            node_red_allowed_modules=_modules(_opt("HCH_NODE_RED_ALLOWED_MODULES")),
            worker_interval_s=float(_int("HCH_WORKER_INTERVAL_S", 10)),
            allow_loopback_hub=_bool("HCH_ALLOW_LOOPBACK_HUB"),
        )


_MODULE_RE = re.compile(r"^(@[a-z0-9][a-z0-9._-]{0,60}/)?[a-z0-9][a-z0-9._-]{0,80}$")


def _modules(raw: str | None) -> tuple[str, ...]:
    """Komma-gescheiden allowlist van Node-RED-modules; ``node-red`` (de kern) hoort er altijd bij."""
    names = ["node-red"]
    for part in (raw or "").split(","):
        name = part.strip()
        if not name or name in names:
            continue
        if not _MODULE_RE.match(name):
            raise ValueError(f"HCH_NODE_RED_ALLOWED_MODULES bevat een ongeldige modulenaam: {name!r}")
        names.append(name)
    return tuple(names)


def _normalize_url(url: str | None) -> str | None:
    if url is None:
        return None
    return url.rstrip("/")
