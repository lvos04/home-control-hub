"""Configuratie uit omgevingsvariabelen.

De standaard TrueNAS Custom App heeft **geen verplichte variabelen**: alles heeft een veilige standaard.
Geheimen staan nooit in de omgeving; die maakt de app zelf aan in ``<data>/secrets`` (zie security.secrets).
Het enrollment-token in de omgeving is eenmalig en na gebruik waardeloos (contract §3).
"""

from __future__ import annotations

import os
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
    public_url: str | None = None
    alembic_dir: Path | None = None
    # JWT/JWKS (contract §4): iss=hub, aud=<dienst>, exp <= 120 s
    jwt_issuer: str = "hub"
    jwt_audience: str = "home-control-hub"
    jwt_max_lifetime_s: int = 120
    jwt_leeway_s: int = 30
    jwks_ttl_s: int = 300
    jwks_max_stale_s: int = 900
    jwks_min_refresh_interval_s: int = 30
    # uitgaande calls (contract §5): 5 s connect / 15 s read, max 3 pogingen
    http_connect_timeout_s: float = 5.0
    http_read_timeout_s: float = 15.0
    http_max_attempts: int = 3
    # B13-001
    break_glass_test_max_age_days: int = 90
    # Bewust GEEN instelling voor vertrouwde proxies: X-Forwarded-*-headers worden nooit gebruikt (uvicorn met
    # proxy_headers=False; B13-003: geen toegang via X-Forwarded-User of vergelijkbare headers).
    worker_interval_s: float = 10.0
    # alleen voor ontwikkeling/tests: een Hub op 127.0.0.1 toestaan (in de container wijst loopback naar zichzelf)
    allow_loopback_hub: bool = False
    # in-app-cache van de koppelstatus (API-proces leest de status die de worker schreef)
    link_cache_ttl_s: float = 5.0

    @property
    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    @classmethod
    def from_env(cls) -> Settings:
        alembic_dir = _opt("HCH_ALEMBIC_DIR")
        return cls(
            data_dir=Path(os.environ.get("HCH_DATA_DIR", DEFAULT_DATA_DIR)),
            database_url=os.environ.get("HCH_DATABASE_URL", DEFAULT_DB_URL),
            port=_int("HCH_PORT", DEFAULT_PORT),
            hub_url=_normalize_url(_opt("HUB_URL")),
            enrollment_token=_opt("HUB_ENROLLMENT_TOKEN") or _opt("ENROLLMENT_TOKEN"),
            public_url=_normalize_url(_opt("HCH_PUBLIC_URL")),
            alembic_dir=Path(alembic_dir) if alembic_dir else None,
            jwks_ttl_s=_int("HCH_JWKS_TTL_S", 300),
            jwks_max_stale_s=_int("HCH_JWKS_MAX_STALE_S", 900),
            break_glass_test_max_age_days=_int("HCH_BREAK_GLASS_MAX_AGE_DAYS", 90),
            worker_interval_s=float(_int("HCH_WORKER_INTERVAL_S", 10)),
            allow_loopback_hub=_bool("HCH_ALLOW_LOOPBACK_HUB"),
        )


def _normalize_url(url: str | None) -> str | None:
    if url is None:
        return None
    return url.rstrip("/")
