"""Actuele volledigheid en openbare projectie van opgeslagen Authentik-exports."""

from __future__ import annotations

import hashlib
from typing import Any

from .authentik.reader import clean_provider, incomplete_provider_details
from .models import SsoAuthentikSnapshot

# Versie 2 controleert de aanwezigheid van verplichte velden bij het uitlezen, vóór normalisatie.
EXPORT_FORMAT = "hch-authentik-config-export/2"


def export_content(row: SsoAuthentikSnapshot) -> dict[str, Any]:
    """Projecteer de opgeslagen gegevens zonder de oorspronkelijke inhoud of hash te wijzigen."""
    content = row.content or {}
    parts = content.get("parts", {})
    rows = parts.get("providers")
    if rows is None and not row.complete:
        return content

    providers = [clean_provider(p) for p in rows if isinstance(p, dict)] if isinstance(rows, list) else []
    missing = list(content.get("missing", []))
    if providers != rows or any(p.get("onvolledige_velden") for p in providers):
        detail = incomplete_provider_details()
        if detail not in missing:
            missing.append(detail)
    if content.get("format") != EXPORT_FORMAT and any(not p["redirect_uris"] for p in providers):
        # In versie 1 leverden een ontbrekend veld en een expliciet lege lijst dezelfde opgeslagen waarde op.
        missing.append({"part": "providers", "reason": "provider_redirects_niet_geverifieerd"})
    if providers == rows and missing == content.get("missing", []):
        return content
    return {**content, "parts": {**parts, "providers": providers}, "missing": missing}


def export_is_complete(row: SsoAuthentikSnapshot, content: dict[str, Any] | None = None) -> bool:
    return row.complete and not (export_content(row) if content is None else content).get("missing")


def source_id(base_url: str) -> str:
    """Welke Authentik-bron een export beschrijft: een hash van het ingestelde adres, zodat geen adres wordt opgeslagen."""
    return hashlib.sha256(base_url.rstrip("/").encode()).hexdigest()
