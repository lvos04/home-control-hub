"""Actuele volledigheid en openbare projectie van opgeslagen Authentik-exports."""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy.orm import Session

from ...models import IntegrationSource, VaultSecret
from .authentik.client import SOURCE_ID
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


def source_binding(session: Session) -> str | None:
    """Welke koppeling met Authentik een export beschrijft: het ingestelde adres plus de revisie van het opgeslagen
    token. Een nieuw token (ook voor een vervangende installatie op hetzelfde adres) of een nieuw adres geeft een
    andere waarde, dus een export van vóór de herkoppeling telt niet als bewijs van continuïteit. Alleen niet-geheime
    gegevens in de hash; ``None`` zolang er geen koppeling is."""
    source = session.get(IntegrationSource, SOURCE_ID)
    secret = session.get(VaultSecret, source.credential_ref) if source is not None and source.credential_ref else None
    if source is None or not source.base_url or secret is None:
        return None
    raw = f"{source.base_url.rstrip('/')}|{source.credential_ref}|{secret.created_at.isoformat()}|{secret.version}"
    return hashlib.sha256(raw.encode()).hexdigest()
