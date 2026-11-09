"""Home Control Hub — integratiedienst van TrueNAS Home Platform V2.

Domeinen (elk een eigen module met duidelijke grenzen):
- ``domains.network``    B10 netwerk en privacy (NetAlertX, AdGuard Home, Tailscale, Cloudflared)
- ``domains.automation`` B11 Node-RED-automatisering
- ``domains.sso``        B13 Authentik/SSO en beheerherstel (break-glass)
- ``domains.energy``     B14 energie en resources
"""

from importlib import metadata

APP_ID = "home-control-hub"
SCHEMA_VERSION = "1.0"
API_PREFIX = "/integrations/v1"
CONNECTOR_PREFIX = "/connector/v1"

try:
    __version__ = metadata.version("home-control-hub")
except metadata.PackageNotFoundError:  # pragma: no cover - alleen bij draaien zonder installatie
    __version__ = "0.1.0"
