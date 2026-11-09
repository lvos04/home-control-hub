"""Aanmelden bij de Hub (contract §3).

Twee routes:
1. **Eenmalig enrollment-token** uit de omgeving (``HUB_URL`` + ``HUB_ENROLLMENT_TOKEN``), gezet door de Hub bij
   installatie via de API. De worker roept ``POST {HUB_URL}/api/v1/services/enroll`` aan.
2. **Koppelcode** uit de Hub-UI, ingevoerd op de statuspagina (handmatig geïnstalleerde app).

Resultaat: een eigen service-token (versleuteld in de vault, alleen SHA-256 + laatste 4 tekens in de status), de
Hub-JWKS en (optioneel) de publieke policy-sleutel. Zonder Hub toont de dienst eerlijk **niet gekoppeld**.
Het verzoek-/antwoordformaat van het enroll-endpoint is een aanname tot de Hub het vastlegt (ADR-0002).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from sqlalchemy.orm import Session

from . import API_PREFIX, APP_ID, CONNECTOR_PREFIX, __version__
from .config import Settings
from .hubclient import HubClient, HubUrlError, validate_hub_url
from .models import ServiceState
from .security.auth import sha256_hex
from .security.jwks import parse_jwks
from .security.vault import Vault
from .timeutil import iso, utcnow

log = logging.getLogger("integrations.enrollment")

STATE_KEY = "hub_link"
JWKS_KEY = "hub_jwks"
POLICY_KEY = "hub_policy_key"
SERVICE_TOKEN_REF = "vault://hub/service-token"  # noqa: S105 - referentie, geen geheim
ENROLL_PATH = "/api/v1/services/enroll"
JWKS_PATH = "/api/v1/auth/jwks"
EVENTS_INBOX_PATH = "/api/v1/events/inbox"

MESSAGES = {
    "geen_hub_url": "Niet gekoppeld: er is geen Hub-adres ingesteld. Koppel via een koppelcode uit de Hub.",
    "wacht_op_koppeling": "Niet gekoppeld: wacht op koppelen met een koppelcode uit de Hub.",
    "ontkoppeld": "Niet gekoppeld: de koppeling met de Hub is verwijderd.",
    "hub_onbereikbaar": "Koppelen mislukt: de Hub is niet bereikbaar. Er wordt later opnieuw geprobeerd.",
    "hub_weigerde_token": "Koppelen mislukt: de Hub weigerde het koppeltoken (verlopen, al gebruikt of ongeldig).",
    "hub_weigerde_code": "Koppelen mislukt: de Hub weigerde de koppelcode (verlopen, al gebruikt of ongeldig).",
    "enroll_endpoint_ontbreekt": "Koppelen mislukt: deze Hub-versie kent het aanmeld-endpoint niet.",
    "hub_antwoord_ongeldig": "Koppelen mislukt: het antwoord van de Hub was onvolledig of ongeldig.",
    "ongeldig_hub_adres": "Koppelen mislukt: het Hub-adres is ongeldig.",
    "gekoppeld": "Gekoppeld met de Hub.",
}


@dataclass
class EnrollOutcome:
    ok: bool
    reason: str
    retryable: bool = False

    @property
    def message_nl(self) -> str:
        return MESSAGES.get(self.reason, self.reason)


def _get(session: Session, key: str) -> dict[str, Any] | None:
    row = session.get(ServiceState, key)
    return dict(row.value) if row is not None else None


def _put(session: Session, key: str, value: dict[str, Any]) -> None:
    row = session.get(ServiceState, key)
    if row is None:
        session.add(ServiceState(key=key, value=value))
    else:
        row.value = value


def _delete(session: Session, key: str) -> None:
    row = session.get(ServiceState, key)
    if row is not None:
        session.delete(row)


class EnrollmentService:
    def __init__(self, settings: Settings, vault: Vault, identity_jwk: dict[str, str], hub: HubClient) -> None:
        self.settings = settings
        self.vault = vault
        self.identity_jwk = identity_jwk
        self.hub = hub

    # ------------------------------------------------------------------ status
    def state(self, session: Session) -> dict[str, Any]:
        st = _get(session, STATE_KEY)
        if st is None:
            reason = "wacht_op_koppeling" if self.settings.hub_url else "geen_hub_url"
            st = {"status": "niet_gekoppeld", "reason": reason}
        st.setdefault("message_nl", MESSAGES.get(st.get("reason", ""), ""))
        return st

    def public_state(self, session: Session) -> dict[str, Any]:
        st = self.state(session)
        return {
            "status": st.get("status"),
            "reason": st.get("reason"),
            "message_nl": st.get("message_nl"),
            "hub_url": st.get("hub_url"),
            "via": st.get("via"),
            "service_id": st.get("service_id"),
            "enrolled_at": st.get("enrolled_at"),
            "service_token_last4": st.get("service_token_last4"),
            "last_attempt_at": st.get("last_attempt_at"),
            "env_token_present": bool(self.settings.enrollment_token),
        }

    def service_token(self, session: Session) -> str | None:
        return self.vault.get(session, SERVICE_TOKEN_REF)

    # ------------------------------------------------------------------ enrollment
    def enroll_with_env_token(self, session: Session) -> EnrollOutcome | None:
        """Voor de worker. Geeft None als er niets te doen is (al gekoppeld, geen token of token al afgewezen)."""
        s = self.settings
        if not s.hub_url or not s.enrollment_token:
            return None
        st = self.state(session)
        if st.get("status") == "gekoppeld":
            return None
        fp = sha256_hex(s.enrollment_token)
        if st.get("rejected_token_sha256") == fp:
            return None  # dit token is definitief afgewezen; wacht op een nieuw token of koppelcode
        return self._enroll(session, s.hub_url, "token", s.enrollment_token, fingerprint=fp)

    def enroll_with_code(self, session: Session, hub_url: str, code: str) -> EnrollOutcome:
        try:
            url = validate_hub_url(hub_url, self.settings.allow_loopback_hub)
        except HubUrlError:
            return EnrollOutcome(False, "ongeldig_hub_adres")
        code = code.strip()
        if not code or len(code) > 128:
            return EnrollOutcome(False, "hub_weigerde_code")
        return self._enroll(session, url, "koppelcode", code, fingerprint=None)

    def _enroll(self, session: Session, hub_url: str, kind: str, secret: str, fingerprint: str | None) -> EnrollOutcome:
        try:
            hub_url = validate_hub_url(hub_url, self.settings.allow_loopback_hub)
        except HubUrlError:
            return self._fail(session, hub_url, kind, EnrollOutcome(False, "ongeldig_hub_adres"), fingerprint)
        body = {
            "app_id": APP_ID,
            "kind": kind,
            "secret": secret,
            "version": __version__,
            "base_url": self.settings.public_url,
            "public_key_jwk": self.identity_jwk,
            "api_prefix": API_PREFIX,
            "connector_prefix": CONNECTOR_PREFIX,
        }
        try:
            resp = self.hub.request("POST", hub_url, ENROLL_PATH, json=body)
        except httpx.HTTPError:
            return self._fail(
                session, hub_url, kind, EnrollOutcome(False, "hub_onbereikbaar", retryable=True), fingerprint
            )
        if resp.status_code == 404:
            return self._fail(session, hub_url, kind, EnrollOutcome(False, "enroll_endpoint_ontbreekt"), fingerprint)
        if resp.status_code in (400, 401, 403, 409, 410, 422):
            reason = "hub_weigerde_token" if kind == "token" else "hub_weigerde_code"
            return self._fail(session, hub_url, kind, EnrollOutcome(False, reason), fingerprint)
        if resp.status_code not in (200, 201):
            return self._fail(
                session, hub_url, kind, EnrollOutcome(False, "hub_onbereikbaar", retryable=True), fingerprint
            )
        try:
            data = resp.json()
            token = data["service_token"]
            if not isinstance(token, str) or len(token) < 32 or token.count(".") == 2:
                raise ValueError("service_token")
            jwks = data.get("jwks")
            if jwks is not None:
                parse_jwks(jwks)  # valideert het formaat
        except (ValueError, KeyError, TypeError):
            return self._fail(
                session, hub_url, kind, EnrollOutcome(False, "hub_antwoord_ongeldig", retryable=True), fingerprint
            )

        last4 = self.vault.put(session, SERVICE_TOKEN_REF, token)
        now = iso(utcnow())
        _put(
            session,
            STATE_KEY,
            {
                "status": "gekoppeld",
                "reason": "gekoppeld",
                "message_nl": MESSAGES["gekoppeld"],
                "hub_url": hub_url,
                "via": kind,
                "service_id": str(data.get("service_id")) if data.get("service_id") else None,
                "enrolled_at": now,
                "last_attempt_at": now,
                "service_token_sha256": sha256_hex(token),
                "service_token_last4": last4,
                "used_token_sha256": fingerprint,
            },
        )
        if jwks is not None:
            _put(session, JWKS_KEY, {"jwks": jwks, "received_at": now, "source": "enroll"})
        else:
            _delete(session, JWKS_KEY)
        policy_key = data.get("policy_public_key")
        if isinstance(policy_key, dict):
            _put(session, POLICY_KEY, {"jwk": policy_key, "received_at": now})
        log.info("gekoppeld met de Hub op %s via %s", hub_url, kind)
        return EnrollOutcome(True, "gekoppeld")

    def _fail(
        self, session: Session, hub_url: str, kind: str, outcome: EnrollOutcome, fingerprint: str | None
    ) -> EnrollOutcome:
        st = self.state(session)
        if st.get("status") == "gekoppeld":
            return outcome  # een mislukte nieuwe poging verbreekt een bestaande koppeling niet
        new = {
            "status": "koppelen_mislukt",
            "reason": outcome.reason,
            "message_nl": outcome.message_nl,
            "hub_url": hub_url,
            "via": kind,
            "last_attempt_at": iso(utcnow()),
            "retryable": outcome.retryable,
            "attempts": int(st.get("attempts", 0)) + 1,
        }
        if fingerprint and not outcome.retryable:
            new["rejected_token_sha256"] = fingerprint
        elif st.get("rejected_token_sha256"):
            new["rejected_token_sha256"] = st["rejected_token_sha256"]
        _put(session, STATE_KEY, new)
        log.warning("koppelen met de Hub mislukt: %s", outcome.reason)
        return outcome

    def unpair(self, session: Session) -> None:
        self.vault.delete(session, SERVICE_TOKEN_REF)
        st = self.state(session)
        _put(
            session,
            STATE_KEY,
            {
                "status": "niet_gekoppeld",
                "reason": "ontkoppeld",
                "message_nl": MESSAGES["ontkoppeld"],
                "previous_hub_url": st.get("hub_url"),
                "unpaired_at": iso(utcnow()),
                # een al gebruikt omgevingstoken mag na ontkoppelen niet opnieuw proberen
                "rejected_token_sha256": st.get("used_token_sha256") or st.get("rejected_token_sha256"),
            },
        )
        _delete(session, JWKS_KEY)
        _delete(session, POLICY_KEY)


def stored_jwks(session: Session) -> Any | None:
    st = _get(session, JWKS_KEY)
    return st.get("jwks") if st else None
