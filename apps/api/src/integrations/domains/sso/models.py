"""B13-001-datamodel: herstelregister voor beheeraccounts, **zonder geheimen**.

Er worden nooit wachtwoorden, herstelcodes, TOTP-seeds of sleutels opgeslagen — ook niet gehasht. Alleen:
welk account bestaat, welke herstelmethodes er zijn en wáár het materiaal bewaard wordt (keuzelijst), MFA-status als
attestatie, de noodtoegang (alleen LAN/VPN-bereiken, sessieduur, herbevestigingstermijn), oefeningen en activaties.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, Timestamps, new_id

SYSTEMS = ("hub_local", "authentik", "truenas", "node_red", "adguard_home", "netalertx", "overig")
LOGIN_KINDS = ("lokaal", "sso", "beide")
MFA_STATUSES = ("bevestigd", "niet_ingesteld", "onbekend")
MFA_METHODS = ("totp", "webauthn", "herstelcodes")
METHOD_TYPES = (
    "lokaal_wachtwoord_lan",
    "lokaal_wachtwoord_vpn",
    "herstelcodes_offline",
    "hardwaresleutel",
    "authentik_herstelsleutel",
    "truenas_console",
    "verzegelde_envelop",
)
# Welke methodes werken zonder SSO/Authentik (deterministisch; niet door de gebruiker in te stellen)
SSO_INDEPENDENT_METHODS = frozenset(
    {
        "lokaal_wachtwoord_lan",
        "lokaal_wachtwoord_vpn",
        "herstelcodes_offline",
        "hardwaresleutel",
        "truenas_console",
        "verzegelde_envelop",
    }
)
STORAGE_HINTS = ("wachtwoordmanager", "verzegelde_envelop", "kluis", "hardwaresleutel", "anders", "onbekend")


def _in(col: str, values: tuple[str, ...]) -> str:
    return f"{col} IN (" + ",".join(f"'{v}'" for v in values) + ")"


class SsoAdminAccount(Timestamps, Base):
    __tablename__ = "sso_admin_account"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    system: Mapped[str] = mapped_column(String(20), nullable=False)
    username: Mapped[str] = mapped_column(String(120), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    is_break_glass: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    login_kind: Mapped[str] = mapped_column(String(10), nullable=False)
    mfa_status: Mapped[str] = mapped_column(String(20), nullable=False, default="onbekend")
    mfa_methods: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    mfa_attested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_attested_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="actief")
    notes: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("system", "username", name="uq_sso_admin_account_system_username"),
        CheckConstraint(_in("system", SYSTEMS), name="system"),
        CheckConstraint(_in("login_kind", LOGIN_KINDS), name="login_kind"),
        CheckConstraint(_in("mfa_status", MFA_STATUSES), name="mfa_status"),
        CheckConstraint("status IN ('actief','uitgeschakeld')", name="status"),
        CheckConstraint("jsonb_typeof(mfa_methods) = 'array'", name="mfa_methods_array"),
        # een noodaccount mag nooit alleen via SSO kunnen inloggen (geen SSO-only lock-out)
        CheckConstraint("NOT is_break_glass OR login_kind <> 'sso'", name="break_glass_not_sso_only"),
    )


class SsoRecoveryMethod(Timestamps, Base):
    __tablename__ = "sso_recovery_method"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_admin_account.id", ondelete="CASCADE"), nullable=False
    )
    method_type: Mapped[str] = mapped_column(String(40), nullable=False)
    storage_hint: Mapped[str] = mapped_column(String(30), nullable=False, default="onbekend")
    sso_independent: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="actief")
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        CheckConstraint(_in("method_type", METHOD_TYPES), name="method_type"),
        CheckConstraint(_in("storage_hint", STORAGE_HINTS), name="storage_hint"),
        CheckConstraint("status IN ('actief','ingetrokken')", name="status"),
        CheckConstraint(
            "sso_independent = (method_type <> 'authentik_herstelsleutel')", name="sso_independent_derived"
        ),
        Index("ix_sso_recovery_method_account", "account_id"),
    )


class SsoEmergencyAccess(Timestamps, Base):
    """Noodtoegang voor een noodaccount: alleen vanaf LAN/VPN-bereiken, met sessieduur en herbevestiging.

    De noodtoegang zelf verloopt niet (dat zou bij nood een lock-out geven); wél verloopt elke activatie na
    ``session_max_minutes`` en wordt de registratie periodiek herbevestigd (``review_interval_days``).
    """

    __tablename__ = "sso_emergency_access"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_admin_account.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    network_scopes: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    session_max_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    review_interval_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    last_reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_reviewed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="actief")
    reason: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    updated_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "jsonb_typeof(network_scopes) = 'array' AND jsonb_array_length(network_scopes) > 0", name="scopes"
        ),
        CheckConstraint("session_max_minutes BETWEEN 5 AND 240", name="session_max"),
        CheckConstraint("review_interval_days BETWEEN 7 AND 365", name="review_interval"),
        CheckConstraint("status IN ('actief','ingetrokken')", name="status"),
    )


class SsoBreakGlassActivation(Base):
    """Gebruik van de noodtoegang (oefening of echt). Echte activatie → wachtwoord roteren vereist."""

    __tablename__ = "sso_break_glass_activation"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_admin_account.id", ondelete="CASCADE"), nullable=False
    )
    mode: Mapped[str] = mapped_column(String(10), nullable=False)
    client_ip: Mapped[str] = mapped_column(String(45), nullable=False)
    matched_scope: Mapped[str | None] = mapped_column(String(50), nullable=True)
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reported_by: Mapped[str] = mapped_column(String(200), nullable=False)
    rotation_required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotated_by: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        CheckConstraint("mode IN ('oefening','echt')", name="mode"),
        CheckConstraint("expires_at > activated_at", name="expiry"),
        CheckConstraint("rotation_required = (mode = 'echt')", name="rotation_after_real_use"),
        Index("ix_sso_break_glass_activation_account", "account_id", "activated_at"),
    )


class SsoBreakGlassDrill(Base):
    __tablename__ = "sso_break_glass_drill"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    account_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_admin_account.id", ondelete="CASCADE"), nullable=False
    )
    method_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sso_recovery_method.id", ondelete="SET NULL"), nullable=True
    )
    mode: Mapped[str] = mapped_column(String(10), nullable=False)
    outcome: Mapped[str] = mapped_column(String(10), nullable=False)
    authenticator_state: Mapped[str] = mapped_column(String(20), nullable=False)
    client_scope: Mapped[str] = mapped_column(String(10), nullable=False, default="onbekend")
    checks: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    notes: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    performed_by: Mapped[str] = mapped_column(String(200), nullable=False)
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    trace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    __table_args__ = (
        CheckConstraint("mode IN ('zelftest','handmatig')", name="mode"),
        CheckConstraint("outcome IN ('ok','mislukt','onvolledig')", name="outcome"),
        CheckConstraint(
            "authenticator_state IN ('online','offline','niet_geconfigureerd','onbekend')", name="authenticator_state"
        ),
        CheckConstraint("client_scope IN ('lan','vpn','onbekend')", name="client_scope"),
        Index("ix_sso_break_glass_drill_account", "account_id", "performed_at"),
    )


class SsoRecoveryKitExport(Base):
    """Metadata van een geëxporteerde, versleutelde herstelkit. Nooit de wachtwoordzin of de inhoud."""

    __tablename__ = "sso_recovery_kit_export"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    format: Mapped[str] = mapped_column(String(40), nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    register_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    accounts_count: Mapped[int] = mapped_column(Integer, nullable=False)
