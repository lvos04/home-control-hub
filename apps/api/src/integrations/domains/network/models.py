"""B10-datamodel (P0: alleen schema; wordt pas gevuld als de adapters gebouwd en echt getest zijn).

Invarianten die het schema zelf afdwingt:
- Eén apparaat per (bron, genormaliseerde MAC): een DHCP-IP-wissel geeft geen tweede apparaat (B10-002);
  IP-adressen staan in de historie-tabel.
- Een bevinding met categorie ``malware`` vereist bewijs (B10-001: geen malwareclaim zonder bewijs).
- Bevindingen en voorstellen hebben een zekerheid en herkomst; classificatie van apparaten is standaard ``onbekend``.
- DNS-aggregaten zeggen niets over "geen verkeer" (B10-004): ``coverage`` is verplicht.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, Integer, Numeric, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, Timestamps, new_id


class NetworkDevice(Timestamps, Base):
    __tablename__ = "network_device"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    mac_normalized: Mapped[str] = mapped_column(String(17), nullable=False)
    mac_is_randomized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    vendor_confidence: Mapped[float | None] = mapped_column(Numeric(3, 2), nullable=True)
    classification: Mapped[str] = mapped_column(String(20), nullable=False, default="onbekend")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("source_id", "mac_normalized", name="uq_network_device_source_mac"),
        CheckConstraint("mac_normalized ~ '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'", name="mac_format"),
        CheckConstraint(
            "classification IN ('onbekend','bekend','infrastructuur','iot','persoonlijk','gast')", name="classification"
        ),
        CheckConstraint(
            "vendor_confidence IS NULL OR (vendor_confidence >= 0 AND vendor_confidence <= 1)", name="conf"
        ),
        CheckConstraint("last_seen >= first_seen", name="seen_order"),
    )


class NetworkAddressObservation(Base):
    """IP/MAC-historie per apparaat (DHCP-wissels)."""

    __tablename__ = "network_address_observation"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("network_device.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)

    __table_args__ = (
        UniqueConstraint("device_id", "ip_address", name="uq_network_address_observation_device_ip"),
        CheckConstraint("last_seen >= first_seen", name="seen_order"),
    )


class NetworkDiscoveryEvent(Base):
    __tablename__ = "network_discovery_event"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(120), nullable=False)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_device.id", ondelete="SET NULL"), nullable=True
    )
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("source_id", "source_event_id", name="uq_network_discovery_event_source"),
        CheckConstraint("kind IN ('nieuw_apparaat','ip_gewijzigd','weer_online','offline')", name="kind"),
    )


class NetworkDnsQueryAggregate(Base):
    __tablename__ = "network_dns_query_aggregate"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bucket_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    client_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    queries_total: Mapped[int] = mapped_column(Integer, nullable=False)
    queries_blocked: Mapped[int] = mapped_column(Integer, nullable=False)
    top_blocked_categories: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    coverage: Mapped[str] = mapped_column(String(20), nullable=False)

    __table_args__ = (
        UniqueConstraint("source_id", "bucket_start", "bucket_seconds", "client_key", name="uq_network_dns_bucket"),
        CheckConstraint("queries_blocked >= 0 AND queries_blocked <= queries_total", name="counts"),
        # B10-004: DNS-logs zijn niet "al het verkeer"; dekking altijd expliciet
        CheckConstraint("coverage IN ('alleen_dns_via_adguard','onvolledig','onbekend')", name="coverage"),
    )


class NetworkBlockRule(Timestamps, Base):
    __tablename__ = "network_block_rule"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    rule_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    pattern: Mapped[str] = mapped_column(String(253), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False, default="pilot")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="voorstel")
    rollback_ttl_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        CheckConstraint("rule_kind IN ('blokkeren','toestaan')", name="rule_kind"),
        CheckConstraint("scope IN ('pilot','kinderprofiel','netwerkbreed')", name="scope"),
        CheckConstraint("status IN ('voorstel','goedgekeurd','actief','teruggedraaid','afgewezen')", name="status"),
    )


class NetworkVpnPeer(Base):
    __tablename__ = "network_vpn_peer"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    peer_key: Mapped[str] = mapped_column(String(120), nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    online: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (UniqueConstraint("source_id", "peer_key", name="uq_network_vpn_peer_source_key"),)


class NetworkTunnelHealth(Base):
    __tablename__ = "network_tunnel_health"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    tunnel_key: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exposes_admin: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    secret_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)

    __table_args__ = (
        CheckConstraint("status IN ('healthy','degraded','down','unknown')", name="status"),
        CheckConstraint("secret_ref IS NULL OR secret_ref LIKE 'vault://%'", name="secret_is_vault_ref"),
        Index("ix_network_tunnel_health_key_at", "source_id", "tunnel_key", "observed_at"),
    )


class NetworkSecurityFinding(Timestamps, Base):
    __tablename__ = "network_security_finding"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_device.id", ondelete="SET NULL"), nullable=True
    )
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    confidence: Mapped[float] = mapped_column(Numeric(3, 2), nullable=False)
    evidence: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    detected_by: Mapped[str] = mapped_column(String(60), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "category IN ('nieuw_apparaat','onbekend_apparaat','dns_afwijking','loginpogingen','malware','overig')",
            name="category",
        ),
        CheckConstraint("severity IN ('info','laag','middel','hoog')", name="severity"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence"),
        CheckConstraint("jsonb_typeof(evidence) = 'array'", name="evidence_array"),
        # B10-001: nooit 'malware' zonder bewijs
        CheckConstraint("category <> 'malware' OR jsonb_array_length(evidence) > 0", name="malware_requires_evidence"),
        CheckConstraint("status IN ('open','bevestigd','onterecht','opgelost')", name="status"),
    )


class NetworkPolicyChange(Base):
    """Voorstel voor firewall/DNS-wijziging; uitvoering alleen via Hub-policy + goedkeuring (B10-006)."""

    __tablename__ = "network_policy_change"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("network_security_finding.id", ondelete="SET NULL"), nullable=True
    )
    action_kind: Mapped[str] = mapped_column(String(30), nullable=False)
    risk_class: Mapped[str] = mapped_column(String(2), nullable=False)
    hub_proposal_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="voorstel")
    requires_independent_test: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        # netwerkwijzigingen zijn nooit R0/R1 (03_RISICO_AUTONOMIE: DNS/VPN/firewall → test + rollback)
        CheckConstraint("risk_class IN ('R2','R3')", name="risk_class"),
        CheckConstraint("status IN ('voorstel','goedgekeurd','uitgevoerd','teruggedraaid','afgewezen')", name="status"),
        CheckConstraint("requires_independent_test", name="independent_test_required"),
    )
