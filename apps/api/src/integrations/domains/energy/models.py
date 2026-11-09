"""B14-datamodel (P0: alleen schema).

Invarianten:
- Meters zijn altijd read-only (geen schakelroute; boiler alleen meten, EX27).
- Elk interval heeft een kwaliteitslabel ``gemeten|geschat|onbekend``; ``geschat`` vereist herkomst
  (``estimate_provenance``); een schatting op basis van CPU-belasting vereist een kalibratie (B14-001).
- Tellerstanden: delta's met expliciete reset/meterwissel-markering (B14-002); tijden in UTC zodat
  zomertijddagen (23/25 uur) correct aggregeren.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, Numeric, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ...db import Base, Timestamps, new_id


class EnergyMeter(Timestamps, Base):
    __tablename__ = "energy_meter"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    source_id: Mapped[str] = mapped_column(String(60), nullable=False)
    source_meter_id: Mapped[str] = mapped_column(String(120), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    unit: Mapped[str] = mapped_column(String(10), nullable=False)
    read_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    replaced_meter_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("energy_meter.id"), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("source_id", "source_meter_id", name="uq_energy_meter_source"),
        CheckConstraint("unit IN ('kWh','m3','W')", name="unit"),
        CheckConstraint("read_only", name="always_read_only"),
    )


class EnergyMeterRole(Base):
    __tablename__ = "energy_meter_role"
    meter_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("energy_meter.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(30), primary_key=True)
    confirmed_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("role IN ('p1_net','boiler_socket','airco_outdoor','nas_host','overig')", name="role"),
    )


class EnergySampleQuality(Base):
    __tablename__ = "energy_sample_quality"
    code: Mapped[str] = mapped_column(String(20), primary_key=True)
    description_nl: Mapped[str] = mapped_column(String(300), nullable=False)

    __table_args__ = (CheckConstraint("code IN ('gemeten','geschat','onbekend')", name="code"),)


class EnergyEstimateProvenance(Base):
    __tablename__ = "energy_estimate_provenance"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    method: Mapped[str] = mapped_column(String(30), nullable=False)
    calibration_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    assumptions: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    confidence: Mapped[float] = mapped_column(Numeric(3, 2), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("method IN ('interpolatie','cpu_model','vergelijkbare_dag','handmatig')", name="method"),
        # B14-001: geen wattage uit CPU% zonder kalibratie
        CheckConstraint("method <> 'cpu_model' OR calibration_ref IS NOT NULL", name="cpu_model_requires_calibration"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="confidence"),
    )


class EnergyUsageInterval(Base):
    __tablename__ = "energy_usage_interval"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    meter_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("energy_meter.id", ondelete="CASCADE"), nullable=False)
    start_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    counter_start: Mapped[float | None] = mapped_column(Numeric(14, 3), nullable=True)
    counter_end: Mapped[float | None] = mapped_column(Numeric(14, 3), nullable=True)
    delta: Mapped[float | None] = mapped_column(Numeric(14, 3), nullable=True)
    direction: Mapped[str] = mapped_column(String(10), nullable=False, default="import")
    quality: Mapped[str] = mapped_column(ForeignKey("energy_sample_quality.code"), nullable=False)
    counter_reset: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    provenance_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("energy_estimate_provenance.id"), nullable=True)
    source_ref: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        UniqueConstraint("meter_id", "start_utc", "direction", name="uq_energy_usage_interval_meter_start"),
        CheckConstraint("end_utc > start_utc", name="interval_order"),
        CheckConstraint("direction IN ('import','export')", name="direction"),
        CheckConstraint("delta IS NULL OR delta >= 0", name="delta_non_negative"),
        CheckConstraint("quality <> 'geschat' OR provenance_id IS NOT NULL", name="estimate_requires_provenance"),
        CheckConstraint("quality <> 'onbekend' OR delta IS NULL", name="unknown_has_no_value"),
    )


class EnergyTariff(Base):
    __tablename__ = "energy_tariff"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    unit: Mapped[str] = mapped_column(String(10), nullable=False)
    price_per_unit: Mapped[float | None] = mapped_column(Numeric(10, 5), nullable=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_ref: Mapped[str] = mapped_column(String(200), nullable=False)

    __table_args__ = (
        CheckConstraint("kind IN ('vast','dynamisch')", name="kind"),
        CheckConstraint("valid_to IS NULL OR valid_to > valid_from", name="validity"),
    )


class EnergyCostModel(Base):
    __tablename__ = "energy_cost_model"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    tariff_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("energy_tariff.id"), nullable=False)
    requires_meter: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # B14-004: zonder meter geen €-besparing → kostenmodellen vereisen een meter
    __table_args__ = (CheckConstraint("requires_meter", name="requires_meter"),)


class EnergyWorkload(Timestamps, Base):
    __tablename__ = "energy_workload"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    owner_app: Mapped[str] = mapped_column(String(60), nullable=False)
    workload_key: Mapped[str] = mapped_column(String(120), nullable=False)
    priority_class: Mapped[str] = mapped_column(String(20), nullable=False)
    preemptible: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    needs_safe_checkpoint: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        UniqueConstraint("owner_app", "workload_key", name="uq_energy_workload_owner_key"),
        CheckConstraint("priority_class IN ('interactief','hoog','normaal','achtergrond')", name="priority_class"),
    )


class EnergyWorkloadReservation(Base):
    __tablename__ = "energy_workload_reservation"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=new_id)
    workload_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("energy_workload.id", ondelete="CASCADE"), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resources: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="voorstel")
    wait_reason_nl: Mapped[str | None] = mapped_column(String(300), nullable=True)

    __table_args__ = (
        CheckConstraint("window_end > window_start", name="window_order"),
        CheckConstraint("status IN ('voorstel','gepland','actief','wacht','klaar','geannuleerd')", name="status"),
    )
