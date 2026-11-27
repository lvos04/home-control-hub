"""Actuele werklast op de bevestigde HTTPS-Hub, met de dienstscope werklast.lezen (contract 1.4 §4.4)."""

from __future__ import annotations

import contextlib
from datetime import datetime
from typing import Literal
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, computed_field
from sqlalchemy.orm import Session

from ...config import Settings
from ...errors import TRACE_HEADER
from ...hubclient import HubClient, validate_hub_url
from ...hublink_store import LinkState
from ...models import IntegrationSource
from ...timeutil import utcnow
from .client import EnergyReadError, read_energy_json
from .readings import source_timestamp

Metric = Literal["cpu.gebruik", "geheugen.beschikbaar_pct", "gpu.gebruik"]
METRICS: tuple[Metric, ...] = ("cpu.gebruik", "geheugen.beschikbaar_pct", "gpu.gebruik")
NAS_PATH = "/api/v1/observability/nas"


class LoadReading(BaseModel):
    id: int
    metriek: Metric
    bron: Literal["truenas.reporting.realtime", "beszel"]
    waarde_pct: float
    observed_at: datetime


class NasLoad(BaseModel):
    status: Literal["gemeten", "gedeeltelijk", "onbekend"] = "onbekend"
    items: list[LoadReading] = Field(default_factory=list)
    onbekend: list[Metric] = Field(default_factory=lambda: list(METRICS))


class Lane(BaseModel):
    model_config = ConfigDict(strict=True)
    lane: Literal["cpu", "gpu"]
    running: int = Field(ge=0)
    paused: bool

    @computed_field
    def wait_reason(self) -> Literal["eigenaar_gepauzeerd"] | None:
        return "eigenaar_gepauzeerd" if self.paused else None


class Encoding(BaseModel):
    status: Literal["gemeten", "onbekend"] = "onbekend"
    observed_at: datetime | None = None
    banen: list[Lane] | None = None


class WorkloadSources(BaseModel):
    truenas_metrics: NasLoad = Field(default_factory=NasLoad)
    mediaguard_encoding: Encoding = Field(default_factory=Encoding)


class _MetricRow(BaseModel):
    model_config = ConfigDict(strict=True)
    id: int = Field(gt=0)
    metriek: Metric
    bron: Literal["truenas.reporting.realtime", "beszel"]
    eenheid: Literal["%"]
    status: Literal["ok", "unknown"]
    laatste_waarde: float | None
    observed_at: str | None


class _NasResponse(BaseModel):
    model_config = ConfigDict(strict=True)
    items: list[_MetricRow]
    onbekend: list[Metric]
    ttl_seconden: int = Field(gt=0)


class _EncodingResponse(BaseModel):
    model_config = ConfigDict(strict=True)
    status: Literal["gemeten", "onbekend"]
    observed_at: str | None
    max_age_s: int | None
    banen: list[Lane] | None


def confirmed_hub(link: LinkState, settings: Settings) -> str | None:
    if link.corrupt or not link.linked or not link.confirmed_at or not link.hub_url:
        return None
    try:
        base = validate_hub_url(link.hub_url, settings.allow_loopback_hub)
    except ValueError:
        return None
    return base if base.startswith("https://") else None


def mediaguard_path(address: str | None, base: str) -> str | None:
    """Alleen een adapter-UUID op déze Hub. Het ingestelde bronadres is nooit het doel van een token."""
    if not address:
        return None
    prefix = "/api/v1/adapterkoppelingen/"
    try:
        link_id = UUID(address.removeprefix(base + prefix).removesuffix("/mediaguard"))
    except ValueError:
        return None
    path = f"{prefix}{link_id}/mediaguard"
    return path if address == base + path else None


def _fresh(at: datetime | None, now: datetime, ttl: int) -> bool:
    return at is not None and 0 <= (now - at).total_seconds() <= min(ttl, 900)


def _nas(raw: object, now: datetime) -> NasLoad:
    body = _NasResponse.model_validate(raw)
    items = []
    for row in body.items:
        at = source_timestamp(row.observed_at)
        value = row.laatste_waarde
        if (
            row.status == "ok"
            and row.metriek not in body.onbekend
            and at is not None
            and _fresh(at, now, body.ttl_seconden)
            and value is not None
            and 0 <= value <= 100
            and (row.metriek != "gpu.gebruik" or row.bron == "beszel")
        ):
            items.append(LoadReading(id=row.id, metriek=row.metriek, bron=row.bron, waarde_pct=value, observed_at=at))
    known = {row.metriek for row in items}
    missing = [metric for metric in METRICS if metric not in known]
    return NasLoad(
        status="onbekend" if not items else "gedeeltelijk" if missing else "gemeten", items=items, onbekend=missing
    )


def _encoding(raw: object, now: datetime) -> Encoding:
    body = _EncodingResponse.model_validate(raw)
    at = source_timestamp(body.observed_at)
    if (
        body.status == "gemeten"
        and body.max_age_s is not None
        and body.max_age_s > 0
        and _fresh(at, now, body.max_age_s)
        and body.banen is not None
        and sorted(b.lane for b in body.banen) == ["cpu", "gpu"]
    ):
        return Encoding(status="gemeten", observed_at=at, banen=body.banen)
    return Encoding(observed_at=at)


def workload_sources(session: Session, hub: HubClient, link: LinkState, trace_id: str) -> WorkloadSources:
    result = WorkloadSources()
    base = confirmed_hub(link, hub.settings)
    if base is None:
        return result
    headers = {"Authorization": f"Bearer {link.service_token}", TRACE_HEADER: trace_id}

    def read(path: str) -> object:
        with hub.stream_get(base, path, headers=headers, params={}) as response:
            if response.status_code != 200:
                raise EnergyReadError("De Hub levert deze werklastbron niet.")
            return read_energy_json(response, "De Hub")

    nas = session.get(IntegrationSource, "truenas_metrics")
    if nas is None or nas.enabled:
        with contextlib.suppress(httpx.HTTPError, httpx.InvalidURL, EnergyReadError, ValidationError):
            result.truenas_metrics = _nas(read(NAS_PATH), utcnow())
    mg = session.get(IntegrationSource, "mediaguard_encoding")
    if mg is not None and mg.enabled and (path := mediaguard_path(mg.base_url, base)):
        with contextlib.suppress(httpx.HTTPError, httpx.InvalidURL, EnergyReadError, ValidationError):
            result.mediaguard_encoding = _encoding(read(path), utcnow())
    return result
