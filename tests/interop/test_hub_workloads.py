"""Contract 1.4 §4.4. Vergelijk de Hub-projecties en de lezer op synthetische data, zonder netwerk of database."""

from datetime import datetime, timedelta

import pytest

from integrations.domains.energy.workload_sources import _encoding, _nas
from integrations.timeutil import utcnow


def test_werklastprojecties_van_de_hub():
    werklast = pytest.importorskip("hub.werklast", reason="De contractbron 1.4 van de Hub ontbreekt op het Python-pad.")
    from hub.adapters.mediaguard_lezen import Encodeerbaan, Encodeerstatus
    from hub.models import MetricSeries

    now = utcnow()
    at = now - timedelta(seconds=7)
    row = MetricSeries(id=1, metriek="cpu.gebruik", laatste_waarde=34, laatste_op=at, bron=werklast.BRON)
    nas = werklast.NasBelasting(
        items=[werklast.projecteer(row, now, 60)], onbekend=["geheugen.beschikbaar_pct", "gpu.gebruik"], ttl_seconden=60
    )
    mg = Encodeerstatus(
        status="gemeten",
        observed_at=at,
        max_age_s=60,
        banen=[Encodeerbaan(lane="cpu", running=0, paused=True), Encodeerbaan(lane="gpu", running=1, paused=False)],
    )
    nas_body = nas.model_dump(mode="json")
    mg_body = mg.model_dump(mode="json")
    data = _nas(nas_body, now)
    assert data.status == "gedeeltelijk" and data.onbekend == nas.onbekend
    assert [(r.id, r.waarde_pct, r.observed_at) for r in data.items] == [
        (1, 34, datetime.fromisoformat(nas_body["items"][0]["observed_at"]))
    ]
    encoding = _encoding(mg_body, now)
    assert encoding.observed_at == datetime.fromisoformat(mg_body["observed_at"]) and encoding.banen is not None
    assert [(b.lane, b.running, b.paused) for b in encoding.banen] == [("cpu", 0, True), ("gpu", 1, False)]
    assert _nas(nas.model_dump(mode="json"), now + timedelta(minutes=2)).status == "onbekend"
    assert _encoding(Encodeerstatus(status="onbekend").model_dump(mode="json"), now).banen is None
