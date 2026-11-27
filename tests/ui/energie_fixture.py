"""Lokale meterstanden voor de statuspagina, met dezelfde meetgegevens in beide browserproeven."""

from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from integrations.domains.energy import alerts
from integrations.domains.energy.meters import SOURCE, STATUS_KEY
from integrations.domains.energy.usage_sync import STATE_KEY
from integrations.models import IntegrationSource, ServiceState

TOESTANDEN = {
    "energie-leeg": "Er is geen actieve woningbron.",
    "energie-bezig": "De dienst wacht op de eerste meting.",
    "energie-gemeten": "Afwijkend boilerverbruik",
    "energie-verouderd": "Huidig vermogen onbekend.",
    "energie-storing": "De laatste leespoging bij de woningbron is mislukt.",
}


def vul_energie(url: str, naam: str) -> None:
    if naam == "energie-leeg":
        return
    engine = create_engine(url)
    try:
        with Session(engine) as db, db.begin():
            bron = db.get(IntegrationSource, SOURCE)
            if bron is None:
                bron = IntegrationSource(
                    source_id=SOURCE,
                    domain="energy",
                    base_url="https://woning.test",
                    enabled=True,
                    updated_by="fixture",
                )
                db.add(bron)
                db.flush()
            if naam == "energie-bezig":
                return
            nu = datetime.now(UTC).replace(microsecond=0)
            meettijd = nu - timedelta(minutes=12 if naam == "energie-verouderd" else 1)
            meters = {
                rol: {"at": (meettijd - timedelta(minutes=i)).isoformat(), "watts": watt, "quality": kwaliteit}
                for i, (rol, watt, kwaliteit) in enumerate(
                    (("p1_net", 420, "gemeten"), ("boiler_socket", 0, "gemeten"), ("airco_outdoor", 74, "geschat"))
                )
            }
            storing = naam == "energie-storing"
            if storing:
                meters = {rol: {"at": rij["at"]} for rol, rij in meters.items()}
            db.merge(
                ServiceState(
                    key=STATUS_KEY, value={"revision": bron.link_revision, "meters": meters, "failed": storing}
                )
            )
            scope = uuid5(NAMESPACE_URL, "https://woning.test")
            db.merge(ServiceState(key=STATE_KEY, value={"scope": str(scope), "revision": bron.link_revision}))
            onderwerp = alerts.Check("boiler_usage", "boiler_socket", scope).subject
            db.merge(
                ServiceState(
                    key=alerts.SETTINGS_KEY,
                    value={
                        "thresholds": alerts.AlertThresholds(
                            offline_after_minutes=60,
                            boiler_increase_kwh=1.0,
                            nas_increase_points=20.0,
                            daily_budget_eur=6.0,
                        ).model_dump(),
                        "evaluated_at": nu.isoformat(),
                        "open": {onderwerp: {"baseline": "1", "meter": None}},
                    },
                )
            )
    finally:
        engine.dispose()
