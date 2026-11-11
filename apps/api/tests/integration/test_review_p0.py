"""Integratie (PostgreSQL): aanvullende tests uit de onafhankelijke P0-review.

- Autorisatie op élke gedocumenteerde route (zonder token, met nep-token, met rol zonder rechten) en
  Idempotency-Key op élke mutatie — afgeleid uit de OpenAPI-export, zodat een nieuwe route niet ongemerkt open staat.
- B13-003: geen toegang via X-Forwarded-User of vergelijkbare "vertrouwde" headers.
- Grens op de verzoekgrootte vóór de authenticatie (ook bij chunked upload).
- Herstelkit van buiten: geheugen-/formaatgrenzen geven een nette 422, nooit een 500.
- Statuspagina zonder hersteldetails; eenmalig enrollment-token (ook na ontkoppelen/herstart, nooit in de log).
- B10-002 in het datamodel: één apparaat per (bron, MAC), IP-wissels apart.
- Back-up vóór migratie is verplicht: mislukt die, dan wordt niet gemigreerd.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text

from integrations.cli import cmd_migrate
from integrations.config import Settings
from integrations.domains.sso.kit import encrypt_kit
from integrations.migrations import alembic_dir, head_revision, upgrade
from integrations.worker import Worker
from tests.conftest import ENV_TOKEN, HUB_URL, REPO_ROOT, FakeHub, idem, recreate_database

pytestmark = pytest.mark.integration

OPENAPI = REPO_ROOT / "docs" / "openapi" / "home-control-hub.openapi.json"
PUBLIC = {"/healthz", "/readyz"}
MUTATING = {"post", "put", "patch", "delete"}
# POST zonder wijziging (alleen beoordelen/controleren) en de eerlijke 501 van het connectorcontract
# (apply vraagt sinds B11-005 een Idempotency-Key en een ondertekend ExecutionRequest)
NON_MUTATING_POSTS = {
    "/integrations/v1/sso/break-glass/evaluate",
    "/integrations/v1/sso/recovery/kit/verify",
}
UNAVAILABLE = {"/connector/v1/rollback"}
# B11-003: de flow-API kent alleen flow-tokens; een Hub-JWT (welke rol ook) komt er niet binnen
FLOW_API = "/integrations/v1/automation/flow-api/"
# B11: wat alleen de Hub zelf (dienst-JWT) mag aanbieden of terugmelden
SERVICE_ONLY = re.compile(r"^/integrations/v1/automation/(events|action-requests/[^/]+/result)$")
PATH_VALUES = {"source_id": "authentik"}


def _routes() -> list[tuple[str, str]]:
    doc = json.loads(OPENAPI.read_text(encoding="utf-8"))
    out = []
    for path, methods in doc["paths"].items():
        if path in PUBLIC:
            continue
        concrete = re.sub(r"\{([a-z_]+)\}", lambda m: PATH_VALUES.get(m.group(1), str(uuid.uuid4())), path)
        out.extend((method, concrete) for method in methods)
    assert len(out) >= 50, "OpenAPI-export lijkt onvolledig"
    return out


ROUTES = _routes()


def _call(c: Any, method: str, url: str, headers: dict[str, str]) -> Any:
    return c.request(method.upper(), url, headers=headers)


# ------------------------------------------------------------------ autorisatie op elke route
@pytest.mark.parametrize(("method", "url"), ROUTES)
def test_every_route_requires_auth_and_a_role(paired_client: Any, hub_keys: Any, method: str, url: str) -> None:
    c = paired_client
    for headers in ({}, {"Authorization": "Bearer abc.def.ghi"}, {"Authorization": "Bearer svc-" + "0" * 64}):
        r = _call(c, method, url, headers)
        assert r.status_code == 401, (method, url, headers, r.status_code)
        body = r.json()
        assert body["code"] == "unauthorized" and set(body) == {"code", "message", "details", "trace_id"}
    # geldig ondertekend, maar alleen de rol 'kind': nergens toegang (least privilege)
    kind = {"Authorization": f"Bearer {hub_keys.token(['kind'])}"}
    r = _call(c, method, url, kind)
    if url.startswith(FLOW_API):
        # ook een geldige Hub-JWT is hier geen toegangsbewijs (zelfs niet die van een beheerder)
        admin = {"Authorization": f"Bearer {hub_keys.token(['admin'])}"}
        for response in (r, _call(c, method, url, admin)):
            assert response.status_code == 401, (method, url, response.status_code)
            assert response.json()["details"]["reason"] == "flow_token_ongeldig"
        return
    assert r.status_code == 403 and r.json()["code"] == "forbidden", (method, url, r.status_code)


@pytest.mark.parametrize(("method", "url"), [(m, u) for m, u in ROUTES if m in MUTATING])
def test_every_mutation_requires_idempotency_key(
    paired_client: Any, auth: Any, fake_hub: FakeHub, method: str, url: str
) -> None:
    if url.startswith(FLOW_API):
        # geen toegang met een Hub-JWT; de Idempotency-Key-eis met een geldig flow-token staat in
        # test_b11_003_veilige_acties.py::test_flow_api_mutations_need_an_idempotency_key
        assert _call(paired_client, method, url, auth("admin")).status_code == 401
        return
    headers = fake_hub.service_auth() if method == "post" and SERVICE_ONLY.fullmatch(url) else auth("admin")
    r = _call(paired_client, method, url, headers)
    if url in NON_MUTATING_POSTS:
        assert r.status_code == 422  # alleen invoervalidatie; er wordt niets gewijzigd
    elif url in UNAVAILABLE:
        assert r.status_code == 501 and r.json()["code"] == "capability_unavailable"
    else:
        assert r.status_code == 400 and r.json()["code"] == "idempotency_key_required", (method, url, r.text)


def test_jwt_cannot_claim_service_role(paired_client: Any, hub_keys: Any) -> None:
    """De rol 'service' komt alleen uit een dienst-JWT (``token_use: hub_service``, ``sub: hub``, eigen
    ``service_id``), nooit uit een gebruikers-JWT (contract 1.2 §4.3: ``token_use_invalid``)."""
    forged = {"Authorization": f"Bearer {hub_keys.token(['service'])}"}
    r = paired_client.get("/connector/v1/events", headers=forged)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "token_use_invalid"
    r = paired_client.post(
        "/integrations/v1/sso/break-glass/evaluate",
        json={"account_id": str(uuid.uuid4()), "client_ip": "10.1.2.3"},
        headers={"Authorization": f"Bearer {hub_keys.token(['service', 'admin'])}"},
    )
    assert r.status_code == 401 and r.json()["details"]["reason"] == "token_use_invalid"


# ------------------------------------------------------------------ B13-003: geen header-SSO
TRUSTED_HEADER_ATTEMPT = {
    "X-Forwarded-User": "admin",
    "X-Forwarded-Groups": "admin",
    "X-Forwarded-Preferred-Username": "admin",
    "X-Authentik-Username": "akadmin",
    "X-Authentik-Groups": "authentik Admins",
    "Remote-User": "admin",
    "X-Remote-User": "admin",
    "X-Forwarded-For": "10.0.0.1",
}


def test_b13_003_no_access_via_forwarded_user_headers(paired_client: Any, auth: Any) -> None:
    c = paired_client
    for url in ("/integrations/v1/sso/recovery/overview", "/connector/v1/discover", "/connector/v1/hub-link"):
        r = c.get(url, headers=TRUSTED_HEADER_ATTEMPT)
        assert r.status_code == 401 and r.json()["code"] == "unauthorized", url
    # een viewer wordt geen admin door headers mee te sturen
    r = c.get("/integrations/v1/sso/recovery/overview", headers={**auth("viewer"), **TRUSTED_HEADER_ATTEMPT})
    assert r.status_code == 403
    r = c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "overig", "username": "hdr", "login_kind": "lokaal"},
        headers=idem({**auth("viewer"), **TRUSTED_HEADER_ATTEMPT}),
    )
    assert r.status_code == 403


# ------------------------------------------------------------------ verzoekgrootte vóór auth
def test_body_limit_before_auth(client: Any) -> None:
    big = b'{"x":"' + b"a" * (1024 * 1024 + 10) + b'"}'
    r = client.post("/integrations/v1/sso/recovery/accounts", content=big, headers={"Content-Type": "application/json"})
    assert r.status_code == 413
    body = r.json()
    assert body["code"] == "payload_too_large" and set(body) == {"code", "message", "details", "trace_id"}

    def chunks() -> Any:
        for _ in range(40):
            yield b"a" * 32768  # 1,25 MiB zonder Content-Length (chunked)

    r = client.post("/integrations/v1/sso/recovery/kit/verify", content=chunks())
    # §4.7: de 1 MiB-laag komt vóór de authenticatie, ook zonder Content-Length (chunked)
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"
    assert r.json()["details"] == {"max_bytes": 1024 * 1024}
    r = client.post("/koppelen", content=chunks(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    # normale verzoeken blijven werken
    assert client.get("/healthz").status_code == 200


# ------------------------------------------------------------------ herstelkit van buiten
def test_kit_verify_rejects_hostile_parameters_without_500(paired_client: Any, auth: Any) -> None:
    passphrase = "een lange wachtwoordzin voor de test!"
    kit = encrypt_kit({"register": {"accounts": []}}, passphrase)
    bad_kits = [
        {**kit, "kdf": {**kit["kdf"], "n": 2**20, "r": 16}},  # > 2 GiB geheugen
        {**kit, "kdf": {**kit["kdf"], "n": 3 * 2**14}},  # geen macht van 2
        {**kit, "kdf": {**kit["kdf"], "p": 64}},
        {**kit, "cipher": {**kit["cipher"], "nonce": "AAAA"}},  # nonce van 3 bytes
        {**kit, "kdf": "scrypt"},
        {**kit, "cipher": ["AES-256-GCM"]},
    ]
    for bad in bad_kits:
        r = paired_client.post(
            "/integrations/v1/sso/recovery/kit/verify",
            json={"passphrase": passphrase, "kit": bad},
            headers=auth("admin"),
        )
        assert r.status_code == 422 and r.json()["code"] == "herstelkit_onleesbaar", r.text
    ok = paired_client.post(
        "/integrations/v1/sso/recovery/kit/verify", json={"passphrase": passphrase, "kit": kit}, headers=auth("admin")
    )
    assert ok.status_code == 200 and ok.json()["readable"] is True


# ------------------------------------------------------------------ statuspagina zonder hersteldetails
def test_status_page_shows_only_recovery_level(paired_client: Any, auth: Any) -> None:
    c = paired_client
    r = c.post(
        "/integrations/v1/sso/recovery/accounts",
        json={"system": "authentik", "username": "akadmin-review", "login_kind": "sso"},
        headers=idem(auth("admin")),
    )
    assert r.status_code == 201
    page = c.get("/").text
    # alleen het totaalniveau (risico → Peil-woord 'Beperkt'), geen accountnamen of aandachtspunten
    assert re.search(
        r'Beheerherstel \(B13-001\)<span class="sr">:</span></span><span class="pil pil-beperkt">.*?</svg>Beperkt</span>',
        page,
    )
    for leak in ("akadmin-review", "geen_noodaccount", "minder_dan_twee_herstelmethodes", "beheeraccount(s)"):
        assert leak not in page, leak


# ------------------------------------------------------------------ eenmalig enrollment-token
def test_env_token_is_single_use_across_unlink_and_restart(
    make_settings: Any, fake_hub: FakeHub, app_factory: Any, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    settings = make_settings(hub_url=HUB_URL, enrollment_token=ENV_TOKEN)
    w = Worker(settings, transport=fake_hub.transport)
    w.run_once()
    assert len(fake_hub.enroll_requests) == 1
    c = app_factory(hub_url=HUB_URL, enrollment_token=ENV_TOKEN)
    token = c.app.state.hublink.state().service_token
    assert token
    h = {"Authorization": f"Bearer {fake_hub.keys.token(['admin'])}"}
    assert c.post("/connector/v1/hub-link/unlink", headers=idem(fake_hub.service_auth())).status_code == 200
    # na ontkoppelen én na een herstart (nieuwe worker) wordt het gebruikte token nooit opnieuw verstuurd (§3.5)
    w.run_once()
    Worker(settings, transport=fake_hub.transport).run_once()
    assert len(fake_hub.enroll_requests) == 1
    assert c.app.state.hublink.state().state == "ontkoppeld"
    r = c.get("/connector/v1/discover", headers=h)
    assert r.status_code == 401 and r.json()["details"]["reason"] == "not_linked"  # fail-closed na ontkoppelen
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert ENV_TOKEN not in logged and token not in logged


# ------------------------------------------------------------------ B10-002 in het datamodel
def test_b10_002_one_device_per_source_and_mac(clean_db: str) -> None:
    eng = create_engine(clean_db)
    dev = uuid.uuid4()
    with eng.begin() as c:
        c.execute(text("TRUNCATE network_device CASCADE"))
        c.execute(
            text(
                "INSERT INTO network_device (id, source_id, mac_normalized, mac_is_randomized, classification, "
                "first_seen, last_seen, version, created_at, updated_at) VALUES "
                "(:id, 'netalertx', 'aa:bb:cc:dd:ee:01', false, 'onbekend', now(), now(), 1, now(), now())"
            ),
            {"id": dev},
        )
        # DHCP-wissel: hetzelfde apparaat krijgt een tweede adres in de historie
        for ip in ("10.20.0.5", "10.20.0.9"):
            c.execute(
                text(
                    "INSERT INTO network_address_observation (id, device_id, ip_address, first_seen, last_seen, "
                    "source_id) VALUES (gen_random_uuid(), :d, :ip, now(), now(), 'netalertx')"
                ),
                {"d": dev, "ip": ip},
            )
    duplicate = (
        "INSERT INTO network_device (id, source_id, mac_normalized, mac_is_randomized, classification, first_seen, "
        "last_seen, version, created_at, updated_at) VALUES (gen_random_uuid(), 'netalertx', :mac, false, "
        "'onbekend', now(), now(), 1, now(), now())"
    )
    with eng.connect() as c, pytest.raises(Exception, match="uq_network_device_source_mac"):
        c.execute(text(duplicate), {"mac": "aa:bb:cc:dd:ee:01"})
    with eng.connect() as c, pytest.raises(Exception, match="mac_format"):
        c.execute(text(duplicate), {"mac": "AA-BB-CC-DD-EE-01"})  # niet-genormaliseerd MAC-adres
    with eng.connect() as c:
        assert c.execute(text("SELECT count(*) FROM network_device")).scalar() == 1
        assert c.execute(text("SELECT count(*) FROM network_address_observation")).scalar() == 2
    eng.dispose()


# ------------------------------------------------------------------ back-up vóór migratie
NOOP_REVISION = '''"""Testrevisie (alleen in de test): voegt een kolom toe."""

import sqlalchemy as sa
from alembic import op

revision = "9999"
down_revision = "{head}"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("service_state", sa.Column("review_test", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("service_state", "review_test")
'''


@pytest.fixture
def two_step_migrations(tmp_path: Path) -> Settings:
    src = alembic_dir(Settings())
    dst = tmp_path / "alembic"
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
    head = head_revision(Settings())
    (dst / "versions" / "9999_review_test.py").write_text(NOOP_REVISION.replace("{head}", str(head)), encoding="utf-8")
    url = recreate_database("hch_test_backup")
    settings = Settings(database_url=url, alembic_dir=dst, data_dir=tmp_path / "appdata")
    upgrade(settings, str(head))
    return settings


def _revision(url: str) -> str:
    eng = create_engine(url)
    with eng.connect() as c:
        rev = str(c.execute(text("SELECT version_num FROM alembic_version")).scalar())
    eng.dispose()
    return rev


def test_migration_refused_when_backup_fails(
    two_step_migrations: Settings, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = two_step_migrations
    backups = tmp_path / "backups"
    import integrations.migrations as mig

    monkeypatch.setattr(mig.shutil, "which", lambda _name: None)  # pg_dump ontbreekt
    assert cmd_migrate(settings, str(backups), None) == 3
    assert _revision(settings.database_url) == head_revision(Settings())

    monkeypatch.setattr(mig.shutil, "which", lambda _name: "/usr/bin/pg_dump")
    monkeypatch.setattr(
        mig.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "schijf vol")
    )  # pg_dump mislukt
    assert cmd_migrate(settings, str(backups), None) == 3
    assert _revision(settings.database_url) == head_revision(Settings())
    assert not list(backups.glob("*.dump"))  # geen half bestand achtergelaten
    # zonder back-upmap (ontwikkeling/CI) migreert het commando wel
    assert cmd_migrate(settings, None, None) == 0
    assert _revision(settings.database_url) == "9999"


def _newest_pg_restore() -> str | None:
    """De nieuwste pg_restore die er is: die leest ook archieven van oudere pg_dump-versies.

    Op een machine met meerdere PostgreSQL-clients kiest Debians pg_wrapper voor ``pg_dump -h …`` de nieuwste versie,
    maar voor ``pg_restore --list`` (zonder server) de versie van het standaardcluster; een ouder pg_restore kan het
    nieuwere archiefformaat dan niet lezen. In de image staat alleen PostgreSQL 16, dus daar speelt dit niet.
    """
    candidates = sorted(
        Path("/usr/lib/postgresql").glob("*/bin/pg_restore"),
        key=lambda p: int(p.parts[-3]) if p.parts[-3].isdigit() else 0,
        reverse=True,
    )
    return str(candidates[0]) if candidates else shutil.which("pg_restore")


def test_backup_before_migration_with_real_pg_dump(two_step_migrations: Settings, tmp_path: Path) -> None:
    import os

    if shutil.which("pg_dump") is None:
        if os.environ.get("CI"):
            pytest.fail("pg_dump ontbreekt in CI")
        pytest.skip("pg_dump niet geïnstalleerd")
    settings = two_step_migrations
    backups = tmp_path / "backups"
    assert cmd_migrate(settings, str(backups), None) == 0
    dumps = list(backups.glob(f"voor-upgrade-{head_revision(Settings())}-*.dump"))
    assert len(dumps) == 1 and dumps[0].stat().st_size > 0
    assert dumps[0].stat().st_mode & 0o777 == 0o600 and backups.stat().st_mode & 0o777 == 0o700
    assert _revision(settings.database_url) == "9999"
    # de dump is een geldig pg_dump-archief met het schema van vóór de migratie
    pg_restore = _newest_pg_restore()
    if pg_restore:
        listing = subprocess.run(  # noqa: S603 - vaste argumenten
            [pg_restore, "--list", str(dumps[0])], capture_output=True, text=True, check=False
        )
        assert listing.returncode == 0 and "service_state" in listing.stdout
    # al op de nieuwste revisie: geen nieuwe back-up
    assert cmd_migrate(settings, str(backups), None) == 0
    assert len(list(backups.glob("*.dump"))) == 1


def test_older_app_refuses_newer_database(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Tag-only rollback (EX15-achtig): een oudere app op een nieuwere database migreert niets en zegt wat te doen."""
    url = recreate_database("hch_test_newer_db")
    upgrade(Settings(database_url=url))  # database op de nieuwste revisie
    old = tmp_path / "alembic"
    shutil.copytree(alembic_dir(Settings()), old, ignore=shutil.ignore_patterns("__pycache__"))
    head = head_revision(Settings())
    for f in (old / "versions").glob(f"{head}_*.py"):
        f.unlink()  # "oudere image": kent de nieuwste revisie niet
    settings = Settings(database_url=url, alembic_dir=old, data_dir=tmp_path / "appdata")
    assert cmd_migrate(settings, str(tmp_path / "backups"), None) == 4
    assert "nieuwer dan deze image" in capsys.readouterr().err
    assert _revision(url) == head and not (tmp_path / "backups").exists()
