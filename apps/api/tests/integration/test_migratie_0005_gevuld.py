"""HARDE EIS: migratie 0005 op een GEVULDE database van de vorige versie (0004), heen en terug, zonder verlies.

POORTEN P-HARDE-EIS punt 3 eist een proef op een gevulde database, niet op een lege (R-HARDE-EIS-1). Deze tests zetten
een database op revisie 0004, vullen de tabellen van gebruikers en SSO (B13), de kluis, de audit, de servicestand, de
bronnen, de outbox en de P0-tabellen van de automatisering, en migreren met dezelfde opdracht als de image
(``python -m integrations migrate --backup-dir``, :func:`integrations.cli.cmd_migrate`). Per tabel worden het aantal
rijen en de inhoud van álle kolommen die er bij 0004 al waren vergeleken (sha256 over de gesorteerde rijen): na de
upgrade, na terug naar 0004 en weer omhoog, en na het terugzetten van de back-up van vóór de upgrade in een tweede
database. Een testmigratie die één rij wist, laat de vergelijking falen (V-003); lege of halve metingen zijn rood
(ondergrenzen, V-116).

Alleen databases met een eigen naam (``hch_test_migratie_0005*``); draai achter ``hch-db.lock`` (POORTEN 0.3 regel 5).
Een upgrade op de echte NAS (vorige image + dataset-snapshot) is NIET GEVALIDEERD (echte NAS).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import IntegrityError

from integrations.cli import cmd_migrate
from integrations.config import Settings
from integrations.migrations import alembic_dir, downgrade, head_revision, upgrade
from tests.conftest import ADMIN_DB_URL, recreate_database

DB = "hch_test_migratie_0005"
DB_TERUG = "hch_test_migratie_0005_terug"
VORIGE = "0004"
Meting = dict[str, tuple[int, str]]

#: minimaal aantal rijen per gevulde tabel (V-116: een lege of halve meting is nooit "niets verloren")
GEVULD = {
    "sso_admin_account": 2,
    "sso_emergency_access": 1,
    "sso_recovery_method": 2,
    "vault_secret": 2,
    "audit_event": 2,
    "service_state": 2,
    "integration_source": 1,
    "outbox_event": 1,
    "automation_flow": 2,
    "automation_flow_version": 2,
    "automation_flow_owner": 1,
    "automation_trigger": 2,
    "automation_rate_limit": 1,
    "automation_flow_run": 1,
    "automation_action_request": 3,
}


def _drop(name: str) -> None:
    eng = create_engine(ADMIN_DB_URL, isolation_level="AUTOCOMMIT")
    try:
        with eng.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    finally:
        eng.dispose()


@pytest.fixture
def vorige_versie(tmp_path: Path) -> Iterator[Settings]:
    """Een database op revisie 0004 (de vorige versie), nog leeg."""
    url = recreate_database(DB)
    settings = Settings(database_url=url, data_dir=tmp_path / "appdata")
    upgrade(settings, VORIGE)
    yield settings
    _drop(DB)
    _drop(DB_TERUG)


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _columns(eng: Engine) -> dict[str, list[str]]:
    """Alle tabellen met hun kolommen (zoals ze er nú zijn), behalve de revisietabel van Alembic."""
    with eng.connect() as c:
        rows = c.execute(
            text(
                "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public' "
                "AND table_name <> 'alembic_version' ORDER BY table_name, ordinal_position"
            )
        ).all()
    out: dict[str, list[str]] = {}
    for table, column in rows:
        out.setdefault(str(table), []).append(str(column))
    return out


def _measure(eng: Engine, columns: dict[str, list[str]]) -> Meting:
    """Per tabel (aantal rijen, sha256 over de gesorteerde rijen van precies deze kolommen)."""
    out: Meting = {}
    with eng.connect() as c:
        for table, cols in sorted(columns.items()):
            row_text = "ROW(" + ", ".join(_q(col) for col in cols) + ")::text"
            stmt = (
                f"SELECT count(*), encode(sha256(convert_to(coalesce(string_agg(r, E'\\n' ORDER BY r), ''), 'UTF8')), "  # noqa: S608
                f"'hex') FROM (SELECT {row_text} AS r FROM {_q(table)}) AS rijen"
            )
            count, digest = c.execute(text(stmt)).one()
            out[table] = (int(count), str(digest))
    return out


def _differences(before: Meting, after: Meting) -> list[str]:
    return sorted(t for t in before if after.get(t) != before[t])


def _revision(eng: Engine) -> str:
    with eng.connect() as c:
        return str(c.execute(text("SELECT version_num FROM alembic_version")).scalar())


def _fill(eng: Engine) -> dict[str, uuid.UUID]:
    """Gegevens zoals een installatie op 0004 ze kan hebben (alle CHECK-constraints van 0004 gerespecteerd)."""
    ids = {name: uuid.uuid4() for name in ("acc1", "acc2", "flow1", "flow2", "ver1", "ver2", "run1")}
    stmts = [
        # B13: beheerders, noodtoegang en herstelmethoden
        "INSERT INTO sso_admin_account (id, system, username, display_name, is_break_glass, login_kind, mfa_status, "
        "mfa_methods, status, notes, version, created_by, updated_by, created_at, updated_at) VALUES "
        "(:acc1, 'hub_local', 'nood-1', 'Noodaccount', true, 'lokaal', 'bevestigd', '[\"totp\"]', 'actief', "
        "'kluis', 3, 'test', 'test', now(), now()), "
        "(:acc2, 'authentik', 'beheerder-2', 'Beheerder Twee', false, 'sso', 'onbekend', '[]', 'uitgeschakeld', '', "
        "1, 'test', 'test', now(), now())",
        "INSERT INTO sso_emergency_access (id, account_id, network_scopes, session_max_minutes, review_interval_days, "
        "last_reviewed_at, last_reviewed_by, status, reason, version, created_by, updated_by, created_at, "
        "updated_at, cgnat_toegestaan) VALUES (gen_random_uuid(), :acc1, '[\"lan\"]', 30, 90, now(), 'test', "
        "'actief', 'noodtoegang thuisnetwerk', 2, 'test', 'test', now(), now(), false)",
        "INSERT INTO sso_recovery_method (id, account_id, method_type, storage_hint, sso_independent, status, "
        "last_verified_at, version, created_by, updated_by, created_at, updated_at) VALUES "
        "(gen_random_uuid(), :acc1, 'herstelcodes_offline', 'kluis', true, 'actief', now(), 1, 'test', 'test', "
        "now(), now()), "
        "(gen_random_uuid(), :acc1, 'authentik_herstelsleutel', 'wachtwoordmanager', false, 'ingetrokken', NULL, 2, "
        "'test', 'test', now(), now())",
        # kluis, audit, servicestand, bronnen en outbox
        "INSERT INTO vault_secret (ref, nonce, ciphertext, last4, version, created_at, updated_at) VALUES "
        "('vault://test/een', decode('000102030405060708090a0b', 'hex'), decode('deadbeef00ff', 'hex'), 'ab12', 1, "
        "now(), now()), "
        "('vault://test/twee', decode('0b0a09080706050403020100', 'hex'), decode('cafebabe', 'hex'), 'cd34', 2, "
        "now(), now())",
        "INSERT INTO audit_event (id, at, domain, action, entity_type, entity_id, actor_type, actor_id, client_scope, "
        "trace_id, details, message_nl) VALUES "
        "(gen_random_uuid(), now(), 'sso', 'sso.account.created', 'account', 'nood-1', 'user', 'user-1', NULL, "
        "gen_random_uuid(), '{\"veld\": 1}', 'Noodaccount vastgelegd.'), "
        "(gen_random_uuid(), now(), 'automation', 'automation.flow.seen', 'flow', 'tab1', 'system', 'worker', NULL, "
        "gen_random_uuid(), '{}', 'Flow gezien.')",
        "INSERT INTO service_state (key, value, updated_at) VALUES "
        "('test_toestand_a', '{\"x\": 1, \"lijst\": [1, 2]}', now()), ('test_toestand_b', '{}', now())",
        "INSERT INTO integration_source (source_id, domain, base_url, credential_ref, enabled, last_probe_at, "
        "last_probe_status, last_probe_reason, last_probe_detail, version, updated_by, created_at, updated_at) VALUES "
        "('node_red', 'automation', 'http://nodered.test:1880', 'vault://source/node-red', true, now(), 'healthy', "
        "'liveness_ok', '{}', 1, 'test', now(), now())",
        "INSERT INTO outbox_event (event_id, event_type, entity_type, entity_id, timestamp_utc, trace_id, "
        "correlation_id, actor_type, actor_id, classification, payload, delivery_status, attempts, "
        "next_attempt_at, last_error, delivered_at) VALUES (gen_random_uuid(), 'sso.account.created', 'account', "
        "'nood-1', now(), gen_random_uuid(), NULL, 'system', 'test', 'internal', '{}', 'pending', 0, now(), NULL, "
        "NULL)",
        # de P0-tabellen van de automatisering (0005 voegt er kolommen en constraints aan toe)
        "INSERT INTO automation_flow (id, source_id, source_flow_id, label, owner, status, current_version_id, "
        "version, created_at, updated_at) VALUES "
        "(:flow1, 'node_red', 'tab0000000000001', 'Melding bij storing', 'user-1', 'actief', NULL, 1, now(), now()), "
        "(:flow2, 'node_red', 'tab0000000000002', 'Gepauzeerd', '', 'gepauzeerd', NULL, 1, now(), now())",
        "INSERT INTO automation_flow_version (id, flow_id, seq, checksum_sha256, export_ref, credentials_ref, "
        "node_types, created_at, created_by) VALUES "
        "(:ver1, :flow1, 1, :sum1, NULL, 'vault://automation/x', '[\"inject\"]', now(), 'test'), "
        "(:ver2, :flow2, 1, :sum2, NULL, NULL, '[]', now(), 'test')",
        "UPDATE automation_flow SET current_version_id = CASE id WHEN :flow1 THEN :ver1 ELSE :ver2 END",
        "INSERT INTO automation_flow_owner (flow_id, principal, role, note) VALUES (:flow1, 'user-1', 'eigenaar', "
        "NULL)",
        "INSERT INTO automation_trigger (id, flow_id, event_type, schema_version, filter) VALUES "
        "(gen_random_uuid(), :flow1, 'energy.reading.recorded', '1.0', '{}'), "
        "(gen_random_uuid(), :flow1, 'backup.run.failed', '1.0', '{\"source_app\": \"home-control-hub\"}')",
        "INSERT INTO automation_rate_limit (flow_id, action_id, max_per_hour, cooldown_s) VALUES "
        "(:flow1, 'app.restart', 5, 60)",
        "INSERT INTO automation_flow_run (id, flow_id, trigger_event_id, mode, status, started_at, finished_at, "
        "error_code) VALUES (:run1, :flow1, NULL, 'dry_run', 'klaar', now(), now(), NULL)",
        # ook een geweigerd verzoek: 0004 kende geen reden, 0005 eist er een (R-HARDE-EIS-2)
        "INSERT INTO automation_action_request (id, flow_id, run_id, idempotency_key, action_id, risk_claim, "
        "hub_risk_class, origin_chain, status, hub_proposal_id, created_at) VALUES "
        "(gen_random_uuid(), :flow1, NULL, gen_random_uuid(), 'app.restart', 'R1', NULL, '[]', 'aangevraagd', NULL, "
        "now()), "
        "(gen_random_uuid(), :flow1, :run1, gen_random_uuid(), 'notification.send', NULL, 'R0', '[]', 'uitgevoerd', "
        "'prop-1', now()), "
        "(gen_random_uuid(), :flow1, NULL, gen_random_uuid(), 'app.update', 'R0', 'R2', '[]', 'geweigerd', 'prop-2', "
        "now())",
    ]
    params: dict[str, Any] = {**ids, "sum1": "a" * 64, "sum2": "b" * 64}
    with eng.begin() as c:
        for stmt in stmts:
            names = {k for k in params if f":{k}" in stmt}
            c.execute(text(stmt), {k: params[k] for k in names})
    return ids


def _filled_enough(meting: Meting) -> None:
    for table, minimum in GEVULD.items():
        assert meting[table][0] >= minimum, f"{table}: {meting[table][0]} rijen, minstens {minimum} verwacht"
    assert sum(n for n, _ in meting.values()) >= sum(GEVULD.values())
    assert len(meting) >= 40, f"maar {len(meting)} tabellen gemeten"


def _restore(dump: Path, url: str) -> None:
    pg_restore = shutil.which("pg_restore")
    if pg_restore is None:
        if os.environ.get("CI"):
            pytest.fail("pg_restore ontbreekt in CI")
        pytest.skip("pg_restore niet geïnstalleerd")
    parts = make_url(url)
    env = {**os.environ}
    if parts.password:
        env["PGPASSWORD"] = str(parts.password)
    result = subprocess.run(  # noqa: S603 - vaste argumenten
        [
            pg_restore,
            "--no-owner",
            "-h",
            str(parts.host or "127.0.0.1"),
            "-p",
            str(parts.port or 5432),
            "-U",
            str(parts.username or "postgres"),
            "-d",
            str(parts.database),
            str(dump),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stderr


def test_upgrade_of_a_filled_0004_database_loses_nothing_and_can_go_back(
    vorige_versie: Settings, tmp_path: Path
) -> None:
    if shutil.which("pg_dump") is None:
        if os.environ.get("CI"):
            pytest.fail("pg_dump ontbreekt in CI")
        pytest.skip("pg_dump niet geïnstalleerd")
    settings = vorige_versie
    eng = create_engine(settings.database_url)
    try:
        _fill(eng)
        columns = _columns(eng)  # de kolommen van 0004: alleen die worden vergeleken
        voor = _measure(eng, columns)
        _filled_enough(voor)

        # dezelfde opdracht als de image bij het starten: back-up vooraf, dan migreren
        backups = tmp_path / "backups"
        assert cmd_migrate(settings, str(backups), None) == 0
        assert _revision(eng) == head_revision(settings) == "0005"
        assert _differences(voor, _measure(eng, columns)) == [], "upgrade 0004 → 0005"
        with eng.connect() as c:  # een geweigerd verzoek van vóór 0005 heeft nu een reden (en is niet weg)
            rows = c.execute(text("SELECT status, rejected_reason FROM automation_action_request")).all()
        assert sorted((str(s), r) for s, r in rows) == [
            ("aangevraagd", None),
            ("geweigerd", "reden_onbekend"),
            ("uitgevoerd", None),
        ]

        # terug naar de vorige versie en weer omhoog: telkens alles gelijk
        downgrade(settings, VORIGE)
        assert _revision(eng) == VORIGE
        assert _differences(voor, _measure(eng, columns)) == [], "terug 0005 → 0004"
        assert _columns(eng) == columns, "na terug staat precies het schema van 0004 er weer"
        assert cmd_migrate(settings, str(backups), None) == 0
        assert _revision(eng) == "0005"
        assert _differences(voor, _measure(eng, columns)) == [], "opnieuw 0004 → 0005"

        # de back-up van vóór de upgrade is een volledige terugweg
        dumps = sorted(backups.glob(f"voor-upgrade-{VORIGE}-*.dump"))
        assert dumps and all(d.stat().st_size > 0 for d in dumps)
        terug_url = recreate_database(DB_TERUG)
        _restore(dumps[0], terug_url)
        terug = create_engine(terug_url)
        try:
            assert _revision(terug) == VORIGE
            assert _differences(voor, _measure(terug, columns)) == [], "teruggezette back-up"
        finally:
            terug.dispose()
    finally:
        eng.dispose()


def test_down_and_up_again_with_b11_data_keeps_every_row(vorige_versie: Settings) -> None:
    """Terug naar 0004 vanaf een database met B11-gegevens (een geblokkeerde flow, een geweigerd verzoek met reden)
    en weer omhoog: de upgrade slaagt en er verdwijnt geen rij (R-HARDE-EIS-2)."""
    settings = vorige_versie
    eng = create_engine(settings.database_url)
    try:
        ids = _fill(eng)
        upgrade(settings)
        with eng.begin() as c:
            c.execute(
                text(
                    "UPDATE automation_flow SET status = 'geblokkeerd', blocked_reason = 'verboden_node' WHERE id = :f"
                ),
                {"f": ids["flow2"]},
            )
            c.execute(
                text(
                    "INSERT INTO automation_action_request (id, flow_id, idempotency_key, action_id, origin_chain, "
                    "status, created_at, rejected_reason) VALUES (gen_random_uuid(), :f, gen_random_uuid(), "
                    "'energy.boiler.switch', '[]', 'geweigerd', now(), 'boiler_nooit')"
                ),
                {"f": ids["flow1"]},
            )
        aantallen = {t: n for t, (n, _) in _measure(eng, _columns(eng)).items()}
        downgrade(settings, VORIGE)
        upgrade(settings)
        assert _revision(eng) == "0005"
        assert {t: n for t, (n, _) in _measure(eng, _columns(eng)).items()} == aantallen
        with eng.connect() as c:
            status = c.execute(text("SELECT status FROM automation_flow WHERE id = :f"), {"f": ids["flow2"]})
            assert status.scalar() == "onbekend", "gedocumenteerd: een geblokkeerde flow wordt 'onbekend' bij terug"
            reasons = c.execute(
                text("SELECT rejected_reason FROM automation_action_request WHERE status = 'geweigerd'")
            ).scalars()
            assert sorted(reasons) == ["reden_onbekend", "reden_onbekend"]
    finally:
        eng.dispose()


@pytest.mark.parametrize(
    ("label", "stmt"),
    [
        (
            "dubbele trigger",
            "INSERT INTO automation_trigger (id, flow_id, event_type, schema_version, filter) SELECT "
            "gen_random_uuid(), flow_id, event_type, schema_version, '{\"ander\": 1}' FROM automation_trigger LIMIT 1",
        ),
        ("risk_claim buiten R0-R3", "UPDATE automation_action_request SET risk_claim = 'r1' WHERE risk_claim = 'R1'"),
    ],
)
def test_rows_that_0005_cannot_take_stop_the_upgrade_and_change_nothing(
    vorige_versie: Settings, tmp_path: Path, label: str, stmt: str
) -> None:
    """Fail-closed: kan 0005 een schema-geldige 0004-rij niet aannemen, dan stopt de upgrade in zijn geheel en blijft
    de database op 0004 met al zijn gegevens (de supervisor start de app dan niet). Zulke rijen schreef de P0-code
    niet; ze opvullen of samenvoegen zou gegevens wijzigen of weggooien (vervolgpunt R-HARDE-EIS-2)."""
    settings = vorige_versie
    eng = create_engine(settings.database_url)
    try:
        _fill(eng)
        with eng.begin() as c:
            c.execute(text(stmt))
        columns = _columns(eng)
        voor = _measure(eng, columns)
        with pytest.raises(IntegrityError):
            cmd_migrate(settings, None, None)
        assert _revision(eng) == VORIGE, label
        assert _columns(eng) == columns, "geen half schema achtergelaten"
        assert _differences(voor, _measure(eng, columns)) == [], label
    finally:
        eng.dispose()


LOSE_ONE_ROW = '''"""testmigratie die één rij wist (alleen voor de tegenproef van de vergelijking)"""
from alembic import op

revision = "9999"
down_revision = "{head}"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM sso_recovery_method WHERE id = (SELECT id FROM sso_recovery_method ORDER BY id LIMIT 1)")


def downgrade() -> None:
    pass
'''


def test_the_comparison_sees_a_lost_row(vorige_versie: Settings, tmp_path: Path) -> None:
    """V-003: de vergelijking kan falen. Een migratie na 0005 die één rij wist, wordt gezien."""
    alembic = tmp_path / "alembic"
    shutil.copytree(alembic_dir(Settings()), alembic, ignore=shutil.ignore_patterns("__pycache__"))
    head = head_revision(Settings())
    (alembic / "versions" / "9999_verliest_een_rij.py").write_text(
        LOSE_ONE_ROW.replace("{head}", str(head)), encoding="utf-8"
    )
    settings = Settings(database_url=vorige_versie.database_url, alembic_dir=alembic, data_dir=tmp_path / "appdata")
    eng = create_engine(settings.database_url)
    try:
        _fill(eng)
        columns = _columns(eng)
        voor = _measure(eng, columns)
        assert cmd_migrate(settings, None, None) == 0
        assert _revision(eng) == "9999"
        assert _differences(voor, _measure(eng, columns)) == ["sso_recovery_method"]
    finally:
        eng.dispose()
