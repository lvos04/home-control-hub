"""De CLI rapporteert de schemarevisie die na een mislukte terugmigratie nog leesbaar is."""

from unittest.mock import Mock

import pytest

from integrations.cli import cmd_migrate
from integrations.config import Settings
from integrations.migrations import BackupError


@pytest.mark.parametrize(
    ("bereikt", "melding"),
    [
        ("0010", "De database is ongewijzigd."),
        ("0009", "De database staat nu op revisie 0009. Controleer het herstelpunt vóór hervatten."),
        (None, "Controleer de schemarevisie vóór hervatten."),
    ],
)
def test_melding_na_mislukte_terugmigratie(monkeypatch, capsys, bereikt, melding):
    db = Mock()
    db.current_revision.side_effect = ["0010", bereikt]
    monkeypatch.setattr("integrations.db.Database", lambda url: db)
    monkeypatch.setattr("integrations.migrations.downgrade", Mock(side_effect=BackupError("opslaguitval")))

    assert cmd_migrate(Settings(), None, "0008") == 3
    assert capsys.readouterr().err.splitlines() == [f"FOUT: terugmigratie geweigerd: opslaguitval. {melding}"]
