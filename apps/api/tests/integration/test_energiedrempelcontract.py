"""HTTP-voorbeelden van het beheercontract voor de energiedrempels."""

import re

import pytest

from integrations.deps import check_if_match
from integrations.errors import ApiError
from tests.conftest import REPO_ROOT, idem
from tests.integration.test_b14_005_meldingen import LIMITS, THRESHOLDS, install


def test_if_match_voorbeelden_uit_de_handleiding():
    handleiding = (REPO_ROOT / "README.md").read_text().split("**B14-005 afwijkingsmeldingen.**", 1)[1]
    voorbeelden = dict(re.findall(r"^\| `([^`]+)` \| (\d{3}) \|", handleiding.split("\n##", 1)[0], re.M))
    assert {tag: voorbeelden.get(tag) for tag in ('W/"1"', "*")} == {'W/"1"': "412", "*": "200"}
    with pytest.raises(ApiError) as oud:
        check_if_match(2, 'W/"1"')
    assert oud.value.status_code == int(voorbeelden['W/"1"'])
    check_if_match(2, "*")


def test_if_match_bij_bestaande_drempels(linked, auth):
    eerste = install(linked, auth)
    tweede = LIMITS | {"daily_budget_eur": 12}
    gewijzigd = linked.put(THRESHOLDS, json=tweede, headers=idem(auth("admin"), **{"If-Match": eerste.headers["etag"]}))
    assert gewijzigd.status_code == 200 and gewijzigd.headers["etag"] == 'W/"2"'

    for tag, status in (('W/"1"', 412), ("*", 200)):
        antwoord = linked.put(THRESHOLDS, json=LIMITS, headers=idem(auth("admin"), **{"If-Match": tag}))
        assert antwoord.status_code == status
        stand = linked.get(THRESHOLDS, headers=auth("admin"))
        assert stand.status_code == 200
        assert stand.json() == (tweede if tag != "*" else LIMITS)
        assert stand.headers["etag"] == ('W/"2"' if tag != "*" else 'W/"3"')
