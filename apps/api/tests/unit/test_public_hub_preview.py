"""Een eerder afgeschermde preview geeft op elke route hetzelfde antwoord (R-VEILIG-3 van de vierde review)."""

from __future__ import annotations

from integrations.domains.sso.proposals import public_hub_preview

INCOMPLETE_PROVIDER_CODE = "providergegevens_onvolledig"

ONVEILIG = {
    "diff": [{"object": "oauth2_provider", "changes": [{"field": "name", "before": None, "after": "  "}]}],
    "requests": [],
    "rollback_recipe": [],
    "changes": 5,
    "warnings": [],
}


def test_afschermen_is_idempotent_en_telt_nul_wijzigingen() -> None:
    eerste = public_hub_preview(ONVEILIG)
    assert eerste["changes"] == 0 and eerste["diff"] == []
    assert public_hub_preview(eerste) == eerste
    assert [w["code"] for w in eerste["warnings"]] == [INCOMPLETE_PROVIDER_CODE]


def test_bewaard_antwoord_met_leeg_diff_maar_oude_telling_wordt_ook_nul() -> None:
    oud = {
        **ONVEILIG,
        "diff": [],
        "warnings": [{"code": INCOMPLETE_PROVIDER_CODE, "message_nl": "Deze preview is onvolledig."}],
    }
    assert public_hub_preview(oud)["changes"] == 0
    assert len(public_hub_preview(oud)["warnings"]) == 1
