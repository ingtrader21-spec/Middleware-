from __future__ import annotations

import json
import re
from pathlib import Path

LOCK_PATH = Path("config/telnexa-sms-provider-source-lock.v1.json")
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def _lock() -> dict:
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def test_source_authorities_are_exact_reviewed_and_merged() -> None:
    lock = _lock()
    authority = lock["authority"]
    certification = lock["certification"]

    for field in (
        "sdkContractSha",
        "middlewareBaseSha",
        "telnexaSourceSha",
        "telnexaSyntheticMergeSha",
        "telnexaMergedMainSha",
    ):
        assert FULL_SHA.fullmatch(authority[field]), field

    assert authority["sdkRepository"] == "appolon1908-hue/SDK-repository"
    assert authority["middlewareRepository"] == "ingtrader21-spec/Middleware-"
    assert authority["telnexaRepository"] == "appolon1908-hue/telnexa"
    assert authority["telnexaSourceBranch"] == "feat/communications-api-v1-sms-provider"
    assert authority["telnexaProtectedBranch"] == "main"
    assert authority["telnexaPullRequest"] == 22
    assert certification["reviewThreadsResolved"] == 4
    assert certification["independentApprovalPending"] is False
    assert certification["independentApprovalBy"] == "kazan555"
    assert certification["sourcePromotionMerged"] is True


def test_recorded_provider_workflows_pass_on_the_locked_source() -> None:
    lock = _lock()
    certification = lock["certification"]

    assert certification["exactHeadWorkflow"] == {
        "name": "Telnexa exact-head CI",
        "runId": 33338423307,
        "conclusion": "success",
    }
    assert certification["providerWorkflow"] == {
        "name": "Step 4 SMS provider certification",
        "runId": 33338423309,
        "conclusion": "success",
    }


def test_unknown_outcome_policy_is_fail_closed() -> None:
    contracts = _lock()["contracts"]

    assert contracts["commandType"] == "sms.message.submit.v1"
    assert contracts["target"] == "telnexa-sms"
    assert contracts["capability"] == "SMS_DELIVERY"
    assert contracts["providerSubmissionMaximum"] == 1
    assert contracts["blindProviderResubmission"] is False
    assert contracts["authoritativeReadbackRequiredAfterUnknownOutcome"] is True
    assert contracts["durableProviderReferenceRequiredBeforeBillingCommit"] is True
    assert contracts["staleSubmittingRecovery"] == "authoritative_readback_only"
    assert contracts["reconciliationAttemptClaim"] == "serialized_row_lock"


def test_all_live_effects_remain_disabled() -> None:
    effects = _lock()["liveEffects"]

    assert effects
    assert all(value is False for value in effects.values())
