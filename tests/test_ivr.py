from concurrent.futures import ThreadPoolExecutor

import pytest

from app.core.ivr import (
    DEFAULT_DIDS,
    Destination,
    FakeIvrAdapter,
    FeaturePolicy,
    IdempotencyConflict,
    IdempotencyLedger,
    IvrDenied,
    IvrSession,
    appointment_lookup,
    classify_intent,
    customer_lookup,
    reclassify,
    resolve_did,
    select_main,
    sign_context,
    validate_destination,
    verify_context,
)


def session(unit="SHARED", campaign=None):
    return IvrSession(
        "ivr-1",
        "SYNTH-CALL-1",
        "TST-MAIN",
        "***0001",
        unit,
        campaign,
        "en",
        "en",
        campaign_lock=campaign,
        correlation_id="corr-1",
    )


@pytest.mark.parametrize(
    "key,unit,campaign",
    [
        ("1", "TL", "TL-GENERAL"),
        ("2", "DEV", "DEV-GENERAL"),
        ("3", "SCP", "SCP-GENERAL"),
    ],
)
def test_main_unit_routes(key, unit, campaign):
    result = select_main(session(), key)
    assert (result.business_unit, result.campaign_lock) == (unit, campaign)


@pytest.mark.parametrize(
    "key,node",
    [
        ("4", "appointments"),
        ("5", "support"),
        ("0", "repeat"),
    ],
)
def test_main_shared_routes(key, node):
    assert select_main(session(), key).ivr_path[-1] == node


def test_spanish_persists_and_invalid_falls_back():
    spanish = select_main(session(), "9")
    assert spanish.final_language == "es"
    assert select_main(spanish, "x").final_language == "es"
    assert select_main(spanish, "x").ivr_path[-1] == "invalid-input"


def test_dedicated_dids_and_unknown_fail_closed():
    assert resolve_did("TST-TL").default_campaign == "TL-GENERAL"
    assert set(DEFAULT_DIDS) >= {"TST-MAIN", "TST-TL", "TST-DEV", "TST-SCP"}
    with pytest.raises(IvrDenied):
        resolve_did("PUBLIC-UNKNOWN")


def test_masked_customer_lookup_only():
    assert customer_lookup("exact_match", "***1234")["state"] == "exact_match"
    with pytest.raises(ValueError):
        customer_lookup("exact_match", "customer@example.invalid")


def test_appointment_same_campaign_only():
    scoped = session("TL", "TL-GENERAL")
    assert (
        appointment_lookup("agent_busy", "TL", "TL-GENERAL", scoped)["state"]
        == "agent_busy"
    )
    with pytest.raises(IvrDenied):
        appointment_lookup("agent_available", "DEV", "DEV-GENERAL", scoped)


def destination(unit="TL", campaign="TL-GENERAL"):
    return Destination(
        campaign,
        "TSTTL01",
        "TST_TL_IN",
        unit,
        "SDR",
        "TST_TL_QUEUE",
        "TST_TL_SUP",
        ("en", "es"),
        ("support", "supervisor"),
        "test-only",
    )


def test_campaign_and_unit_lock():
    scoped = session("TL", "TL-GENERAL")
    validate_destination(destination(), scoped)
    with pytest.raises(IvrDenied):
        validate_destination(destination("DEV", "DEV-GENERAL"), scoped)
    with pytest.raises(IvrDenied):
        validate_destination(destination("TL", "TL-OTHER"), scoped)


def test_signed_context_tamper_rejected():
    scoped = session("TL", "TL-GENERAL")
    key = b"x" * 32
    signature = sign_context(scoped, key)
    assert verify_context(scoped, key, signature)
    assert not verify_context(scoped, key, "0" * 64)


def test_controlled_reclassification_preserves_link():
    original = session("TL", "TL-GENERAL")
    closed, linked, audit = reclassify(original, "support", "ivr-2", "wrong selection")
    assert closed.final_result == "MISROUTED_IVR"
    assert linked.session_id == "ivr-2"
    assert audit["original_session"] == original.session_id


def test_ai_intent_is_scoped_and_has_keypad_fallback():
    scoped = session("DEV", "DEV-GENERAL")
    result = classify_intent("ai_project", 0.70, scoped, "DEV", "DEV-GENERAL")
    assert result["confirmation_required"] and result["fallback_menu"] == "keypad"
    assert (
        classify_intent("unsupported", 0.9, scoped, "DEV", "DEV-GENERAL")["intent"]
        is None
    )
    with pytest.raises(IvrDenied):
        classify_intent("support", 0.99, scoped, "SCP", "SCP-GENERAL")


def test_ten_concurrent_duplicates_and_conflict():
    ledger = IdempotencyLedger()
    with ThreadPoolExecutor(max_workers=10) as pool:
        values = list(
            pool.map(
                lambda _: ledger.claim(
                    "ivr-session:v1:SYNTH-CALL-1", {"unit": "TL"}, {"id": "ivr-1"}
                ),
                range(10),
            )
        )
    assert values == [{"id": "ivr-1"}] * 10
    with pytest.raises(IdempotencyConflict):
        ledger.claim("ivr-session:v1:SYNTH-CALL-1", {"unit": "DEV"}, {"id": "ivr-2"})


def test_fake_adapter_cannot_touch_live_telephony():
    adapter = FakeIvrAdapter()
    assert (
        adapter.route(destination(), session("TL", "TL-GENERAL"))["state"]
        == "synthetic_route_validated"
    )
    for operation in (adapter.answer, adapter.originate, adapter.activate_did):
        with pytest.raises(IvrDenied):
            operation()


def test_all_feature_flags_default_false_and_are_scope_specific():
    defaults = FeaturePolicy()
    assert not defaults.enabled("ENABLE_MAIN_IVR", "staging", "TL", "TL-GENERAL")
    policy = FeaturePolicy(
        {
            ("staging", "TL", "TL-GENERAL", "ENABLE_TL_IVR"): True,
        }
    )
    assert policy.enabled("ENABLE_TL_IVR", "staging", "TL", "TL-GENERAL")
    assert not policy.enabled("ENABLE_TL_IVR", "staging", "DEV", "DEV-GENERAL")


def test_high_synthetic_session_volume():
    ledger = IdempotencyLedger()
    for index in range(3000):
        key = f"ivr-session:v1:SYNTH-{index}"
        assert ledger.claim(key, {"unit": "TL"}, index) == index
