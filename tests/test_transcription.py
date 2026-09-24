from concurrent.futures import ThreadPoolExecutor

import pytest

from app.core.transcription import (
    FeaturePolicy,
    IdempotencyConflict,
    IdempotencyLedger,
    TranscriptSegment,
    TranscriptionDenied,
    channel_identity,
    create_audio_session,
    finalize_audio_session,
    redact,
    structured_analysis,
    validate_segment,
)


def make_session(**overrides):
    data = dict(
        call_reference="SYNTH-CALL-1",
        business_unit="TL",
        campaign="TL-TEST",
        media_checksum="a" * 64,
        consent=True,
        classification="synthetic",
        retention_policy="test-24h",
        correlation_id="corr-1",
    )
    data.update(overrides)
    return create_audio_session(**data)


def test_audio_session_scope_consent_and_integrity():
    session = make_session()
    assert finalize_audio_session(session, "a" * 64).state == "finalized"
    with pytest.raises(TranscriptionDenied):
        make_session(campaign="DEV-TEST")
    with pytest.raises(TranscriptionDenied):
        make_session(consent=False)
    with pytest.raises(ValueError):
        finalize_audio_session(session, "b" * 64)


def test_segment_validation_and_channel_identity_first():
    segment = TranscriptSegment(
        "SYNTH-CALL-1",
        "agent",
        "agent",
        1,
        0,
        500,
        "en",
        0.95,
        "final",
        "Synthetic speech",
    )
    validate_segment(segment)
    assert channel_identity("local/agent", {"local/agent": "agent"}) == ("agent", False)
    assert channel_identity("mixed", {}) == ("unknown", True)


@pytest.mark.parametrize(
    "source,marker",
    [
        ("4111 1111 1111 1111", "payment_card"),
        ("CVV 123", "cvv"),
        ("password=secret-value", "credential"),
        ("123-45-6789", "government_id"),
    ],
)
def test_redaction(source, marker):
    redacted, events = redact(source)
    assert source not in redacted
    assert events[0]["category"] == marker
    assert source not in str(events)


def test_structured_analysis_is_advisory_and_cannot_command_telephony():
    result = structured_analysis(
        primary_intent="support",
        secondary_intents=[],
        resolution="follow_up_required",
        sentiment="neutral",
        objections=[],
        action_items=["synthetic follow-up"],
        dnc=False,
        confusion=False,
    )
    assert result["advisory_only"] is True
    assert result["allowed_commands"] == []


def test_all_flags_default_false_and_are_scope_specific():
    assert not FeaturePolicy().enabled(
        "ENABLE_FINAL_TRANSCRIPTION", "staging", "TL", "TL-TEST"
    )
    enabled = FeaturePolicy(
        {
            ("staging", "TL", "TL-TEST", "ENABLE_FINAL_TRANSCRIPTION"): True,
        }
    )
    assert enabled.enabled("ENABLE_FINAL_TRANSCRIPTION", "staging", "TL", "TL-TEST")
    assert not enabled.enabled(
        "ENABLE_FINAL_TRANSCRIPTION", "staging", "DEV", "DEV-TEST"
    )


def test_ten_concurrent_duplicates_and_changed_payload_conflict():
    ledger = IdempotencyLedger()
    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(
            pool.map(
                lambda _: ledger.claim(
                    "transcript-final:SYNTH-CALL-1:v1", b"same", {"job": "one"}
                ),
                range(10),
            )
        )
    assert results == [{"job": "one"}] * 10
    with pytest.raises(IdempotencyConflict):
        ledger.claim("transcript-final:SYNTH-CALL-1:v1", b"changed", {"job": "two"})
