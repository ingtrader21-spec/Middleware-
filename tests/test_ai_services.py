import pytest
from pydantic import ValidationError

from app.core.ai_services import (
    AIRequest,
    AIResult,
    FeatureFlags,
    knowledge_allowed,
    qualify,
    redact_text,
    request_hash,
)


def request(**overrides):
    data = dict(
        schema_version=1,
        task_id="task-0001",
        task_type="lead_prequalification",
        business_unit="TL",
        campaign_id="TST-TL",
        entity_type="lead",
        entity_id="lead-1",
        language="en",
        priority=2,
        minimized_input={"base_score": 82},
        output_schema="qualification_v1",
        correlation_id="corr-1",
        idempotency_key="ai:v1:lead:1",
        request_timestamp="2026-07-25T00:00:00Z",
        consent=True,
    )
    data.update(overrides)
    return AIRequest(**data)


@pytest.mark.parametrize(
    "unit,score,category",
    [
        ("TL", 95, "exceptional_fit"),
        ("DEV", 82, "strong_fit"),
        ("SCP", 65, "moderate_fit"),
        ("TL", 45, "weak_fit"),
        ("DEV", 20, "very_low_fit"),
    ],
)
def test_fit_categories(unit, score, category):
    assert (
        qualify(unit, {"consent": True, "base_score": score}).fit_category == category
    )


def test_dnc_and_consent_override():
    assert qualify("TL", {"consent": True, "dnc": True}).score == 0
    assert qualify("DEV", {"consent": False}).category == "suppressed"


def test_scp_medical_claim_requires_review():
    result = qualify("SCP", {"consent": True, "medical_claim": True})
    assert result.category == "compliance_review" and result.human_review_required


def test_low_confidence_review_and_invalid_urgency():
    assert qualify("TL", {"consent": True, "confidence": 0.4}).human_review_required
    with pytest.raises(ValueError):
        qualify("TL", {"consent": True, "urgency": "now"})


def test_strict_request_and_sensitive_rejection():
    with pytest.raises(ValidationError):
        request(extra="bad")
    with pytest.raises(ValidationError):
        request(minimized_input={"card_number": "x"})
    with pytest.raises(ValidationError):
        request(business_unit="DEVX")


def test_hash_is_stable_and_changed_payload_differs():
    assert request_hash(request()) == request_hash(request())
    assert request_hash(request(entity_id="lead-2")) != request_hash(request())


def test_redaction():
    value = redact_text("card 4111 1111 1111 1111 password=unsafe")
    assert "4111" not in value and "unsafe" not in value


def test_knowledge_isolation():
    item = {
        "business_unit": "TL",
        "campaign_id": "C1",
        "language": "en",
        "status": "published",
        "archived": False,
    }
    assert knowledge_allowed(item, "TL", "C1", "en")
    assert not knowledge_allowed(item, "DEV", "C1", "en")


def test_flags_default_false_and_kill_switch():
    assert not FeatureFlags().enabled("ENABLE_AI_PREQUALIFICATION")
    assert not FeatureFlags({"ENABLE_AI_PREQUALIFICATION": True}).enabled(
        "ENABLE_AI_PREQUALIFICATION"
    )
    assert FeatureFlags(
        {"ENABLE_AI_PROVIDERS": True, "ENABLE_AI_PREQUALIFICATION": True}
    ).enabled("ENABLE_AI_PREQUALIFICATION")


def test_result_rejects_unknown_and_score_range():
    base = dict(
        schema_version=1,
        task_id="task-1",
        task_type="call_summary",
        status="completed",
        provider="fake",
        model="fake-v1",
        output_schema="summary_v1",
        result={},
        confidence=0.8,
        human_review_required=False,
        correlation_id="c",
    )
    AIResult(**base)
    with pytest.raises(ValidationError):
        AIResult(**base, unknown=True)
    with pytest.raises(ValidationError):
        AIResult(**{**base, "confidence": 2})
