from app.provider_mocks import POSTIZ_MOCK, QWEN_MOCK, VICIDIAL_MOCK


def test_mock_adapters_are_deterministic_and_side_effect_free() -> None:
    first = QWEN_MOCK.execute("lead_analysis", "fixture-1")
    second = QWEN_MOCK.execute("lead_analysis", "fixture-1")
    assert first["fixture_id"] == second["fixture_id"]
    assert first["status"] == "COMPLETED"
    assert VICIDIAL_MOCK.execute("manual_call_request", "fixture-2")["status"] == "COMPLETED"
    assert POSTIZ_MOCK.execute("draft_create", "fixture-3")["status"] == "COMPLETED"


def test_mock_failure_outcomes_are_classified() -> None:
    assert QWEN_MOCK.execute("x", "t", "temporary_failure")["status"] == "RETRYABLE_FAILURE"
    assert VICIDIAL_MOCK.execute("x", "p", "permanent_failure")["status"] == "FAILED"
    assert POSTIZ_MOCK.execute("x", "o", "timeout")["status"] == "TIMEOUT"
    assert POSTIZ_MOCK.execute("x", "d", "duplicate_callback")["duplicate"] is True
    assert VICIDIAL_MOCK.execute("x", "r", "reconciliation_mismatch")["status"] == "RECONCILIATION_MISMATCH"
