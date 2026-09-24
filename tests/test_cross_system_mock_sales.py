from app.provider_mocks import POSTIZ_MOCK, QWEN_MOCK, VICIDIAL_MOCK


def test_offline_sales_flow_is_trace_continuous_and_idempotent() -> None:
    lead = "CODESTRA-INTEGRATION-TEST-LEAD-001"
    trace_id = "trace-offline-001"
    correlation_id = "correlation-offline-001"
    events: dict[str, dict] = {}
    for _ in range(2):
        analysis = QWEN_MOCK.execute("lead_analysis", f"{lead}:analysis")
        call = VICIDIAL_MOCK.execute("callback_schedule", f"{lead}:call")
        summary = QWEN_MOCK.execute("call_summary", f"{lead}:summary")
        draft = POSTIZ_MOCK.execute("draft_create", f"{lead}:draft")
        events.setdefault(lead, {"trace_id": trace_id, "correlation_id": correlation_id,
                                 "analysis": analysis, "call": call, "summary": summary,
                                 "draft": draft, "status": "COMPLETED"})
    record = events[lead]
    assert record["trace_id"] == trace_id
    assert record["correlation_id"] == correlation_id
    assert all(record[key]["status"] == "COMPLETED" for key in ("analysis", "call", "summary", "draft"))
    assert len(events) == 1
    assert QWEN_MOCK.calls[f"{lead}:analysis"] == 2  # adapter is deterministic; store dedupe is canonical
    assert QWEN_MOCK.calls[f"{lead}:summary"] == 2
    assert VICIDIAL_MOCK.calls[f"{lead}:call"] == 2
    assert POSTIZ_MOCK.calls[f"{lead}:draft"] == 2
