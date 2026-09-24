from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.ai_tasks import AiTask, AiTaskStore, TaskStatus


def task(key="ai-1"):
    now = datetime.now(timezone.utc)
    return AiTask(
        schema_version="codestra.ai.task.v1", task_id=key, task_type="lead_analysis",
        model_policy="CODESTRA-QWEN-LEAD-ANALYSIS-V1", source_system="odoo",
        organization_id="ORG-TEST", input_reference="CODESTRA-INTEGRATION-TEST-LEAD-001",
        approved_context={"synthetic": True}, requested_outputs=["classification"],
        constraints={"max_tokens": 128}, idempotency_key=key, trace_id="trace-1",
        correlation_id="corr-1", requested_at=now, expires_at=now + timedelta(minutes=5),
    )


def test_ai_task_is_idempotent_and_audited():
    store = AiTaskStore()
    store.create(task())
    duplicate = store.create(task())
    assert duplicate["duplicate"] is True
    assert store.transition("ai-1", TaskStatus.RUNNING)["status"] == "RUNNING"
    assert any(e["event"] == "task_received" for e in store.audit)


def test_ai_task_expiration_and_conflict_fail_closed():
    store = AiTaskStore()
    now = datetime.now(timezone.utc)
    with pytest.raises(HTTPException):
        store.create(task("expired").model_copy(update={"requested_at": now, "expires_at": now}))
    store.create(task("same"))
    with pytest.raises(HTTPException):
        store.create(task("other").model_copy(update={"idempotency_key": "same", "trace_id": "different"}))
