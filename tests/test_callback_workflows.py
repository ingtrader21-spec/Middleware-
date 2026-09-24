import json
from pathlib import Path


def test_modular_callback_workflows_are_inactive_and_non_authoritative():
    workflows = json.loads(
        (
            Path(__file__).parents[1]
            / "deploy/n8n/callbacks/callback-workflows-v1.json"
        ).read_text()
    )
    assert {w["name"] for w in workflows} == {
        "CallbackScheduledV1",
        "CallbackReminderV1",
        "CallbackDueV1",
        "CallbackMissedV1",
        "CallbackEscalationV1",
        "CallbackCompletedV1",
    }
    assert all(
        w["active"] is False and w["meta"]["authority"] == "middleware"
        for w in workflows
    )
    assert all(
        w["meta"].get("rejectStaleVersion") or w["meta"].get("cancelOlderDeliveries")
        for w in workflows
    )
