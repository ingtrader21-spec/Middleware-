from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "config" / "api-webhook-contracts.json"
EXPECTED_MERGE_SHA = "922d039b5143f3ac738e88998036355562a8dd5d"
EXPECTED_LIFECYCLE_TYPES = (
    "codestra.vicidial.call.lifecycle.answered",
    "codestra.vicidial.call.lifecycle.completed",
    "codestra.vicidial.call.lifecycle.connected",
    "codestra.vicidial.call.lifecycle.created",
    "codestra.vicidial.call.lifecycle.failed",
    "codestra.vicidial.call.lifecycle.hangup",
    "codestra.vicidial.call.lifecycle.held",
    "codestra.vicidial.call.lifecycle.missed",
    "codestra.vicidial.call.lifecycle.offered",
    "codestra.vicidial.call.lifecycle.resumed",
    "codestra.vicidial.call.lifecycle.ringing",
    "codestra.vicidial.call.lifecycle.transfer.completed",
    "codestra.vicidial.call.lifecycle.transfer.started",
)
EXPECTED_COMPATIBILITY_TYPES = (
    "codestra.events.call_disposition_updated",
    "codestra.vicidial.call.completed",
    "codestra.vicidial.call.started",
    "codestra.vicidial.callback.requested",
)
EXPECTED_ROUTE_TYPES = tuple(
    sorted((*EXPECTED_COMPATIBILITY_TYPES, *EXPECTED_LIFECYCLE_TYPES))
)


def test_lifecycle_contract_is_pinned_to_protected_merge() -> None:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    lock = value["lifecycleContract"]
    assert lock == {
        "repository": "appolon1908-hue/Keycloak",
        "path": "config/contracts/webhook-contracts.json",
        "protectedBranch": "main",
        "mergeSha": EXPECTED_MERGE_SHA,
    }
    hook = next(
        item
        for item in value["webhooks"]
        if item["producerClientId"] == "vicidial-adapter"
    )
    assert tuple(hook["eventTypes"]) == EXPECTED_ROUTE_TYPES
    assert tuple(
        item for item in hook["eventTypes"] if ".call.lifecycle." in item
    ) == EXPECTED_LIFECYCLE_TYPES
    assert len(hook["eventTypes"]) == len(set(hook["eventTypes"]))


def test_existing_sdk_disposition_event_remains_outside_lifecycle_worker() -> None:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    hook = next(
        item
        for item in value["webhooks"]
        if item["producerClientId"] == "vicidial-adapter"
    )
    assert "codestra.events.call_disposition_updated" in hook["eventTypes"]
    assert ".call.lifecycle." not in "codestra.events.call_disposition_updated"
