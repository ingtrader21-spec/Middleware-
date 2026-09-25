from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.api.v1 import commands


def test_reconciliation_bounds_are_explicit():
    assert "READBACK_PENDING" in commands._ACTIVE_STALE_STATES
    assert "READBACK_MISMATCH" in commands._ACTIVE_STALE_STATES
    assert "RECONCILIATION_REQUIRED" in commands._REPLAYABLE_STATES
    assert "SUCCEEDED" not in commands._REPLAYABLE_STATES


def test_replay_request_rejects_short_reason():
    with pytest.raises(Exception):
        commands.ReplayRequest(reason="short", expected_state="READBACK_MISMATCH", operator_id="op-1")


def test_result_view_is_bounded_and_safe():
    row = SimpleNamespace(
        result_public_id="RES-1",
        immutable_json={"operation_public_id": "OPR-1", "command_public_id": "CMD-1"},
        application_status="APPLIED",
        readback_status="READBACK_VERIFIED",
        reconciliation_status="IN_SYNC",
        correlation_id="corr-1",
    )
    view = commands._result_view(row)
    assert view["result_public_id"] == "RES-1"
    assert "immutable_json" not in view
    assert "safe_summary" not in view


def test_repair_intent_validation_and_classification():
    req = commands.RepairIntentRequest(
        reason="readback mismatch requires operator repair",
        expected_state="READBACK_MISMATCH",
        operator_id="operator-1",
        classification="RECONCILE_READBACK",
    )
    assert req.classification == "RECONCILE_READBACK"
    with pytest.raises(Exception):
        commands.RepairIntentRequest(
            reason="valid repair reason",
            expected_state="READBACK_MISMATCH",
            operator_id="operator-1",
            classification="ARBITRARY",
        )
