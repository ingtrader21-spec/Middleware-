from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from scripts.reconcile_runtime_inventory import InventoryError, load_bound, reconcile

NOW = datetime(2026, 9, 9, 20, tzinfo=timezone.utc)


def documents():
    workload = {
        "name": "middleware-api",
        "source_repository": "https://github.com/ingtrader21-spec/Middleware-",
        "source_revision": "a" * 40,
        "image_reference": "ghcr.io/ingtrader21-spec/codestra-middleware@sha256:" + "b" * 64,
    }
    expected = {"schema_version": "1.0", "workloads": [workload]}
    observed = {"observed_at": NOW.isoformat(), "workloads": [
        {**workload, "status": "running", "health": "healthy"}
    ]}
    return observed, expected


def test_matching_inventory_is_not_runtime_certification():
    observed, expected = documents()
    report = reconcile(observed, expected, now=NOW)
    assert report["inventory_matches"] is True
    assert report["runtime_certified"] is False
    assert report["deployment_authorized"] is False
    assert report["workloads"][0]["classification"] == "CURRENT"


@pytest.mark.parametrize("field,value", [
    ("source_revision", "c" * 40),
    ("source_repository", None),
    ("image_reference", "middleware:latest"),
    ("status", "exited"),
    ("health", None),
    ("health", "unhealthy"),
])
def test_drift_needs_actual_readback(field, value):
    observed, expected = documents()
    observed["workloads"][0][field] = value
    report = reconcile(observed, expected, now=NOW)
    assert report["inventory_matches"] is False
    assert report["workloads"][0]["classification"] == "REQUIRES_RUNTIME_READBACK"


def test_missing_and_unowned_workloads_are_both_retained():
    observed, expected = documents()
    observed["workloads"][0]["name"] = "unowned-worker"
    report = reconcile(observed, expected, now=NOW)
    assert [row["classification"] for row in report["workloads"]] == [
        "REQUIRES_RUNTIME_READBACK", "UNKNOWN"
    ]
    assert report["expected_count"] == report["observed_count"] == 1
    assert report["inventory_matches"] is False


def test_old_capture_is_historical_not_current_truth():
    observed, expected = documents()
    report = reconcile(observed, expected, now=NOW + timedelta(hours=2))
    assert report["workloads"][0]["classification"] == "HISTORICAL"
    assert report["inventory_matches"] is False


@pytest.mark.parametrize("timestamp", ["2026-09-09T20:00:00", "invalid", "2027-01-01T00:00:00Z"])
def test_ambiguous_or_future_timestamp_is_rejected(timestamp):
    observed, expected = documents()
    observed["observed_at"] = timestamp
    with pytest.raises(InventoryError):
        reconcile(observed, expected, now=NOW)


@pytest.mark.parametrize("target", ["expected", "observed"])
def test_duplicate_workload_cannot_hide_drift(target):
    observed, expected = documents()
    selected = expected if target == "expected" else observed
    selected["workloads"].append(copy.deepcopy(selected["workloads"][0]))
    with pytest.raises(InventoryError, match="duplicate workload"):
        reconcile(observed, expected, now=NOW)


def test_empty_expected_inventory_and_mutable_authority_are_rejected():
    observed, expected = documents()
    expected["workloads"][0]["image_reference"] = "middleware:latest"
    with pytest.raises(InventoryError, match="immutable"):
        reconcile(observed, expected, now=NOW)
    expected["workloads"] = []
    with pytest.raises(InventoryError, match="nonempty"):
        reconcile(observed, expected, now=NOW)


def test_checksum_and_duplicate_json_members_are_rejected(tmp_path):
    path = tmp_path / "inventory.json"
    raw = b'{"workloads":[],"workloads":[{}]}'
    path.write_bytes(raw)
    with pytest.raises(InventoryError, match="checksum mismatch"):
        load_bound(path, "sha256:" + "0" * 64)
    with pytest.raises(InventoryError, match="duplicate JSON"):
        load_bound(path, "sha256:" + hashlib.sha256(raw).hexdigest())


def test_report_does_not_echo_sensitive_observation_fields():
    observed, expected = documents()
    observed["workloads"][0]["environment"] = {"PRIVATE_TOKEN": "synthetic-sensitive-value"}
    report = reconcile(observed, expected, now=NOW)
    assert "synthetic-sensitive-value" not in json.dumps(report)


def test_cli_replaces_old_success_when_checksum_is_invalid(tmp_path):
    inventory = tmp_path / "inventory.json"
    expected = tmp_path / "expected.json"
    output = tmp_path / "report.json"
    observed, wanted = documents()
    inventory.write_text(json.dumps(observed))
    expected.write_text(json.dumps(wanted))
    output.write_text('{"inventory_matches":true}')
    script = Path(__file__).resolve().parents[1] / "scripts/reconcile_runtime_inventory.py"
    result = subprocess.run([
        sys.executable, str(script), "--inventory", str(inventory),
        "--inventory-sha256", "sha256:" + "0" * 64,
        "--expected", str(expected), "--expected-sha256", "sha256:" + "0" * 64,
        "--output", str(output),
    ], capture_output=True, text=True)
    assert result.returncode == 2
    assert json.loads(output.read_text())["inventory_matches"] is False
    assert json.loads(inventory.read_text()) == observed
