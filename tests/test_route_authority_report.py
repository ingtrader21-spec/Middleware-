"""The route authority report (config/route-authority-report.v1.json) is generated
from the canonical integration application and must not drift; no mutating
operation may reach an external provider outside the command kernel."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "config" / "route-authority-report.v1.json"
GENERATOR = ROOT / "scripts" / "generate_route_authority_report.py"
ALLOWED = {"READ_ONLY", "KERNEL_WRAPPER", "INTERNAL_EVENT_INGRESS", "DURABLE_OUTBOX_INTENT", "DIRECT_INTERNAL_SERVICE", "DENIED_LEGACY"}
KERNEL_ROUTES = {
    ("POST", "/platform/v1/commands"): "KERNEL_WRAPPER",
    ("GET", "/platform/v1/operations/{operation_id}"): "READ_ONLY",
    ("GET", "/platform/v1/operations/{operation_id}/timeline"): "READ_ONLY",
    ("POST", "/platform/v1/operations/{operation_id}/cancel"): "KERNEL_WRAPPER",
    ("POST", "/platform/v1/operations/{operation_id}/replay"): "KERNEL_WRAPPER",
    ("GET", "/platform/v1/kernel/describe"): "READ_ONLY",
    ("POST", "/platform/v1/rehearsals/no-effect"): "READ_ONLY",
    ("GET", "/platform/v1/rehearsals/{rehearsal_id}"): "READ_ONLY",
}


def _generator():
    spec = importlib.util.spec_from_file_location("generate_route_authority_report", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_committed_report_matches_the_generator() -> None:
    module = _generator()
    assert REPORT.read_text(encoding="utf-8") == module.render(module.build())


def test_every_operation_is_classified_and_no_direct_effect_bypass_exists() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    assert report["service"] == "middleware-integration-api" and report["listener_port"] == 8095
    rows = report["routes"]
    assert rows, "empty report"
    for row in rows:
        assert row["classification"] in ALLOWED, row
        if row["classification"] == "KERNEL_WRAPPER":
            assert row["kernel_delegate"], row
        if row["method"] in {"GET", "HEAD", "OPTIONS"}:
            assert row["classification"] in {"READ_ONLY", "DENIED_LEGACY"}, row
    assert report["summary"]["DIRECT_EFFECT_BYPASSES"] == 0
    assert report["summary"]["direct_effect_bypasses"] == []
    # The kernel-convergence backlog may only shrink.
    assert report["summary"]["KERNEL_CONVERGENCE_PENDING"] <= 5
    assert report["summary"]["DIRECT_INTERNAL_SERVICE_CALLS"] <= 3


def test_kernel_and_crm_routes_are_kernel_wrappers() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    by_key = {(row["method"], row["path"]): row for row in report["routes"]}
    for key, expected in KERNEL_ROUTES.items():
        assert by_key[key]["classification"] == expected, key
    crm_writes = [row for row in report["routes"] if row["path"].startswith(("/platform/v1/contacts", "/platform/v1/opportunities", "/platform/v1/tickets", "/platform/v1/tasks")) and row["method"] in {"POST", "PATCH"}]
    assert crm_writes and all(row["classification"] == "KERNEL_WRAPPER" for row in crm_writes)
