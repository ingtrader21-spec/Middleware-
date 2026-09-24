#!/usr/bin/env python3
"""Fail closed on unified-intake observability or activation drift."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / "config" / "intake-observability.v1.json"
METRICS_SOURCE = ROOT / "app" / "intake_observability.py"
OBSERVABILITY_SOURCE = ROOT / "app" / "observability.py"
# The authenticated /metrics read and the lead-intake request context live on
# the control-plane router mounted by the single application factory.
MAIN_SOURCE = ROOT / "app" / "appolon_routes.py"
SURVEY_SOURCE = ROOT / "app" / "survey_routes.py"
TEST_SOURCE = ROOT / "tests" / "test_intake_observability.py"
DOC = ROOT / "docs" / "INTAKE-OBSERVABILITY.md"

EXPECTED_METRICS = {
    "lead_submissions_total",
    "lead_duplicates_total",
    "lead_validation_failures_total",
    "lead_processing_duration_seconds",
    "lead_odoo_delivery_total",
    "lead_odoo_delivery_failures_total",
    "survey_responses_total",
    "survey_validation_failures_total",
    "survey_processing_duration_seconds",
    "intake_inbox_backlog",
    "intake_outbox_backlog",
    "intake_oldest_pending_seconds",
    "intake_backlog_collection_success",
    "intake_rate_limit_rejections_total",
    "intake_spam_rejections_total",
}
EXPECTED_REQUIRED_LABELS = {
    "codestra_business",
    "application",
    "service",
    "environment",
}
ALLOWED_REQUEST_CONTEXT = {
    "channel",
    "form_kind",
    "survey_kind",
    "anonymous",
}
FORBIDDEN_LABEL_FIELDS = {
    "tenant_id",
    "tenantid",
    "customer_id",
    "customerid",
    "contact_id",
    "contactid",
    "lead_id",
    "leadid",
    "response_id",
    "userid",
    "user_id",
    "email",
    "phone",
    "name",
    "address",
    "form_id",
    "formid",
    "survey_id",
    "surveyid",
    "campaign_id",
    "campaignid",
    "request_id",
    "correlation_id",
    "trace_id",
    "idempotency_key",
    "message",
    "transcript",
    "consent_text",
    "answers",
    "custom_fields",
    "utm_source",
    "utm_campaign",
    "raw_url",
    "query_string",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"INTAKE_OBSERVABILITY_VALIDATION=FAIL: {message}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def require_file(path: Path) -> str:
    if not path.is_file():
        fail(f"missing {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def string_literals(node: ast.AST) -> set[str]:
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    }


def validate_control() -> None:
    control = load_json(CONTROL)
    if control.get("schemaVersion") != "1.0":
        fail("control schemaVersion must be 1.0")
    if control.get("status") != "SOURCE_WIRED_TARGETS_PENDING":
        fail("control status must remain SOURCE_WIRED_TARGETS_PENDING")
    if control.get("authority") != "ingtrader21-spec/Middleware-":
        fail("Middleware repository must remain the metrics authority")

    endpoint = control.get("metricsEndpoint", {})
    expected_endpoint = {
        "method": "GET",
        "path": "/metrics",
        "clientId": "monitoring-readonly",
        "requiredScope": "metrics.read",
        "anonymousAccess": False,
        "publicExposure": False,
    }
    if endpoint != expected_endpoint:
        fail("private metrics endpoint contract drifted")

    if set(control.get("rawMetrics", [])) != EXPECTED_METRICS:
        fail("raw intake metric catalogue drifted")
    if set(control.get("requiredCorporateLabels", [])) != EXPECTED_REQUIRED_LABELS:
        fail("required corporate label catalogue drifted")

    forbidden = {str(item).lower() for item in control.get("forbiddenMetricLabelsOrValues", [])}
    if not FORBIDDEN_LABEL_FIELDS.issubset(forbidden):
        missing = sorted(FORBIDDEN_LABEL_FIELDS - forbidden)
        fail(f"forbidden metric field catalogue is incomplete: {missing}")

    backlog = control.get("backlogCollection", {})
    if backlog.get("aggregateOnly") is not True:
        fail("backlog collection must remain aggregate-only")
    if backlog.get("tenantDimensionAllowed") is not False:
        fail("tenant backlog dimensions are prohibited")
    if backlog.get("customerDimensionAllowed") is not False:
        fail("customer backlog dimensions are prohibited")

    worker = control.get("workerInstrumentation", {})
    if worker.get("falseSuccessAllowed") is not False:
        fail("false delivery success is prohibited")
    if worker.get("odooWorkerWired") is not False:
        fail("Odoo worker must not be claimed wired before implementation evidence")
    if worker.get("spamControlWired") is not False:
        fail("spam-control worker must not be claimed wired before evidence")

    release_gates = control.get("releaseGates", {})
    for key in (
        "prometheusTargetActivation",
        "blackboxTargetActivation",
        "stagingEndpointAuthenticationVerified",
        "stagingNoPiiScrapeVerified",
        "stagingRecordingRulesVerified",
        "stagingAlertsVerified",
        "stagingBacklogQueryVerified",
        "stagingLoadAndCardinalityVerified",
        "stagingEvidencePassed",
        "productionDeploymentApproved",
    ):
        if release_gates.get(key) is not False:
            fail(f"release gate must remain false: {key}")

    effects = control.get("runtimeEffects", {})
    if not effects or any(value is not False for value in effects.values()):
        fail("all runtime effects must remain false")


def validate_prometheus_definitions() -> None:
    source = require_file(METRICS_SOURCE)
    tree = ast.parse(source, filename=str(METRICS_SOURCE))
    metric_names: set[str] = set()
    observed_label_literals: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        function_name = ""
        if isinstance(node.func, ast.Name):
            function_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            function_name = node.func.attr
        if function_name not in {"Counter", "Gauge", "Histogram"}:
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            fail("every Prometheus metric must use a static name")
        metric_name = node.args[0].value
        if not isinstance(metric_name, str):
            fail("every Prometheus metric name must be a string literal")
        metric_names.add(metric_name)
        if len(node.args) >= 3:
            observed_label_literals |= {
                value.lower() for value in string_literals(node.args[2])
            }

    if metric_names != EXPECTED_METRICS:
        fail(f"source metric catalogue mismatch: {sorted(metric_names)}")
    unsafe_literals = observed_label_literals & FORBIDDEN_LABEL_FIELDS
    if unsafe_literals:
        fail(f"unsafe Prometheus label names found: {sorted(unsafe_literals)}")

    required_fragments = (
        'CODESTRA_BUSINESS: Final = "platform"',
        'APPLICATION: Final = "integration"',
        'SERVICE: Final = "middleware-api"',
        "WHERE event_type = ANY($1::text[])",
        "processed_at IS NULL",
        "completed_at IS NULL",
        "dead_lettered_at IS NULL",
        "GROUP BY destination",
        "record_odoo_delivery",
        "record_spam_rejection",
    )
    for fragment in required_fragments:
        if fragment not in source:
            fail(f"intake metrics source is missing: {fragment}")
    for forbidden_fragment in (
        "GROUP BY tenant_id",
        "GROUP BY customer_id",
        "GROUP BY contact_id",
        "GROUP BY lead_id",
    ):
        if forbidden_fragment in source:
            fail(f"aggregate backlog query contains: {forbidden_fragment}")


def intake_context_keys(path: Path) -> list[set[str]]:
    tree = ast.parse(require_file(path), filename=str(path))
    results: list[set[str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(
            isinstance(target, ast.Attribute) and target.attr == "intake_metrics"
            for target in targets
        ):
            continue
        value = node.value
        if not isinstance(value, ast.Dict):
            fail(f"intake_metrics must be assigned a static dict in {path.name}")
        keys = {
            key.value
            for key in value.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        results.append(keys)
    return results


def validate_http_wiring() -> None:
    main = require_file(MAIN_SOURCE)
    survey = require_file(SURVEY_SOURCE)
    observability = require_file(OBSERVABILITY_SOURCE)

    if '@router.get("/metrics")' not in main:
        fail("Middleware metrics endpoint is missing")
    for fragment in (
        '"channel": submission.source',
        '"survey_kind": submission.surveyCategory',
        '"anonymous": "true" if submission.anonymous else "false"',
    ):
        if fragment not in survey:
            fail(f"survey metrics wiring is missing: {fragment}")
    for fragment in (
        "IntakeMetrics",
        "record_http_outcome",
        "collect_intake_backlog",
        "intake_context",
    ):
        if fragment not in observability:
            fail(f"observability integration is missing: {fragment}")

    all_contexts = intake_context_keys(MAIN_SOURCE) + intake_context_keys(SURVEY_SOURCE)
    if not all_contexts:
        fail("no bounded intake request context is attached")
    for keys in all_contexts:
        if not keys or not keys.issubset(ALLOWED_REQUEST_CONTEXT):
            fail(f"unsafe intake request context keys: {sorted(keys)}")


def validate_tests_and_docs() -> None:
    tests = require_file(TEST_SOURCE)
    for fragment in (
        '"tenant-1"',
        '"private-contact@example.test"',
        '"credit-repair-lead-never-a-label"',
        '"nps-private-survey-id"',
        "all(value not in metrics.text for value in forbidden_values)",
        '"Bearer metrics-token"',
        "assert missing.status_code == 401",
        "assert wrong_identity.status_code == 401",
        '"landing_page"',
        '"configured"',
        '"nps"',
        '"true"',
    ):
        if fragment not in tests:
            fail(f"intake metrics regression test is missing: {fragment}")

    doc = require_file(DOC)
    for fragment in (
        "monitoring-readonly",
        "metrics.read",
        "prometheusTargetActivation = false",
        "blackboxTargetActivation    = false",
        "stagingEvidencePassed       = false",
        "Fabricating a delivery success",
        "no tenant, contact, lead, response or customer grouping",
    ):
        if fragment not in doc:
            fail(f"intake observability documentation is missing: {fragment}")


def main() -> None:
    validate_control()
    validate_prometheus_definitions()
    validate_http_wiring()
    validate_tests_and_docs()
    print("INTAKE_OBSERVABILITY_VALIDATION=PASS")


if __name__ == "__main__":
    main()
