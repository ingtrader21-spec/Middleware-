#!/usr/bin/env python3
"""Validate the fail-closed MCR-L monitoring and readback contracts offline."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def validate(*, contract: dict | None = None, root: Path = ROOT) -> list[str]:
    errors = []
    try:
        spec = (
            contract
            if contract is not None
            else json.loads(
                (
                    root / "contracts/campaign-recycling/observability.v1.json"
                ).read_text()
            )
        )
        for key in ("public_metrics", "provider_effects_enabled"):
            if spec.get(key) is not False:
                errors.append(f"{key} must be false")
        if spec.get("metric_labels") != [
            "mode",
            "channel",
            "reason",
            "family",
            "outcome",
            "operation",
            "event_type",
        ]:
            errors.append(
                "metric labels must use the closed non-identifying vocabulary"
            )
        if spec.get("slos") != {
            "projection_lag_seconds": 300,
            "readback_freshness_seconds": 60,
            "projection_within_budget_ratio": 0.99,
            "window": "30d",
            "dead_letter_budget": 0,
            "unknown_evidence_is_healthy": False,
        }:
            errors.append("SLO contract drift")
        catalog = spec["service_catalog"]
        if (
            catalog.get("public_origin") is not None
            or catalog.get("registration_enabled") is not False
            or catalog.get("monitoring_state") != "pending"
        ):
            errors.append("catalog must remain private and uncertified")
        if spec.get("dead_letter") != {
            "durable_authority": None,
            "readback_when_unavailable": None,
            "evidence_available_metric": "codestra_mcr_dead_letter_evidence_available",
            "activation_blocked": True,
        }:
            errors.append("missing dead-letter authority must block readiness")
        connectors = spec["connector_catalog"]
        if {item["connector_id"] for item in connectors} != {
            "klyrow",
            "telnexa",
            "evolution",
            "vicidial",
            "odoo",
            "middleware",
        } or len(connectors) != 6:
            errors.append("connector catalog coverage drift")
        for item in connectors:
            if (
                item.get("registration_enabled") is not False
                or item.get("provider_effects_enabled") is not False
                or item.get("monitoring_state") != "pending"
                or not item.get("authority")
            ):
                errors.append("connector must remain uncertified and inactive")
        reconciliation = spec["reconciliation"]
        if (
            reconciliation.get("poller_enabled") is not False
            or reconciliation.get("missing_polling_is_healthy") is not False
            or reconciliation.get("authority") != "mcr_delivery_events"
        ):
            errors.append("reconciliation coverage must fail closed")
        health = spec["delivery_health"]
        if health.get("counted_outcomes") != ["applied", "replayed"] or health.get(
            "excluded_outcomes"
        ) != ["partial", "duplicate", "rejected", "failed"]:
            errors.append("delivery health must count completed projections only")
        rollback = spec["rollback_observability"]
        if (
            rollback.get("preserve_delivery_ledger") is not True
            or rollback.get("missing_metrics_is_healthy") is not False
            or rollback.get("production_mutation_authorized") is not False
            or rollback.get("runbook") != spec["runbook"]
        ):
            errors.append("rollback must preserve evidence and remain unauthorized")
        evidence = json.loads((root / spec["staging_evidence"]).read_text())
        if (
            evidence.get("environment") != "staging"
            or evidence.get("status") != "not_executed"
            or evidence.get("activation_blocked") is not True
            or evidence.get("provider_effects_enabled") is not False
            or evidence.get("production_mutation_performed") is not False
            or evidence.get("deployment_revision") is not None
            or evidence.get("observed_at") is not None
            or set(evidence.get("checks", {}))
            != {
                "private_scrape_auth",
                "redaction",
                "connector_readback",
                "reconciliation",
                "dead_letter_authority",
                "duplicate_and_partial_replay",
                "alert_evaluation",
                "rollback_metrics_loss",
            }
            or set(evidence.get("checks", {}).values()) != {"not_executed"}
        ):
            errors.append("uncertified staging evidence must not claim execution")
        schema = json.loads((root / spec["readback_schema"]).read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(
            schema, format_checker=Draft202012Validator.FORMAT_CHECKER
        )
        valid = {
            "ready": False,
            "pending": 0,
            "partial": 0,
            "oldest_seconds": 0,
            "dead_letter": None,
            "sampled_at": None,
            "reasons": ["DEAD_LETTER_EVIDENCE_UNAVAILABLE"],
            "provider_effects_enabled": False,
        }
        if not validator.is_valid(valid):
            errors.append("readback schema rejects missing evidence")
        for change in (
            {"ready": True},
            {"tenant_id": "sensitive"},
            {"provider_effects_enabled": True},
            {"pending": -1},
            {"reasons": ["arbitrary"]},
        ):
            if validator.is_valid({**valid, **change}):
                errors.append("readback schema permits unsafe evidence")
        api = json.loads((root / spec["openapi"]).read_text())
        if (
            api.get("x-runtime-route-enabled") is not False
            or api.get("x-public") is not False
        ):
            errors.append("OpenAPI must not activate a public or runtime route")
        if api.get("security") != [{"monitoringBearer": []}]:
            errors.append("OpenAPI monitoring authentication missing")
        if set(api["paths"]) != {"/internal/mcr/delivery-readback"}:
            errors.append("unexpected readback paths")
        rules = yaml.safe_load((root / spec["alerts"]).read_text())["groups"][0][
            "rules"
        ]
        if {rule["alert"] for rule in rules} != {
            "MCRDeadLetterEvidenceUnavailable",
            "MCRProjectionLagHigh",
            "MCRProjectionIncomplete",
            "MCRReplaySpike",
            "MCRReadbackUnavailable",
            "MCRDeliveryNegativeSignal",
        }:
            errors.append("missing MCR alert coverage")
        for rule in rules:
            if (
                not rule.get("for")
                or rule["annotations"].get("runbook") != spec["runbook"]
            ):
                errors.append("alert requires duration and runbook")
        missing = next(
            rule
            for rule in rules
            if rule["alert"] == "MCRDeadLetterEvidenceUnavailable"
        )
        if "absent(codestra_mcr_dead_letter_evidence_available)" not in missing["expr"]:
            errors.append("missing telemetry must alert")
        if not (root / spec["runbook"]).is_file():
            errors.append("missing runbook")
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        errors.append(f"invalid MCR observability contract: {type(exc).__name__}")
    return errors


if __name__ == "__main__":
    findings = validate()
    for finding in findings:
        print(finding, file=sys.stderr)
    if not findings:
        print("MCR observability contracts valid")
    raise SystemExit(bool(findings))
