#!/usr/bin/env python3
"""Fail-closed validator for isolated-staging security-owner decisions."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
NEGATIVE_KEYS = {
    "production_deployment_gate", "production_activation_gate", "server_b_access_gate",
    "customer_data_gate", "telephony_access_gate", "recording_access_gate",
    "public_ingress_gate", "n8n_activation_gate", "n8n_binding_gate",
}
REQUEST_KEYS = {
    "schema_version", "request_type", "repository", "pr_number", "pr_head_sha",
    "middleware_main_sha", "odoo_main_sha", "created_at_utc", "requested_expiration_utc",
    "approved_scope", "image_manifest_sha256", "image_digests", "vulnerability_findings",
    "compensating_controls", "odoo_isolation_evidence", "middleware_isolation_evidence",
    "limitations", "negative_authorizations", "revocation_conditions",
}
DECISION_KEYS = {
    "schema_version", "decision_status", "decision_request_sha256", "repository",
    "pr_number", "pr_head_sha", "middleware_main_sha", "odoo_main_sha", "approved_scope",
    "approved_image_digests", "accepted_vulnerability_findings",
    "compensating_controls_sha256", "odoo_isolation_evidence_sha256",
    "middleware_isolation_evidence_sha256", "security_owner_approver_login",
    "security_owner_authority_reference", "environment_name", "environment_approval_record_id",
    "workflow_repository", "workflow_path", "workflow_ref", "workflow_sha", "workflow_run_id",
    "workflow_run_attempt", "signed_at_utc", "expires_at_utc", "negative_authorizations",
    "revocation_conditions", "image_manifest_sha256",
}


class ValidationError(ValueError):
    pass


def load_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError("document must be an object")
    return value


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError("timestamp must be UTC and end in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")  # noqa: FURB162
    except ValueError as exc:
        raise ValidationError("invalid timestamp") from exc


def exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValidationError(f"{label} fields mismatch")


def validate_negative(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != NEGATIVE_KEYS:
        raise ValidationError("negative authorizations are incomplete")
    if any(gate != "blocked" for gate in value.values()):
        raise ValidationError("all negative authorizations must be blocked")


def validate_request(
    request: dict[str, Any], manifest: dict[str, Any], *, repository: str, pr_number: int,
    pr_head: str, now: datetime | None = None,
) -> None:
    exact_keys(request, REQUEST_KEYS, "request")
    if request["schema_version"] != "1.0.0" or request["request_type"] != "security_owner_staging_preparation":
        raise ValidationError("unsupported request schema or type")
    if request["repository"] != repository or request["pr_number"] != pr_number or request["pr_head_sha"] != pr_head:
        raise ValidationError("request identity mismatch")
    for key in ("pr_head_sha", "middleware_main_sha", "odoo_main_sha"):
        if not isinstance(request[key], str) or not SHA.fullmatch(request[key]):
            raise ValidationError(f"invalid {key}")
    if request["approved_scope"] != "server_a_isolated_staging":
        raise ValidationError("scope is not isolated staging")
    created = parse_time(request["created_at_utc"])
    expires = parse_time(request["requested_expiration_utc"])
    current = now or datetime.now(timezone.utc)  # noqa: UP017
    if expires <= current or expires <= created or (expires - created).total_seconds() > 30 * 86400:
        raise ValidationError("request expiry must be future, positive, and at most 30 days")
    if not HASH.fullmatch(str(request["image_manifest_sha256"])):
        raise ValidationError("invalid image manifest hash")
    manifest_hash = sha256_bytes(canonical_bytes(manifest))
    if request["image_manifest_sha256"] != manifest_hash:
        raise ValidationError("image manifest hash mismatch")
    digests = request["image_digests"]
    if not isinstance(digests, dict) or not digests or any(not isinstance(v, str) or not DIGEST.fullmatch(v) for v in digests.values()):
        raise ValidationError("invalid image digests")
    if manifest.get("image_digests") != digests:
        raise ValidationError("manifest digest binding mismatch")
    for key in ("odoo_isolation_evidence", "middleware_isolation_evidence"):
        evidence = request[key]
        if not isinstance(evidence, dict) or set(evidence) != {"gate", "sha256"}:
            raise ValidationError(f"invalid {key}")
        if evidence["gate"] != "PASS" or not HASH.fullmatch(str(evidence["sha256"])):
            raise ValidationError(f"unproven {key}")
    if not isinstance(request["compensating_controls"], list) or not request["compensating_controls"]:
        raise ValidationError("missing compensating controls")
    if not isinstance(request["revocation_conditions"], list) or not request["revocation_conditions"]:
        raise ValidationError("missing revocation conditions")
    if not isinstance(request["vulnerability_findings"], list):
        raise ValidationError("invalid vulnerability findings")
    validate_negative(request["negative_authorizations"])


def validate_decision(decision: dict[str, Any], request: dict[str, Any], audit: dict[str, Any]) -> None:
    exact_keys(decision, DECISION_KEYS, "decision")
    if decision["decision_status"] != "approved_for_staging_preparation":
        raise ValidationError("decision is not approved for preparation")
    if decision["decision_request_sha256"] != sha256_bytes(canonical_bytes(request)):
        raise ValidationError("decision request binding mismatch")
    bindings = {
        "repository": "repository", "pr_number": "pr_number", "pr_head_sha": "pr_head_sha",
        "middleware_main_sha": "middleware_main_sha", "odoo_main_sha": "odoo_main_sha",
        "approved_scope": "approved_scope", "approved_image_digests": "image_digests",
        "accepted_vulnerability_findings": "vulnerability_findings",
        "negative_authorizations": "negative_authorizations", "revocation_conditions": "revocation_conditions",
        "image_manifest_sha256": "image_manifest_sha256",
    }
    if any(decision[d] != request[r] for d, r in bindings.items()):
        raise ValidationError("decision content binding mismatch")
    if decision["odoo_isolation_evidence_sha256"] != request["odoo_isolation_evidence"]["sha256"]:
        raise ValidationError("Odoo evidence binding mismatch")
    if decision["middleware_isolation_evidence_sha256"] != request["middleware_isolation_evidence"]["sha256"]:
        raise ValidationError("Middleware evidence binding mismatch")
    expected_controls = sha256_bytes(canonical_bytes(request["compensating_controls"]))
    if decision["compensating_controls_sha256"] != expected_controls:
        raise ValidationError("compensating controls binding mismatch")
    if decision["security_owner_approver_login"] != "kazan555":
        raise ValidationError("unallowlisted security owner")
    if decision["security_owner_authority_reference"] != "SECURITY.md#isolated-staging-security-owner":
        raise ValidationError("authority reference mismatch")
    if decision["environment_name"] != "security-owner-signing":
        raise ValidationError("environment mismatch")
    if decision["workflow_repository"] != "ingtrader21-spec/Middleware-" or decision["workflow_path"] != ".github/workflows/security-owner-decision-sign.yml" or decision["workflow_ref"] != "refs/heads/main":
        raise ValidationError("workflow identity mismatch")
    if audit.get("approver") != "kazan555" or audit.get("self_review") is not False or audit.get("bypass_used") is not False:
        raise ValidationError("invalid environment approval audit")
    signed = parse_time(decision["signed_at_utc"])
    expires = parse_time(decision["expires_at_utc"])
    if expires <= signed or (expires - signed).total_seconds() > 30 * 86400:
        raise ValidationError("decision expiry is invalid")
    validate_negative(decision["negative_authorizations"])


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    request_parser = sub.add_parser("request")
    request_parser.add_argument("--request", required=True)
    request_parser.add_argument("--image-manifest", required=True)
    request_parser.add_argument("--expected-repository", required=True)
    request_parser.add_argument("--expected-pr-number", required=True, type=int)
    request_parser.add_argument("--expected-pr-head", required=True)
    decision_parser = sub.add_parser("decision")
    decision_parser.add_argument("--decision", required=True)
    decision_parser.add_argument("--request", required=True)
    decision_parser.add_argument("--approval-audit", required=True)
    args = parser.parse_args()
    if args.command == "request":
        validate_request(load_json(args.request), load_json(args.image_manifest), repository=args.expected_repository, pr_number=args.expected_pr_number, pr_head=args.expected_pr_head)
    else:
        validate_decision(load_json(args.decision), load_json(args.request), load_json(args.approval_audit))
    print("SECURITY_OWNER_DECISION_VALIDATION_GATE=PASS")


if __name__ == "__main__":
    main()
