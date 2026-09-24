#!/usr/bin/env python3
"""Fail closed on cross-run or incomplete Security Owner decision requests."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PLACEHOLDER = re.compile(r"(?:<[^>]+>|\\b(?:unknown|placeholder|tbd|todo)\\b)", re.IGNORECASE)
BLOCKED = [
    "production_deployment_gate", "production_activation_gate", "canary_activation_gate",
    "server_b_access_gate", "customer_data_gate", "n8n_activation_gate",
    "external_delivery_gate", "live_calling_gate", "email_delivery_gate",
    "sms_delivery_gate", "social_posting_gate",
]


def fail(message: str) -> None:
    raise SystemExit(f"security owner decision validation failed: {message}")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        fail(f"{path} must contain an object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("--authority-run-id", required=True)
    parser.add_argument("--authority-artifact", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--grype", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()
    decision, schema, authority = load(args.decision), load(args.schema), load(args.authority)
    required, properties = set(schema["required"]), schema["properties"]
    if schema.get("additionalProperties") is not False or set(decision) != required or set(properties) != required:
        fail("decision fields do not exactly match the schema")
    for field, rules in properties.items():
        if "const" in rules and decision[field] != rules["const"]:
            fail(f"{field} violates schema constant")
        if "enum" in rules and decision[field] not in rules["enum"]:
            fail(f"{field} violates schema enum")
        if isinstance(decision[field], str) and (not decision[field] or PLACEHOLDER.search(decision[field])):
            fail(f"{field} is blank or a placeholder")
    exact = {
        "pr_head_sha": args.source_sha, "image_digest": args.image_digest,
        "build_run_id": args.run_id, "build_run_attempt": args.run_attempt,
        "candidate_manifest_sha256": sha(args.manifest), "matrix_sha256": sha(args.matrix),
        "sbom_sha256": sha(args.sbom), "trivy_sha256": sha(args.trivy),
        "grype_sha256": sha(args.grype), "provenance_sha256": sha(args.provenance),
        "authority_reference": authority["authority_id"],
        "authority_document_sha256": args.authority_sha256,
        "authority_run_id": args.authority_run_id,
        "authority_artifact": args.authority_artifact,
    }
    if sha(args.authority) != args.authority_sha256:
        fail("authority file checksum mismatch")
    for field, value in exact.items():
        if decision[field] != value:
            fail(f"{field} binding mismatch")
    if any(decision[field] != "blocked" for field in BLOCKED):
        fail("an operational boundary is not blocked")
    issued = datetime.fromisoformat(decision["issued_utc"].replace("Z", "+00:00"))  # noqa: FURB162
    expires = datetime.fromisoformat(decision["expires_utc"].replace("Z", "+00:00"))  # noqa: FURB162
    now = datetime.now(timezone.utc)  # noqa: UP017
    if issued > now or expires <= now or expires <= issued:
        fail("decision validity window is invalid")
    rows = list(csv.DictReader(args.matrix.open(newline="", encoding="utf-8")))
    matrix_ids = {row["vulnerability_id"] for row in rows if row["severity"] in {"HIGH", "CRITICAL"}}
    accepted = decision["accepted_vulnerabilities"]
    if not isinstance(accepted, list) or {item.get("vulnerability_id") for item in accepted} != matrix_ids:
        fail("accepted vulnerability set differs from the current matrix")
    for item in accepted:
        if item.get("image_digest") != args.image_digest or item.get("source_sha") != args.source_sha:
            fail("accepted vulnerability identity mismatch")
        if item.get("upstream_remediation_status") != "no_safe_compatible_python_minor_fix_confirmed":
            fail("a finding has a safe fix or still requires remediation evaluation")
        for field in ("package", "installed_version", "runtime_paths", "scanners", "compensating_controls", "remediation_owner", "remediation_deadline", "exception_expires_utc", "revocation_conditions"):
            if not item.get(field):
                fail(f"accepted vulnerability missing {field}")


if __name__ == "__main__":
    main()
