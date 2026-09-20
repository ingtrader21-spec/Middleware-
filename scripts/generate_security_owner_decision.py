#!/usr/bin/env python3
"""Generate an unsigned, exact-run Security Owner decision request."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--image-repository")
    parser.add_argument(
        "--signer-identity",
        default="https://github.com/ingtrader21-spec/Middleware-/.github/workflows/staging-candidate-build-sign.yml@refs/heads/main",
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--authority-sha256", required=True)
    parser.add_argument("--authority-run-id", required=True)
    parser.add_argument("--authority-artifact", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--trivy", type=Path, required=True)
    parser.add_argument("--grype", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    authority = json.loads(args.authority.read_text())
    if sha(args.authority) != args.authority_sha256:
        raise SystemExit("authority checksum mismatch")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    pr_number = manifest.get("pr_number")
    if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number < 1:
        raise SystemExit("candidate manifest PR number is invalid")
    if manifest.get("head_sha") != args.source_sha:
        raise SystemExit("candidate manifest source SHA mismatch")
    if manifest.get("image_digest") != args.image_digest:
        raise SystemExit("candidate manifest image digest mismatch")
    if args.image_repository is None:
        args.image_repository = manifest.get("image_repository", "ghcr.io/appolon1908-hue/codestra-middleware")
    if manifest.get("image_repository", args.image_repository) != args.image_repository:
        raise SystemExit("candidate manifest image repository mismatch")
    rows = list(csv.DictReader(args.matrix.open(newline="", encoding="utf-8")))
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for row in rows:
        if row["severity"] not in {"HIGH", "CRITICAL"}:
            continue
        grouped.setdefault((row["vulnerability_id"], row["package"], row["installed_version"]), []).append(row)
    now = datetime.now(timezone.utc).replace(microsecond=0)  # noqa: UP017
    deadline = now + timedelta(days=13)
    expires = now + timedelta(days=14)
    findings = []
    for (vulnerability_id, package, installed_version), matches in sorted(grouped.items()):
        fixed_versions = sorted({version for m in matches for version in m["fixed_versions"].split(";") if version})
        installed_minor = ".".join(installed_version.split(".")[:2]) + "."
        no_compatible_fix = (
            package == "python"
            and installed_minor.count(".") == 2
            and not any(version.lstrip("*").startswith(installed_minor) for version in fixed_versions)
        )
        findings.append({
            "vulnerability_id": vulnerability_id,
            "package": package,
            "installed_version": installed_version,
            "fixed_version": ";".join(fixed_versions) or "none",
            "runtime_paths": sorted({m["package_path"] for m in matches}),
            "scanners": sorted({scanner for m in matches for scanner in m["scanners"].split(";") if scanner}),
            "severity": max((m["severity"] for m in matches), key=lambda value: {"HIGH": 1, "CRITICAL": 2}[value]),
            "image_digest": args.image_digest,
            "source_sha": args.source_sha,
            "upstream_remediation_status": "no_safe_compatible_python_minor_fix_confirmed" if no_compatible_fix else "safe_fix_available_review_required",
            "runtime_reachability": "python_interpreter_and_shared_runtime_present",
            "compensating_controls": [
                "server_a_isolated_staging_only",
                "all_external_delivery_and_activation_gates_blocked",
                "no_production_credentials_or_customer_data",
            ],
            "remediation_owner": "Codestra LLC Middleware Maintainers",
            "remediation_deadline": deadline.isoformat().replace("+00:00", "Z"),
            "exception_expires_utc": expires.isoformat().replace("+00:00", "Z"),
            "revocation_conditions": [
                "safe_compatible_fix_becomes_available",
                "source_or_digest_changes",
                "staging_isolation_control_failure",
            ],
        })
    decision = {
        "$schema": "https://codestra.internal/schemas/security-owner-decision-request.v1.json",
        "decision_version": 1,
        "decision_status": "pending_security_owner_environment_approval",
        "company": "Codestra LLC",
        "repository": "ingtrader21-spec/Middleware-",
        "pr_number": pr_number,
        "pr_head_sha": args.source_sha,
        "image_repository": args.image_repository,
        "image_digest": args.image_digest,
        "candidate_manifest_sha256": sha(args.manifest),
        "matrix_sha256": sha(args.matrix),
        "sbom_sha256": sha(args.sbom),
        "trivy_sha256": sha(args.trivy),
        "grype_sha256": sha(args.grype),
        "provenance_sha256": sha(args.provenance),
        "build_run_id": args.run_id,
        "build_run_attempt": args.run_attempt,
        "approved_scope": "server_a_isolated_staging",
        "authority_reference": authority["authority_id"],
        "authority_document_sha256": args.authority_sha256,
        "authority_run_id": args.authority_run_id,
        "authority_artifact": args.authority_artifact,
        "oidc_issuer": "https://token.actions.githubusercontent.com",
        "signer_identity": args.signer_identity,
        "issued_utc": now.isoformat().replace("+00:00", "Z"),
        "expires_utc": expires.isoformat().replace("+00:00", "Z"),
        "production_deployment_gate": "blocked",
        "production_activation_gate": "blocked",
        "canary_activation_gate": "blocked",
        "server_b_access_gate": "blocked",
        "customer_data_gate": "blocked",
        "n8n_activation_gate": "blocked",
        "external_delivery_gate": "blocked",
        "live_calling_gate": "blocked",
        "email_delivery_gate": "blocked",
        "sms_delivery_gate": "blocked",
        "social_posting_gate": "blocked",
        "accepted_vulnerabilities": findings,
    }
    args.output.write_text(json.dumps(decision, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
