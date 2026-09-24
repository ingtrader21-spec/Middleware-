#!/usr/bin/env python3
"""Fail-closed validation and generation for the three-component M05 decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

COMPONENTS = {
    "middleware": "ghcr.io/ingtrader21-spec/codestra-middleware",
    "agent-desktop": "ghcr.io/codestra-srl/codestra-agent-desktop",
    "websocket-gateway": "ghcr.io/codestra-srl/codestra-websocket-gateway",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def fail(message: str) -> NoReturn:
    raise ValueError(message)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid or missing JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON object required: {path}")
    return value


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_sum_file(directory: Path, name: str) -> None:
    manifest = directory / name
    if not manifest.is_file():
        fail(f"missing checksum manifest: {manifest}")
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            fail(f"invalid checksum line in {manifest}")
        relative = parts[1].lstrip("* ")
        target = directory / relative
        if not target.is_file() or sha256(target) != parts[0]:
            fail(f"checksum mismatch: {relative}")


def parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        fail(f"{field} must be an RFC3339 timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        fail(f"invalid {field}")


def required_equal(document: dict, field: str, expected: object, context: str) -> None:
    if document.get(field) != expected:
        fail(f"{context} {field} binding mismatch")


def validate_authority(args: argparse.Namespace, now: datetime) -> dict:
    authority = load(args.authority_dir / "security-owner-authority.json")
    verify_sum_file(args.authority_dir, "authority-signing-SHA256SUMS")
    required_equal(authority, "source_sha", args.artifact_source_sha, "authority")
    required_equal(authority, "github_identity", args.authorized_reviewer, "authority")
    if sha256(args.authority_dir / "security-owner-authority.json") != args.production_authority_sha256:
        fail("authority document SHA-256 mismatch")
    if parse_time(authority.get("expires_utc"), "authority expires_utc") <= now:
        fail("expired authority")
    scopes = authority.get("approved_scopes", [])
    if not all(scope in scopes for scope in ("server_a_production_release", "production_deployment", "external_delivery_synthetic_only")):
        fail("authority lacks required synthetic release scopes")
    communications = authority.get("communications")
    if not isinstance(communications, dict) or any(communications.get(key) is not False for key in ("calls", "sms", "email")):
        fail("authority permits production/PSTN or external delivery scope")
    if not (args.authority_dir / "security-owner-authority.sigstore.json").is_file():
        fail("missing authority signature")
    return authority


def validate_component(args: argparse.Namespace, component: str, digest: str, now: datetime) -> tuple[dict, list[dict], int]:
    candidate = args.candidate_root / component
    signing = args.signing_root / component
    verify_sum_file(candidate, "SHA256SUMS")
    verify_sum_file(candidate, "decision-SHA256SUMS")
    verify_sum_file(signing, "signing-SHA256SUMS")
    manifest = load(candidate / "candidate-image-manifest.json")
    summary = load(candidate / "vulnerability-summary.json")
    decision = load(candidate / "security-owner-decision.json")
    provenance = load(candidate / "provenance.json")
    required_equal(manifest, "head_sha", args.artifact_source_sha, component)
    required_equal(manifest, "build_run_id", str(args.candidate_run_id), component)
    required_equal(manifest, "build_run_attempt", str(args.candidate_run_attempt), component)
    required_equal(manifest, "image_repository", COMPONENTS[component], component)
    required_equal(manifest, "image_digest", digest, component)
    if manifest.get("candidate_scope") != "server_a_isolated_staging_candidate":
        fail(f"{component} candidate scope is not the approved isolated Server A scope")
    if (candidate / "image-digest.txt").read_text(encoding="utf-8").strip() != digest:
        fail(f"{component} digest file mismatch")
    if summary.get("critical_count") != 0:
        fail(f"{component} Critical vulnerability count is not zero")
    required_equal(decision, "pr_head_sha", args.artifact_source_sha, component)
    required_equal(decision, "image_repository", COMPONENTS[component], component)
    required_equal(decision, "image_digest", digest, component)
    required_equal(decision, "build_run_id", str(args.candidate_run_id), component)
    required_equal(decision, "build_run_attempt", str(args.candidate_run_attempt), component)
    if decision.get("decision_status") != "pending_security_owner_environment_approval":
        fail(f"{component} security decision state is not eligible")
    exceptions = decision.get("accepted_vulnerabilities", [])
    if not isinstance(exceptions, list):
        fail(f"{component} accepted vulnerabilities must be a list")
    if int(summary.get("high_count", 0)) > 0 and not exceptions:
        fail(f"{component} High findings lack authorized exceptions")
    for exception in exceptions:
        if not isinstance(exception, dict):
            fail(f"{component} invalid vulnerability exception")
        required_equal(exception, "source_sha", args.artifact_source_sha, component)
        required_equal(exception, "image_digest", digest, component)
        if parse_time(exception.get("exception_expires_utc"), "exception expiry") <= now:
            fail(f"{component} expired vulnerability exception")
    subjects = provenance.get("subject", [])
    if not any(
        item.get("name") == COMPONENTS[component]
        and item.get("digest", {}).get("sha256") == digest.removeprefix("sha256:")
        for item in subjects if isinstance(item, dict)
    ):
        fail(f"{component} provenance digest mismatch")
    resolved = provenance.get("predicate", {}).get("buildDefinition", {}).get("resolvedDependencies", [])
    if not any(item.get("digest", {}).get("gitCommit") == args.artifact_source_sha for item in resolved if isinstance(item, dict)):
        fail(f"{component} provenance source SHA mismatch")
    for name in (
        "image-signature.sigstore.json", "sbom-attestation.sigstore.json",
        "provenance-attestation.sigstore.json", "security-owner-decision.sigstore.json",
        "signature-verification.json", "sbom-verification.json", "provenance-verification.json",
    ):
        if not (signing / name).is_file() or (signing / name).stat().st_size == 0:
            fail(f"{component} missing signing evidence {name}")
    return decision, exceptions, int(summary.get("high_count", 0))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-source-sha", required=True)
    parser.add_argument("--m05-workflow-sha", required=True)
    parser.add_argument("--production-authority-run-id", type=int, required=True)
    parser.add_argument("--production-authority-sha256", required=True)
    parser.add_argument("--candidate-run-id", type=int, required=True)
    parser.add_argument("--candidate-run-attempt", type=int, required=True)
    parser.add_argument("--signing-run-id", type=int, required=True)
    parser.add_argument("--signing-run-attempt", type=int, required=True)
    parser.add_argument("--middleware-digest", required=True)
    parser.add_argument("--agent-desktop-digest", required=True)
    parser.add_argument("--websocket-gateway-digest", required=True)
    parser.add_argument("--authority-dir", type=Path, required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--signing-root", type=Path, required=True)
    parser.add_argument("--authorized-reviewer", default="kazan555")
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    if not SHA_RE.fullmatch(args.artifact_source_sha) or not SHA_RE.fullmatch(args.m05_workflow_sha):
        fail("exact artifact and workflow SHAs are required")
    digests = {
        "middleware": args.middleware_digest,
        "agent-desktop": args.agent_desktop_digest,
        "websocket-gateway": args.websocket_gateway_digest,
    }
    if any(not DIGEST_RE.fullmatch(value) for value in digests.values()):
        fail("all release identities must be immutable sha256 digests")
    expires = parse_time(args.expires_at, "release expiry")
    if expires <= now:
        fail("release decision expiry must be in the future")
    authority = validate_authority(args, now)
    accepted: list[dict] = []
    high_total = 0
    for component, digest in digests.items():
        _, exceptions, high_count = validate_component(args, component, digest, now)
        accepted.extend({"component": component, **item} for item in exceptions)
        high_total += high_count
    document = {
        "$schema": "https://codestra.internal/schemas/three-component-production-release-decision.v1.json",
        "schema_version": "codestra.three-component-production-release-decision.v1",
        "decision": "PASS",
        "created_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "artifact_source_sha": args.artifact_source_sha,
        "m05_workflow_sha": args.m05_workflow_sha,
        "authority_run_id": args.production_authority_run_id,
        "authority_artifact_sha256": args.production_authority_sha256,
        "authority_identity": authority["authorized_identity"],
        "candidate_run_id": args.candidate_run_id,
        "candidate_run_attempt": args.candidate_run_attempt,
        "signing_run_id": args.signing_run_id,
        "signing_run_attempt": args.signing_run_attempt,
        "components": {key: {"image": COMPONENTS[key], "digest": value, "security_decision": "PASS"} for key, value in digests.items()},
        "critical_findings_total": 0,
        "high_findings_total": high_total,
        "accepted_exceptions": accepted,
        "synthetic_only": True,
        "customer_calls_allowed": False,
        "pstn_calls_allowed": False,
        "live_sms_allowed": False,
        "live_email_allowed": False,
        "deployment_scope": "server_a_exact_digest_test_syn_6101_only",
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"M05 validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
