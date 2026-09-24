#!/usr/bin/env python3
"""Validate a finite, staging-only Security Owner authority document."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

REQUIRED = {
    "company", "authority_id", "role", "authorized_identity", "github_identity",
    "authority_reference", "approved_scopes", "prohibited_scopes", "issued_utc",
    "not_before_utc", "expires_utc", "approving_authority", "signature_method",
    "signature_key_id", "detached_signature_path", "document_sha256",
}
PROHIBITED = {
    "production_deployment", "production_activation", "canary_activation",
    "server_b_access", "customer_data", "unrestricted_n8n_activation",
    "external_delivery",
}
PLACEHOLDER = re.compile(r"(?:<[^>]+>|\\b(?:unknown|placeholder|tbd|todo|pending)\\b)", re.IGNORECASE)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"security owner authority validation failed: {message}")


def canonical_payload(document: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in document.items() if key != "document_sha256"}
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        fail(f"{field} must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")  # noqa: FURB162
    except ValueError as exc:
        fail(f"invalid {field}: {exc}")


def validate(document: dict[str, Any], *, now: datetime) -> None:
    if set(document) != REQUIRED:
        fail("document fields do not match the authority contract")
    if document["company"] != "Codestra LLC" or document["role"] != "Security Owner":
        fail("company or role mismatch")
    if document["authorized_identity"] != f"https://github.com/{document['github_identity']}":
        fail("authorized and GitHub identities differ")
    if any(not isinstance(value, str) or not value or PLACEHOLDER.search(value) for key, value in document.items() if isinstance(value, str) and key != "document_sha256"):
        fail("blank or placeholder authority value")
    if document["approved_scopes"] != ["server_a_isolated_staging"]:
        fail("authority grants an unapproved scope")
    if set(document["prohibited_scopes"]) != PROHIBITED:
        fail("prohibited scope set is incomplete")
    if document["signature_method"] != "sigstore-keyless-oidc":
        fail("unsupported signature method")
    if document["signature_key_id"] != "https://token.actions.githubusercontent.com":
        fail("OIDC issuer mismatch")
    issued = parse_time(document["issued_utc"], "issued_utc")
    not_before = parse_time(document["not_before_utc"], "not_before_utc")
    expires = parse_time(document["expires_utc"], "expires_utc")
    if issued > now or not_before > now or expires <= now or expires <= not_before:
        fail("authority validity window is not currently finite and active")
    expected = hashlib.sha256(canonical_payload(document)).hexdigest()
    if document["document_sha256"] != expected:
        fail("document checksum mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args()
    raw = args.authority.read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict):
        fail("authority must be a JSON object")
    if args.expected_sha256 and hashlib.sha256(raw).hexdigest() != args.expected_sha256:
        fail("exact authority file checksum mismatch")
    validate(document, now=datetime.now(timezone.utc))  # noqa: UP017


if __name__ == "__main__":
    main()
