#!/usr/bin/env python3
"""Validate finite production authority without weakening staging authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
FIELDS = {
    "schema_version", "company", "authority_id", "role", "authorized_identity",
    "github_identity", "authority_reference", "approved_scopes", "prohibited_scopes",
    "source_sha", "communications", "issued_utc", "not_before_utc", "expires_utc",
    "approving_authority", "signature_method", "signature_key_id",
    "detached_signature_path", "document_sha256",
}
SCOPES = {
    "server_a_production_release", "production_deployment",
    "external_delivery_synthetic_only",
}
COMMUNICATIONS = {"calls": False, "sms": False, "email": False, "callbacks": False}


class ValidationError(ValueError):
    pass


def canonical_payload(document: dict[str, Any]) -> bytes:
    payload = {key: value for key, value in document.items() if key != "document_sha256"}
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError("timestamp must be RFC3339 UTC")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def validate(document: dict[str, Any], *, source_sha: str, now: datetime | None = None) -> None:
    if set(document) != FIELDS:
        raise ValidationError("authority fields do not match production contract")
    if document["schema_version"] != "codestra.security-owner.production-authority.v1":
        raise ValidationError("unsupported authority schema")
    if document["company"] != "Codestra LLC" or document["role"] != "Security Owner":
        raise ValidationError("company or role mismatch")
    if document["source_sha"] != source_sha or not SHA.fullmatch(source_sha):
        raise ValidationError("source SHA binding mismatch")
    if set(document["approved_scopes"]) != SCOPES:
        raise ValidationError("production scopes are incomplete")
    prohibited = document["prohibited_scopes"]
    if not isinstance(prohibited, list) or {"production_deployment", "external_delivery"} & set(prohibited):
        raise ValidationError("approved production scope is prohibited")
    if document["communications"] != COMMUNICATIONS:
        raise ValidationError("communications must remain disabled")
    if document["authorized_identity"] != f"https://github.com/{document['github_identity']}":
        raise ValidationError("authorized identity mismatch")
    if document["signature_method"] != "sigstore-keyless-oidc":
        raise ValidationError("signature method mismatch")
    if document["signature_key_id"] != "https://token.actions.githubusercontent.com":
        raise ValidationError("OIDC issuer mismatch")
    if document["detached_signature_path"] != "security-owner-authority.sigstore.json":
        raise ValidationError("signature path mismatch")
    issued, not_before, expires = map(parse_time, (
        document["issued_utc"], document["not_before_utc"], document["expires_utc"]
    ))
    current = now or datetime.now(timezone.utc)  # noqa: UP017
    if issued > current or not_before > current or expires <= current:
        raise ValidationError("authority is not currently active")
    if expires <= not_before or (expires - not_before).total_seconds() > 7 * 86400:
        raise ValidationError("authority must have a positive validity of at most seven days")
    expected = hashlib.sha256(canonical_payload(document)).hexdigest()
    if document["document_sha256"] != expected:
        raise ValidationError("authority document checksum mismatch")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    try:
        value = json.loads(args.authority.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValidationError("authority must be an object")
        validate(value, source_sha=args.source_sha)
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        raise SystemExit(f"production authority validation failed: {exc}") from exc
    print("PRODUCTION_AUTHORITY_VALIDATION_GATE=PASS")


if __name__ == "__main__":
    main()
