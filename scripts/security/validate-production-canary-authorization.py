#!/usr/bin/env python3
"""Validate an exact, bounded production telephony canary request."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUEST_KEYS = {
    "schema_version",
    "middleware_repository",
    "pr_number",
    "release_sha",
    "image_digest",
    "deployment_environment",
    "test_campaign",
    "test_agent",
    "test_extension",
    "test_lead",
    "test_list",
    "test_destination",
    "test_disposition",
    "minimum_call_count",
    "maximum_call_count",
    "allowed_call_type",
    "customer_data_allowed",
    "pstn_allowed",
    "valid_from",
    "valid_until",
    "rollback_authority",
    "authorized_flags",
}
ALLOWED_FLAGS = {
    "OUTBOX_PROCESSING_ENABLED",
    "ODOO_RESULT_DELIVERY_ENABLED",
    "N8N_RUNTIME_ENABLED",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED",
    "PRODUCTION_N8N_ENABLED",
}


class ValidationError(ValueError):
    pass


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError("timestamp must be UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValidationError("timestamp is invalid") from exc


def load(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError("request must be an object")
    return value


def validate(
    request: dict[str, Any],
    *,
    repository: str,
    pr_number: int,
    release_sha: str,
    image_digest: str,
    now: datetime | None = None,
) -> None:
    if set(request) != REQUEST_KEYS:
        raise ValidationError("request fields mismatch")
    expected = {
        "schema_version": "codestra.production-canary.authorization.v2",
        "middleware_repository": repository,
        "pr_number": pr_number,
        "release_sha": release_sha,
        "image_digest": image_digest,
        "deployment_environment": "production",
        "test_campaign": "TEST_SYN",
        "test_agent": "webtest001",
        "test_extension": "6101",
        "test_lead": 41,
        "test_list": 9001,
        "test_destination": "6000",
        "test_disposition": "CALLBK",
        "minimum_call_count": 5,
        "maximum_call_count": 10,
        "allowed_call_type": "internal_test_only",
        "customer_data_allowed": False,
        "pstn_allowed": False,
    }
    if any(request.get(key) != value for key, value in expected.items()):
        raise ValidationError("request identity or canary scope mismatch")
    if not SHA.fullmatch(release_sha):
        raise ValidationError("release SHA is invalid")
    if not DIGEST.fullmatch(image_digest):
        raise ValidationError("image digest is invalid")
    start = _time(request["valid_from"])
    expiry = _time(request["valid_until"])
    current = now or datetime.now(timezone.utc)
    if start < current or expiry <= start:
        raise ValidationError("execution window is invalid")
    if (expiry - start).total_seconds() > 3600:
        raise ValidationError("authorization window is too broad")
    rollback_authority = request["rollback_authority"]
    if not isinstance(rollback_authority, str) or not rollback_authority.strip():
        raise ValidationError("rollback authority is invalid")
    flags = request["authorized_flags"]
    if (
        not isinstance(flags, dict)
        or not flags
        or not set(flags).issubset(ALLOWED_FLAGS)
        or any(value is not True for value in flags.values())
    ):
        raise ValidationError("production flags exceed the canary allowlist")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", required=True, type=int)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    args = parser.parse_args()
    validate(
        load(args.request),
        repository=args.repository,
        pr_number=args.pr_number,
        release_sha=args.release_sha,
        image_digest=args.image_digest,
    )
    print("PRODUCTION_CANARY_AUTHORIZATION_REQUEST=PASS")


if __name__ == "__main__":
    main()
