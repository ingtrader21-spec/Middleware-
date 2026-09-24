#!/usr/bin/env python3
"""Fail-closed validation for the staging candidate image manifest."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, cast


PLACEHOLDER = re.compile(r"(?:<[^>]+>|\b(?:unknown|placeholder|tbd|todo)\b)", re.IGNORECASE)


def fail(message: str) -> None:
    raise SystemExit(f"candidate image manifest validation failed: {message}")


def load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def validate(args: argparse.Namespace) -> None:
    schema = load_object(args.schema, "schema")
    manifest = load_object(args.manifest, "manifest")
    required = schema.get("required")
    properties = schema.get("properties")
    if schema.get("additionalProperties") is not False or not isinstance(required, list) or not isinstance(properties, dict):
        fail("schema must define required properties and reject additions")
    required = cast(list[str], required)
    properties = cast(dict[str, dict[str, Any]], properties)

    keys = set(manifest)
    missing = set(required) - keys
    additional = keys - set(properties)
    if missing:
        fail(f"missing fields: {','.join(sorted(missing))}")
    if additional:
        fail(f"unapproved fields: {','.join(sorted(additional))}")

    for name, rules in properties.items():
        value = manifest[name]
        if "const" in rules and value != rules["const"]:
            fail(f"{name} does not match schema constant")
        if "enum" in rules and value not in rules["enum"]:
            fail(f"{name} is not an approved schema value")
        expected_type = rules.get("type")
        if expected_type == "string" and not isinstance(value, str):
            fail(f"{name} must be a string")
        if isinstance(value, str):
            if not value or PLACEHOLDER.search(value):
                fail(f"{name} contains a placeholder")
            pattern = rules.get("pattern")
            if pattern and re.search(pattern, value) is None:
                fail(f"{name} does not match schema pattern")

    exact = {
        "company": args.expected_company,
        "repository": args.expected_repository,
        "pr_number": args.expected_pr_number,
        "head_sha": args.expected_head_sha,
        "image_repository": args.expected_image_repository,
        "image_digest": args.expected_image_digest,
    }
    for name, expected in exact.items():
        if manifest[name] != expected:
            fail(f"{name} does not match the expected build identity")
    if "@sha256:" in manifest["image_repository"] or ":" in manifest["image_repository"].split("/")[-1]:
        fail("image_repository must not contain a tag or digest")
    try:
        datetime.fromisoformat(manifest["created_utc"].removesuffix("Z") + "+00:00")
    except ValueError as exc:
        fail(f"created_utc is not RFC3339 UTC: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--expected-company", required=True)
    parser.add_argument("--expected-repository", required=True)
    parser.add_argument("--expected-pr-number", type=int, required=True)
    parser.add_argument("--expected-head-sha", required=True)
    parser.add_argument("--expected-image-repository", required=True)
    parser.add_argument("--expected-image-digest", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    validate(parse_args())
