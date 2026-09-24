#!/usr/bin/env python3
"""Compare checksum-bound observations with an explicit expected runtime inventory.

This offline report cannot authorize deployment or certify runtime acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
IMAGE = re.compile(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")


class InventoryError(ValueError):
    pass


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise InventoryError("observation timestamp must be a string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InventoryError("invalid observation timestamp") from exc
    if result.utcoffset() is None:
        raise InventoryError("observation timestamp requires a timezone")
    return result.astimezone(timezone.utc)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError("duplicate JSON member")
        result[key] = value
    return result


def load_bound(path: Path, digest: str) -> dict[str, Any]:
    if not DIGEST.fullmatch(digest):
        raise InventoryError("expected file checksum must be sha256:<64 lowercase hex>")
    raw = path.read_bytes()
    if len(raw) > 16 * 1024 * 1024:
        raise InventoryError("inventory exceeds 16 MiB")
    if hashlib.sha256(raw).hexdigest() != digest.removeprefix("sha256:"):
        raise InventoryError("inventory checksum mismatch")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict):
        raise InventoryError("inventory must be a JSON object")
    return value


def index_rows(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise InventoryError("workloads must be a nonempty array")
    result = {}
    for row in value:
        if not isinstance(row, dict):
            raise InventoryError("workload must be an object")
        name = row.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", name):
            raise InventoryError("invalid workload name")
        if name in result:
            raise InventoryError("duplicate workload name")
        result[name] = row
    return result


def reconcile(
    observation: dict[str, Any], expected: dict[str, Any], *, now: datetime,
    max_age: timedelta = timedelta(hours=1),
) -> dict[str, Any]:
    if now.utcoffset() is None or max_age <= timedelta(0):
        raise InventoryError("a timezone-aware clock and positive maximum age are required")
    if expected.get("schema_version") != "1.0":
        raise InventoryError("unsupported expected inventory schema")
    expected_rows = index_rows(expected.get("workloads"))
    actual_rows = index_rows(observation.get("workloads"))
    captured = timestamp(observation.get("observed_at"))
    if captured > now:
        raise InventoryError("observation is in the future")
    stale = now - captured > max_age
    for row in expected_rows.values():
        if set(row) != {"name", "source_repository", "source_revision", "image_reference"}:
            raise InventoryError("expected workloads require exactly name, repository, revision and image")
        repository = row["source_repository"]
        if not isinstance(repository, str) or not re.fullmatch(
            r"https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository
        ):
            raise InventoryError("expected workload requires explicit repository ownership")
        if not isinstance(row["source_revision"], str) or not SHA.fullmatch(row["source_revision"]):
            raise InventoryError("expected source revision must be an exact commit")
        if not isinstance(row["image_reference"], str) or not IMAGE.fullmatch(row["image_reference"]):
            raise InventoryError("expected image must be immutable")
    rows = []
    for name in sorted(actual_rows.keys() | expected_rows.keys()):
        actual = actual_rows.get(name)
        wanted = expected_rows.get(name)
        reasons = []
        classification = "CURRENT"
        if actual is None:
            classification = "REQUIRES_RUNTIME_READBACK"
            reasons.append("expected_workload_missing")
        elif wanted is None:
            classification = "UNKNOWN"
            reasons.append("workload_has_no_expected_owner_binding")
        else:
            for key in ("source_repository", "source_revision", "image_reference"):
                if actual.get(key) != wanted[key]:
                    reasons.append(f"{key}_mismatch")
            reference = actual.get("image_reference")
            if not isinstance(reference, str) or not IMAGE.fullmatch(reference):
                reasons.append("mutable_or_invalid_image_reference")
            if actual.get("status") != "running":
                reasons.append("workload_not_running")
            if actual.get("health") != "healthy":
                reasons.append("health_not_proven")
            if reasons:
                classification = "REQUIRES_RUNTIME_READBACK"
        if stale:
            classification = "HISTORICAL"
            reasons.append("observation_expired")
        rows.append({"name": name, "classification": classification, "blockers": reasons})
    return {
        "schema_version": "1.0", "observed_at": captured.isoformat(),
        "evaluated_at": now.astimezone(timezone.utc).isoformat(),
        "expected_count": len(expected_rows), "observed_count": len(actual_rows),
        "inventory_matches": all(not row["blockers"] for row in rows),
        "runtime_certified": False, "deployment_authorized": False,
        "workloads": rows,
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(report, handle, indent=2, allow_nan=False)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--expected", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-age-seconds", type=int, default=3600)
    args = parser.parse_args()
    if args.output.resolve() in {args.inventory.resolve(), args.expected.resolve()}:
        parser.exit(2, "Output must not overwrite an input inventory\n")
    try:
        report = reconcile(
            load_bound(args.inventory, args.inventory_sha256),
            load_bound(args.expected, args.expected_sha256),
            now=datetime.now(timezone.utc), max_age=timedelta(seconds=args.max_age_seconds),
        )
        report["inventory_sha256"] = args.inventory_sha256
        report["expected_sha256"] = args.expected_sha256
        write_report(args.output, report)
    except (InventoryError, OSError, ValueError):
        # Replace any prior success so a rejected run cannot leave stale PASS evidence.
        try:
            write_report(args.output, {
                "schema_version": "1.0", "inventory_matches": False,
                "runtime_certified": False, "deployment_authorized": False,
                "error": "invalid_inventory_or_io_failure",
            })
        except OSError:
            pass
        parser.exit(2, "Inventory reconciliation rejected; no acceptance evidence produced\n")
    return 0 if report["inventory_matches"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
