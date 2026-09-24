#!/usr/bin/env python3
"""Validate every manifest file and cross-file invariant; incomplete means failure."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = {
    "service.yaml", "observability.yaml", "dependencies.yaml", "permissions.yaml",
    "integration.yaml", "slo.yaml", "runbook.md",
}
KNOWN_DEPENDENCIES = {
    "alertmanager", "alloy", "caddy", "grafana", "keycloak", "kong", "loki",
    "middleware", "n8n", "odoo", "openbao", "postgres", "prometheus", "redis",
    "superset", "tempo", "telemetry", "vicidial",
}


class UniqueLoader(yaml.SafeLoader):
    """Duplicate YAML fields must not silently override a reviewed safety value."""


def unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in values:
            raise ValueError("duplicate or non-string YAML field")
        values[key] = loader.construct_object(value_node, deep=deep)
    return values


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def validate(manifest: Path, schema_path: Path) -> list[str]:
    directory = manifest.parent
    for name in REQUIRED_FILES:
        file = directory / name
        if not file.is_file() or file.is_symlink() or not file.read_text(encoding="utf-8").strip():
            raise ValueError(f"{name}: nonempty regular file required")
    documents: dict[str, Any] = {}
    for name in sorted(REQUIRED_FILES - {"runbook.md"}):
        documents[name] = yaml.load((directory / name).read_text(encoding="utf-8"), Loader=UniqueLoader)
    # JSON canonicalizability also rejects YAML dates, bytes and NaN/Infinity.
    json.dumps(documents, allow_nan=False)
    service = documents.pop("service.yaml")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    bundle_schema = json.loads((schema_path.parent / "service-bundle.v1.schema.json").read_text(encoding="utf-8"))
    errors: list[str] = []
    for name, value, contract in (("service.yaml", service, schema), ("bundle", documents, bundle_schema)):
        Draft202012Validator.check_schema(contract)
        for error in Draft202012Validator(contract, format_checker=FormatChecker()).iter_errors(value):
            location = ".".join(map(str, error.absolute_path)) or "$"
            # Field locations, never potentially secret rejected values.
            errors.append(f"{name}:{location}: invalid {error.validator}")
    if errors:
        return sorted(errors)
    spec = service["spec"]
    ids = [item["id"] for item in documents["dependencies.yaml"]["items"]]
    if len(ids) != len(set(ids)) or set(ids) != set(spec["dependencies"]) or set(ids) - KNOWN_DEPENDENCIES:
        errors.append("dependencies.yaml: unique dependencies must equal service.yaml")
    # This repository's integration runtime requires all three for safe admission.
    if service["metadata"]["name"] == "middleware-integration-api":
        requirements = {item["id"]: item["requiredForReadiness"] for item in documents["dependencies.yaml"]["items"]}
        if not all(requirements.get(key) is True for key in ("postgres", "redis", "keycloak")):
            errors.append("dependencies.yaml: integration readiness requires postgres, redis and keycloak")
        if spec["ingress"]["authentication"] != "keycloak":
            errors.append("service.yaml: integration authentication must use Keycloak")
    if documents["observability.yaml"]["metrics"]["path"] != spec["contracts"]["metrics"]:
        errors.append("observability.yaml: metrics path differs from service contract")
    if documents["slo.yaml"]["profile"] != spec["sloProfile"]:
        errors.append("slo.yaml: profile differs from service contract")
    runbook = (directory / "runbook.md").read_text(encoding="utf-8").lower()
    if not all(word in runbook for word in ("rollback", "owner:", "approval", "digest")):
        errors.append("runbook.md: owner, approval, immutable digest and rollback are required")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=ROOT / ".codestra/service.yaml")
    parser.add_argument("--schema", type=Path, default=ROOT / "contracts/platform/service.v1.schema.json")
    args = parser.parse_args()
    try:
        errors = validate(args.manifest, args.schema)
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        print("MANIFEST_VALID=FAIL unreadable, incomplete or malformed contract")
        return 1
    if errors:
        print("MANIFEST_VALID=FAIL\n" + "\n".join(errors))
        return 1
    print("MANIFEST_VALID=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
