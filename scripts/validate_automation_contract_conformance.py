#!/usr/bin/env python3
"""Strict source-route conformance against the declared automation v2 contract."""

from __future__ import annotations

import ast
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "contracts" / "automation" / "n8n-control-plane.v2.json"
WAIVER_PATH = ROOT / "config" / "automation-conformance-waivers.v1.json"
ROUTE_AUTHORITY_PATH = ROOT / "config" / "route-authority.v1.json"
ADR_PATH = ROOT / "docs" / "decisions" / "ADR-0001-AUTOMATION-CONTRACT-V2.md"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


class ConformanceError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConformanceError(message)


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"{path.relative_to(ROOT)} is not valid JSON") from exc
    require(isinstance(value, dict), f"{path.relative_to(ROOT)} must be an object")
    return value


def literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def discover_routes() -> set[str]:
    discovered: set[str] = set()
    for path in sorted((ROOT / "app").rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError) as exc:
            raise ConformanceError(f"cannot parse {path.relative_to(ROOT)}") from exc

        prefixes: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if not isinstance(value, ast.Call):
                continue
            func = value.func
            if not (
                (isinstance(func, ast.Name) and func.id == "APIRouter")
                or (isinstance(func, ast.Attribute) and func.attr == "APIRouter")
            ):
                continue
            prefix = ""
            for keyword in value.keywords:
                if keyword.arg == "prefix":
                    parsed = literal_string(keyword.value)
                    if parsed is not None:
                        prefix = parsed
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    prefixes[target.id] = prefix

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call) or not decorator.args:
                    continue
                attr = decorator.func
                if not isinstance(attr, ast.Attribute) or attr.attr.lower() not in HTTP_METHODS:
                    continue
                if not isinstance(attr.value, ast.Name):
                    continue
                route_path = literal_string(decorator.args[0])
                if route_path is None:
                    continue
                prefix = prefixes.get(attr.value.id, "")
                full_path = (prefix.rstrip("/") + "/" + route_path.lstrip("/")).replace("//", "/")
                if not full_path.startswith("/"):
                    full_path = "/" + full_path
                discovered.add(f"{attr.attr.upper()} {full_path}")
    return discovered


def validate() -> tuple[int, int]:
    contract = load_object(CONTRACT_PATH)
    require(contract.get("schema_version") == "2.1", "unsupported automation contract schema")
    expected_raw = contract.get("endpoints")
    require(
        isinstance(expected_raw, list)
        and bool(expected_raw)
        and all(isinstance(item, str) for item in expected_raw),
        "automation endpoint contract is invalid",
    )
    assert isinstance(expected_raw, list)
    expected = set(expected_raw)
    require(len(expected) == len(expected_raw), "automation contract contains duplicate endpoints")

    authority = load_object(ROUTE_AUTHORITY_PATH)
    require(
        authority.get("decision") == "middleware_adopts_automation_v2",
        "route decision drift",
    )
    automation = authority.get("automation")
    require(isinstance(automation, dict), "automation route authority is missing")
    assert isinstance(automation, dict)
    require(
        automation.get("canonical_command_submit") == "POST /v2/automation/commands",
        "canonical automation command submit route drift",
    )
    require(
        automation.get("canonical_command_read")
        == "GET /v2/automation/commands/{command_id}",
        "canonical automation command read route drift",
    )
    adr = ADR_PATH.read_text(encoding="utf-8")
    require(
        "Middleware adopts the automation v2 contract" in adr,
        "Option A ADR is missing",
    )
    require("**Status:** Accepted" in adr, "Option A ADR is not accepted")

    discovered = discover_routes()
    missing = expected - discovered

    waiver_document = load_object(WAIVER_PATH)
    require(waiver_document.get("mode") == "strict_expected_gap", "waiver mode must be strict")
    raw_waivers = waiver_document.get("waivers")
    require(isinstance(raw_waivers, list), "waiver registry is invalid")
    assert isinstance(raw_waivers, list)
    waivers: dict[str, dict[str, Any]] = {}
    today = date.today()
    for item in raw_waivers:
        require(isinstance(item, dict), "invalid conformance waiver")
        operation = item.get("operation")
        require(
            isinstance(operation, str) and operation in expected,
            f"unknown waived operation: {operation}",
        )
        require(operation not in waivers, f"duplicate waiver: {operation}")
        require(
            isinstance(item.get("finding"), str) and item["finding"],
            f"{operation}: finding is required",
        )
        require(
            isinstance(item.get("owner"), str) and item["owner"],
            f"{operation}: owner is required",
        )
        try:
            expiry = date.fromisoformat(str(item.get("expires_on")))
        except ValueError as exc:
            raise ConformanceError(f"{operation}: invalid waiver expiry") from exc
        require(expiry >= today, f"{operation}: conformance waiver expired")
        waivers[operation] = item

    undocumented = missing - set(waivers)
    stale = set(waivers) - missing
    require(
        not undocumented,
        "missing routes without strict waiver: " + ", ".join(sorted(undocumented)),
    )
    require(
        not stale,
        "implemented routes retain stale waivers: " + ", ".join(sorted(stale)),
    )

    print(f"AUTOMATION_CONFORMANCE_EXPECTED={len(expected)}")
    print(f"AUTOMATION_CONFORMANCE_IMPLEMENTED={len(expected) - len(missing)}")
    print(f"AUTOMATION_CONFORMANCE_STRICT_XFAIL={len(missing)}")
    for operation in sorted(missing):
        print(f"XFAIL {operation} finding={waivers[operation]['finding']}")
    return len(expected), len(missing)


def main() -> int:
    try:
        expected, missing = validate()
    except ConformanceError as exc:
        print(f"AUTOMATION_CONFORMANCE=FAIL reason={exc}", file=sys.stderr)
        return 1
    print(f"AUTOMATION_CONFORMANCE=PASS expected={expected} strict_xfail={missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
