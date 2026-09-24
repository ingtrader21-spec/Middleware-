#!/usr/bin/env python3
"""Close bypasses around n8n destinations, tracked-file scanning, and timestamps."""

from __future__ import annotations

import io
import json
import posixpath
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, BinaryIO, Iterator

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "write-boundary-hardening.json"
SCHEMA_PATH = ROOT / "contracts" / "mutation-command.schema.json"
THIS_FILE = Path(__file__).resolve()
LEGACY_VALIDATOR = ROOT / "scripts" / "validate_write_boundary.py"

STRICT_DATETIME_PATTERN = (
    r"^(?:"
    r"(?:(?!0000)[0-9]{4}-(?:"
    r"(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])"
    r"|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)"
    r"|02-(?:0[1-9]|1[0-9]|2[0-8])"
    r"))"
    r"|(?:(?!0000)(?:"
    r"[0-9]{2}(?:0[48]|[2468][048]|[13579][26])"
    r"|(?:[02468][048]|[13579][26])00"
    r")-02-29)"
    r")"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,9})?"
    r"(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))$"
)

APPROVED_PATH_PREFIXES = {
    "/v1/commands",
    "/v1/queries",
    "/v1/triggers",
}

APPROVED_N8N_NODE_TYPES = {
    "n8n-nodes-base.aggregate",
    "n8n-nodes-base.dateTime",
    "n8n-nodes-base.filter",
    "n8n-nodes-base.httpRequest",
    "n8n-nodes-base.if",
    "n8n-nodes-base.itemLists",
    "n8n-nodes-base.limit",
    "n8n-nodes-base.manualTrigger",
    "n8n-nodes-base.merge",
    "n8n-nodes-base.noOp",
    "n8n-nodes-base.removeDuplicates",
    "n8n-nodes-base.respondToWebhook",
    "n8n-nodes-base.scheduleTrigger",
    "n8n-nodes-base.set",
    "n8n-nodes-base.sort",
    "n8n-nodes-base.splitInBatches",
    "n8n-nodes-base.stopAndError",
    "n8n-nodes-base.switch",
    "n8n-nodes-base.wait",
    "n8n-nodes-base.webhook",
}

ODOO_CREDENTIAL_BYTES_RE = re.compile(
    rb"\b(?:"
    rb"ODOO_(?:DB|DATABASE|POSTGRES)_(?:HOST|PORT|NAME|USER|PASSWORD)"
    rb"|ODOO_(?:DATABASE_URL|PG_DSN|PGHOST|PGPORT|PGDATABASE|PGUSER|PGPASSWORD)"
    rb")\b",
    re.IGNORECASE,
)

EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}

BINARY_SUFFIXES = {
    ".aof",
    ".backup",
    ".dump",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".pyc",
    ".rdb",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".webp",
    ".zip",
}

CHUNK_SIZE = 64 * 1024
OVERLAP_SIZE = 512


def load_object(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load {path.relative_to(ROOT)}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{path.relative_to(ROOT)} root must be an object")
        return None
    return value


def string_set(value: Any, location: str, errors: list[str]) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{location} must be an array of strings")
        return set()
    if len(value) != len(set(value)):
        errors.append(f"{location} contains duplicates")
    return set(value)


def validate_policy(policy: dict[str, Any], errors: list[str]) -> None:
    if policy.get("version") != 1:
        errors.append("hardening policy version must be 1")

    scan = policy.get("tracked_file_scan")
    if not isinstance(scan, dict):
        errors.append("tracked_file_scan must be an object")
        scan = {}
    if scan.get("tracked_files_only") is not True:
        errors.append("tracked_file_scan.tracked_files_only must be true")
    if scan.get("size_exemptions_allowed") is not False:
        errors.append("tracked_file_scan.size_exemptions_allowed must be false")
    if scan.get("streaming_scan_required") is not True:
        errors.append("tracked_file_scan.streaming_scan_required must be true")

    n8n = policy.get("n8n")
    if not isinstance(n8n, dict):
        errors.append("n8n must be an object")
        n8n = {}
    if n8n.get("base_expression") != "{{$env.MIDDLEWARE_BASE_URL}}":
        errors.append("n8n.base_expression must be {{$env.MIDDLEWARE_BASE_URL}}")
    prefixes = string_set(
        n8n.get("approved_path_prefixes"),
        "n8n.approved_path_prefixes",
        errors,
    )
    if prefixes != APPROVED_PATH_PREFIXES:
        errors.append("n8n approved path prefixes do not match the reviewed allowlist")
    node_types = string_set(
        n8n.get("approved_node_types"),
        "n8n.approved_node_types",
        errors,
    )
    if node_types != APPROVED_N8N_NODE_TYPES:
        errors.append("n8n approved node types do not match the reviewed allowlist")
    for key in (
        "paths_must_be_static",
        "paths_must_be_canonical",
        "webhook_authentication_required",
    ):
        if n8n.get(key) is not True:
            errors.append(f"n8n.{key} must be true")
    for key in (
        "dot_segments_allowed",
        "percent_encoded_paths_allowed",
        "repeated_slashes_allowed",
        "backslashes_allowed",
    ):
        if n8n.get(key) is not False:
            errors.append(f"n8n.{key} must be false")
    if n8n.get("webhook_path_prefix") != "middleware/":
        errors.append("n8n.webhook_path_prefix must be middleware/")

    timestamp = policy.get("timestamp")
    if not isinstance(timestamp, dict):
        errors.append("timestamp must be an object")
        timestamp = {}
    if timestamp.get("calendar_validity_required") is not True:
        errors.append("timestamp.calendar_validity_required must be true")
    if timestamp.get("year_zero_allowed") is not False:
        errors.append("timestamp.year_zero_allowed must be false")
    if (
        timestamp.get("strict_pattern_location")
        != "properties.requested_at.allOf[0].pattern"
    ):
        errors.append("timestamp strict_pattern_location is not canonical")


def validate_schema(schema: dict[str, Any], errors: list[str]) -> None:
    properties = schema.get("properties")
    requested_at = properties.get("requested_at") if isinstance(properties, dict) else None
    if not isinstance(requested_at, dict):
        errors.append("mutation schema requested_at must be an object")
        return

    all_of = requested_at.get("allOf")
    if (
        not isinstance(all_of, list)
        or len(all_of) != 1
        or not isinstance(all_of[0], dict)
    ):
        errors.append("requested_at must contain exactly one strict allOf assertion")
        return
    if all_of[0].get("pattern") != STRICT_DATETIME_PATTERN:
        errors.append("requested_at strict calendar-valid pattern is missing or changed")
        return

    try:
        compiled = re.compile(STRICT_DATETIME_PATTERN)
    except re.error as exc:
        errors.append(f"strict date-time pattern is invalid: {exc}")
        return

    valid = (
        "2026-08-26T18:45:30Z",
        "2024-02-29T00:00:00Z",
        "2000-02-29T23:59:59.123456789+14:00",
        "2026-04-30T23:59:59-04:00",
    )
    invalid = (
        "2026-02-31T00:00:00Z",
        "2025-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "1900-02-29T00:00:00Z",
        "0000-01-01T00:00:00Z",
        "2026-13-01T00:00:00Z",
    )
    for sample in valid:
        if compiled.fullmatch(sample) is None:
            errors.append(f"strict date-time assertion rejects valid sample {sample!r}")
    for sample in invalid:
        if compiled.fullmatch(sample) is not None:
            errors.append(f"strict date-time assertion accepts invalid sample {sample!r}")


def iter_tracked_files(errors: list[str]) -> Iterator[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        errors.append(f"cannot list tracked repository files: {exc}")
        return

    root = ROOT.resolve()
    excluded_files = {THIS_FILE, LEGACY_VALIDATOR.resolve()}
    for raw_name in result.stdout.split(b"\0"):
        if not raw_name:
            continue
        relative = Path(raw_name.decode("utf-8", errors="surrogateescape"))
        path = ROOT / relative
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            errors.append(f"tracked path escapes repository root: {relative}: {exc}")
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if resolved in excluded_files:
            continue
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        if (
            "tests" in relative.parts
            and "fixtures" in relative.parts
            and "negative" in relative.parts
        ):
            continue
        yield path


def stream_contains_pattern(
    stream: BinaryIO,
    pattern: re.Pattern[bytes],
    *,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = OVERLAP_SIZE,
) -> bool:
    if chunk_size <= overlap:
        raise ValueError("chunk_size must be larger than overlap")

    tail = b""
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            return pattern.search(tail) is not None

        buffer = tail + chunk
        safe_end = max(0, len(buffer) - overlap)
        for match in pattern.finditer(buffer):
            if match.end() <= safe_end:
                return True
        tail = buffer[-overlap:]


def validate_credentials(files: tuple[Path, ...], errors: list[str]) -> None:
    for path in files:
        try:
            with path.open("rb") as stream:
                found = stream_contains_pattern(stream, ODOO_CREDENTIAL_BYTES_RE)
        except OSError as exc:
            errors.append(f"cannot inspect {path.relative_to(ROOT)}: {exc}")
            continue
        if found:
            errors.append(
                "direct Odoo database credential reference is forbidden: "
                f"{path.relative_to(ROOT)}"
            )


def walk_json(value: Any) -> Iterator[Any]:
    yield value
    if isinstance(value, dict):
        for nested in value.values():
            yield from walk_json(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_json(nested)


def http_url_error(url: Any) -> str | None:
    if not isinstance(url, str):
        return "URL must be a string expression rooted at MIDDLEWARE_BASE_URL"

    compact = re.sub(r"\s+", "", url)
    match = re.fullmatch(
        r"=?\{\{\$env\.MIDDLEWARE_BASE_URL\}\}"
        r"(?P<path>/[^?#]*)?"
        r"(?P<query>\?[^#]*)?"
        r"(?P<fragment>#.*)?",
        compact,
    )
    if match is None:
        return "URL must start with {{$env.MIDDLEWARE_BASE_URL}}"
    if match.group("fragment") is not None:
        return "URL fragments are forbidden"

    path = match.group("path") or ""
    if not path:
        return "URL path must use an approved Middleware endpoint"
    if "{{" in path or "}}" in path:
        return "URL path must be static; dynamic path expressions are forbidden"
    if "%" in path:
        return "percent-encoded URL paths are forbidden"
    if "\\" in path:
        return "backslashes are forbidden in URL paths"
    if "//" in path:
        return "repeated slashes are forbidden in URL paths"

    segments = path.strip("/").split("/")
    if any(segment in {".", "..", ""} for segment in segments):
        return "URL path contains forbidden empty or traversal segments"

    canonical = posixpath.normpath(path)
    if canonical != path.rstrip("/"):
        return "URL path must already be canonical"
    if not any(
        canonical == prefix or canonical.startswith(prefix + "/")
        for prefix in APPROVED_PATH_PREFIXES
    ):
        return "URL path must use an approved Middleware command/query/trigger prefix"
    return None


def webhook_error(parameters: Any) -> str | None:
    if not isinstance(parameters, dict):
        return "webhook node has no parameters object"

    authentication = parameters.get("authentication")
    if (
        not isinstance(authentication, str)
        or authentication.strip().lower() in {"", "none"}
    ):
        return "webhook nodes must use an explicit authentication mode"

    path = parameters.get("path")
    if not isinstance(path, str):
        return "webhook path must be a static string"
    if "{{" in path or "}}" in path or "%" in path or "\\" in path:
        return "webhook path must be static, unencoded, and slash-safe"
    if "//" in path or not path.startswith("middleware/"):
        return "webhook path must use the middleware/ namespace without repeated slashes"
    if any(
        not segment
        or segment in {".", ".."}
        or re.fullmatch(r"[a-z0-9][a-z0-9_-]*", segment) is None
        for segment in path.split("/")
    ):
        return "webhook path contains an invalid or traversal segment"
    return None


def validate_workflows(files: tuple[Path, ...], errors: list[str]) -> None:
    for path in files:
        if path.suffix.lower() != ".json":
            continue
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            errors.append(f"cannot read JSON file {path.relative_to(ROOT)}: {exc}")
            continue

        appears_n8n = "n8n-nodes-" in raw
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            if appears_n8n or any(
                part in {"n8n", "workflows"} for part in path.relative_to(ROOT).parts
            ):
                errors.append(f"cannot parse n8n workflow {path.relative_to(ROOT)}: {exc}")
            continue

        nodes = [
            item
            for item in walk_json(value)
            if isinstance(item, dict)
            and isinstance(item.get("type"), str)
            and item["type"].startswith("n8n-nodes-")
        ]
        for node in nodes:
            node_type = node["type"]
            node_name = (
                node.get("name") if isinstance(node.get("name"), str) else "unnamed"
            )
            if node_type not in APPROVED_N8N_NODE_TYPES:
                errors.append(
                    f"{path.relative_to(ROOT)} node {node_name!r} uses "
                    f"unapproved n8n type {node_type!r}"
                )
                continue

            parameters = node.get("parameters")
            if node_type == "n8n-nodes-base.httpRequest":
                problem = http_url_error(
                    parameters.get("url") if isinstance(parameters, dict) else None
                )
                if problem:
                    errors.append(
                        f"{path.relative_to(ROOT)} HTTP Request node "
                        f"{node_name!r}: {problem}"
                    )
            elif node_type == "n8n-nodes-base.webhook":
                problem = webhook_error(parameters)
                if problem:
                    errors.append(
                        f"{path.relative_to(ROOT)} webhook node "
                        f"{node_name!r}: {problem}"
                    )


def self_test(errors: list[str]) -> None:
    large = io.BytesIO(
        b"x" * (2 * 1024 * 1024 + 257)
        + b"\nODOO_DATABASE_URL=postgresql://example"
    )
    if not stream_contains_pattern(large, ODOO_CREDENTIAL_BYTES_RE):
        errors.append("large tracked-file credential scanner self-test failed")

    approved = (
        "={{ $env.MIDDLEWARE_BASE_URL }}"
        "/v1/commands/odoo/contact-upsert?source=n8n"
    )
    if http_url_error(approved) is not None:
        errors.append("approved Middleware HTTP positive self-test failed")

    unsafe_urls = (
        "https://odoo.example.invalid/web/dataset/call_kw",
        "={{$env.MIDDLEWARE_BASE_URL}}/v1/commands/../../admin",
        "={{$env.MIDDLEWARE_BASE_URL}}/v1/commands/%2e%2e/%2e%2e/admin",
        "={{$env.MIDDLEWARE_BASE_URL}}/v1/commands//admin",
        r"={{$env.MIDDLEWARE_BASE_URL}}/v1/commands\..\admin",
        "={{$env.MIDDLEWARE_BASE_URL}}/v1/commands/{{$json.target}}",
    )
    for unsafe in unsafe_urls:
        if http_url_error(unsafe) is None:
            errors.append(f"unsafe n8n HTTP negative self-test failed for {unsafe!r}")

    if webhook_error(
        {"authentication": "headerAuth", "path": "middleware/campaign/approved"}
    ) is not None:
        errors.append("authenticated Middleware webhook positive self-test failed")
    if webhook_error(
        {"authentication": "none", "path": "middleware/campaign/approved"}
    ) is None:
        errors.append("unauthenticated webhook negative self-test failed")


def main() -> int:
    errors: list[str] = []
    policy = load_object(POLICY_PATH, errors)
    schema = load_object(SCHEMA_PATH, errors)
    if policy is not None:
        validate_policy(policy, errors)
    if schema is not None:
        validate_schema(schema, errors)

    files = tuple(iter_tracked_files(errors))
    validate_credentials(files, errors)
    validate_workflows(files, errors)
    self_test(errors)

    if errors:
        print("Write-boundary hardening validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        "Write-boundary hardening passed: n8n paths are canonical, tracked-file "
        "credential scans have no size exemption, and timestamps reject "
        "impossible calendar dates."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
