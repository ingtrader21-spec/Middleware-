#!/usr/bin/env python3
"""Validate the sole cross-system write boundary and Odoo ownership contract."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "system-ownership.json"
MUTATION_SCHEMA_PATH = ROOT / "contracts" / "mutation-command.schema.json"
HTTP_CONVENTIONS_PATH = ROOT / "contracts" / "http-conventions.md"
BOUNDARY_DOC_PATH = ROOT / "docs" / "WRITE-BOUNDARY-AND-OWNERSHIP.md"
THIS_FILE = Path(__file__).resolve()

UUID_PATTERN = (
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
DATETIME_PATTERN = (
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T"
    r"(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-](?:(?:0[0-9]|1[0-3]):[0-5][0-9]|14:00))$"
)

REQUIRED_MIDDLEWARE_OWNERSHIP = {
    "service_authorization",
    "tenant_isolation",
    "contract_validation",
    "event_normalization",
    "idempotency",
    "semantic_replay_detection",
    "correlation_ids",
    "signed_webhook_inbox",
    "transactional_outbox",
    "retry_and_backoff",
    "dead_letter_queues",
    "circuit_breakers",
    "consent_and_suppression_checks",
    "provider_adapters",
    "odoo_mappings",
    "n8n_trigger_contracts",
    "telephony_command_records",
    "audit_and_reconciliation",
}

REQUIRED_ODOO_OWNERSHIP = {
    "customers_and_contacts",
    "leads_and_opportunities",
    "activities_and_campaigns",
    "call_history",
    "post_call_forms_and_notes",
    "callbacks_and_appointments",
    "consent_and_communication_preferences",
    "sms_and_email_history",
    "delivery_results",
    "agent_and_supervisor_business_views",
    "business_reporting",
}

REQUIRED_MUTATION_FIELDS = {
    "specversion",
    "command_id",
    "command_type",
    "schema_version",
    "tenant_id",
    "actor",
    "target",
    "operation",
    "requested_at",
    "correlation_id",
    "causation_id",
    "idempotency_key",
    "semantic_fingerprint",
    "policy_context",
    "payload",
}

REQUIRED_MUTATING_CONTROLS = {
    "service_authorization_required": True,
    "tenant_authorization_required": True,
    "contract_validation_required": True,
    "idempotency_required": True,
    "semantic_replay_detection_required": True,
    "correlation_id_required": True,
    "causation_id_required": True,
    "audit_record_required": True,
    "transactional_outbox_for_external_effects": True,
    "durable_inbox_for_callbacks": True,
    "bounded_retry_and_dead_letter_required": True,
    "provider_reconciliation_after_unknown_outcome": True,
    "consent_and_suppression_required_when_applicable": True,
}

REQUIRED_N8N_PATH_PREFIXES = {
    "/v1/commands",
    "/v1/queries",
    "/v1/triggers",
}

FORBIDDEN_N8N_NODE_MARKERS = {
    "n8n-nodes-base.odoo",
    "n8n-nodes-base.postgres",
    "n8n-nodes-base.mySql",
    "n8n-nodes-base.microsoftSql",
    "n8n-nodes-base.twilio",
    "n8n-nodes-base.emailSend",
}

ODOO_DATABASE_CREDENTIAL_RE = re.compile(
    r"\b(?:"
    r"ODOO_(?:DB|DATABASE|POSTGRES)_(?:HOST|PORT|NAME|USER|PASSWORD)"
    r"|ODOO_(?:DATABASE_URL|PG_DSN|PGHOST|PGPORT|PGDATABASE|PGUSER|PGPASSWORD)"
    r")\b",
    re.IGNORECASE,
)

EXCLUDED_SCAN_PARTS = {
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
MAX_TEXT_SCAN_BYTES = 2 * 1024 * 1024


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
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
        errors.append("system ownership policy version must be 1")
    if policy.get("repository_role") != "sole_cross_system_write_boundary":
        errors.append("repository_role must declare the sole cross-system write boundary")
    if policy.get("orchestration_system") != "n8n":
        errors.append("orchestration_system must be n8n")
    if policy.get("business_system_of_record") != "odoo-19":
        errors.append("business_system_of_record must be odoo-19")

    ownership = policy.get("ownership")
    if not isinstance(ownership, dict):
        errors.append("ownership must be an object")
        ownership = {}

    middleware = string_set(ownership.get("middleware"), "ownership.middleware", errors)
    missing_middleware = sorted(REQUIRED_MIDDLEWARE_OWNERSHIP - middleware)
    if missing_middleware:
        errors.append(
            "Middleware ownership is incomplete: " + ", ".join(missing_middleware)
        )

    odoo = string_set(ownership.get("odoo-19"), "ownership.odoo-19", errors)
    missing_odoo = sorted(REQUIRED_ODOO_OWNERSHIP - odoo)
    if missing_odoo:
        errors.append("Odoo ownership is incomplete: " + ", ".join(missing_odoo))

    n8n = string_set(ownership.get("n8n"), "ownership.n8n", errors)
    if "workflow_orchestration" not in n8n:
        errors.append("n8n must own workflow_orchestration")

    mutating = policy.get("mutating_path_requirements")
    if not isinstance(mutating, dict):
        errors.append("mutating_path_requirements must be an object")
        mutating = {}
    if mutating.get("entrypoint") != "middleware":
        errors.append("every mutating path must enter through middleware")
    for key, expected in REQUIRED_MUTATING_CONTROLS.items():
        if mutating.get(key) is not expected:
            errors.append(f"mutating_path_requirements.{key} must be true")

    odoo_policy = policy.get("odoo_write_policy")
    if not isinstance(odoo_policy, dict):
        errors.append("odoo_write_policy must be an object")
        odoo_policy = {}
    interfaces = string_set(
        odoo_policy.get("approved_interfaces"),
        "odoo_write_policy.approved_interfaces",
        errors,
    )
    if interfaces != {"odoo_service_api", "odoo_orm_bridge"}:
        errors.append(
            "approved Odoo interfaces must be exactly odoo_service_api and "
            "odoo_orm_bridge"
        )
    for key in (
        "direct_postgresql_write_allowed",
        "external_service_database_credentials_allowed",
        "generic_model_write_endpoint_allowed",
    ):
        if odoo_policy.get(key) is not False:
            errors.append(f"odoo_write_policy.{key} must be false")
    for key in (
        "service_identity_required",
        "tenant_mapping_required",
        "idempotency_required",
    ):
        if odoo_policy.get(key) is not True:
            errors.append(f"odoo_write_policy.{key} must be true")

    n8n_policy = policy.get("n8n_policy")
    if not isinstance(n8n_policy, dict):
        errors.append("n8n_policy must be an object")
        n8n_policy = {}
    if n8n_policy.get("owns_orchestration_only") is not True:
        errors.append("n8n must own orchestration only")
    if (
        n8n_policy.get(
            "direct_mutating_calls_to_business_or_provider_systems_allowed"
        )
        is not False
    ):
        errors.append("n8n direct mutating calls must be forbidden")
    if n8n_policy.get("http_request_nodes_must_target_middleware") is not True:
        errors.append("n8n HTTP Request nodes must target Middleware")
    if n8n_policy.get("approved_http_base_variable") != "MIDDLEWARE_BASE_URL":
        errors.append("n8n approved HTTP base variable must be MIDDLEWARE_BASE_URL")
    approved_paths = string_set(
        n8n_policy.get("approved_http_path_prefixes"),
        "n8n_policy.approved_http_path_prefixes",
        errors,
    )
    if approved_paths != REQUIRED_N8N_PATH_PREFIXES:
        errors.append(
            "n8n approved HTTP paths must be exactly /v1/commands, "
            "/v1/queries, and /v1/triggers"
        )

    forbidden = string_set(
        policy.get("forbidden_write_paths"), "forbidden_write_paths", errors
    )
    required_forbidden = {
        "n8n_to_odoo",
        "n8n_to_provider",
        "external_service_to_odoo_postgresql",
        "external_service_to_provider_without_middleware",
        "browser_or_portal_to_odoo",
        "browser_or_portal_to_provider",
    }
    missing_forbidden = sorted(required_forbidden - forbidden)
    if missing_forbidden:
        errors.append(
            "forbidden write paths are incomplete: " + ", ".join(missing_forbidden)
        )


def validate_assertive_pattern(
    properties: dict[str, Any],
    field: str,
    expected_pattern: str,
    valid_sample: str,
    invalid_samples: tuple[str, ...],
    errors: list[str],
) -> None:
    definition = properties.get(field)
    if not isinstance(definition, dict):
        errors.append(f"mutation command {field} definition must be an object")
        return
    pattern = definition.get("pattern")
    if pattern != expected_pattern:
        errors.append(f"mutation command {field} must use an assertive pattern")
        return
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        errors.append(f"mutation command {field} pattern is invalid: {exc}")
        return
    if compiled.fullmatch(valid_sample) is None:
        errors.append(f"mutation command {field} pattern rejects a canonical value")
    for invalid in invalid_samples:
        if compiled.fullmatch(invalid) is not None:
            errors.append(
                f"mutation command {field} pattern accepts malformed value {invalid!r}"
            )


def validate_mutation_schema(schema: dict[str, Any], errors: list[str]) -> None:
    if schema.get("type") != "object":
        errors.append("mutation command schema type must be object")
    if schema.get("additionalProperties") is not False:
        errors.append("mutation command schema must reject unknown top-level fields")

    required = string_set(schema.get("required"), "mutation schema required", errors)
    missing = sorted(REQUIRED_MUTATION_FIELDS - required)
    if missing:
        errors.append("mutation command schema is missing: " + ", ".join(missing))

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        errors.append("mutation command schema properties must be an object")
        return

    missing_properties = sorted(REQUIRED_MUTATION_FIELDS - set(properties))
    if missing_properties:
        errors.append(
            "mutation command schema has no definitions for: "
            + ", ".join(missing_properties)
        )

    specversion = properties.get("specversion")
    if not isinstance(specversion, dict) or specversion.get("const") != "1.0":
        errors.append("mutation command specversion must be fixed to 1.0")

    validate_assertive_pattern(
        properties,
        "command_id",
        UUID_PATTERN,
        "123e4567-e89b-12d3-a456-426614174000",
        ("not-a-uuid", "123e4567-e89b-12d3-a456"),
        errors,
    )
    validate_assertive_pattern(
        properties,
        "requested_at",
        DATETIME_PATTERN,
        "2026-08-26T18:45:30Z",
        ("not-a-time", "2026-99-99T88:77:66Z"),
        errors,
    )

    fingerprint = properties.get("semantic_fingerprint")
    if (
        not isinstance(fingerprint, dict)
        or fingerprint.get("pattern") != "^[a-f0-9]{64}$"
    ):
        errors.append("semantic_fingerprint must be a lowercase SHA-256 digest")


def validate_contract_text(errors: list[str]) -> None:
    required_files = (
        POLICY_PATH,
        MUTATION_SCHEMA_PATH,
        HTTP_CONVENTIONS_PATH,
        BOUNDARY_DOC_PATH,
    )
    missing_file = False
    for path in required_files:
        if not path.is_file():
            errors.append(f"missing write-boundary artifact: {path.relative_to(ROOT)}")
            missing_file = True
    if missing_file:
        return

    http_text = HTTP_CONVENTIONS_PATH.read_text(encoding="utf-8")
    for phrase in ("Idempotency-Key", "Every write is idempotent"):
        if phrase not in http_text:
            errors.append(f"HTTP conventions are missing required phrase: {phrase}")

    boundary_text = BOUNDARY_DOC_PATH.read_text(encoding="utf-8")
    for phrase in (
        "Middleware is the only component allowed",
        "n8n owns orchestration",
        "No external service may receive Odoo PostgreSQL write credentials",
        "{{$env.MIDDLEWARE_BASE_URL}}",
    ):
        if phrase not in boundary_text:
            errors.append(f"write-boundary document is missing required phrase: {phrase}")


def iter_repository_text_files(errors: list[str]) -> Iterator[tuple[Path, str]]:
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_SCAN_PARTS for part in relative.parts):
            continue
        if path.resolve() == THIS_FILE:
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        if "tests" in relative.parts and "fixtures" in relative.parts and "negative" in relative.parts:
            continue
        try:
            size = path.stat().st_size
            if size > MAX_TEXT_SCAN_BYTES:
                continue
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"cannot inspect {relative}: {exc}")
            continue
        if b"\x00" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        yield path, text


def validate_no_odoo_database_credentials(errors: list[str]) -> None:
    for path, text in iter_repository_text_files(errors):
        if ODOO_DATABASE_CREDENTIAL_RE.search(text):
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


def n8n_http_url_error(url: Any, approved_paths: set[str]) -> str | None:
    if not isinstance(url, str):
        return "URL must be a string expression rooted at MIDDLEWARE_BASE_URL"
    compact = re.sub(r"\s+", "", url)
    match = re.fullmatch(r"=?\{\{\$env\.MIDDLEWARE_BASE_URL\}\}(/[^?#]*)?(?:[?#].*)?", compact)
    if match is None:
        return "URL must start with {{$env.MIDDLEWARE_BASE_URL}}"
    path = match.group(1) or ""
    if not any(path == prefix or path.startswith(prefix + "/") for prefix in approved_paths):
        return "URL path must use an approved Middleware command/query/trigger prefix"
    return None


def validate_n8n_exports(policy: dict[str, Any] | None, errors: list[str]) -> None:
    n8n_policy = policy.get("n8n_policy") if isinstance(policy, dict) else None
    approved_paths = (
        string_set(
            n8n_policy.get("approved_http_path_prefixes"),
            "n8n_policy.approved_http_path_prefixes",
            errors,
        )
        if isinstance(n8n_policy, dict)
        else set()
    )

    workflow_paths: list[Path] = []
    for directory_name in ("n8n", "workflows"):
        directory = ROOT / directory_name
        if directory.is_dir():
            workflow_paths.extend(sorted(directory.rglob("*.json")))

    for path in workflow_paths:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            errors.append(f"cannot parse n8n workflow {path.relative_to(ROOT)}: {exc}")
            continue

        markers = {
            item
            for item in walk_json(value)
            if isinstance(item, str) and item in FORBIDDEN_N8N_NODE_MARKERS
        }
        if markers:
            errors.append(
                f"{path.relative_to(ROOT)} contains direct-effect n8n nodes: "
                + ", ".join(sorted(markers))
            )

        for item in walk_json(value):
            if not isinstance(item, dict) or item.get("type") != "n8n-nodes-base.httpRequest":
                continue
            parameters = item.get("parameters")
            node_name = item.get("name") if isinstance(item.get("name"), str) else "unnamed"
            if not isinstance(parameters, dict):
                errors.append(
                    f"{path.relative_to(ROOT)} HTTP Request node {node_name!r} "
                    "has no parameters object"
                )
                continue
            problem = n8n_http_url_error(parameters.get("url"), approved_paths)
            if problem:
                errors.append(
                    f"{path.relative_to(ROOT)} HTTP Request node {node_name!r}: {problem}"
                )


def validate_guard_self_tests(errors: list[str]) -> None:
    if ODOO_DATABASE_CREDENTIAL_RE.search("ODOO_DATABASE_URL=postgresql://example") is None:
        errors.append("Odoo credential scanner self-test failed")
    if n8n_http_url_error(
        "https://odoo.example.invalid/web/dataset/call_kw",
        REQUIRED_N8N_PATH_PREFIXES,
    ) is None:
        errors.append("n8n direct-Odoo HTTP negative self-test failed")
    if n8n_http_url_error(
        "={{ $env.MIDDLEWARE_BASE_URL }}/v1/commands/odoo/contact-upsert",
        REQUIRED_N8N_PATH_PREFIXES,
    ) is not None:
        errors.append("n8n approved-Middleware HTTP positive self-test failed")


def report(errors: list[str]) -> int:
    print("Write-boundary validation failed:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    return 1


def main() -> int:
    errors: list[str] = []
    policy = load_json(POLICY_PATH, errors)
    schema = load_json(MUTATION_SCHEMA_PATH, errors)
    validate_contract_text(errors)
    if policy is not None:
        validate_policy(policy, errors)
    if schema is not None:
        validate_mutation_schema(schema, errors)
    validate_no_odoo_database_credentials(errors)
    validate_n8n_exports(policy, errors)
    validate_guard_self_tests(errors)

    if errors:
        return report(errors)

    print(
        "Write-boundary validation passed: Middleware is the sole mutation "
        "boundary, n8n is orchestration-only, and Odoo writes require the "
        "approved service API or ORM bridge."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
