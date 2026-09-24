#!/usr/bin/env python3
"""Validate the fixed-recipient observability alert source contract."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any, Never, cast

ROOT = Path(__file__).resolve().parents[1]

POLICY_SCALARS: dict[str, object] = {
    "schema_version": "1.0",
    "policy_id": "codestra-observability-alert-mail-v1",
    "tenant_id": "codestra-platform",
    "receiver": "codestra-observability-email",
    "recipient_policy_id": "codestra-observability-admin-v1",
    "sender_policy_id": "codestra-alert-sender-v1",
    "recipient": "appolon1908@gmail.com",
    "sender": "alerts@codestra.co",
    "reply_to": "appolon1908@gmail.com",
    "warning_group_wait_seconds": 300,
    "warning_repeat_interval_seconds": 14400,
    "max_alerts_per_request": 1,
    "max_body_bytes": 131072,
    "normal_delivery_path": "middleware-klyrow-adapter",
    "direct_smtp_allowed": False,
    "delivery_enabled_by_default": False,
}
POLICY_LISTS = {
    "allowed_environments": ["production"],
    "allowed_severities": ["critical", "high", "warning", "info"],
    "immediate_severities": ["critical", "high"],
    "grouped_severities": ["warning"],
    "state_only_severities": ["info"],
}
CALLER_CONTRACTS: dict[str, dict[str, object]] = {
    "alertmanager": {
        "command_scope": "alerts.write",
        "status_scope": "alerts.read",
        "allowed_command_prefixes": ["observability.alert."],
        "allowed_targets": ["klyrow-alert-email"],
        "compatibility_only": False,
        "staging_auth_matrix": True,
    },
    "klyrow-alert-adapter": {
        "command_scope": "observability.alerts.events.write",
        "status_scope": "observability.alerts.read",
        "allowed_command_prefixes": ["observability.alert."],
        "allowed_targets": ["klyrow-alert-email"],
        "compatibility_only": False,
        "staging_auth_matrix": True,
    },
    "observability-operator": {
        "command_scope": "observability.incidents.write",
        "status_scope": "observability.incidents.read",
        "connector_commands_allowed": False,
        "allowed_command_prefixes": [],
        "allowed_targets": [],
        "compatibility_only": False,
        "staging_auth_matrix": True,
    },
}
CALLER_REGISTRY_SCALARS: dict[str, object] = {
    "schema_version": "1.0",
    "issuer": "https://auth.codestra.co/realms/codestra",
    "audience": "middleware-api",
    "token_exchange": False,
    "original_bearer_required": True,
    "maximum_token_lifetime_seconds": 300,
    "tenant_claim": "tenant_id",
}
CAPABILITY_REGISTRY_SCALARS: dict[str, object] = {
    "schema_version": "2.0",
    "default_policy": "DENY",
}
CAPABILITY_ACTIVATION_REQUIREMENTS = [
    "protected_merged_sha",
    "exact_head_tests",
    "independent_approval",
    "staging_no_effect",
    "backup_restore",
    "rollback_rehearsal",
    "bounded_canary",
    "runtime_readback",
]
COMMAND_CONTRACT: dict[str, object] = {
    "connector_id": "klyrow-alert-email",
    "prefix": "observability.alert.",
    "readback_required": True,
    "required_capability": "OBSERVABILITY_ALERT_EMAIL_DELIVERY",
    "timeout_seconds": 30,
    "unknown_outcome_requires_readback": True,
}
ADAPTER_CONTRACT: dict[str, object] = {
    "id": "klyrow-alert-email",
    "cell": "core-communications",
    "repository": "appolon1908-hue/klyrow.com",
    "command_prefixes": ["observability.alert."],
    "direct_n8n": False,
}
REQUIRED_PATHS = {
    "/health",
    "/readiness",
    "/platform/v1/health",
    "/platform/v1/readiness",
    "/version",
    "/capabilities",
    "/internal/v1/alerts/alertmanager",
    "/v1/integrations/alertmanager/events",
    "/v1/integrations/alertmanager/status-events",
    "/v1/observability/alerts",
    "/v1/observability/alerts/{operation_id}",
    "/v1/observability/alerts/{operation_id}/events",
    "/v1/observability/incidents",
    "/v1/observability/incidents/{incident_id}",
    "/v1/observability/incidents/{incident_id}/timeline",
    "/v1/observability/incidents/{incident_id}/notification-attempts",
    "/v1/observability/incidents/{incident_id}/acknowledge",
    "/v1/observability/incidents/{incident_id}/resolve",
    "/v1/observability/incidents/{incident_id}/reopen",
    "/v1/observability/alert-delivery-events",
    "/metrics",
}
COMMAND_FIELDS = set(COMMAND_CONTRACT)
ADAPTER_FIELDS = set(ADAPTER_CONTRACT)
CALLER_FIELDS = {
    "command_scope",
    "status_scope",
    "allowed_command_prefixes",
    "allowed_targets",
    "compatibility_only",
    "staging_auth_matrix",
}
COMPOSE_SERVICE_FIELDS = {
    "image",
    "command",
    "env_file",
    "user",
    "init",
    "read_only",
    "restart",
    "cap_drop",
    "security_opt",
    "pids_limit",
    "mem_limit",
    "cpus",
    "tmpfs",
    "expose",
    "secrets",
    "networks",
    "healthcheck",
    "labels",
}
CONNECTOR_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
COMMAND_PREFIX_PATTERN = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*\.\Z")
CAPABILITY_PATTERN = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*\Z")

def fail(message: str) -> Never:
    raise SystemExit(f"OBSERVABILITY_ALERT_CONTRACT=FAIL {message}")


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def reject_nonstandard_json_constant(value: str) -> Never:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_object(root: Path, relative: str) -> dict[str, Any]:
    path = root / relative
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as error:
        fail(f"invalid_json:{relative}:{error}")
    if not isinstance(value, dict):
        fail(f"invalid_object:{relative}")
    return cast(dict[str, Any], value)


def read_text(root: Path, relative: str) -> str:
    try:
        return (root / relative).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        fail(f"invalid_text:{relative}:{error}")


def require_object(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        fail(message)
    return cast(dict[str, Any], value)


def require_list(value: object, message: str) -> list[Any]:
    if not isinstance(value, list):
        fail(message)
    return cast(list[Any], value)


def require_string(value: object, message: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(message)
    return cast(str, value)


def require_string_list(value: object, message: str) -> list[str]:
    items = [require_string(item, message) for item in require_list(value, message)]
    if len(items) != len(set(items)):
        fail(message)
    return items


def require_matching_string(
    value: object, pattern: re.Pattern[str], message: str
) -> str:
    item = require_string(value, message)
    if pattern.fullmatch(item) is None:
        fail(message)
    return item


def require_exact_record(
    record: dict[str, Any], expected: dict[str, object], message: str
) -> None:
    if set(record) != set(expected):
        fail(f"{message}:fields")
    for key, expected_value in expected.items():
        observed = record.get(key)
        if type(observed) is not type(expected_value) or observed != expected_value:
            fail(f"{message}:{key}")


def require_record_list(value: object, message: str) -> list[dict[str, Any]]:
    return [
        require_object(item, f"{message}:{index}")
        for index, item in enumerate(require_list(value, message))
    ]


def find_exact_record(
    records: list[dict[str, Any]], key: str, value: str, message: str
) -> dict[str, Any]:
    matches = [record for record in records if record.get(key) == value]
    if len(matches) != 1:
        fail(f"{message}:count={len(matches)}")
    return matches[0]


def yaml_mapping_block(source: str, key: str, indent: int, message: str) -> str:
    prefix = " " * indent
    header = f"{prefix}{key}:"
    lines = source.splitlines()
    matches = [index for index, line in enumerate(lines) if line.rstrip() == header]
    if len(matches) != 1:
        fail(f"{message}:count={len(matches)}")
    start = matches[0] + 1
    end = len(lines)
    for index in range(start, len(lines)):
        line = lines[index]
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        leading_spaces = len(line) - len(stripped)
        if leading_spaces <= indent:
            end = index
            break
    return "\n".join(lines[start:end])


def yaml_mapping_keys(source: str, indent: int, message: str) -> list[str]:
    prefix = " " * indent
    keys: list[str] = []
    for line in source.splitlines():
        stripped = line.lstrip(" ")
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(prefix) or line.startswith(prefix + " "):
            continue
        match = re.fullmatch(rf"{re.escape(prefix)}([^:#][^:]*):(?:\s.*)?", line)
        if match is None:
            fail(message)
        key = match.group(1)
        if key != key.strip():
            fail(message)
        keys.append(key)
    return keys


def require_module_string_constant(
    root: Path, relative: str, name: str, expected: str
) -> None:
    source = read_text(root, relative)
    try:
        tree = ast.parse(source, filename=relative)
    except (SyntaxError, ValueError) as error:
        fail(f"invalid_python:{relative}:{error}")
    assignments: list[ast.expr | None] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name
            for target in node.targets
        ):
            assignments.append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        ):
            assignments.append(node.value)
    if (
        len(assignments) != 1
        or not isinstance(assignments[0], ast.Constant)
        or type(assignments[0].value) is not str
        or assignments[0].value != expected
    ):
        fail(f"python_constant_drifted:{relative}:{name}")


def validate(root: Path = ROOT) -> tuple[int, int]:
    policy = load_object(root, "config/observability-alert-policy.v1.json")
    if set(policy) != set(POLICY_SCALARS) | set(POLICY_LISTS):
        fail("policy_fields_drifted")
    for key, expected in POLICY_SCALARS.items():
        observed = policy.get(key)
        if type(observed) is not type(expected) or observed != expected:
            fail(f"policy_field_drifted:{key}")
    for key, expected in POLICY_LISTS.items():
        if (
            require_string_list(policy.get(key), f"invalid_policy_list:{key}")
            != expected
        ):
            fail(f"policy_list_drifted:{key}")

    capability_registry = load_object(root, "config/capabilities.v2.json")
    if set(capability_registry) != (
        set(CAPABILITY_REGISTRY_SCALARS) | {"activation_requirements", "capabilities"}
    ):
        fail("capability_registry_fields_drifted")
    for key, expected in CAPABILITY_REGISTRY_SCALARS.items():
        observed = capability_registry.get(key)
        if type(observed) is not type(expected) or observed != expected:
            fail(f"capability_registry_policy_drifted:{key}")
    if (
        require_string_list(
            capability_registry.get("activation_requirements"),
            "invalid_capability_activation_requirements",
        )
        != CAPABILITY_ACTIVATION_REQUIREMENTS
    ):
        fail("capability_activation_requirements_drifted")
    capabilities = require_object(
        capability_registry.get("capabilities"), "invalid_capability_registry"
    )
    if not capabilities:
        fail("empty_capability_registry")
    if capabilities.get("OBSERVABILITY_ALERT_EMAIL_DELIVERY") is not False:
        fail("alert_capability_must_default_false")
    for capability, value in capabilities.items():
        if CAPABILITY_PATTERN.fullmatch(capability) is None:
            fail(f"invalid_capability_name:{capability}")
        if value is not False:
            fail("all_repository_capabilities_must_remain_false")

    caller_registry = load_object(root, "config/control-plane-callers.v1.json")
    if set(caller_registry) != set(CALLER_REGISTRY_SCALARS) | {"callers"}:
        fail("caller_registry_fields_drifted")
    for key, expected in CALLER_REGISTRY_SCALARS.items():
        observed = caller_registry.get(key)
        if type(observed) is not type(expected) or observed != expected:
            fail(f"caller_registry_policy_drifted:{key}")
    callers = require_object(caller_registry.get("callers"), "invalid_caller_registry")

    command_registry = load_object(
        root, "connectors/generated/command-registry.v1.json"
    )
    if set(command_registry) != {"schema_version", "default_policy", "commands"}:
        fail("command_registry_fields_drifted")
    if command_registry.get("schema_version") != "1.0":
        fail("command_registry_schema_drifted")
    if command_registry.get("default_policy") != "DENY":
        fail("command_registry_default_policy_drifted")
    commands = require_record_list(
        command_registry.get("commands"), "invalid_command_registry"
    )
    command_prefixes: dict[str, str] = {}
    commands_by_connector: dict[str, set[str]] = {}
    for index, candidate in enumerate(commands):
        if set(candidate) != COMMAND_FIELDS:
            fail(f"invalid_command_registry_entry:{index}:fields")
        connector_id = require_matching_string(
            candidate.get("connector_id"),
            CONNECTOR_ID_PATTERN,
            f"invalid_command_registry_entry:{index}:connector_id",
        )
        prefix = require_matching_string(
            candidate.get("prefix"),
            COMMAND_PREFIX_PATTERN,
            f"invalid_command_registry_entry:{index}:prefix",
        )
        capability = require_matching_string(
            candidate.get("required_capability"),
            CAPABILITY_PATTERN,
            f"invalid_command_registry_entry:{index}:required_capability",
        )
        if prefix in command_prefixes:
            fail(f"duplicate_command_prefix:{prefix}")
        command_prefixes[prefix] = connector_id
        commands_by_connector.setdefault(connector_id, set()).add(prefix)
        if capability not in capabilities:
            fail(f"unknown_command_capability:{capability}")
        if candidate.get("readback_required") is not True:
            fail(f"command_readback_required:{prefix}")
        if candidate.get("unknown_outcome_requires_readback") is not True:
            fail(f"command_unknown_outcome_readback_required:{prefix}")
        timeout = candidate.get("timeout_seconds")
        if type(timeout) is not int or not 1 <= timeout <= 30:
            fail(f"command_timeout_invalid:{prefix}")
    command = find_exact_record(
        commands,
        "prefix",
        "observability.alert.",
        "alert_command_policy_missing_or_duplicate",
    )
    require_exact_record(command, COMMAND_CONTRACT, "alert_command_policy_drifted")

    adapter_registry = load_object(root, "config/adapter-registry.v2.json")
    if set(adapter_registry) != {"schema_version", "adapters"}:
        fail("adapter_registry_fields_drifted")
    if adapter_registry.get("schema_version") != "2.0":
        fail("adapter_registry_schema_drifted")
    adapters = require_record_list(
        adapter_registry.get("adapters"), "invalid_adapter_registry"
    )
    adapter_prefixes: dict[str, str] = {}
    adapters_by_id: dict[str, set[str]] = {}
    for index, candidate in enumerate(adapters):
        if set(candidate) not in (
            ADAPTER_FIELDS,
            ADAPTER_FIELDS | {"forbidden_prefixes"},
        ):
            fail(f"invalid_adapter_registry_entry:{index}:fields")
        connector_id = require_matching_string(
            candidate.get("id"),
            CONNECTOR_ID_PATTERN,
            f"invalid_adapter_registry_entry:{index}:id",
        )
        if connector_id in adapters_by_id:
            fail(f"duplicate_adapter_id:{connector_id}")
        require_string(candidate.get("cell"), f"invalid_adapter_cell:{connector_id}")
        repository = require_string(
            candidate.get("repository"), f"invalid_adapter_repository:{connector_id}"
        )
        if (
            re.fullmatch(
                r"(?:ingtrader21-spec|appolon1908-hue)/[A-Za-z0-9_.-]+", repository
            )
            is None
        ):
            fail(f"invalid_adapter_repository:{connector_id}")
        prefixes = require_string_list(
            candidate.get("command_prefixes"),
            f"invalid_adapter_prefixes:{connector_id}",
        )
        if not prefixes:
            fail(f"invalid_adapter_prefixes:{connector_id}")
        for prefix in prefixes:
            if COMMAND_PREFIX_PATTERN.fullmatch(prefix) is None:
                fail(f"invalid_adapter_prefix:{connector_id}:{prefix}")
            if prefix in adapter_prefixes:
                fail(f"duplicate_adapter_prefix:{prefix}")
            adapter_prefixes[prefix] = connector_id
        if candidate.get("direct_n8n") is not False:
            fail(f"adapter_direct_n8n_forbidden:{connector_id}")
        if "forbidden_prefixes" in candidate:
            forbidden = require_string_list(
                candidate.get("forbidden_prefixes"),
                f"invalid_forbidden_prefixes:{connector_id}",
            )
            if (
                not forbidden
                or any(
                    COMMAND_PREFIX_PATTERN.fullmatch(item) is None for item in forbidden
                )
                or set(forbidden) & set(prefixes)
            ):
                fail(f"invalid_forbidden_prefixes:{connector_id}")
        adapters_by_id[connector_id] = set(prefixes)
    if commands_by_connector != adapters_by_id:
        fail("command_adapter_inventory_drifted")
    if command_prefixes != adapter_prefixes:
        fail("command_adapter_prefix_mapping_drifted")
    adapter = find_exact_record(
        adapters,
        "id",
        "klyrow-alert-email",
        "alert_adapter_missing_or_duplicate",
    )
    require_exact_record(adapter, ADAPTER_CONTRACT, "alert_adapter_drifted")

    for caller_id, raw_caller in callers.items():
        if CONNECTOR_ID_PATTERN.fullmatch(caller_id) is None:
            fail(f"invalid_caller_id:{caller_id}")
        caller = require_object(raw_caller, f"invalid_caller:{caller_id}")
        allowed_fields = CALLER_FIELDS | {"connector_commands_allowed"}
        if set(caller) not in (CALLER_FIELDS, allowed_fields):
            fail(f"caller_fields_drifted:{caller_id}")
        require_string(caller.get("command_scope"), f"invalid_caller:{caller_id}")
        require_string(caller.get("status_scope"), f"invalid_caller:{caller_id}")
        allowed_prefixes = require_string_list(
            caller.get("allowed_command_prefixes"), f"invalid_caller:{caller_id}"
        )
        allowed_targets = require_string_list(
            caller.get("allowed_targets"), f"invalid_caller:{caller_id}"
        )
        if type(caller.get("compatibility_only")) is not bool:
            fail(f"invalid_caller:{caller_id}")
        if type(caller.get("staging_auth_matrix")) is not bool:
            fail(f"invalid_caller:{caller_id}")
        connector_commands_allowed = caller.get("connector_commands_allowed", True)
        if type(connector_commands_allowed) is not bool:
            fail(f"invalid_caller:{caller_id}")
        if "connector_commands_allowed" in caller and connector_commands_allowed:
            fail(f"redundant_caller_allow_override:{caller_id}")
        if not connector_commands_allowed and (allowed_prefixes or allowed_targets):
            fail(f"denied_caller_has_connector_authority:{caller_id}")
        for prefix in allowed_prefixes:
            owner = command_prefixes.get(prefix)
            if owner is None or owner not in allowed_targets:
                fail(f"caller_prefix_target_mismatch:{caller_id}:{prefix}")
        for target in allowed_targets:
            target_prefixes = adapters_by_id.get(target)
            if target_prefixes is None or not target_prefixes.intersection(
                allowed_prefixes
            ):
                fail(f"caller_target_prefix_mismatch:{caller_id}:{target}")
    for caller_id, expected in CALLER_CONTRACTS.items():
        caller = require_object(callers.get(caller_id), f"missing_caller:{caller_id}")
        require_exact_record(caller, expected, f"caller_drifted:{caller_id}")

    contract_source = read_text(
        root, "contracts/observability/alert-api.v1.openapi.yaml"
    )
    if "\t" in contract_source:
        fail("openapi_tabs_forbidden")
    paths_source = yaml_mapping_block(
        contract_source, "paths", 0, "openapi_paths_block"
    )
    route_entries = yaml_mapping_keys(paths_source, 2, "invalid_openapi_route_key")
    if len(route_entries) != len(set(route_entries)):
        fail("duplicate_openapi_route")
    if set(route_entries) != REQUIRED_PATHS:
        fail("openapi_route_inventory_drifted")

    compose_source = read_text(
        root, "deploy/observability-alerts/compose.core-production.yaml"
    )
    if "\t" in compose_source:
        fail("compose_tabs_forbidden")
    services_source = yaml_mapping_block(
        compose_source, "services", 0, "compose_services_block"
    )
    service_source = yaml_mapping_block(
        services_source,
        "observability-alert-api",
        2,
        "observability_alert_compose_service",
    )
    service_fields = yaml_mapping_keys(
        service_source, 4, "invalid_observability_alert_service_field"
    )
    if len(service_fields) != len(set(service_fields)):
        fail("duplicate_observability_alert_service_field")
    image_authority = (
        "image: ${MIDDLEWARE_IMAGE:?set exact registry/repository@sha256:<digest>}"
    )
    if (
        re.search(
            rf"^    {re.escape(image_authority)}\s*$",
            service_source,
            flags=re.MULTILINE,
        )
        is None
    ):
        fail("production_image_must_require_immutable_digest")
    for pattern, label in (
        (r"^    read_only:\s*true\s*$", "read_only"),
        (r"^    cap_drop:\s*\[ALL\]\s*$", "cap_drop"),
        (r"^      - no-new-privileges:true\s*$", "no_new_privileges"),
        (r'^    user:\s*["\']65532:65532["\']\s*$', "unprivileged_user"),
    ):
        if re.search(pattern, service_source, flags=re.MULTILINE) is None:
            fail(f"container_hardening_drifted:{label}")
    for pattern, label in (
        (r"^    ports:\s*", "host_port"),
        (r'^    privileged:\s*["\']?true["\']?\s*$', "privileged"),
        (r'^    network_mode:\s*["\']?host["\']?\s*$', "host_network"),
        (r'^    pid:\s*["\']?host["\']?\s*$', "host_pid"),
    ):
        if re.search(pattern, service_source, flags=re.MULTILINE | re.IGNORECASE):
            fail(f"container_boundary_forbidden:{label}")
    if set(service_fields) != COMPOSE_SERVICE_FIELDS:
        fail("observability_alert_service_fields_drifted")

    for name, expected in (
        ("COMMAND_TYPE", "observability.alert.email.send.v1"),
        ("COMMAND_TARGET", "klyrow-alert-email"),
        ("COMMAND_CAPABILITY", "OBSERVABILITY_ALERT_EMAIL_DELIVERY"),
    ):
        require_module_string_constant(
            root, "app/observability_alert_contract.py", name, expected
        )

    api_source = "".join(
        read_text(root, relative)
        for relative in (
            "app/observability_alerts.py",
            "app/observability_alert_contract.py",
            "app/observability_incidents.py",
        )
    )
    adapter_source = read_text(root, "app/klyrow_alert_adapter.py")
    worker_source = read_text(root, "workers/run_temporal.py")
    implementation_source = "\n".join(
        (api_source, adapter_source, worker_source)
    ).casefold()
    if re.search(r"\b(?:aiosmtplib|smtplib)\b|\bsmtps?://", implementation_source):
        fail("direct_smtp_implementation_forbidden")
    required_api_markers = (
        "recipient_policy_id",
        "direct_smtp_allowed",
        'authoritative_completion": "provider-readback"',
        "PostgresIncidentStore",
        "request_idempotency_key",
        "X-Source-Deployment",
    )
    for marker in required_api_markers:
        if marker not in api_source:
            fail(f"alert_api_marker_missing:{marker}")

    migration = read_text(root, "migrations/0009_observability_incidents.sql")
    for marker in (
        "middleware_observability_incidents",
        "middleware_observability_incident_events",
        "middleware_observability_incident_audit",
        "middleware_observability_notification_intents",
        "middleware_observability_incident_mutations",
        "request_idempotency_key",
        "notification_repeat",
        "notification_suppressed",
        "REFERENCES middleware_commands(tenant_id,command_id)",
    ):
        if marker not in migration:
            fail(f"incident_migration_marker_missing:{marker}")
    for marker in (
        'MESSAGE_PATH = "/v1/email/messages"',
        'MESSAGE_STATUS_PATH = "/v1/email/messages/{message_id}"',
        'CLIENT_ID = "middleware-alert-delivery"',
        '"appolon1908@gmail.com"',
        '"alerts@codestra.co"',
        "general LIVE_EMAIL_DELIVERY must remain disabled",
    ):
        if marker not in adapter_source:
            fail(f"klyrow_alert_adapter_marker_missing:{marker}")
    if "KlyrowAlertAdapter(settings)" not in worker_source:
        fail("temporal_worker_alert_adapter_missing")

    serialized = "\n".join(
        read_text(root, relative).casefold()
        for relative in (
            "config/observability-alert-policy.v1.json",
            "deploy/observability-alerts/compose.core-production.yaml",
            "deploy/observability-alerts/production.env.example",
        )
    )
    for pattern, label in (
        (r"\bsmtp(?:[._-][a-z0-9]+)?\s*[:=]", "direct_smtp_configuration"),
        (r"\bsmtps?://", "direct_smtp_url"),
        (r"\bclient_secret\s*[:=]", "inline_client_secret"),
    ):
        if re.search(pattern, serialized):
            fail(f"secret_bearing_alert_configuration:{label}")

    return len(REQUIRED_PATHS), len(capabilities)


def main() -> None:
    route_count, capability_count = validate()
    print("OBSERVABILITY_ALERT_CONTRACT=PASS")
    print(f"OBSERVABILITY_ALERT_ROUTES={route_count}")
    print(f"REPOSITORY_CAPABILITIES_DISABLED={capability_count}")
    print("ALERT_RECIPIENT=appolon1908@gmail.com")
    print("ALERT_SENDER=alerts@codestra.co")
    print("DIRECT_SMTP_ALLOWED=NO")
    print("ALERT_DELIVERY_DEFAULT=DISABLED")


if __name__ == "__main__":
    main()
