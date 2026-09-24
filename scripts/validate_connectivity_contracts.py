#!/usr/bin/env python3
"""Validate middleware branch dependencies and cross-system communication contracts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config" / "integration-branches.json"
CONNECTIVITY_PATH = ROOT / "config" / "connectivity-map.json"
EVENT_SCHEMA_PATH = (
    ROOT / "contracts" / "platform" / "event-envelope.v1.schema.json"
)

LINK_ID_RE = re.compile(r"^[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?$")

EXPECTED_POLICIES = {
    "all_workstreams_must_depend_on_canonical_contracts": True,
    "all_links_require_explicit_authentication": True,
    "all_effectful_delivery_requires_idempotency": True,
    "webhooks_require_signature_timestamp_and_replay_protection": True,
    "tenant_correlation_and_causation_metadata_required": True,
    "external_effects_disabled_by_default": True,
    "runtime_verification_required_before_activation": True,
    "direct_deployment_from_workstream_branches": False,
}

REQUIRED_EVENT_FIELDS = {
    "event_id",
    "event_type",
    "event_version",
    "occurred_at",
    "received_at",
    "source",
    "tenant_id",
    "correlation_id",
    "causation_id",
    "idempotency_key",
    "payload",
    "metadata",
}

ALLOWED_DIRECTIONS = {
    "alert",
    "contract",
    "identity",
    "internal",
    "lease",
    "log",
    "probe",
    "query",
    "queue",
    "request_response",
    "scrape",
    "state",
    "test",
    "workflow",
}

ALLOWED_TRANSPORTS = {
    "amqp",
    "https",
    "internal",
    "oidc_jwks",
    "nats_jetstream",
    "postgresql",
    "prometheus_scrape",
    "redis",
    "temporal_rpc",
}

ALLOWED_AUTHENTICATION = {
    "amqp_tls_identity",
    "database_role",
    "internal_service_policy",
    "mtls_or_oidc_jwt",
    "nats_tls_service_identity",
    "none_private_network",
    "oidc_jwt",
    "redis_acl",
    "service_identity",
    "test_identity",
}

ALLOWED_RELIABILITY = {
    "at_least_once",
    "best_effort_observation",
    "durable_inbox",
    "durable_workflow",
    "lease_retry",
    "read_only",
    "synchronous",
    "transactional_outbox",
}

ALLOWED_CONNECTION_STATUS = {"declared", "verification_only"}

VERIFICATION_RUNTIME_STATUSES = {
    "not_observed_on_middleware_host_verification_only",
    "configured_worker_not_observed",
    "configured_runtime_not_confirmed",
}


def load_json(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load {path.relative_to(ROOT)}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{path.relative_to(ROOT)} root must be a JSON object")
        return None
    return value


def find_cycle(graph: dict[str, list[str]]) -> list[str] | None:
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        marker = state.get(node, 0)
        if marker == 2:
            return None
        if marker == 1:
            try:
                start = stack.index(node)
            except ValueError:
                start = 0
            return stack[start:] + [node]

        state[node] = 1
        stack.append(node)
        for dependency in graph.get(node, []):
            cycle = visit(dependency)
            if cycle:
                return cycle
        stack.pop()
        state[node] = 2
        return None

    for node in graph:
        cycle = visit(node)
        if cycle:
            return cycle
    return None


def transitive_dependencies(
    branch: str, graph: dict[str, list[str]]
) -> set[str]:
    discovered: set[str] = set()
    pending = list(graph.get(branch, []))
    while pending:
        dependency = pending.pop()
        if dependency in discovered:
            continue
        discovered.add(dependency)
        pending.extend(graph.get(dependency, []))
    return discovered


def validate_event_schema(errors: list[str]) -> None:
    schema = load_json(EVENT_SCHEMA_PATH, errors)
    if schema is None:
        return

    if schema.get("type") != "object":
        errors.append("event envelope schema type must be 'object'")
    if schema.get("additionalProperties") is not False:
        errors.append("event envelope must reject unknown top-level properties")

    required = schema.get("required")
    if not isinstance(required, list) or not all(
        isinstance(item, str) for item in required
    ):
        errors.append("event envelope required must be an array of field names")
        required_set: set[str] = set()
    else:
        required_set = set(required)

    missing_required = sorted(REQUIRED_EVENT_FIELDS - required_set)
    if missing_required:
        errors.append(
            "event envelope is missing required fields: "
            + ", ".join(missing_required)
        )

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        errors.append("event envelope properties must be an object")
        return

    missing_properties = sorted(REQUIRED_EVENT_FIELDS - set(properties))
    if missing_properties:
        errors.append(
            "event envelope has no definitions for: "
            + ", ".join(missing_properties)
        )

    event_version = properties.get("event_version")
    if (
        not isinstance(event_version, dict)
        or event_version.get("const") != "1.0"
    ):
        errors.append("event envelope event_version must be fixed to '1.0'")

    payload = properties.get("payload")
    if not isinstance(payload, dict) or payload.get("type") != "object":
        errors.append("event envelope payload must be an object")


def main() -> int:
    errors: list[str] = []
    manifest = load_json(MANIFEST_PATH, errors)
    connectivity = load_json(CONNECTIVITY_PATH, errors)
    if manifest is None or connectivity is None:
        return report(errors)

    version = manifest.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 4:
        errors.append("workstream manifest version must be at least 4")

    raw_workstreams = manifest.get("workstreams")
    if not isinstance(raw_workstreams, list):
        errors.append("workstream manifest must contain a workstreams array")
        raw_workstreams = []

    branch_status: dict[str, str] = {}
    for index, item in enumerate(raw_workstreams):
        if not isinstance(item, dict):
            continue
        branch = item.get("branch")
        runtime_status = item.get("runtime_status")
        if isinstance(branch, str) and isinstance(runtime_status, str):
            branch_status[branch] = runtime_status
        else:
            errors.append(
                f"workstreams[{index}] requires string branch and runtime_status"
            )

    branches = set(branch_status)
    contract_branch = manifest.get("canonical_contract_branch")
    if contract_branch != "core/integration-contracts":
        errors.append(
            "canonical_contract_branch must be 'core/integration-contracts'"
        )
    if contract_branch not in branches:
        errors.append("canonical contract branch is missing from workstreams")

    if manifest.get("connectivity_map") != "config/connectivity-map.json":
        errors.append("manifest connectivity_map path is not canonical")
    if manifest.get("canonical_event_schema") != (
        "contracts/platform/event-envelope.v1.schema.json"
    ):
        errors.append("manifest canonical_event_schema path is not canonical")

    expected_sync_policy = {
        "main_must_be_ancestor_of_active_work": True,
        "completed_workstreams_refresh_from_main": True,
        "direct_workstream_deployment": False,
        "immutable_release_from_merged_sha_only": True,
    }
    if manifest.get("synchronization_policy") != expected_sync_policy:
        errors.append("manifest synchronization_policy is incomplete or unsafe")

    if connectivity.get("canonical_contract_branch") != contract_branch:
        errors.append(
            "connectivity map and workstream manifest disagree on contract branch"
        )

    connectivity_version = connectivity.get("version")
    if (
        not isinstance(connectivity_version, int)
        or isinstance(connectivity_version, bool)
        or connectivity_version < 2
    ):
        errors.append("connectivity map version must be at least 2")

    policies = connectivity.get("policies")
    if not isinstance(policies, dict):
        errors.append("connectivity policies must be an object")
    else:
        for key, expected in EXPECTED_POLICIES.items():
            if policies.get(key) is not expected:
                errors.append(
                    f"connectivity policy {key} must be exactly {expected!r}"
                )

    raw_dependencies = connectivity.get("workstream_dependencies")
    if not isinstance(raw_dependencies, dict):
        errors.append("workstream_dependencies must be an object")
        raw_dependencies = {}

    dependency_keys = set(raw_dependencies)
    if dependency_keys != branches:
        missing = sorted(branches - dependency_keys)
        extra = sorted(dependency_keys - branches)
        if missing:
            errors.append(
                "workstreams missing dependency declarations: "
                + ", ".join(missing)
            )
        if extra:
            errors.append(
                "dependency declarations for unknown workstreams: "
                + ", ".join(extra)
            )

    graph: dict[str, list[str]] = {}
    for branch in sorted(branches):
        raw = raw_dependencies.get(branch)
        if not isinstance(raw, list) or not all(
            isinstance(item, str) for item in raw
        ):
            errors.append(f"dependencies for {branch} must be an array of branches")
            graph[branch] = []
            continue

        if len(raw) != len(set(raw)):
            errors.append(f"dependencies for {branch} contain duplicates")
        if branch in raw:
            errors.append(f"{branch} cannot depend on itself")

        unknown = sorted(set(raw) - branches)
        if unknown:
            errors.append(
                f"{branch} has unknown dependencies: " + ", ".join(unknown)
            )
        graph[branch] = list(raw)

    if graph.get(str(contract_branch)) != []:
        errors.append("canonical contract branch must not depend on another workstream")

    cycle = find_cycle(graph)
    if cycle:
        errors.append("workstream dependency cycle: " + " -> ".join(cycle))

    for branch in sorted(branches - {str(contract_branch)}):
        if str(contract_branch) not in transitive_dependencies(branch, graph):
            errors.append(f"{branch} is disconnected from {contract_branch}")

    raw_connections = connectivity.get("connections")
    if not isinstance(raw_connections, list) or not raw_connections:
        errors.append("connectivity connections must be a non-empty array")
        raw_connections = []

    connection_ids: list[str] = []
    connected_branches: set[str] = set()

    for index, connection in enumerate(raw_connections):
        location = f"connections[{index}]"
        if not isinstance(connection, dict):
            errors.append(f"{location} must be an object")
            continue

        connection_id = connection.get("id")
        source = connection.get("source_branch")
        target = connection.get("target_branch")
        owner = connection.get("owner_branch")
        runtime_status = connection.get("runtime_status")
        contract_path = connection.get("contract")

        if (
            not isinstance(connection_id, str)
            or not LINK_ID_RE.fullmatch(connection_id)
        ):
            errors.append(f"{location}.id is not canonical")
        else:
            connection_ids.append(connection_id)

        if source not in branches:
            errors.append(f"{location}.source_branch is unknown: {source!r}")
        if target not in branches:
            errors.append(f"{location}.target_branch is unknown: {target!r}")
        if source == target:
            errors.append(f"{location} cannot connect a branch to itself")

        if isinstance(source, str):
            connected_branches.add(source)
        if isinstance(target, str):
            connected_branches.add(target)

        if connection.get("direction") not in ALLOWED_DIRECTIONS:
            errors.append(f"{location}.direction is invalid")
        if connection.get("transport") not in ALLOWED_TRANSPORTS:
            errors.append(f"{location}.transport is invalid")
        if connection.get("authentication") not in ALLOWED_AUTHENTICATION:
            errors.append(f"{location}.authentication is invalid")
        if connection.get("reliability") not in ALLOWED_RELIABILITY:
            errors.append(f"{location}.reliability is invalid")
        if owner not in branches:
            errors.append(f"{location}.owner_branch is not a workstream")
        if runtime_status not in ALLOWED_CONNECTION_STATUS:
            errors.append(f"{location}.runtime_status is invalid")

        endpoint_statuses = {
            branch_status.get(str(source)),
            branch_status.get(str(target)),
        }
        if (
            endpoint_statuses & VERIFICATION_RUNTIME_STATUSES
            and runtime_status != "verification_only"
        ):
            errors.append(
                f"{location} touches a verification-only workstream but is not "
                "marked verification_only"
            )

        if not isinstance(contract_path, str):
            errors.append(f"{location}.contract must be a repository path")
        elif not (ROOT / contract_path).is_file():
            errors.append(
                f"{location}.contract does not exist: {contract_path}"
            )

    duplicate_ids = sorted(
        value for value in set(connection_ids) if connection_ids.count(value) > 1
    )
    if duplicate_ids:
        errors.append("duplicate connection IDs: " + ", ".join(duplicate_ids))

    by_id = {
        connection.get("id"): connection
        for connection in raw_connections
        if isinstance(connection, dict) and isinstance(connection.get("id"), str)
    }
    required_central_links = {
        "event-ledger-to-nats": (
            "core/event-ledger-outbox",
            "platform/nats-jetstream",
            "nats_jetstream",
        ),
        "workers-to-temporal": (
            "core/workers-scheduler",
            "platform/temporal",
            "temporal_rpc",
        ),
    }
    for connection_id, expected_link in required_central_links.items():
        connection = by_id.get(connection_id)
        if connection is None:
            errors.append(f"required central connection is missing: {connection_id}")
            continue
        actual = (
            connection.get("source_branch"),
            connection.get("target_branch"),
            connection.get("transport"),
        )
        if actual != expected_link:
            errors.append(
                f"{connection_id} must connect {expected_link[0]} to {expected_link[1]} "
                f"using {expected_link[2]}"
            )

    central_rabbitmq_links = [
        connection.get("id")
        for connection in raw_connections
        if isinstance(connection, dict)
        and connection.get("target_branch") == "platform/rabbitmq"
    ]
    if central_rabbitmq_links:
        errors.append(
            "RabbitMQ is provider-local and cannot be a central connection target: "
            + ", ".join(str(item) for item in central_rabbitmq_links)
        )

    provider_local_branches = {
        branch
        for branch, status in branch_status.items()
        if status == "provider_local_not_central_verification_only"
    }
    disconnected = sorted(branches - connected_branches - provider_local_branches)
    if disconnected:
        errors.append(
            "workstreams with no communication connection: "
            + ", ".join(disconnected)
        )

    validate_event_schema(errors)

    for required_path in (
        ROOT / "contracts" / "http-conventions.md",
        ROOT / "contracts" / "observability-conventions.md",
        ROOT / "docs" / "CONNECTIVITY-AND-COMMUNICATION.md",
    ):
        if not required_path.is_file():
            errors.append(
                f"missing contract documentation: {required_path.relative_to(ROOT)}"
            )

    if errors:
        return report(errors)

    print(
        "Connectivity contract validation passed: "
        f"{len(branches)} workstreams, "
        f"{len(raw_connections)} connections, "
        "one acyclic dependency graph."
    )
    return 0


def report(errors: list[str]) -> int:
    print("Connectivity contract validation failed:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
