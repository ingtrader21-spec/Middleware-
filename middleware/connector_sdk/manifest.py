"""Load, validate, and hash Codestra Connector SDK v1 manifests."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import ManifestValidationError, StandardsValidationError
from .models import (
    AuthenticationPolicy,
    CommandPolicy,
    ConnectorCell,
    ConnectorManifest,
    EventPolicy,
    RetryPolicy,
    RuntimeBinding,
    WebhookPolicy,
)
from .standards import SemanticVersion, is_secret_key_name, normalized_key

CONNECTOR_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
PREFIX = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*\.$")
EVENT = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*\.v[1-9][0-9]*$")
CAPABILITY = re.compile(r"^(?:NONE|[A-Z][A-Z0-9_]*)$")
HEADER = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$")
FAMILY = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
SECRET_REF = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
AUDIENCE = re.compile(r"^[A-Za-z0-9._:/-]{1,200}$")
SCOPE = re.compile(r"^[a-z0-9]+(?:[.:-][a-z0-9-]+)*$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@/{}/-]*$")
JWT_LIKE = re.compile(r"^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
REQUIRED_FORBIDDEN_PAYLOAD_KEYS = {
    "access_token",
    "client_secret",
    "password",
    "private_key",
    "provider_token",
    "refresh_token",
}
ALLOWED_TOP_LEVEL = {
    "$schema",
    "manifest_version",
    "connector_id",
    "display_name",
    "version",
    "cell",
    "repository",
    "enabled_by_default",
    "direct_n8n_access",
    "runtime_binding",
    "authentication",
    "commands",
    "events",
    "webhooks",
    "forbidden_command_prefixes",
    "forbidden_payload_keys",
    "workflow_families",
    "metadata",
}


def _object(value: Any, label: str, errors: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{label} must be an object")
        return {}
    return value


def _array(value: Any, label: str, errors: list[str]) -> list[Any]:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array")
        return []
    return value


def _string(
    data: Mapping[str, Any],
    key: str,
    label: str,
    errors: list[str],
) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        errors.append(f"{label}.{key} must be a non-empty string")
        return ""
    return value


def _integer(
    data: Mapping[str, Any],
    key: str,
    label: str,
    errors: list[str],
    minimum: int,
    maximum: int,
) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        errors.append(f"{label}.{key} must be an integer")
        return minimum
    if not minimum <= value <= maximum:
        errors.append(f"{label}.{key} must be between {minimum} and {maximum}")
    return value


def _number(
    data: Mapping[str, Any],
    key: str,
    label: str,
    errors: list[str],
    minimum: float,
    maximum: float,
) -> float:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{label}.{key} must be a number")
        return minimum
    number = float(value)
    if not minimum <= number <= maximum:
        errors.append(f"{label}.{key} must be between {minimum} and {maximum}")
    return number


def _secret_errors(value: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if is_secret_key_name(str(key)):
                errors.append(
                    f"{child_path} is secret material; use an external secret reference"
                )
            errors.extend(_secret_errors(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(_secret_errors(child, f"{path}[{index}]"))
    elif isinstance(value, str):
        if "-----BEGIN" in value and "PRIVATE KEY-----" in value:
            errors.append(f"{path} appears to contain private-key material")
        elif JWT_LIKE.fullmatch(value):
            errors.append(f"{path} appears to contain a bearer token")
    return errors


def _safe_path(
    value: str,
    label: str,
    errors: list[str],
    allow_operation_template: bool,
) -> None:
    if not value.startswith("/") or value.startswith("//"):
        errors.append(f"{label} must start with exactly one slash")
    if "%" in value:
        errors.append(f"{label} must be canonical and cannot be percent-encoded")
    if "?" in value or "#" in value or "\\" in value:
        errors.append(f"{label} contains a forbidden delimiter")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        errors.append(f"{label} contains an ASCII control character")
    if "//" in value:
        errors.append(f"{label} contains an empty path segment")
    if any(part in {".", ".."} for part in value.split("/")):
        errors.append(f"{label} contains a dot path segment")
    if SAFE_PATH.fullmatch(value) is None:
        errors.append(f"{label} contains a non-canonical path character")
    placeholders = re.findall(r"\{[^{}]+\}", value)
    if allow_operation_template:
        if placeholders != ["{operation_id}"]:
            errors.append(
                f"{label} must contain exactly one {{operation_id}} placeholder"
            )
    elif placeholders or "{" in value or "}" in value:
        errors.append(f"{label} cannot contain a path placeholder")


def _safe_base_url(value: str, status: str, errors: list[str]) -> None:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        errors.append("runtime_binding.base_url is malformed")
        return
    if parsed.scheme != "https" or not parsed.hostname:
        errors.append("runtime_binding.base_url must be an absolute HTTPS origin")
        return
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        errors.append(
            "runtime_binding.base_url cannot contain userinfo, query, or fragment"
        )
    if parsed.path not in {"", "/"}:
        errors.append("runtime_binding.base_url must be an origin without a path")
    hostname = parsed.hostname.lower()
    placeholder = hostname.endswith(".invalid")
    if status == "UNVERIFIED_TEMPLATE_ONLY" and not placeholder:
        errors.append(
            "unverified runtime bindings must use a reserved .invalid hostname"
        )
    if status == "VERIFIED" and placeholder:
        errors.append("verified runtime bindings cannot use a .invalid hostname")


def _unique_strings(
    values: list[Any],
    label: str,
    errors: list[str],
) -> tuple[str, ...]:
    output = tuple(item for item in values if isinstance(item, str) and item)
    if len(output) != len(values):
        errors.append(f"{label} entries must be non-empty strings")
    if len(set(output)) != len(output):
        errors.append(f"{label} entries must be unique")
    return output


def parse_manifest(data: Mapping[str, Any]) -> ConnectorManifest:
    if not isinstance(data, Mapping):
        raise ManifestValidationError(["manifest must be an object"])

    errors = _secret_errors(data)
    unexpected = sorted(set(data) - ALLOWED_TOP_LEVEL)
    if unexpected:
        errors.append("unexpected top-level fields: " + ", ".join(unexpected))

    manifest_version = _string(data, "manifest_version", "$", errors)
    if manifest_version != "1.0":
        errors.append("manifest_version must equal 1.0")

    connector_id = _string(data, "connector_id", "$", errors)
    if connector_id and CONNECTOR_ID.fullmatch(connector_id) is None:
        errors.append("connector_id must be lowercase kebab-case")

    display_name = _string(data, "display_name", "$", errors)
    if len(display_name) > 120:
        errors.append("display_name exceeds 120 characters")

    version = _string(data, "version", "$", errors)
    if version:
        try:
            SemanticVersion.parse(version)
        except StandardsValidationError as error:
            errors.append(str(error))

    repository = _string(data, "repository", "$", errors)
    if repository and REPOSITORY.fullmatch(repository) is None:
        errors.append("repository must be owner/name")

    raw_cell = _string(data, "cell", "$", errors)
    try:
        cell = ConnectorCell(raw_cell)
    except ValueError:
        errors.append("cell is not a supported isolation cell")
        cell = ConnectorCell.CORE_COMMUNICATIONS

    if data.get("enabled_by_default") is not False:
        errors.append("enabled_by_default must be false")
    if data.get("direct_n8n_access") is not False:
        errors.append("direct_n8n_access must be false")

    binding = _object(data.get("runtime_binding"), "runtime_binding", errors)
    status = _string(binding, "status", "runtime_binding", errors)
    if status not in {"UNVERIFIED_TEMPLATE_ONLY", "VERIFIED"}:
        errors.append("runtime_binding.status is unsupported")
    base_url = _string(binding, "base_url", "runtime_binding", errors)
    if base_url:
        _safe_base_url(base_url, status, errors)
    health_path = _string(binding, "health_path", "runtime_binding", errors)
    operation_template = _string(
        binding,
        "operation_path_template",
        "runtime_binding",
        errors,
    )
    if health_path:
        _safe_path(
            health_path,
            "runtime_binding.health_path",
            errors,
            False,
        )
    if operation_template:
        _safe_path(
            operation_template,
            "runtime_binding.operation_path_template",
            errors,
            True,
        )

    authentication = _object(
        data.get("authentication"),
        "authentication",
        errors,
    )
    auth_type = _string(authentication, "type", "authentication", errors)
    if auth_type not in {
        "oauth2-client-credentials",
        "oauth2-plus-mtls",
        "mtls",
    }:
        errors.append("authentication.type is unsupported")

    audience = _string(authentication, "audience", "authentication", errors)
    if audience and AUDIENCE.fullmatch(audience) is None:
        errors.append("authentication.audience is invalid")

    scopes = _unique_strings(
        _array(authentication.get("scopes"), "authentication.scopes", errors),
        "authentication.scopes",
        errors,
    )
    if not scopes:
        errors.append("authentication.scopes cannot be empty")
    for scope in scopes:
        if SCOPE.fullmatch(scope) is None:
            errors.append(f"invalid OAuth scope: {scope}")

    secret_references = _unique_strings(
        _array(
            authentication.get("secret_references"),
            "authentication.secret_references",
            errors,
        ),
        "authentication.secret_references",
        errors,
    )
    if not secret_references:
        errors.append("authentication.secret_references cannot be empty")
    for reference in secret_references:
        if SECRET_REF.fullmatch(reference) is None:
            errors.append(f"invalid secret reference alias: {reference}")

    command_policies: list[CommandPolicy] = []
    seen_prefixes: set[str] = set()
    for index, raw in enumerate(_array(data.get("commands"), "commands", errors)):
        label = f"commands[{index}]"
        command = _object(raw, label, errors)
        prefix = _string(command, "prefix", label, errors)
        if prefix and PREFIX.fullmatch(prefix) is None:
            errors.append(f"{label}.prefix is invalid")
        if prefix in seen_prefixes:
            errors.append(f"duplicate command prefix: {prefix}")
        seen_prefixes.add(prefix)

        capability = _string(
            command,
            "required_capability",
            label,
            errors,
        )
        if capability and CAPABILITY.fullmatch(capability) is None:
            errors.append(f"{label}.required_capability is invalid")

        timeout = _integer(
            command,
            "timeout_seconds",
            label,
            errors,
            1,
            300,
        )
        if not isinstance(command.get("readback_required"), bool):
            errors.append(f"{label}.readback_required must be boolean")

        retry = _object(
            command.get("retry_policy"),
            f"{label}.retry_policy",
            errors,
        )
        maximum_attempts = _integer(
            retry,
            "maximum_attempts",
            f"{label}.retry_policy",
            errors,
            1,
            20,
        )
        initial = _number(
            retry,
            "initial_backoff_seconds",
            f"{label}.retry_policy",
            errors,
            0,
            3600,
        )
        maximum = _number(
            retry,
            "maximum_backoff_seconds",
            f"{label}.retry_policy",
            errors,
            0,
            86400,
        )
        jitter = _number(
            retry,
            "jitter_ratio",
            f"{label}.retry_policy",
            errors,
            0,
            1,
        )
        if maximum < initial:
            errors.append(
                f"{label}.retry_policy maximum backoff is below initial"
            )
        if retry.get("unknown_outcome_requires_readback") is not True:
            errors.append(
                f"{label}.retry_policy."
                "unknown_outcome_requires_readback must be true"
            )

        command_policies.append(
            CommandPolicy(
                prefix=prefix,
                required_capability=capability,
                timeout_seconds=timeout,
                readback_required=command.get("readback_required") is True,
                retry_policy=RetryPolicy(
                    maximum_attempts=maximum_attempts,
                    initial_backoff_seconds=initial,
                    maximum_backoff_seconds=maximum,
                    jitter_ratio=jitter,
                    unknown_outcome_requires_readback=True,
                ),
            )
        )
    if not command_policies:
        errors.append("commands cannot be empty")

    event_policies: list[EventPolicy] = []
    seen_events: set[str] = set()
    for index, raw in enumerate(_array(data.get("events"), "events", errors)):
        label = f"events[{index}]"
        event = _object(raw, label, errors)
        event_type = _string(event, "event_type", label, errors)
        direction = _string(event, "direction", label, errors)
        if event_type and EVENT.fullmatch(event_type) is None:
            errors.append(f"{label}.event_type is invalid")
        if event_type in seen_events:
            errors.append(f"duplicate event type: {event_type}")
        seen_events.add(event_type)
        if direction not in {"inbound", "outbound"}:
            errors.append(f"{label}.direction is unsupported")
        event_policies.append(
            EventPolicy(event_type=event_type, direction=direction)
        )

    webhook_policies: list[WebhookPolicy] = []
    seen_endpoints: set[str] = set()
    seen_routes: set[str] = set()
    for index, raw in enumerate(_array(data.get("webhooks"), "webhooks", errors)):
        label = f"webhooks[{index}]"
        webhook = _object(raw, label, errors)

        endpoint_key = _string(webhook, "endpoint_key", label, errors)
        if endpoint_key and CONNECTOR_ID.fullmatch(endpoint_key) is None:
            errors.append(f"{label}.endpoint_key must be kebab-case")

        route_path = _string(webhook, "route_path", label, errors)
        if route_path:
            _safe_path(route_path, f"{label}.route_path", errors, False)
            if not route_path.startswith(
                ("/v1/webhooks/", "/internal/v1/adapters/")
            ):
                errors.append(f"{label}.route_path uses an unapproved prefix")

        if endpoint_key in seen_endpoints:
            errors.append(f"duplicate endpoint key: {endpoint_key}")
        if route_path in seen_routes:
            errors.append(f"duplicate webhook route: {route_path}")
        seen_endpoints.add(endpoint_key)
        seen_routes.add(route_path)

        algorithm = _string(
            webhook,
            "signature_algorithm",
            label,
            errors,
        )
        if algorithm != "hmac-sha256":
            errors.append(
                f"{label}.signature_algorithm must be hmac-sha256"
            )

        headers: dict[str, str] = {}
        for key in (
            "signature_header",
            "timestamp_header",
            "event_id_header",
        ):
            value = _string(webhook, key, label, errors)
            headers[key] = value
            if value and HEADER.fullmatch(value) is None:
                errors.append(f"{label}.{key} is invalid")
        lowered_headers = [value.lower() for value in headers.values() if value]
        if len(lowered_headers) != len(set(lowered_headers)):
            errors.append(f"{label} webhook header names must be distinct")

        skew = _integer(
            webhook,
            "maximum_clock_skew_seconds",
            label,
            errors,
            30,
            900,
        )
        body_limit = _integer(
            webhook,
            "maximum_body_bytes",
            label,
            errors,
            1,
            10 * 1024 * 1024,
        )
        ack = _integer(
            webhook,
            "acknowledgement_deadline_seconds",
            label,
            errors,
            1,
            30,
        )
        secret_reference = _string(
            webhook,
            "secret_reference",
            label,
            errors,
        )
        if (
            secret_reference
            and SECRET_REF.fullmatch(secret_reference) is None
        ):
            errors.append(f"{label}.secret_reference is invalid")

        webhook_policies.append(
            WebhookPolicy(
                endpoint_key=endpoint_key,
                route_path=route_path,
                signature_algorithm=algorithm,
                signature_header=headers["signature_header"],
                timestamp_header=headers["timestamp_header"],
                event_id_header=headers["event_id_header"],
                maximum_clock_skew_seconds=skew,
                maximum_body_bytes=body_limit,
                acknowledgement_deadline_seconds=ack,
                secret_reference=secret_reference,
            )
        )

    forbidden_prefixes = _unique_strings(
        _array(
            data.get("forbidden_command_prefixes", []),
            "forbidden_command_prefixes",
            errors,
        ),
        "forbidden_command_prefixes",
        errors,
    )
    for prefix in forbidden_prefixes:
        if PREFIX.fullmatch(prefix) is None:
            errors.append(f"invalid forbidden command prefix: {prefix}")
    for allowed in seen_prefixes:
        for forbidden in forbidden_prefixes:
            if allowed.startswith(forbidden) or forbidden.startswith(allowed):
                errors.append(
                    f"allowed command prefix {allowed} overlaps "
                    f"forbidden prefix {forbidden}"
                )

    forbidden_payload_keys = _unique_strings(
        _array(
            data.get("forbidden_payload_keys"),
            "forbidden_payload_keys",
            errors,
        ),
        "forbidden_payload_keys",
        errors,
    )
    normalized_payload_keys = {
        normalized_key(item) for item in forbidden_payload_keys
    }
    missing = sorted(
        normalized_key(item)
        for item in REQUIRED_FORBIDDEN_PAYLOAD_KEYS
        if normalized_key(item) not in normalized_payload_keys
    )
    if missing:
        errors.append(
            "forbidden_payload_keys is missing normalized keys: "
            + ", ".join(missing)
        )

    workflow_families = _unique_strings(
        _array(
            data.get("workflow_families"),
            "workflow_families",
            errors,
        ),
        "workflow_families",
        errors,
    )
    if not workflow_families:
        errors.append("workflow_families cannot be empty")
    for family in workflow_families:
        if FAMILY.fullmatch(family) is None:
            errors.append(f"invalid workflow family: {family}")

    metadata = data.get("metadata", {})
    if not isinstance(metadata, Mapping):
        errors.append("metadata must be an object")
        metadata = {}

    if errors:
        raise ManifestValidationError(errors)

    return ConnectorManifest(
        manifest_version=manifest_version,
        connector_id=connector_id,
        display_name=display_name,
        version=version,
        cell=cell,
        repository=repository,
        enabled_by_default=False,
        direct_n8n_access=False,
        runtime_binding=RuntimeBinding(
            status=status,
            base_url=base_url,
            health_path=health_path,
            operation_path_template=operation_template,
        ),
        authentication=AuthenticationPolicy(
            type=auth_type,
            audience=audience,
            scopes=scopes,
            secret_references=secret_references,
        ),
        command_policies=tuple(command_policies),
        event_policies=tuple(event_policies),
        webhook_policies=tuple(webhook_policies),
        forbidden_command_prefixes=forbidden_prefixes,
        forbidden_payload_keys=forbidden_payload_keys,
        workflow_families=workflow_families,
        metadata=metadata,
    )


def load_manifest(path: Path) -> ConnectorManifest:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ManifestValidationError(
            [f"cannot read manifest {path}: {error}"]
        ) from error
    if not isinstance(raw, Mapping):
        raise ManifestValidationError(
            ["manifest must contain a JSON object"]
        )
    return parse_manifest(raw)


def canonical_manifest_json(data: Mapping[str, Any]) -> bytes:
    parse_manifest(data)
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def manifest_digest(data: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_manifest_json(data)
    ).hexdigest()
