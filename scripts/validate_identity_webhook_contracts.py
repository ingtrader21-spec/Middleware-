#!/usr/bin/env python3
"""Validate canonical Codestra identity, API, webhook, and source-readiness contracts."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Never, cast

ROOT = Path(__file__).resolve().parents[1]
CANONICAL_ISSUER = "https://auth.codestra.co/realms/codestra"
IDENTITY_UPSTREAM_REVIEW_SHA = "85738deb86c409208b0ec17e1f017d78586eed25"
WEBHOOK_UPSTREAM_REVIEW_SHA = "187d058423dc7703deee9132f4a750222b3d974b"
WEBHOOK_LIFECYCLE_MERGE_SHA = "922d039b5143f3ac738e88998036355562a8dd5d"
EXPECTED_CLIENTS = [
    "kong-gateway",
    "middleware-api",
    "middleware-worker",
    "codestra-ai",
    "codestra-communication",
    "codestra-marketing",
    "codestra-social",
    "ai-provider-adapter",
    "marketing-provider-adapter",
    "odoo-integration",
    "n8n-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
    "provisioning-service",
    "monitoring-readonly",
]
EXPECTED_WEBHOOK_PRODUCERS = {
    "odoo-integration",
    "n8n-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
}
EXPECTED_REQUIRED_HEADERS = {
    "Authorization",
    "Content-Type",
    "Idempotency-Key",
    "X-Codestra-Event-Id",
    "X-Codestra-Event-Type",
    "X-Codestra-Source",
    "X-Codestra-Tenant-Id",
    "X-Codestra-Timestamp",
    "X-Codestra-Signature",
    "X-Correlation-Id",
}
EXPECTED_REQUIRED_HEADER_ORDER = [
    "Authorization",
    "Content-Type",
    "Idempotency-Key",
    "X-Codestra-Event-Id",
    "X-Codestra-Event-Type",
    "X-Codestra-Source",
    "X-Codestra-Tenant-Id",
    "X-Codestra-Timestamp",
    "X-Codestra-Signature",
    "X-Correlation-Id",
]
EXPECTED_ENVELOPE_REQUIRED = [
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
]
EXPECTED_GRANTS: dict[tuple[str, str], set[str]] = {
    ("kong-gateway", "middleware-api"): {
        "middleware.request.forward",
        "middleware.status.read",
    },
    ("middleware-worker", "middleware-api"): {
        "delivery.retry",
        "dlq.replay",
        "inbox.process",
        "outbox.dispatch",
    },
    ("codestra-ai", "middleware-api"): {
        "ai.inference.request",
    },
    ("codestra-communication", "middleware-api"): {
        "communication.email.request",
        "communication.sms.request",
    },
    ("codestra-marketing", "middleware-api"): {
        "marketing.campaign.request",
    },
    ("codestra-social", "middleware-api"): {
        "social.publish.request",
    },
    ("odoo-integration", "middleware-api"): {
        "odoo.delivery.result.publish",
        "odoo.events.publish",
    },
    ("middleware-api", "odoo-integration"): {
        "odoo.activities.write",
        "odoo.leads.read",
        "odoo.leads.write",
    },
    ("middleware-api", "n8n-automation"): {
        "workflow.status.read",
        "workflow.trigger",
    },
    ("n8n-automation", "middleware-api"): {
        "middleware.request.forward",
        "middleware.status.read",
        "workflow.result.publish",
    },
    ("vicidial-adapter", "middleware-api"): {
        "callbacks.update",
        "recordings.metadata.publish",
        "telephony.events.publish",
    },
    ("middleware-api", "vicidial-adapter"): {
        "callbacks.dispatch",
        "telephony.commands.write",
    },
    ("middleware-worker", "telnexa-gateway"): {
        "sms.send",
        "sms.status.read",
    },
    ("telnexa-gateway", "middleware-api"): {
        "sms.events.publish",
        "sms.inbound.publish",
    },
    ("middleware-worker", "klyrow-gateway"): {
        "email.send",
        "email.status.read",
    },
    ("klyrow-gateway", "middleware-api"): {
        "email.events.publish",
        "email.inbound.publish",
    },
    ("middleware-api", "kyqra-gateway"): {
        "crawler.jobs.read",
        "crawler.jobs.submit",
        "crawler.results.read",
    },
    ("kyqra-gateway", "middleware-api"): {
        "crawler.progress.publish",
        "crawler.results.publish",
    },
    ("middleware-worker", "postly-adapter"): {
        "social.publish",
        "social.status.read",
    },
    ("middleware-worker", "ai-provider-adapter"): {
        "ai.provider.dispatch",
        "ai.provider.status.read",
    },
    ("middleware-worker", "marketing-provider-adapter"): {
        "marketing.provider.dispatch",
        "marketing.provider.status.read",
    },
    ("postly-adapter", "middleware-api"): {
        "social.events.publish",
    },
    ("provisioning-service", "middleware-api"): {
        "identity.request",
        "integration.configure",
        "tenant.provision",
    },
    ("monitoring-readonly", "kong-gateway"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "middleware-api"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "odoo-integration"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "n8n-automation"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "vicidial-adapter"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "telnexa-gateway"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "klyrow-gateway"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "kyqra-gateway"): {
        "health.read",
        "metrics.read",
    },
    ("monitoring-readonly", "postly-adapter"): {
        "health.read",
        "metrics.read",
    },
}
ALLOWED_SOURCE_STATES = {
    "contract-only",
    "contract-source-missing",
    "adapter-source-missing",
    "workflow-source-missing",
    "adapter-present-runtime-unverified",
    "gateway-present-runtime-unverified",
    "repository-unconfirmed",
}
RESOURCE_BASE_URL = re.compile(r"^[A-Z][A-Z0-9_]*_BASE_URL$")
SCOPE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
EVENT_TYPE = re.compile(r"^codestra\.[a-z0-9_]+(?:\.[a-z0-9_]+)+$")
CLIENT_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
WEBHOOK_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
WEBHOOK_PATH = re.compile(r"^/api/v1/[a-z0-9-]+(?:/[a-z0-9-]+)*$")
REPOSITORY = re.compile(r"^(?:ingtrader21-spec|appolon1908-hue)/[A-Za-z0-9_.-]+$")
ACCESS_FIELDS = {
    "schemaVersion",
    "upstreamContract",
    "issuer",
    "tokenEndpoint",
    "jwksUri",
    "machineTokenPolicy",
    "services",
    "grants",
    "prohibitedDirectTargets",
    "administrativeBoundaries",
}
WEBHOOK_FIELDS = {
    "schemaVersion",
    "upstreamContract",
    "issuer",
    "consumerClientId",
    "consumerBaseUrlEnvironment",
    "eventEnvelopeSchema",
    "security",
    "webhooks",
    "lifecycleContract",
}
TOKEN_POLICY_FIELDS = {
    "grantType",
    "maximumAccessTokenLifetimeSeconds",
    "refreshTokensAllowed",
    "fullScopeAllowed",
    "requiredClaims",
}
SERVICE_FIELDS = {
    "clientId",
    "workstream",
    "repository",
    "sourceState",
    "resourceServer",
    "audience",
}
GRANT_FIELDS = {"callerClientId", "targetClientId", "audience", "scopes"}
WEBHOOK_RECORD_FIELDS = {
    "id",
    "producerClientId",
    "consumerClientId",
    "audience",
    "requiredScope",
    "path",
    "eventTypes",
    "delivery",
}
SECURITY_FIELDS = {
    "authorization",
    "signatureAlgorithm",
    "signatureVersion",
    "maximumClockSkewSeconds",
    "replayRetentionSeconds",
    "canonicalSignatureFields",
    "requiredHeaders",
    "contentType",
    "signatureHeaderFormat",
    "idempotencyKeySource",
}
CONNECTIVITY_FIELDS = {
    "version",
    "canonical_contract_branch",
    "canonical_event_schema",
    "http_conventions",
    "observability_conventions",
    "policies",
    "workstream_dependencies",
    "connections",
}
CONNECTION_FIELDS = {
    "id",
    "source_branch",
    "target_branch",
    "direction",
    "transport",
    "authentication",
    "reliability",
    "owner_branch",
    "runtime_status",
    "contract",
}
CONNECTIVITY_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
WORKSTREAM = re.compile(r"^[a-z0-9-]+/[a-z0-9-]+$")
ALLOWED_CONNECTIVITY_CONTRACTS = {
    "contracts/beyvra-identity-provisioned.schema.json",
    "contracts/event-envelope.schema.json",
    "contracts/http-conventions.md",
    "contracts/observability-conventions.md",
}
ALLOWED_RUNTIME_STATES = {"declared", "verification_only"}
ALLOWED_CONNECTION_DIRECTIONS = {
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
ALLOWED_CONNECTION_TRANSPORTS = {
    "https",
    "internal",
    "nats_jetstream",
    "oidc_jwks",
    "postgresql",
    "prometheus_scrape",
    "redis",
    "temporal_rpc",
}
ALLOWED_CONNECTION_AUTHENTICATION = {
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
ALLOWED_CONNECTION_RELIABILITY = {
    "at_least_once",
    "best_effort_observation",
    "durable_inbox",
    "durable_workflow",
    "lease_retry",
    "read_only",
    "synchronous",
    "transactional_outbox",
}
EXPECTED_ENVELOPE_PROPERTIES: dict[str, object] = {
    "event_id": {"type": "string", "minLength": 1, "maxLength": 128},
    "event_type": {
        "type": "string",
        "pattern": EVENT_TYPE.pattern,
        "maxLength": 180,
    },
    "event_version": {"const": "1.0"},
    "occurred_at": {"type": "string", "format": "date-time"},
    "received_at": {"type": "string", "format": "date-time"},
    "source": {
        "type": "string",
        "pattern": CLIENT_ID.pattern,
        "maxLength": 100,
    },
    "tenant_id": {"type": "string", "minLength": 1, "maxLength": 128},
    "customer_id": {
        "type": ["string", "null"],
        "minLength": 1,
        "maxLength": 128,
    },
    "correlation_id": {"type": "string", "minLength": 1, "maxLength": 180},
    "causation_id": {"type": "string", "minLength": 1, "maxLength": 180},
    "idempotency_key": {"type": "string", "minLength": 8, "maxLength": 180},
    "payload": {"type": "object"},
    "metadata": {"type": "object", "maxProperties": 64},
}


class ContractError(RuntimeError):
    pass


def fail(message: str) -> Never:
    raise ContractError(message)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def reject_nonstandard_json_constant(value: str) -> Never:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as exc:
        fail(f"{path}: unable to load JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path}: document root must be an object")
    return cast(dict[str, Any], value)


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


def require_string_list(
    value: object,
    message: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    items = [require_string(item, message) for item in require_list(value, message)]
    if (not allow_empty and not items) or len(items) != len(set(items)):
        fail(message)
    return items


def require_exact_fields(
    value: dict[str, Any], expected: set[str], message: str
) -> None:
    if set(value) != expected:
        fail(message)


def exact_json_value(value: object, expected: object) -> bool:
    """Compare decoded JSON without Python's bool/int and int/float coercions."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        if not isinstance(value, dict) or set(value) != set(expected):
            return False
        return all(exact_json_value(value[key], item) for key, item in expected.items())
    if isinstance(expected, list):
        if not isinstance(value, list) or len(value) != len(expected):
            return False
        return all(
            exact_json_value(actual_item, expected_item)
            for actual_item, expected_item in zip(value, expected, strict=True)
        )
    return value == expected


def validate_upstream(
    value: object, expected_path: str, expected_sha: str, label: str
) -> None:
    upstream = require_object(value, f"{label}: upstreamContract must be an object")
    require_exact_fields(
        upstream,
        {"repository", "path", "reviewBranch", "reviewSha"},
        f"{label}: upstreamContract fields changed",
    )
    if upstream.get("repository") != "appolon1908-hue/Keycloak":
        fail(f"{label}: upstream repository must be appolon1908-hue/Keycloak")
    if upstream.get("path") != expected_path:
        fail(f"{label}: unexpected upstream path")
    if upstream.get("reviewBranch") != "feat/service-api-webhook-identity-contracts":
        fail(f"{label}: unexpected upstream review branch")
    if upstream.get("reviewSha") != expected_sha:
        fail(f"{label}: upstream review SHA must match approved source authority")


def validate_lifecycle_contract(value: object) -> None:
    lifecycle = require_object(value, "webhook lifecycleContract must be an object")
    require_exact_fields(
        lifecycle,
        {"repository", "path", "protectedBranch", "mergeSha"},
        "webhook lifecycleContract fields changed",
    )
    if lifecycle.get("repository") != "appolon1908-hue/Keycloak":
        fail("webhook lifecycle repository must be appolon1908-hue/Keycloak")
    if lifecycle.get("path") != "config/contracts/webhook-contracts.json":
        fail("webhook lifecycle path changed")
    if lifecycle.get("protectedBranch") != "main":
        fail("webhook lifecycle source must be protected main")
    if lifecycle.get("mergeSha") != WEBHOOK_LIFECYCLE_MERGE_SHA:
        fail("webhook lifecycle merge SHA must match approved protected-main authority")


def validate_access(
    access: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], set[str]]]:
    require_exact_fields(
        access, ACCESS_FIELDS, "identity-access-map.json fields changed"
    )
    if type(access.get("schemaVersion")) is not int or access["schemaVersion"] != 1:
        fail("identity-access-map.json: schemaVersion must be 1")
    validate_upstream(
        access.get("upstreamContract"),
        "config/contracts/service-access-matrix.json",
        IDENTITY_UPSTREAM_REVIEW_SHA,
        "identity-access-map.json",
    )
    if access.get("issuer") != CANONICAL_ISSUER:
        fail("identity-access-map.json: issuer is not canonical")
    if (
        access.get("tokenEndpoint")
        != f"{CANONICAL_ISSUER}/protocol/openid-connect/token"
    ):
        fail("identity-access-map.json: token endpoint is not canonical")
    if access.get("jwksUri") != f"{CANONICAL_ISSUER}/protocol/openid-connect/certs":
        fail("identity-access-map.json: JWKS URI is not canonical")

    token_policy = require_object(
        access.get("machineTokenPolicy"),
        "identity-access-map.json: machineTokenPolicy must be an object",
    )
    require_exact_fields(
        token_policy, TOKEN_POLICY_FIELDS, "machineTokenPolicy fields changed"
    )
    if token_policy.get("grantType") != "client_credentials":
        fail("machine identities must use client_credentials")
    lifetime = token_policy.get("maximumAccessTokenLifetimeSeconds")
    if type(lifetime) is not int or not 1 <= lifetime <= 300:
        fail("machine access-token lifetime must be 1..300 seconds")
    if token_policy.get("refreshTokensAllowed") is not False:
        fail("machine refresh tokens must be disabled")
    if token_policy.get("fullScopeAllowed") is not False:
        fail("machine full-scope mode must be disabled")
    if token_policy.get("requiredClaims") != [
        "iss",
        "sub",
        "aud",
        "azp",
        "iat",
        "exp",
        "jti",
        "scope",
    ]:
        fail("required machine-token claims changed")

    services = require_list(
        access.get("services"), "identity-access-map.json: services must be an array"
    )
    ids: list[str] = []
    service_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(services):
        service = require_object(raw, f"services[{index}] must be an object")
        resource_server = service.get("resourceServer")
        if type(resource_server) is not bool:
            fail(f"services[{index}]: resourceServer must be boolean")
        expected_fields = SERVICE_FIELDS | (
            {"baseUrlEnvironment"} if resource_server else set()
        )
        require_exact_fields(
            service, expected_fields, f"services[{index}] has an invalid shape"
        )
        client_id = require_string(
            service.get("clientId"), f"services[{index}] has an invalid clientId"
        )
        if CLIENT_ID.fullmatch(client_id) is None:
            fail(f"services[{index}] has an invalid clientId")
        if client_id not in EXPECTED_CLIENTS:
            fail(f"services[{index}] has an unknown clientId")
        if client_id in service_by_id:
            fail(f"duplicate service: {client_id}")
        if service.get("audience") != client_id:
            fail(f"{client_id}: audience must equal clientId")
        require_string(
            service.get("workstream"), f"{client_id}: workstream is required"
        )
        source_state = require_string(
            service.get("sourceState"), f"{client_id}: sourceState is required"
        )
        if source_state not in ALLOWED_SOURCE_STATES:
            fail(f"{client_id}: invalid or overclaimed sourceState {source_state!r}")
        repository = service.get("repository")
        if source_state == "repository-unconfirmed":
            if repository is not None:
                fail(f"{client_id}: repository-unconfirmed must not name a repository")
        elif source_state == "contract-only" and repository is None:
            pass
        elif (
            not isinstance(repository, str) or REPOSITORY.fullmatch(repository) is None
        ):
            fail(f"{client_id}: an explicit repository is required")
        if resource_server:
            variable = service.get("baseUrlEnvironment")
            if not isinstance(variable, str) or not RESOURCE_BASE_URL.fullmatch(
                variable
            ):
                fail(
                    f"{client_id}: resource server requires a *_BASE_URL runtime variable"
                )
        ids.append(client_id)
        service_by_id[client_id] = service
    if ids != EXPECTED_CLIENTS:
        fail("services must list every canonical machine client in canonical order")

    grants = require_list(
        access.get("grants"), "identity-access-map.json: grants must be an array"
    )
    if not grants:
        fail("identity-access-map.json: grants must be a non-empty array")
    grant_index: dict[tuple[str, str], set[str]] = {}
    for index, raw in enumerate(grants):
        grant = require_object(raw, f"grants[{index}] has an invalid shape")
        require_exact_fields(
            grant, GRANT_FIELDS, f"grants[{index}] has an invalid shape"
        )
        caller = require_string(
            grant.get("callerClientId"), f"grants[{index}] has an invalid caller"
        )
        target = require_string(
            grant.get("targetClientId"), f"grants[{index}] has an invalid target"
        )
        if (
            caller not in service_by_id
            or target not in service_by_id
            or caller == target
        ):
            fail(f"grants[{index}] has an invalid caller or target")
        if grant.get("audience") != target:
            fail(f"grants[{index}] audience must equal targetClientId")
        if not service_by_id[target]["resourceServer"]:
            fail(f"grants[{index}] target is not a resource server")
        scopes = require_string_list(
            grant.get("scopes"),
            f"grants[{index}] scopes must be sorted, unique, and explicit",
        )
        if scopes != sorted(scopes) or not all(
            SCOPE.fullmatch(scope) for scope in scopes
        ):
            fail(f"grants[{index}] scopes must be sorted, unique, and explicit")
        key = (caller, target)
        if key in grant_index:
            fail(f"duplicate caller-target grant: {caller}->{target}")
        grant_index[key] = set(scopes)

    if grant_index != EXPECTED_GRANTS:
        missing = sorted(set(EXPECTED_GRANTS) - set(grant_index))
        unexpected = sorted(set(grant_index) - set(EXPECTED_GRANTS))
        mismatched = sorted(
            (
                caller,
                target,
                sorted(EXPECTED_GRANTS[(caller, target)]),
                sorted(grant_index[(caller, target)]),
            )
            for caller, target in set(EXPECTED_GRANTS) & set(grant_index)
            if EXPECTED_GRANTS[(caller, target)] != grant_index[(caller, target)]
        )
        fail(
            "least-privilege grant matrix changed: "
            f"missing={missing}, unexpected={unexpected}, scope_mismatches={mismatched}"
        )

    expected_prohibited = {
        "n8n-automation": [
            "odoo-integration",
            "vicidial-adapter",
            "telnexa-gateway",
            "klyrow-gateway",
            "kyqra-gateway",
            "postly-adapter",
            "ai-provider-adapter",
            "marketing-provider-adapter",
        ]
    }
    if access.get("prohibitedDirectTargets") != expected_prohibited:
        fail("n8n direct-provider prohibition changed")
    for target in expected_prohibited["n8n-automation"]:
        if ("n8n-automation", target) in grant_index:
            fail(f"n8n must not receive a direct grant to {target}")

    for (caller, _target), granted_scopes in grant_index.items():
        if "*" in granted_scopes:
            fail("wildcard scopes are prohibited")
        if caller == "monitoring-readonly" and granted_scopes != {
            "health.read",
            "metrics.read",
        }:
            fail("monitoring-readonly may receive only health.read and metrics.read")

    boundaries = require_object(
        access.get("administrativeBoundaries"),
        "administrativeBoundaries must be an object",
    )
    require_exact_fields(
        boundaries,
        {"provisioning-service"},
        "administrative boundary inventory changed",
    )
    boundary = require_object(
        boundaries.get("provisioning-service"),
        "provisioning-service administrative boundary is missing",
    )
    require_exact_fields(
        boundary,
        {"keycloakAdminApiAccess", "prohibitedRealmManagementRoles"},
        "provisioning-service administrative boundary fields changed",
    )
    if boundary.get("keycloakAdminApiAccess") is not False:
        fail("provisioning-service must not receive Keycloak Admin API access")
    if boundary.get("prohibitedRealmManagementRoles") != [
        "realm-admin",
        "manage-realm",
        "manage-clients",
    ]:
        fail("provisioning-service realm-management prohibition changed")

    return service_by_id, grant_index


def validate_webhooks(
    webhooks: dict[str, Any],
    service_by_id: dict[str, dict[str, Any]],
    grant_index: dict[tuple[str, str], set[str]],
    root: Path,
) -> tuple[int, int]:
    require_exact_fields(
        webhooks, WEBHOOK_FIELDS, "api-webhook-contracts.json fields changed"
    )
    if (
        type(webhooks.get("schemaVersion")) is not int
        or webhooks["schemaVersion"] != 1
    ):
        fail("api-webhook-contracts.json: schemaVersion must be 1")
    validate_upstream(
        webhooks.get("upstreamContract"),
        "config/contracts/webhook-contracts.json",
        WEBHOOK_UPSTREAM_REVIEW_SHA,
        "api-webhook-contracts.json",
    )
    if webhooks.get("issuer") != CANONICAL_ISSUER:
        fail("api-webhook-contracts.json: issuer is not canonical")
    if webhooks.get("consumerClientId") != "middleware-api":
        fail("middleware-api must be the webhook consumer")
    if webhooks.get("consumerBaseUrlEnvironment") != "MIDDLEWARE_API_BASE_URL":
        fail("webhook consumer URL must use MIDDLEWARE_API_BASE_URL")
    validate_lifecycle_contract(webhooks.get("lifecycleContract"))
    schema_path = require_string(
        webhooks.get("eventEnvelopeSchema"),
        "webhooks must use the canonical event-envelope schema",
    )
    if schema_path != "contracts/platform/event-envelope.v1.schema.json":
        fail("webhooks must use the canonical event-envelope schema")
    schema = load_json(root / schema_path)
    require_exact_fields(
        schema,
        {
            "$schema",
            "$id",
            "title",
            "description",
            "type",
            "additionalProperties",
            "required",
            "properties",
        },
        "event envelope schema fields changed",
    )
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        fail("event envelope must use JSON Schema draft 2020-12")
    if (
        schema.get("$id")
        != "https://contracts.codestra.co/platform/event-envelope.v1.schema.json"
    ):
        fail("event envelope schema identity changed")
    if (
        schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        fail("event envelope must be a closed object schema")
    required = require_string_list(
        schema.get("required"), "event envelope required fields must be strings"
    )
    if required != EXPECTED_ENVELOPE_REQUIRED:
        fail("event envelope required field inventory changed")
    properties = require_object(
        schema.get("properties"), "event envelope properties must be an object"
    )
    event_type_schema = require_object(
        properties.get("event_type"), "event_type schema must be an object"
    )
    require_exact_fields(
        event_type_schema,
        {"type", "pattern", "maxLength"},
        "event_type schema fields changed",
    )
    if (
        event_type_schema.get("type") != "string"
        or event_type_schema.get("pattern") != EVENT_TYPE.pattern
        or event_type_schema.get("maxLength") != 180
    ):
        fail("event envelope type pattern must require the codestra namespace")
    if not exact_json_value(properties, EXPECTED_ENVELOPE_PROPERTIES):
        fail("event envelope property contracts changed")

    security = require_object(
        webhooks.get("security"), "webhook security policy is missing"
    )
    require_exact_fields(security, SECURITY_FIELDS, "webhook security fields changed")
    if security.get("authorization") != "oidc_bearer":
        fail("webhooks must require an OIDC bearer token")
    if security.get("signatureAlgorithm") != "hmac-sha256":
        fail("webhooks must use HMAC-SHA256")
    if security.get("signatureVersion") != "v1":
        fail("webhook signature version must be v1")
    clock_skew = security.get("maximumClockSkewSeconds")
    if type(clock_skew) is not int or clock_skew != 300:
        fail("webhook maximum clock skew must be 300 seconds")
    retention = security.get("replayRetentionSeconds")
    if type(retention) is not int or retention < 86400:
        fail("webhook replay retention must be at least 24 hours")
    required_headers = require_string_list(
        security.get("requiredHeaders"), "webhook required header set changed"
    )
    if (
        required_headers != EXPECTED_REQUIRED_HEADER_ORDER
        or set(required_headers) != EXPECTED_REQUIRED_HEADERS
    ):
        fail("webhook required header set changed")
    if security.get("canonicalSignatureFields") != [
        "version",
        "method",
        "path",
        "timestamp",
        "eventId",
        "sourceClientId",
        "bodySha256",
    ]:
        fail("webhook canonical signature fields changed")
    if security.get("signatureHeaderFormat") != "sha256=<lowercase-hex>":
        fail("webhook signature header format changed")
    if security.get("idempotencyKeySource") != "X-Codestra-Event-Id":
        fail("webhook idempotency source must be X-Codestra-Event-Id")
    if security.get("contentType") != "application/json":
        fail("webhook content type must be application/json")

    hooks = require_list(
        webhooks.get("webhooks"),
        "api-webhook-contracts.json: webhooks must be an array",
    )
    if not hooks:
        fail("api-webhook-contracts.json: webhooks must be a non-empty array")
    producers: set[str] = set()
    hook_ids: set[str] = set()
    paths: set[str] = set()
    event_types: set[str] = set()
    for index, raw in enumerate(hooks):
        hook = require_object(raw, f"webhooks[{index}] has an invalid shape")
        require_exact_fields(
            hook, WEBHOOK_RECORD_FIELDS, f"webhooks[{index}] has an invalid shape"
        )
        hook_id = require_string(
            hook.get("id"), f"webhooks[{index}] has a duplicate or invalid id"
        )
        if WEBHOOK_ID.fullmatch(hook_id) is None or hook_id in hook_ids:
            fail(f"webhooks[{index}] has a duplicate or invalid id")
        hook_ids.add(hook_id)
        producer = require_string(
            hook.get("producerClientId"),
            f"webhooks[{index}] has an invalid producer or consumer",
        )
        consumer = require_string(
            hook.get("consumerClientId"),
            f"webhooks[{index}] has an invalid producer or consumer",
        )
        if producer not in service_by_id or consumer != "middleware-api":
            fail(f"webhooks[{index}] has an invalid producer or consumer")
        if hook.get("audience") != "middleware-api":
            fail(f"webhooks[{index}] must target the middleware-api audience")
        scope = require_string(
            hook.get("requiredScope"), f"webhooks[{index}] required scope is invalid"
        )
        if scope not in grant_index.get((producer, consumer), set()):
            fail(f"webhooks[{index}] required scope is not granted")
        path = require_string(
            hook.get("path"),
            f"webhooks[{index}] has an invalid or duplicate relative path",
        )
        if WEBHOOK_PATH.fullmatch(path) is None or path in paths:
            fail(f"webhooks[{index}] has an invalid or duplicate relative path")
        paths.add(path)
        if hook.get("delivery") != "at_least_once":
            fail(f"webhooks[{index}] must use at_least_once delivery")
        values = require_string_list(
            hook.get("eventTypes"),
            f"webhooks[{index}] event types must be sorted and unique",
        )
        if values != sorted(values):
            fail(f"webhooks[{index}] event types must be sorted and unique")
        for event_type in values:
            if EVENT_TYPE.fullmatch(event_type) is None:
                fail(f"webhooks[{index}] has a non-canonical event type")
            if event_type in event_types:
                fail(f"duplicate event type: {event_type}")
            event_types.add(event_type)
        producers.add(producer)
    if producers != EXPECTED_WEBHOOK_PRODUCERS:
        fail(
            "every adapter/provider must publish a webhook contract: "
            f"expected {sorted(EXPECTED_WEBHOOK_PRODUCERS)}, found {sorted(producers)}"
        )

    connectivity = load_json(root / "config/connectivity-map.json")
    require_exact_fields(
        connectivity, CONNECTIVITY_FIELDS, "connectivity-map.json fields changed"
    )
    if type(connectivity.get("version")) is not int or connectivity["version"] != 2:
        fail("connectivity map version must be 2")
    if connectivity.get("canonical_contract_branch") != "core/integration-contracts":
        fail("connectivity canonical contract branch changed")
    if connectivity.get("canonical_event_schema") != schema_path:
        fail("connectivity canonical event schema drifted from webhook authority")
    if connectivity.get("http_conventions") != "contracts/http-conventions.md":
        fail("connectivity HTTP conventions path changed")
    if (
        connectivity.get("observability_conventions")
        != "contracts/observability-conventions.md"
    ):
        fail("connectivity observability conventions path changed")
    policies = require_object(
        connectivity.get("policies"), "connectivity policies must be an object"
    )
    expected_policy = {
        "all_workstreams_must_depend_on_canonical_contracts": True,
        "all_links_require_explicit_authentication": True,
        "all_effectful_delivery_requires_idempotency": True,
        "webhooks_require_signature_timestamp_and_replay_protection": True,
        "tenant_correlation_and_causation_metadata_required": True,
        "external_effects_disabled_by_default": True,
        "runtime_verification_required_before_activation": True,
        "direct_deployment_from_workstream_branches": False,
    }
    require_exact_fields(
        policies, set(expected_policy), "connectivity policy inventory changed"
    )
    for key, expected in expected_policy.items():
        if policies.get(key) is not expected:
            fail(f"connectivity policy {key} must be {expected!r}")
    dependencies = require_object(
        connectivity.get("workstream_dependencies"),
        "connectivity workstream dependencies must be an object",
    )
    dependency_index: dict[str, list[str]] = {}
    for workstream, raw_dependencies in dependencies.items():
        if WORKSTREAM.fullmatch(workstream) is None:
            fail("connectivity workstream name must be canonical")
        values = require_string_list(
            raw_dependencies,
            f"{workstream}: dependencies must be unique strings",
            allow_empty=True,
        )
        dependency_index[workstream] = values
    canonical_workstream = "core/integration-contracts"
    if dependency_index.get(canonical_workstream) != []:
        fail("canonical contract workstream must have no dependencies")
    for workstream, values in dependency_index.items():
        if workstream != canonical_workstream and canonical_workstream not in values:
            fail(f"{workstream} must depend on {canonical_workstream}")
        unknown = sorted(set(values) - set(dependency_index))
        if unknown:
            fail(f"{workstream} has unknown dependencies: {unknown}")

    connections = require_list(
        connectivity.get("connections"), "connectivity connections must be an array"
    )
    if not connections:
        fail("connectivity connections must be a non-empty array")
    connection_ids: set[str] = set()
    for index, raw in enumerate(connections):
        connection = require_object(raw, f"connections[{index}] must be an object")
        require_exact_fields(
            connection,
            CONNECTION_FIELDS,
            f"connections[{index}] fields changed",
        )
        connection_id = require_string(
            connection.get("id"), f"connections[{index}] has an invalid id"
        )
        if (
            CONNECTIVITY_ID.fullmatch(connection_id) is None
            or connection_id in connection_ids
        ):
            fail(f"connections[{index}] has an invalid or duplicate id")
        connection_ids.add(connection_id)
        source = require_string(
            connection.get("source_branch"),
            f"connections[{index}] has an invalid source branch",
        )
        target = require_string(
            connection.get("target_branch"),
            f"connections[{index}] has an invalid target branch",
        )
        owner = require_string(
            connection.get("owner_branch"),
            f"connections[{index}] has an invalid owner branch",
        )
        if source not in dependency_index or target not in dependency_index:
            fail(f"connections[{index}] references an unknown workstream")
        if source == target or owner not in {source, target}:
            fail(f"connections[{index}] has an invalid source, target, or owner")
        enum_fields = {
            "direction": ALLOWED_CONNECTION_DIRECTIONS,
            "transport": ALLOWED_CONNECTION_TRANSPORTS,
            "reliability": ALLOWED_CONNECTION_RELIABILITY,
        }
        for field, allowed_values in enum_fields.items():
            item = require_string(
                connection.get(field),
                f"connections[{index}] has an invalid {field}",
            )
            if item not in allowed_values:
                fail(f"connections[{index}] has an invalid {field}")
        authentication = require_string(
            connection.get("authentication"),
            f"connections[{index}] requires explicit authentication",
        )
        if authentication not in ALLOWED_CONNECTION_AUTHENTICATION:
            fail(f"connections[{index}] requires explicit authentication")
        runtime_status = require_string(
            connection.get("runtime_status"),
            f"connections[{index}] has an unverified runtime status",
        )
        if runtime_status not in ALLOWED_RUNTIME_STATES:
            fail(f"connections[{index}] has an unverified runtime status")
        contract = require_string(
            connection.get("contract"),
            f"connections[{index}] has an invalid contract",
        )
        if contract not in ALLOWED_CONNECTIVITY_CONTRACTS:
            fail(f"connections[{index}] references an unapproved contract")
        if not (root / contract).is_file():
            fail(f"connections[{index}] references a missing contract")
    keycloak_bound_workstreams = {
        "platform/kong",
        "integration/odoo-19",
        "integration/n8n",
        "integration/vicidial",
        "integration/telnexa-sms",
        "integration/klyrow-email",
        "integration/kyqra",
        "integration/postly-social",
    }
    for service in service_by_id.values():
        workstream = require_string(
            service.get("workstream"), "service workstream must be a string"
        )
        if workstream not in dependency_index:
            fail(
                f"service workstream is absent from connectivity-map.json: {workstream}"
            )
        workstream_dependencies = dependency_index[workstream]
        if workstream in keycloak_bound_workstreams:
            if "integration/keycloak" not in workstream_dependencies:
                fail(f"{workstream} must depend on integration/keycloak")
    return len(hooks), len(event_types)


def validate(root: Path = ROOT) -> tuple[int, int, int, int, dict[str, int]]:
    access = load_json(root / "config/identity-access-map.json")
    webhooks = load_json(root / "config/api-webhook-contracts.json")
    service_by_id, grant_index = validate_access(access)
    webhook_count, event_type_count = validate_webhooks(
        webhooks, service_by_id, grant_index, root
    )

    source_states: dict[str, int] = {}
    for service in service_by_id.values():
        source_state = require_string(
            service.get("sourceState"), "service sourceState must be a string"
        )
        source_states[source_state] = source_states.get(source_state, 0) + 1

    return (
        len(service_by_id),
        len(grant_index),
        webhook_count,
        event_type_count,
        source_states,
    )


def main() -> None:
    service_count, grant_count, webhook_count, event_type_count, source_states = (
        validate()
    )

    print(f"SERVICE_CLIENTS={service_count}")
    print(f"SERVICE_GRANTS={grant_count}")
    print(f"WEBHOOK_CONTRACTS={webhook_count}")
    print(f"WEBHOOK_EVENT_TYPES={event_type_count}")
    print(
        f"SOURCE_STATE_COUNTS={json.dumps(source_states, sort_keys=True, separators=(',', ':'))}"
    )
    print("IDENTITY_ACCESS_POLICY=PASS")
    print("API_WEBHOOK_CONTRACT_POLICY=PASS")
    print("MIDDLEWARE_INTEGRATION_CONTRACTS=PASS")


if __name__ == "__main__":
    try:
        main()
    except ContractError as exc:
        print(f"IDENTITY_WEBHOOK_CONTRACT_ERROR={exc}", file=sys.stderr)
        raise SystemExit(1)
