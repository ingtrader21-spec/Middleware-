#!/usr/bin/env python3
"""Validate the canonical no-bypass provider-operation authority."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).parents[1]
POLICY = ROOT / "config" / "provider-operation-policy.json"
IDENTITY = ROOT / "config" / "identity-access-map.json"
SAFETY_BASELINE = ROOT / "config" / "preproduction-safety.env.example"
SCOPE = re.compile(r"^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$")
ROUTE = re.compile(r"^/api/v1/[a-z0-9][a-z0-9/_-]*$")
EXPECTED_CALLERS = {"codestra-ai", "codestra-communication", "codestra-marketing", "codestra-social", "odoo-integration"}
EXPECTED_PROVIDER_FLAGS = {"advertising": "LIVE_ADVERTISING_ENABLED", "ai": "EXTERNAL_MODEL_CALLS_ENABLED", "email": "LIVE_EMAIL_DELIVERY", "sms": "LIVE_SMS_DELIVERY", "social": "SOCIAL_PUBLISHING_ENABLED"}
EXPECTED_OPERATIONS = {
    "ai.inference.request": (
        "codestra-ai",
        "ai.inference.request",
        "/api/v1/control/ai/inference-requests",
        True,
        "transactional_outbox",
        "ai",
        "ai.inference.request.v1",
        "ai-provider",
        "EXTERNAL_MODEL_CALLS",
    ),
    "communication.email.request": (
        "codestra-communication",
        "communication.email.request",
        "/api/v1/control/communications/email",
        True,
        "transactional_outbox",
        "email",
        "email.message.send.v1",
        "klyrow-email",
        "EMAIL_DELIVERY",
    ),
    "communication.sms.request": (
        "codestra-communication",
        "communication.sms.request",
        "/api/v1/control/communications/sms",
        True,
        "transactional_outbox",
        "sms",
        "sms.message.submit.v1",
        "telnexa-sms",
        "SMS_DELIVERY",
    ),
    "marketing.campaign.request": (
        "codestra-marketing",
        "marketing.campaign.request",
        "/api/v1/control/marketing/campaigns",
        True,
        "transactional_outbox",
        "advertising",
        "marketing.campaign.activate.v1",
        "marketing-provider",
        "LIVE_ADVERTISING",
    ),
    "odoo.event.publish": (
        "odoo-integration",
        "odoo.events.publish",
        "/api/v1/odoo/events",
        False,
        "durable_inbox",
        "none",
        None,
        None,
        None,
    ),
    "social.publish.request": (
        "codestra-social",
        "social.publish.request",
        "/api/v1/control/social/publications",
        True,
        "transactional_outbox",
        "social",
        "social.publication.publish.v1",
        "postly-social",
        "SOCIAL_PUBLISH",
    ),
}
EXPECTED_ADAPTERS = {
    "advertising": ("marketing-provider-adapter", "marketing.provider.dispatch", ("marketing.provider.status.read",)),
    "ai": ("ai-provider-adapter", "ai.provider.dispatch", ("ai.provider.status.read",)),
    "email": ("klyrow-gateway", "email.send", ("email.status.read",)),
    "sms": ("telnexa-gateway", "sms.send", ("sms.status.read",)),
    "social": ("postly-adapter", "social.publish", ("social.status.read",)),
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"PROVIDER_OPERATION_POLICY=FAIL: {message}")


def validate(value: dict, identity: dict, safety_baseline: dict[str, str]) -> None:
    if value.get("schemaVersion") != 1:
        fail("schemaVersion must be 1")
    if value.get("architecture") != ["application_or_n8n", "kong", "middleware_api", "durable_outbox", "approved_provider_adapter"]:
        fail("canonical architecture changed")
    authority = value.get("authority", {})
    for key, expected in {"issuer": "https://auth.codestra.co/realms/codestra", "audience": "middleware-api", "grantType": "client_credentials", "fullScopeAllowed": False, "wildcardScopesAllowed": False, "directProviderCallsAllowed": False, "sharedProviderKeysAllowed": False}.items():
        if authority.get(key) != expected:
            fail(f"authority.{key} must be {expected!r}")
    operations = value.get("operations")
    if not isinstance(operations, list) or operations != sorted(operations, key=lambda operation: operation.get("id", "")):
        fail("operations must be a non-empty sorted list")
    callers, identifiers, routes = set(), set(), set()
    for operation in operations:
        if set(operation) != {
            "id",
            "caller",
            "scope",
            "route",
            "externalEffect",
            "durability",
            "providerClass",
            "commandType",
            "target",
            "capability",
        }:
            fail("operation fields invalid")
        identifier, route = operation["id"], operation["route"]
        if identifier in identifiers or not SCOPE.fullmatch(identifier):
            fail(f"operation id invalid or duplicate: {identifier}")
        if route in routes or not ROUTE.fullmatch(route):
            fail(f"route invalid or duplicate: {route}")
        if not SCOPE.fullmatch(operation["scope"]):
            fail(f"scope invalid: {operation['scope']}")
        exact_operation = (
            operation["caller"],
            operation["scope"],
            operation["route"],
            operation["externalEffect"],
            operation["durability"],
            operation["providerClass"],
            operation["commandType"],
            operation["target"],
            operation["capability"],
        )
        if exact_operation != EXPECTED_OPERATIONS.get(identifier):
            fail(f"operation authority mismatch: {identifier}")
        identifiers.add(identifier)
        routes.add(route)
        callers.add(operation["caller"])
        if operation["externalEffect"]:
            if operation["durability"] != "transactional_outbox":
                fail(f"external effect bypasses transactional outbox: {identifier}")
            if operation["providerClass"] not in EXPECTED_PROVIDER_FLAGS:
                fail(f"unapproved provider class: {identifier}")
            if not SCOPE.fullmatch(operation["commandType"]):
                fail(f"external operation command type is invalid: {identifier}")
            if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", operation["target"]):
                fail(f"external operation target is invalid: {identifier}")
            if not re.fullmatch(r"[A-Z][A-Z0-9_]+", operation["capability"]):
                fail(f"external operation capability is invalid: {identifier}")
        elif (
            operation["providerClass"] != "none"
            or operation["commandType"] is not None
            or operation["target"] is not None
            or operation["capability"] is not None
        ):
            fail(f"non-effectful operation contains provider command binding: {identifier}")
    if callers != EXPECTED_CALLERS:
        fail("caller coverage mismatch")
    if identifiers != set(EXPECTED_OPERATIONS):
        fail("operation coverage mismatch")
    services = {
        service.get("clientId"): service
        for service in identity.get("services", [])
        if isinstance(service, dict)
    }
    grants = identity.get("grants", [])
    if not isinstance(grants, list):
        fail("identity grants must be a list")
    for operation in operations:
        caller = operation["caller"]
        if caller not in services:
            fail(f"operation caller is absent from identity map: {caller}")
        matching = [
            grant
            for grant in grants
            if grant.get("callerClientId") == caller
            and grant.get("targetClientId") == "middleware-api"
            and grant.get("audience") == value["authority"]["audience"]
        ]
        if len(matching) != 1 or operation["scope"] not in matching[0].get("scopes", []):
            fail(f"operation caller lacks exact audience/scope grant: {operation['id']}")
    adapters = value.get("providerAdapters")
    if not isinstance(adapters, list) or adapters != sorted(adapters, key=lambda adapter: adapter.get("providerClass", "")):
        fail("providerAdapters must be a non-empty sorted list")
    classes = set()
    for adapter in adapters:
        if set(adapter) != {"providerClass", "adapterClientId", "workerClientId", "dispatchScope", "readbackScopes", "safetyFlag"}:
            fail("provider adapter fields invalid")
        provider_class = adapter["providerClass"]
        if provider_class in classes:
            fail(f"duplicate provider adapter: {provider_class}")
        classes.add(provider_class)
        if adapter["workerClientId"] != "middleware-worker":
            fail(f"direct provider caller found: {provider_class}")
        exact_adapter = (
            adapter["adapterClientId"], adapter["dispatchScope"],
            tuple(adapter["readbackScopes"]),
        )
        if exact_adapter != EXPECTED_ADAPTERS.get(provider_class):
            fail(f"provider adapter authority mismatch: {provider_class}")
        if adapter["safetyFlag"] != EXPECTED_PROVIDER_FLAGS.get(provider_class):
            fail(f"provider safety flag mismatch: {provider_class}")
        if safety_baseline.get(adapter["safetyFlag"], "").lower() not in {
            "0", "false", "no", "off", "disabled"
        }:
            fail(f"provider safety flag is not disabled in baseline: {provider_class}")
        if not SCOPE.fullmatch(adapter["dispatchScope"]) or any(
            not SCOPE.fullmatch(scope) for scope in adapter["readbackScopes"]
        ):
            fail(f"provider dispatch scope invalid: {provider_class}")
        adapter_client = adapter["adapterClientId"]
        matching = [
            grant
            for grant in grants
            if grant.get("callerClientId") == adapter["workerClientId"]
            and grant.get("targetClientId") == adapter_client
            and grant.get("audience") == adapter_client
        ]
        required_adapter_scopes = {
            adapter["dispatchScope"], *adapter["readbackScopes"]
        }
        if len(matching) != 1 or set(matching[0].get("scopes", [])) != required_adapter_scopes:
            fail(f"worker lacks exact adapter audience/scope grant: {provider_class}")
        direct = [
            grant
            for grant in grants
            if grant.get("callerClientId") == "middleware-api"
            and grant.get("targetClientId") == adapter_client
        ]
        if direct:
            fail(f"middleware API retains direct provider grant: {provider_class}")
    if classes != set(EXPECTED_PROVIDER_FLAGS):
        fail("provider adapter coverage mismatch")
    evidence = value.get("requiredEvidence")
    expected_evidence = {"authenticated_caller", "authorized_operation", "correlation_id", "durable_inbox_or_outbox_id", "idempotency_key", "provider_policy_decision", "sanitized_safety_readback", "tenant_context"}
    if not isinstance(evidence, list) or evidence != sorted(expected_evidence):
        fail("required evidence coverage mismatch")


def main() -> int:
    try:
        value = json.loads(POLICY.read_text(encoding="utf-8"))
        identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
        safety_baseline = {
            name.strip(): setting.strip()
            for line in SAFETY_BASELINE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and "=" in line
            for name, setting in [line.split("=", 1)]
        }
    except (OSError, json.JSONDecodeError) as exc:
        fail(str(exc))
    validate(value, identity, safety_baseline)
    print("MIDDLEWARE_PROVIDER_POLICY=PASS")
    print("DIRECT_PROVIDER_BYPASS_PATHS=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
