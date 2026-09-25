"""Generate the canonical cross-repository route contract.

The generated document is the only edge-route catalog.  Consumers MUST emit
only ``shared_edge`` rows; ``private_only`` rows document Middleware outbound
calls and ``denied`` rows drive fail-closed negative tests.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "deploy/public-api-route-contract.json"
PINNED = ROOT / "deploy/public-api-route-contract.sha256"
OPENAPI = ROOT / "contracts/platform/integration-fabric-api.v2.yaml"
AUTOMATION_POLICY = ROOT / "contracts/automation/operation-policy.v2.json"


def _schema(operation_id: str, operation: dict[str, Any], *, request: bool) -> str:
    if request:
        schema = (
            operation.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema")
        )
        side = "request"
    else:
        responses = operation.get("responses", {})
        successful = next(
            (value for code, value in responses.items() if str(code).startswith("2")),
            {},
        )
        schema = (
            successful.get("content", {})
            .get("application/json", {})
            .get("schema")
        )
        side = "response"
    if not schema:
        return "none"
    if "$ref" in schema:
        return str(schema["$ref"])
    return f"openapi:inline:{operation_id}:{side}"


KERNEL_ROUTE_SCOPES = {
    ("POST", "/platform/v1/commands"): "platform.command",
    ("GET", "/platform/v1/operations"): "platform.command.read",
    ("GET", "/platform/v1/operations/{operation_id}"): "platform.command.read",
    ("GET", "/platform/v1/operations/{operation_id}/attempts"): "platform.command.read",
    ("GET", "/platform/v1/operations/{operation_id}/timeline"): "platform.command.read",
    ("POST", "/platform/v1/operations/{operation_id}/cancel"): "platform.command",
    ("POST", "/platform/v1/operations/{operation_id}/replay"): "platform.command.replay",
    ("GET", "/platform/v1/kernel/describe"): "platform.command.read",
}
# The registered workload callers (config/control-plane-callers.v1.json) that
# hold the platform.command* scopes; Kong verifies issuer/audience/scope, the
# kernel re-authorizes the client, tenant and (for replay) the platform-operator role.
KERNEL_CALLING_CLIENT = "platform-command-client"


def _platform_scope(path: str, method: str) -> tuple[str, str]:
    kernel_scope = KERNEL_ROUTE_SCOPES.get((method, path))
    if kernel_scope is not None:
        return KERNEL_CALLING_CLIENT, kernel_scope
    if path.startswith("/platform/v1/email/production/"):
        return "production-operator", (
            "email.production.read" if method == "GET" else "email.production.write"
        )
    if path == "/platform/v1/tenants":
        return "platform-operator", "platform.tenants.read"
    if path.startswith("/platform/v1/repositories") or path.startswith(
        "/platform/v1/hosts"
    ):
        return "platform-operator", "platform.services.read"
    if path.endswith("/deployments") or path.endswith("/endpoints") or path.endswith(
        "/dependencies"
    ):
        return "platform-operator", "platform.services.read"
    if path.endswith("/coverage"):
        return "platform-operator", "observability.health.read"
    if path.endswith("/telemetry-profile") or path.endswith("/contract-refresh"):
        return "platform-operator", "platform.services.write"
    if path == "/platform/v1/sync/status" or (
        path.startswith("/platform/v1/sync/reconciliations/") and method == "GET"
    ):
        return "platform-operator", "platform.sync.read"
    if path == "/platform/v1/sync/reconciliations":
        return "platform-operator", "platform.sync.reconcile"
    if path == "/platform/v1/integrations/github/events":
        return "github-app", "github.webhooks.publish"
    if path == "/platform/v1/runtime/observations":
        return "observability-collector", "platform.runtime.observe"
    if path == "/platform/v1/telemetry/heartbeats":
        return "observability-collector", "telemetry.heartbeat.write"
    if path == "/platform/v1/me/presence":
        return "browser-session", "identity.session"
    return "authorized-provisioning-client", "identity.request"


def _idempotency(method: str, required_fields: list[str] | None = None) -> dict[str, Any]:
    fields = required_fields or []
    if method == "GET":
        return {"required": False, "carrier": "none", "replay": "safe-read"}
    if "idempotency_key" in fields:
        return {"required": True, "carrier": "body.idempotency_key", "replay": "return-original"}
    return {"required": True, "carrier": "Idempotency-Key", "replay": "return-original"}


def _row(
    *,
    operation_id: str,
    method: str,
    path: str,
    classification: str,
    calling_client: str | list[str],
    audience: str,
    scope: str,
    request_schema: str,
    response_schema: str,
    owner: str,
    upstream: str,
    auth: str,
    idempotency: dict[str, Any] | None = None,
    error_statuses: list[int] | None = None,
) -> dict[str, Any]:
    return {
        "operation_id": operation_id,
        "method": method,
        "path": path,
        "classification": classification,
        "calling_client": calling_client,
        "audience": audience,
        "scope": scope,
        "auth": auth,
        "request_schema": request_schema,
        "response_schema": response_schema,
        "idempotency": idempotency or _idempotency(method),
        "correlation_fields": ["X-Correlation-ID", "body.correlation_id"],
        "echo_fields": ["X-Correlation-ID", "body.correlation_id"],
        "error_statuses": error_statuses or [400, 401, 403, 404, 409, 422, 429, 503],
        "owner": owner,
        "upstream": upstream,
    }


def build_contract() -> dict[str, Any]:
    openapi = yaml.safe_load(OPENAPI.read_text(encoding="utf-8"))
    policy = json.loads(AUTOMATION_POLICY.read_text(encoding="utf-8"))
    automation = {
        (operation["method"], operation["path"]): operation
        for operation in policy["operations"]
    }
    routes: list[dict[str, Any]] = []

    for path, path_item in openapi["paths"].items():
        if not (
            path.startswith("/v2/automation/")
            or path.startswith("/platform/v1/")
            or path == "/api/v1/odoo/events"
        ):
            continue
        for method_lower, operation in path_item.items():
            if method_lower not in {"get", "post", "put", "patch", "delete"}:
                continue
            method = method_lower.upper()
            operation_id = operation["operationId"]
            if path.startswith("/v2/automation/"):
                specification = automation[(method, path)]
                calling_client = specification["allowed_clients"]
                scope = specification["scope"]
                auth = "automation-service-jwt"
                idempotency = _idempotency(method, specification.get("required_fields"))
            elif path == "/api/v1/odoo/events":
                calling_client = "odoo-integration"
                scope = "odoo.events.publish"
                auth = "odoo-service-jwt"
                idempotency = {
                    "required": True,
                    "carrier": "body.event_id",
                    "replay": "one-event-one-saga",
                }
            else:
                calling_client, scope = _platform_scope(path, method)
                auth = "service-or-user-jwt"
                idempotency = _idempotency(method)
            response_codes = sorted(
                {
                    int(code)
                    for code in operation.get("responses", {})
                    if str(code).isdigit() and int(code) >= 400
                }
                | {401, 403}
            )
            routes.append(
                _row(
                    operation_id=operation_id,
                    method=method,
                    path=path,
                    classification="shared_edge",
                    calling_client=calling_client,
                    audience="middleware-api",
                    scope=scope,
                    request_schema=_schema(operation_id, operation, request=True),
                    response_schema=_schema(operation_id, operation, request=False),
                    owner="middleware",
                    upstream="middleware-integration-api:8095",
                    auth=auth,
                    idempotency=idempotency,
                    error_statuses=response_codes,
                )
            )

    extras = [
        ("list_callbacks", "GET", "/api/v1/callbacks", "callback-ui", "callbacks.read", "callback-jwt"),
        ("create_callback", "POST", "/api/v1/control/callbacks", "callback-ui", "callbacks.write", "callback-jwt"),
        ("check_automation_policy", "POST", "/api/v1/automation/policy-check", "n8n-automation", "n8n.policy.check", "n8n-service-jwt"),
        ("submit_n8n_result", "POST", "/api/v1/integrations/n8n/results", "n8n-automation", "n8n.results.submit", "n8n-service-jwt"),
        ("read_n8n_result", "GET", "/api/v1/integrations/n8n/results/{event_id}", "n8n-automation", "n8n.results.read", "n8n-service-jwt"),
        ("read_odoo_campaign", "GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}", "odoo-integration", "odoo.campaigns.read", "odoo-service-jwt"),
        ("read_odoo_campaign_desired_state", "GET", "/api/v1/integrations/odoo/campaigns/{campaign_id}/desired-state", "odoo-integration", "odoo.campaigns.read", "odoo-service-jwt"),
    ]
    for operation_id, method, path, client, scope, auth in extras:
        routes.append(
            _row(
                operation_id=operation_id,
                method=method,
                path=path,
                classification="shared_edge",
                calling_client=client,
                audience=(
                    "codestra-callback-api" if auth == "callback-jwt" else "middleware-api"
                ),
                scope=scope,
                request_schema=f"internal://middleware/{operation_id}/request/v1",
                response_schema=f"internal://middleware/{operation_id}/response/v1",
                owner="middleware",
                upstream="middleware-integration-api:8095",
                auth=auth,
            )
        )

    for values in (
        (
            "deliver_automation_result_to_odoo",
            "/api/v1/integration/automation-results",
            "odoo.integration.automation_results.write",
            "internal://odoo/automation-results/v1",
        ),
        (
            "report_campaign_actual_state_to_odoo",
            "/api/v1/integration/campaigns/actual-state",
            "odoo.campaign.actual_state.write",
            "internal://odoo/campaigns/actual-state/v1",
        ),
    ):
        operation_id, path, scope, schema = values
        routes.append(
            _row(
                operation_id=operation_id,
                method="POST",
                path=path,
                classification="private_only",
                calling_client="middleware-worker",
                audience="codestra-odoo",
                scope=scope,
                request_schema=schema,
                response_schema=f"{schema}/response",
                owner="odoo",
                upstream="odoo:8069",
                auth="middleware-service-jwt",
            )
        )

    for operation_id, method, path in (
        ("deny_retired_campaign_actions", "POST", "/api/v1/integration/campaign-actions"),
        ("deny_retired_odoo_campaign_actions", "POST", "/api/v1/odoo/campaign-actions"),
        ("deny_retired_integration_campaign_actions", "POST", "/api/v1/integrations/odoo/campaign-actions"),
        ("deny_retired_odoo_campaign_commands", "POST", "/api/v1/integrations/odoo/campaign-commands"),
        ("deny_retired_odoo_campaign_command_read", "GET", "/api/v1/integrations/odoo/campaign-commands/{command_id}"),
        ("deny_deprecated_n8n_commands", "POST", "/v1/integrations/n8n/commands"),
        ("deny_deprecated_n8n_operation", "GET", "/v1/integrations/n8n/operations/{command_id}"),
        ("deny_deprecated_n8n_operations", "GET", "/v1/integrations/n8n/operations"),
        ("deny_deprecated_n8n_cancel", "POST", "/v1/integrations/n8n/operations/{command_id}/cancel"),
        ("deny_deprecated_n8n_reconcile", "POST", "/v1/integrations/n8n/operations/{command_id}/reconcile"),
    ):
        routes.append(
            _row(
                operation_id=operation_id,
                method=method,
                path=path,
                classification="denied",
                calling_client="none",
                audience="middleware-api",
                scope="none",
                request_schema="none",
                response_schema="none",
                owner="middleware",
                upstream="none",
                auth="deny",
                idempotency={"required": False, "carrier": "none", "replay": "denied"},
                error_statuses=[404, 405],
            )
        )

    routes.sort(key=lambda row: (row["classification"], row["path"], row["method"]))
    return {
        "schema": "codestra.middleware.public-api-route-contract.v2",
        "service": "middleware-integration-api",
        "listener_port": 8095,
        "environment": "TEST_SYN",
        "live_apply_authorized": False,
        "provider_effects_enabled": False,
        "hash_rule": "sha256 over json.dumps(contract, sort_keys=True, separators=(',', ':')).encode('utf-8')",
        "edge": {
            "path": "caddy -> kong -> middleware-integration-api:8095",
            "rule": "Caddy routes shared_edge operations to Kong. Kong enforces issuer, audience, azp, scope, rate and size before Middleware re-authorizes the request.",
        },
        "routes": routes,
    }


def main() -> None:
    contract = build_contract()
    OUTPUT.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    canonical = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    PINNED.write_text(hashlib.sha256(canonical).hexdigest() + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
