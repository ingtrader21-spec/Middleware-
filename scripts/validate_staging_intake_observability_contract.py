#!/usr/bin/env python3
"""Historical Stage 6 staging intake observability source contract.

The contract binds the immutable staging release record, its runtime
profile and environment template to source-level guarantees of the single
canonical application:

* the two governed reads (``GET /metrics`` and ``GET /v1/runtime/safety``)
  authenticate against the runtime token verifier before doing anything
  else, with static client/scope bindings,
* nothing anywhere in the mounted route set can shadow those paths,
* the application is built by exactly one factory that only ever calls the
  approved registration helpers and mounts routers through the registry,
* exactly one HTTP middleware exists (the request guard); it delegates to
  the router exactly once, never rewrites the routed response or the
  request routing state, and may only refuse a request with a fail-closed
  pre-routing status.

Every clause is proven from executable Python syntax; nothing is asserted
from documentation.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SOURCE = "f6748a58f8d2590520a4f28776770957061cdea1"
EXPECTED_DIGEST = (
    "sha256:695fa3ce3f50ba4d0ae0784976b946a0a683ca731155e4bd3bd9e90a4670b820"
)
EXPECTED_PROFILE: dict[str, Any] = {
    "profile_id": "codestra-middleware-staging-v1",
    "environment": "staging",
    "database": {
        "scheme": "postgresql",
        "host": "postgresql.middleware-staging.svc.cluster.local",
        "port": 5432,
        "name": "codestra_staging",
        "username": "middleware_staging",
        "sslmode": "verify-full",
    },
    "redis": {
        "scheme": "rediss",
        "host": "redis.middleware-staging.svc.cluster.local",
        "port": 6379,
        "database": 14,
        "username": "middleware-staging",
    },
    "nats": {
        "host": "nats.middleware-staging.svc.cluster.local",
        "port": 4222,
        "stream": "CODESTRA_STAGING_EVENTS",
        "subject_prefix": "codestra.staging.events",
    },
    "temporal": {
        "address": "temporal.middleware-staging.svc.cluster.local:7233",
        "namespace": "codestra-staging",
        "task_queue": "codestra-staging-critical",
    },
    "secret_path_prefix": "/run/secrets/middleware-staging-",
    "production_activation_allowed": False,
}
WEBHOOK_SECRET_NAMES = {
    "WEBHOOK_SECRET_ODOO_INTEGRATION",
    "WEBHOOK_SECRET_N8N_AUTOMATION",
    "WEBHOOK_SECRET_VICIDIAL_ADAPTER",
    "WEBHOOK_SECRET_TELNEXA_GATEWAY",
    "WEBHOOK_SECRET_KLYROW_GATEWAY",
    "WEBHOOK_SECRET_KYQRA_GATEWAY",
    "WEBHOOK_SECRET_POSTLY_ADAPTER",
}
GOVERNED_READ_PATHS = {"/metrics", "/v1/runtime/safety"}

# The single application factory and the modules it delegates to.
FACTORY_MODULE = "application"
GUARD_MODULE = "core.request_guard"
HEALTH_MODULE = "core.health"
CONTROL_PLANE_ROUTES_MODULE = "appolon_routes"
EXPECTED_ROUTER_REGISTRY_MODULE = "router_registry"

# Every router the registry imports: binding -> (module, imported name),
# relative to the ``app`` package.
EXPECTED_REGISTRY_ROUTERS = {
    "internal_ai_jobs_router": ("api.internal.ai_jobs", "router"),
    "internal_database_router": ("api.internal.database", "router"),
    "klyrow_events_router": ("api.internal.klyrow_events", "router"),
    "klyrow_mail_router": ("api.internal.klyrow_mail", "router"),
    "telnexa_events_router": ("api.internal.telnexa_events", "router"),
    "activity_router": ("api.v1.activity", "router"),
    "agent_provisioning_router": ("api.v1.agent_provisioning", "router"),
    "agent_provisioning_reads_router": ("api.v1.agent_provisioning_reads", "router"),
    "agent_realtime_router": ("api.v1.agent_realtime", "router"),
    "ai_router": ("api.v1.ai", "router"),
    "ai_commands_router": ("api.v1.ai_commands", "router"),
    "ai_console_router": ("api.v1.ai_console", "router"),
    "automation_router": ("api.v1.automation", "router"),
    "booking_router": ("api.v1.booking", "router"),
    "callbacks_router": ("api.v1.callbacks", "router"),
    "calls_router": ("api.v1.calls", "router"),
    "campaign_search_router": ("api.v1.campaign_search", "router"),
    "campaigns_router": ("api.v1.campaigns", "router"),
    "commands_router": ("api.v1.commands", "router"),
    "contacts_router": ("api.v1.contacts", "router"),
    "control_legacy_events_router": ("api.v1.control", "legacy_events_router"),
    "control_router": ("api.v1.control", "router"),
    "events_router": ("api.v1.events", "router"),
    "integrations_router": ("api.v1.integrations", "router"),
    "lead_automation_router": ("api.v1.lead_automation", "router"),
    "lead_reconciliation_router": ("api.v1.lead_reconciliation", "router"),
    "mappings_router": ("api.v1.mappings", "router"),
    "n8n_runtime_router": ("api.v1.n8n_runtime", "router"),
    "n8n_staging_router": ("api.v1.n8n_staging", "router"),
    "n8n_target_router": ("api.v1.n8n_target", "router"),
    "n8n_transport_router": ("api.v1.n8n_transport", "router"),
    "observability_sync_router": ("api.v1.observability_sync", "router"),
    "opportunities_router": ("api.v1.opportunities", "router"),
    "operations_router": ("api.v1.operations", "router"),
    "orchestration_router": ("api.v1.orchestration", "router"),
    "orders_router": ("api.v1.orders", "router"),
    "platform_router": ("api.v1.platform", "router"),
    "presence_router": ("api.v1.presence", "router"),
    "provider_commands_router": ("api.v1.provider_commands", "router"),
    "provider_webhooks_router": ("api.v1.provider_webhooks", "router"),
    "publisher_router": ("api.v1.publisher", "router"),
    "quarantine_router": ("api.v1.quarantine", "router"),
    "queues_router": ("api.v1.queues", "router"),
    "recordings_router": ("api.v1.recordings", "router"),
    "recording_identity_router": ("api.v1.service_identity", "router"),
    "registry_router": ("api.v1.registry", "router"),
    "reports_router": ("api.v1.reports", "router"),
    "sales_router": ("api.v1.sales", "router"),
    "session_context_router": ("api.v1.session_context", "router"),
    "social_router": ("api.v1.social", "router"),
    "telephony_router": ("api.v1.telephony", "router"),
    "tenants_router": ("api.v1.tenants", "router"),
    "tickets_router": ("api.v1.tickets", "router"),
    "tts_router": ("api.v1.tts", "router"),
    "webphone_router": ("api.v1.webphone", "router"),
    "appolon_control_plane_router": ("appolon_routes", "router"),
    "automation_v2_router": ("automation_v2", "v2_router"),
    "campaign_design_router": ("campaign_design_api", "router"),
    "compatibility_api_router": ("compatibility_api", "router"),
    "control_api_router": ("control_api", "router"),
    "domain_legacy_n8n_router": ("domain_api", "legacy_n8n_router"),
    "domain_api_router": ("domain_api", "router"),
    "email_production_router": ("email_production_control", "router"),
    "postiz_router": ("integrations.postiz.routes", "router"),
    "monitoring_router": ("monitoring.routes", "router"),
    "n8n_control_plane_router": ("n8n_control_plane", "router"),
    "appolon_operations_router": ("operations", "router"),
    "operations_dashboard_router": ("operations_dashboard", "router"),
    # V3 command kernel: the six /platform/v1 kernel routes (app.platform.api).
    "platform_kernel_router": ("platform.api", "router"),
    "odoo_event_router": ("webhook_api", "odoo_event_router"),
    "webhook_api_router": ("webhook_api", "router"),
}
EXPECTED_REGISTRY_TUPLES = {
    "CANONICAL_ROUTERS": frozenset(
        {
            "internal_database_router",
            "platform_kernel_router",
            "leads_journey_router",
            "automation_v2_router",
            "automation_router",
            "callbacks_router",
            "email_production_router",
            "agent_provisioning_router",
            "agent_provisioning_reads_router",
            "session_context_router",
            "calls_router",
            "activity_router",
            "presence_router",
            "queues_router",
            "contacts_router",
            "opportunities_router",
            "tickets_router",
            "tenants_router",
            "campaigns_router",
            "monitoring_router",
            "observability_sync_router",
            "integrations_router",
            "odoo_event_router",
        }
    ),
    "COMMON_ROUTERS": frozenset(
        {"campaign_design_router", "klyrow_events_router", "telnexa_events_router"}
    ),
    "INTEGRATION_ROUTERS": frozenset(
        {
            "commands_router",
            "control_router",
            "reports_router",
            "operations_router",
            "lead_reconciliation_router",
            "lead_automation_router",
            "orchestration_router",
            "provider_webhooks_router",
            "mappings_router",
            "webphone_router",
            "n8n_staging_router",
            "n8n_transport_router",
            "n8n_runtime_router",
            "quarantine_router",
            "telephony_router",
            "sales_router",
            "booking_router",
            "platform_router",
        }
    ),
    "APPOLON_ROUTERS": frozenset(
        {
            "operations_dashboard_router",
            "appolon_operations_router",
            "control_api_router",
            "compatibility_api_router",
            "domain_api_router",
            "webhook_api_router",
            "appolon_control_plane_router",
        }
    ),
    "MONOLITH_ROUTERS": frozenset(
        {
            "events_router",
            "control_legacy_events_router",
            "publisher_router",
            "agent_realtime_router",
            "n8n_target_router",
            "internal_ai_jobs_router",
            "klyrow_mail_router",
            "ai_console_router",
            "tts_router",
            "ai_commands_router",
            "orders_router",
            "ai_router",
            "provider_commands_router",
            "postiz_router",
            "campaign_search_router",
            "registry_router",
            "recordings_router",
            "recording_identity_router",
            "social_router",
        }
    ),
    "LEGACY_MONOLITH_ONLY_ROUTERS": frozenset(
        {"n8n_control_plane_router", "domain_legacy_n8n_router"}
    ),
}
EXPECTED_REGISTRY_MOUNTERS = {
    "mount_canonical_routers": "CANONICAL_ROUTERS",
    "mount_common_routers": "COMMON_ROUTERS",
    "mount_integration_routers": "INTEGRATION_ROUTERS",
    "mount_appolon_routers": "APPOLON_ROUTERS",
    "mount_monolith_routers": "MONOLITH_ROUTERS",
    "mount_legacy_monolith_routers": "LEGACY_MONOLITH_ONLY_ROUTERS",
}
EXPECTED_SIDE_EFFECT_ROUTER_MODULES = {"provider_control_api"}
EXPECTED_ROUTE_HELPERS = {"register_survey_routes": "survey_routes"}
# Calls in the factory that receive ``app``: name -> (module attribute or None).
EXPECTED_FACTORY_APP_CALLS: dict[str, str | None] = {
    **{name: None for name in EXPECTED_REGISTRY_MOUNTERS},
    "install_request_guard": None,
    "register_health_routes": None,
    "assert_unique_routes": None,
    "install_error_handlers": "appolon_routes",
    "install_canonical_openapi": "appolon_routes",
    "install_leads_openapi": None,
}
# Statuses the guard may answer with before routing (fail-closed refusals).
GUARD_REFUSAL_STATUSES = {400, 401, 413, 415, 429, 503}
GUARD_RESPONSE_HEADERS = {"X-Correlation-ID", "Cache-Control", "traceparent"}
GUARD_REQUEST_READS = {
    ("request", "headers", "get"),
    ("request", "headers", "getlist"),
    ("request", "scope", "get"),
}
ROUTE_REGISTRATION_METHODS = {
    "add_api_route",
    "add_route",
    "api_route",
    "get",
    "head",
    "mount",
    "options",
    "patch",
    "post",
    "put",
    "route",
    "trace",
    "websocket",
}
WORKFLOW_REQUIRED_PATHS = {
    ".github/workflows/staging-intake-observability-contract.yml",
    "app/**/*.py",
    "config/api-webhook-contracts.json",
    "config/environments/staging.intake-observability.runtime.env.example",
    "config/provider-operation-policy.json",
    "config/runtime-profiles.v1.json",
    "contracts/staging-intake-observability-runtime.v1.json",
    "scripts/validate_staging_intake_observability_contract.py",
    "tests/test_staging_intake_observability_contract_validation.py",
}


class ContractError(ValueError):
    """The staging contract or one of its bound sources is invalid."""


def require(condition: object, message: str) -> None:
    if not condition:
        raise ContractError(message)


# ----------------------------------------------------------------------
# Workflow, environment and profile helpers
# ----------------------------------------------------------------------
def workflow_trigger_paths(source: str, trigger: str) -> set[str]:
    """Read one workflow paths filter without accepting another YAML section."""
    lines = source.splitlines()
    trigger_header = f"  {trigger}:"
    try:
        trigger_index = lines.index(trigger_header)
    except ValueError as error:
        raise ContractError(f"workflow {trigger} trigger is missing") from error
    paths_index: int | None = None
    for index in range(trigger_index + 1, len(lines)):
        line = lines[index]
        if line.startswith("  ") and not line.startswith("    ") and line.strip():
            break
        if line == "    paths:":
            paths_index = index
            break
    require(paths_index is not None, f"workflow {trigger} paths filter is missing")
    paths: list[str] = []
    if paths_index is None:
        raise ContractError(f"workflow {trigger} paths filter is missing")
    for line in lines[paths_index + 1 :]:
        if line.startswith("      - "):
            raw = line.removeprefix("      - ").strip()
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ContractError(
                    f"workflow {trigger} path is not a JSON string"
                ) from error
            require(
                isinstance(value, str) and bool(value),
                f"workflow {trigger} path is invalid",
            )
            paths.append(value)
            continue
        if line.strip() and not line.startswith("      "):
            break
    require(
        len(paths) == len(set(paths)),
        f"workflow {trigger} paths contain duplicates",
    )
    return set(paths)


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        require(
            separator == "=" and bool(key) and key not in values,
            f"invalid or duplicate environment key: {key!r}",
        )
        values[key] = value
    return values


def assert_database_url(value: str) -> None:
    parsed = urlparse(value)
    require(
        parsed.scheme == EXPECTED_PROFILE["database"]["scheme"],
        "database scheme drift",
    )
    require(
        parsed.hostname == EXPECTED_PROFILE["database"]["host"],
        "database host drift",
    )
    require(
        parsed.port == EXPECTED_PROFILE["database"]["port"],
        "database port drift",
    )
    require(
        unquote(parsed.username or "") == EXPECTED_PROFILE["database"]["username"],
        "database username drift",
    )
    require(
        parsed.password == "REPLACE_WITH_DATABASE_SECRET",
        "database password placeholder drift",
    )
    require(
        unquote(parsed.path.lstrip("/")) == EXPECTED_PROFILE["database"]["name"],
        "database name drift",
    )
    require(
        parse_qs(parsed.query, strict_parsing=True) == {"sslmode": ["verify-full"]},
        "database TLS policy drift",
    )
    require(not parsed.fragment, "database URL must not contain a fragment")


def assert_redis_url(value: str) -> None:
    parsed = urlparse(value)
    require(
        parsed.scheme == EXPECTED_PROFILE["redis"]["scheme"],
        "Redis scheme drift",
    )
    require(
        parsed.hostname == EXPECTED_PROFILE["redis"]["host"],
        "Redis host drift",
    )
    require(parsed.port == EXPECTED_PROFILE["redis"]["port"], "Redis port drift")
    require(
        unquote(parsed.username or "") == EXPECTED_PROFILE["redis"]["username"],
        "Redis username drift",
    )
    require(
        parsed.password == "REPLACE_WITH_REDIS_SECRET",
        "Redis password placeholder drift",
    )
    require(
        int(parsed.path.lstrip("/")) == EXPECTED_PROFILE["redis"]["database"],
        "Redis database drift",
    )
    require(
        not parsed.query and not parsed.fragment,
        "Redis URL must not contain a query or fragment",
    )


# ----------------------------------------------------------------------
# AST helpers
# ----------------------------------------------------------------------
def current_scope_nodes(node: ast.AST) -> list[ast.AST]:
    """Nodes of ``node``'s own scope (nested functions/classes not entered)."""
    nodes: list[ast.AST] = []

    def visit(candidate: ast.AST) -> None:
        nodes.append(candidate)
        if isinstance(
            candidate,
            (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Lambda),
        ):
            return
        for child in ast.iter_child_nodes(candidate):
            visit(child)

    body = (
        node.body
        if isinstance(
            node,
            (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Module),
        )
        else []
    )
    for statement in body:
        visit(statement)
    return nodes


def attribute_path(node: ast.expr) -> list[str] | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return list(reversed(parts))


def static_string(
    node: ast.expr,
    names: dict[str, str] | None = None,
) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and names is not None:
        return names.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = static_string(node.left, names)
        right = static_string(node.right, names)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        values: list[str] = []
        for item in node.values:
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                return None
            values.append(item.value)
        return "".join(values)
    return None


def module_string_constants(module_tree: ast.Module) -> dict[str, str]:
    constants: dict[str, str] = {}
    assignments: dict[str, list[ast.expr]] = {}
    for statement in module_tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target = statement.target
            value = statement.value
        else:
            continue
        if isinstance(target, ast.Name):
            assignments.setdefault(target.id, []).append(value)
    unresolved = {
        name: values[0] for name, values in assignments.items() if len(values) == 1
    }
    changed = True
    while changed:
        changed = False
        for name, value in list(unresolved.items()):
            resolved = static_string(value, constants)
            if resolved is not None:
                constants[name] = resolved
                unresolved.pop(name)
                changed = True
    return constants


def route_template_pattern(value: str) -> str:
    parts: list[str] = []
    index = 0
    while index < len(value):
        opening = value.find("{", index)
        closing = value.find("}", index)
        if opening == -1:
            require(closing == -1, "route template contains an unmatched brace")
            parts.append(re.escape(value[index:]))
            break
        require(
            closing == -1 or opening < closing,
            "route template contains an unmatched brace",
        )
        parts.append(re.escape(value[index:opening]))
        end = value.find("}", opening + 1)
        require(end != -1, "route template contains an unmatched brace")
        token = value[opening + 1 : end]
        require(
            bool(token) and "{" not in token,
            "route template parameter is malformed",
        )
        name, separator, converter = token.partition(":")
        require(
            bool(name) and name.isidentifier() and (not separator or bool(converter)),
            "route template parameter is malformed",
        )
        parts.append(
            "[^/]+" if converter in {"", "float", "int", "str", "uuid"} else ".*"
        )
        index = end + 1
    return "".join(parts)


def route_pattern(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return route_template_pattern(node.value)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = route_pattern(node.left)
        right = route_pattern(node.right)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for item in node.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                parts.append(route_template_pattern(item.value))
            elif isinstance(item, ast.FormattedValue):
                parts.append(".*")
            else:
                return None
        return "".join(parts)
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return ".*"
    return None


def registration_path_argument(call: ast.Call) -> ast.expr:
    require(
        not any(keyword.arg is None for keyword in call.keywords),
        "route registration uses expanded keywords",
    )
    candidates: list[ast.expr] = list(call.args[:1])
    candidates.extend(keyword.value for keyword in call.keywords if keyword.arg == "path")
    require(len(candidates) == 1, "route registration path is missing or ambiguous")
    return candidates[0]


def exact_methods(call: ast.Call) -> list[str] | None:
    values = [keyword.value for keyword in call.keywords if keyword.arg == "methods"]
    if len(values) != 1 or not isinstance(values[0], (ast.List, ast.Tuple)):
        return None
    methods: list[str] = []
    for item in values[0].elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        methods.append(item.value)
    return methods


def joined_path(prefix: str, path: str) -> str:
    if not prefix:
        return path or "/"
    if not path:
        return prefix
    return prefix.rstrip("/") + "/" + path.lstrip("/")


def assert_request_binding(tree: ast.Module, module_name: str) -> None:
    """``Request`` must be FastAPI's, imported exactly once and never rebound."""
    request_bindings: list[str] = []
    for candidate in current_scope_nodes(tree):
        if isinstance(candidate, ast.ImportFrom):
            for imported in candidate.names:
                bound = imported.asname or imported.name
                if bound != "Request":
                    continue
                if (
                    candidate.level == 0
                    and candidate.module == "fastapi"
                    and imported.name == "Request"
                    and imported.asname is None
                ):
                    request_bindings.append("fastapi.Request")
                else:
                    request_bindings.append("another import")
        elif isinstance(candidate, ast.Import):
            for imported in candidate.names:
                if (imported.asname or imported.name.split(".", 1)[0]) == "Request":
                    request_bindings.append("another import")
        elif isinstance(candidate, (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef)):
            if candidate.name == "Request":
                request_bindings.append("a definition")
        elif (
            isinstance(candidate, ast.Name)
            and candidate.id == "Request"
            and isinstance(candidate.ctx, (ast.Store, ast.Del))
        ):
            request_bindings.append("an assignment")
        elif isinstance(candidate, ast.ExceptHandler) and candidate.name == "Request":
            request_bindings.append("an exception target")
        elif isinstance(candidate, (ast.MatchAs, ast.MatchStar)):
            if candidate.name == "Request":
                request_bindings.append("a pattern target")
        elif isinstance(candidate, ast.MatchMapping) and candidate.rest == "Request":
            request_bindings.append("a pattern target")
    require(
        request_bindings == ["fastapi.Request"],
        f"FastAPI Request import is missing, ambiguous, or rebound: {module_name}",
    )


def registered_paths(
    module_tree: ast.Module,
    *,
    module_name: str,
    receiver_prefixes: dict[str, str],
    webhook_paths: list[str],
    provider_paths: list[str],
    static_names: dict[str, str] | None = None,
    allow_webhook_dynamic: bool = False,
    allow_provider_dynamic: bool = False,
    allow_http_middleware: bool = False,
) -> list[str]:
    """Governed paths registered in ``module_tree``; refuse anything that could shadow one."""
    paths: list[str] = []
    webhook_registrations = 0
    provider_registrations = 0

    def record_path(path: str, *, prefix: str, mount: bool) -> None:
        full_path = joined_path(prefix, path)
        pattern = route_template_pattern(full_path)
        if mount:
            pattern = pattern.rstrip("/")
            pattern = (pattern or re.escape("/")) + (
                ".*" if full_path.rstrip("/") in {"", "/"} else "(?:/.*)?"
            )
        matches = {
            governed
            for governed in GOVERNED_READ_PATHS
            if re.fullmatch(pattern, governed) is not None
        }
        if matches and (mount or full_path not in GOVERNED_READ_PATHS):
            raise ContractError("route registration may shadow a governed GET route")
        if full_path in GOVERNED_READ_PATHS:
            paths.append(full_path)

    for candidate in ast.walk(module_tree):
        if not isinstance(candidate, ast.Call) or not isinstance(candidate.func, ast.Attribute):
            continue
        receiver = attribute_path(candidate.func.value)
        if receiver is None or len(receiver) != 1:
            continue
        receiver_name = receiver[0]
        if receiver_name not in receiver_prefixes:
            if receiver_name == "app" or receiver_name.endswith("router"):
                raise ContractError(
                    f"route registration receiver is not tracked: {module_name}:{candidate.lineno}"
                )
            continue
        if candidate.func.attr == "add_middleware":
            raise ContractError(
                f"custom middleware is not permitted: {module_name}:{candidate.lineno}"
            )
        if candidate.func.attr == "middleware":
            require(
                allow_http_middleware,
                f"untracked middleware registration: {module_name}:{candidate.lineno}",
            )
            continue
        if candidate.func.attr not in ROUTE_REGISTRATION_METHODS:
            continue
        path_argument = registration_path_argument(candidate)
        if (
            allow_webhook_dynamic
            and receiver == ["router"]
            and candidate.func.attr == "add_api_route"
            and attribute_path(path_argument) == ["route", "path"]
            and exact_methods(candidate) == ["POST"]
        ):
            webhook_registrations += 1
            for configured_path in webhook_paths:
                record_path(configured_path, prefix="", mount=False)
            continue
        if (
            allow_provider_dynamic
            and receiver == ["router"]
            and candidate.func.attr == "add_api_route"
            and attribute_path(path_argument) == ["_spec", "route"]
            and exact_methods(candidate) == ["POST"]
        ):
            provider_registrations += 1
            for configured_path in provider_paths:
                record_path(configured_path, prefix="", mount=False)
            continue
        prefix = receiver_prefixes[receiver_name]
        path = static_string(path_argument, static_names)
        if path is not None:
            record_path(path, prefix=prefix, mount=candidate.func.attr == "mount")
            continue
        pattern = route_pattern(path_argument)
        if pattern is None:
            raise ContractError(
                f"route registration path cannot be proven safe: {module_name}:{candidate.lineno}"
            )
        prefixed_pattern = route_template_pattern(prefix.rstrip("/")) + pattern
        if candidate.func.attr == "mount":
            prefixed_pattern += ".*"
        require(
            not any(
                re.fullmatch(prefixed_pattern, governed) is not None
                for governed in GOVERNED_READ_PATHS
            ),
            f"dynamic route registration may shadow a governed GET route: {module_name}:{candidate.lineno}",
        )
    require(
        webhook_registrations == (1 if allow_webhook_dynamic else 0),
        "dynamic webhook route registration is missing or ambiguous",
    )
    require(
        provider_registrations == (1 if allow_provider_dynamic else 0),
        "dynamic provider route registration is missing or ambiguous",
    )
    return paths


# ----------------------------------------------------------------------
# Source loading
# ----------------------------------------------------------------------
class Sources:
    def __init__(self) -> None:
        self.module_trees: dict[str, ast.Module] = {}
        self.local_prefix_cache: dict[str, dict[str, str]] = {}
        self.imported_binding_cache: dict[str, dict[str, tuple[str, str]]] = {}

    def load(self, module_name: str) -> ast.Module:
        require(
            bool(re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", module_name)),
            "included router module name is invalid",
        )
        if module_name in self.module_trees:
            return self.module_trees[module_name]
        module_path = ROOT / "app" / (module_name.replace(".", "/") + ".py")
        try:
            module_tree = ast.parse(
                module_path.read_text(encoding="utf-8"),
                filename=module_path.relative_to(ROOT).as_posix(),
            )
        except (OSError, SyntaxError) as error:
            raise ContractError(
                f"bound source is unavailable or invalid: {module_name}"
            ) from error
        self.module_trees[module_name] = module_tree
        return module_tree

    def local_router_prefixes(self, module_name: str) -> dict[str, str]:
        if module_name in self.local_prefix_cache:
            return self.local_prefix_cache[module_name]
        prefixes: dict[str, str] = {}
        for statement in self.load(module_name).body:
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            targets = (
                statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            )
            value = statement.value
            if not (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "APIRouter"
            ):
                continue
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                raise ContractError(f"router definition is ambiguous: {module_name}")
            name = targets[0].id
            prefix_values = [
                static_string(keyword.value)
                for keyword in value.keywords
                if keyword.arg == "prefix"
            ]
            require(
                len(prefix_values) <= 1 and all(item is not None for item in prefix_values),
                f"router prefix is dynamic or ambiguous: {module_name}.{name}",
            )
            prefix = prefix_values[0] if prefix_values else ""
            if prefix is None:
                raise ContractError(f"router prefix is dynamic or ambiguous: {module_name}.{name}")
            require(name not in prefixes, f"duplicate router definition: {module_name}.{name}")
            prefixes[name] = prefix
        self.local_prefix_cache[module_name] = prefixes
        return prefixes

    def imported_router_bindings(self, module_name: str) -> dict[str, tuple[str, str]]:
        if module_name in self.imported_binding_cache:
            return self.imported_binding_cache[module_name]
        bindings: dict[str, tuple[str, str]] = {}
        for statement in self.load(module_name).body:
            if not isinstance(statement, ast.ImportFrom) or statement.module is None:
                continue
            if statement.level == 1:
                module = statement.module
            elif statement.level == 0 and statement.module.startswith("app."):
                module = statement.module.removeprefix("app.")
            else:
                continue
            for imported in statement.names:
                bound = imported.asname or imported.name
                if not (
                    imported.name == "router"
                    or imported.name.endswith("_router")
                    or bound == "router"
                    or bound.endswith("_router")
                ):
                    continue
                require(
                    bound not in bindings,
                    f"duplicate imported router binding: {module_name}.{bound}",
                )
                bindings[bound] = (module, imported.name)
        self.imported_binding_cache[module_name] = bindings
        return bindings

    def router_prefix(
        self,
        module_name: str,
        binding_name: str,
        resolving: set[tuple[str, str]] | None = None,
    ) -> str:
        marker = (module_name, binding_name)
        active = set() if resolving is None else set(resolving)
        require(marker not in active, "included router import cycle is ambiguous")
        active.add(marker)
        local = self.local_router_prefixes(module_name)
        imported = self.imported_router_bindings(module_name)
        require(
            not (binding_name in local and binding_name in imported),
            f"router binding is ambiguous: {module_name}.{binding_name}",
        )
        if binding_name in local:
            return local[binding_name]
        require(binding_name in imported, f"router binding is unresolved: {module_name}.{binding_name}")
        source_module, source_binding = imported[binding_name]
        return self.router_prefix(source_module, source_binding, active)


# ----------------------------------------------------------------------
# Factory, guard, health, control-plane routes and registry contracts
# ----------------------------------------------------------------------
def verify_factory(sources: Sources) -> None:
    """``app/application.py``: one factory, one FastAPI, only approved helpers."""
    tree = sources.load(FACTORY_MODULE)
    factories = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "create_app"
    ]
    require(len(factories) == 1, "application factory definition is not unique")
    factory = factories[0]
    app_assignments = [
        statement
        for statement in factory.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "app"
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "FastAPI"
    ]
    require(len(app_assignments) == 1, "FastAPI app binding is missing or ambiguous")
    constructor = app_assignments[0].value
    if not isinstance(constructor, ast.Call):
        raise ContractError("FastAPI app binding is missing or ambiguous")
    require(
        not any(keyword.arg in {None, "middleware"} for keyword in constructor.keywords),
        "FastAPI constructor middleware is not permitted",
    )
    canonical_app_target = app_assignments[0].targets[0]
    factory_scope = current_scope_nodes(ast.Module(body=factory.body, type_ignores=[]))
    require(
        not any(
            isinstance(candidate, ast.Name)
            and candidate.id == "app"
            and isinstance(candidate.ctx, (ast.Store, ast.Del))
            and candidate is not canonical_app_target
            for candidate in factory_scope
        ),
        "FastAPI app binding is reassigned",
    )
    for candidate in ast.walk(factory):
        value: ast.expr | None = None
        if isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            value = candidate.value
        if isinstance(value, ast.Name) and value.id == "app":
            raise ContractError("FastAPI app alias makes route registration ambiguous")

    # ``app`` is only ever handed to the approved helpers, each exactly once,
    # and the factory itself registers nothing on it.
    for candidate in ast.walk(factory):
        if isinstance(candidate, ast.Call) and attribute_path(candidate.func) is not None:
            path = attribute_path(candidate.func)
            if path and path[0] == "app":
                raise ContractError(
                    f"application factory registers directly on the app: {'.'.join(path)}"
                )
    seen: dict[str, int] = {}
    for call in factory_scope:
        if not isinstance(call, ast.Call):
            continue
        receives_app = any(
            isinstance(argument, ast.Name) and argument.id == "app" for argument in call.args
        )
        if not receives_app:
            continue
        path = attribute_path(call.func)
        if path is None:
            raise ContractError("FastAPI app is passed to an untracked registration helper")
        name = path[-1]
        owner = path[0] if len(path) == 2 else None
        expected_owner = EXPECTED_FACTORY_APP_CALLS.get(name, "unexpected")
        require(
            name in EXPECTED_FACTORY_APP_CALLS
            and expected_owner == owner
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "app",
            f"FastAPI app is passed to an untracked registration helper: {'.'.join(path)}",
        )
        seen[name] = seen.get(name, 0) + 1
    require(
        seen == {name: 1 for name in EXPECTED_FACTORY_APP_CALLS},
        "application factory registration helpers are incomplete or duplicated",
    )
    # Mounters and helpers are imported from their canonical modules.
    registry_imports = {
        imported.asname or imported.name
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == f"app.{EXPECTED_ROUTER_REGISTRY_MODULE}"
        for imported in statement.names
        if imported.asname is None
    }
    require(
        set(EXPECTED_REGISTRY_MOUNTERS) | {"assert_unique_routes"} <= registry_imports,
        "application factory router registry imports are incomplete",
    )
    helper_imports = {
        (statement.module, imported.name)
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom) and statement.level == 0
        for imported in statement.names
        if imported.asname is None
    }
    require(
        {
            (f"app.{GUARD_MODULE}", "install_request_guard"),
            (f"app.{HEALTH_MODULE}", "register_health_routes"),
        }
        <= helper_imports,
        "application factory guard/health imports drifted",
    )
    control_plane_imports = {
        imported.asname or imported.name
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module == "app"
        for imported in statement.names
    }
    require(CONTROL_PLANE_ROUTES_MODULE in control_plane_imports, "control-plane routes import drifted")
    rebound = {
        candidate.id
        for candidate in current_scope_nodes(tree)
        if isinstance(candidate, ast.Name)
        and isinstance(candidate.ctx, (ast.Store, ast.Del))
        and candidate.id in set(EXPECTED_FACTORY_APP_CALLS) | {CONTROL_PLANE_ROUTES_MODULE}
    }
    require(not rebound, "application factory helper binding is reassigned")


def verify_guard(sources: Sources) -> None:
    """``app/core/request_guard.py``: the single, non-rewriting HTTP middleware."""
    tree = sources.load(GUARD_MODULE)
    assert_request_binding(tree, GUARD_MODULE)
    middleware_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and attribute_path(node.func) == ["app", "middleware"]
    ]
    require(len(middleware_calls) == 1, "HTTP middleware registration is missing or ambiguous")
    decorator = middleware_calls[0]
    require(
        len(decorator.args) == 1
        and not decorator.keywords
        and isinstance(decorator.args[0], ast.Constant)
        and decorator.args[0].value == "http",
        "HTTP middleware registration is not exact",
    )
    installs = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Call)
        and node.func is decorator
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id == "guard"
    ]
    require(len(installs) == 1, "HTTP middleware is not installed as the request guard")
    require(
        not any(
            isinstance(node, ast.Call) and attribute_path(node.func) == ["app", "add_middleware"]
            for node in ast.walk(tree)
        ),
        "custom middleware is not permitted",
    )

    guard_classes = [
        node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "RequestGuard"
    ]
    require(len(guard_classes) == 1, "request guard class is missing or ambiguous")
    handlers = [
        node
        for node in guard_classes[0].body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "__call__"
    ]
    require(len(handlers) == 1, "HTTP middleware definition is ambiguous")
    middleware = handlers[0]
    require(not middleware.decorator_list, "HTTP middleware definition is ambiguous")
    arguments = [*middleware.args.posonlyargs, *middleware.args.args]
    require(
        [argument.arg for argument in arguments] == ["self", "request", "call_next"]
        and isinstance(arguments[1].annotation, ast.Name)
        and arguments[1].annotation.id == "Request"
        and not middleware.args.defaults
        and middleware.args.vararg is None
        and middleware.args.kwarg is None
        and not middleware.args.kwonlyargs,
        "HTTP middleware parameters are not exact",
    )
    scope = current_scope_nodes(middleware)
    delegated = [
        node
        for node in scope
        if isinstance(node, ast.Await)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "call_next"
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Name)
        and node.value.args[0].id == "request"
        and not node.value.keywords
    ]
    require(len(delegated) == 1, "HTTP middleware delegation is not exact")
    delegated_call = delegated[0].value
    call_next_loads = [
        node
        for node in scope
        if isinstance(node, ast.Name) and node.id == "call_next" and isinstance(node.ctx, ast.Load)
    ]
    require(
        isinstance(delegated_call, ast.Call) and call_next_loads == [delegated_call.func],
        "HTTP middleware delegation callable is reused or aliased",
    )
    response_assignments = [
        node
        for node in scope
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "response"
        and node.value is delegated[0]
    ]
    require(len(response_assignments) == 1, "HTTP middleware does not preserve the delegated response")
    response_bindings = [
        node
        for node in scope
        if isinstance(node, ast.Name)
        and node.id == "response"
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    require(
        response_bindings == [response_assignments[0].targets[0]],
        "HTTP middleware response binding is reassigned",
    )

    def root_name(node: ast.expr) -> str | None:
        current = node
        while isinstance(current, (ast.Attribute, ast.Subscript)):
            current = current.value
        return current.id if isinstance(current, ast.Name) else None

    mutated_headers: list[str] = []
    for node in scope:
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets.extend(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            targets.append(node.target)
        elif isinstance(node, ast.Delete):
            targets.extend(node.targets)
        for target in targets:
            root = root_name(target)
            if root == "response":
                if target is response_assignments[0].targets[0]:
                    continue
                if not (
                    isinstance(target, ast.Subscript)
                    and attribute_path(target.value) == ["response", "headers"]
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value in GUARD_RESPONSE_HEADERS
                ):
                    raise ContractError("HTTP middleware mutates the delegated response")
                mutated_headers.append(str(target.slice.value))
            elif root == "request":
                target_path = attribute_path(target)
                require(
                    target_path is not None and target_path[:2] == ["request", "state"],
                    "HTTP middleware mutates request routing state",
                )
    require(
        set(mutated_headers) == GUARD_RESPONSE_HEADERS,
        "HTTP middleware response-header mutations drifted",
    )
    for node in scope:
        if not isinstance(node, ast.Call):
            continue
        call_path = attribute_path(node.func)
        if call_path is None:
            continue
        if call_path[:1] == ["response"]:
            raise ContractError("HTTP middleware mutates the delegated response")
        if call_path[:1] == ["request"]:
            require(
                tuple(call_path) in GUARD_REQUEST_READS,
                "HTTP middleware mutates or ambiguously consumes the request",
            )
    returns = [node for node in scope if isinstance(node, ast.Return)]
    require(bool(returns), "HTTP middleware never returns")
    for statement in returns:
        value = statement.value
        if isinstance(value, ast.Name) and value.id == "response":
            continue
        # A pre-routing refusal: JSONResponse(...) with a fail-closed status.
        require(
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "JSONResponse",
            "HTTP middleware may return without routing the request",
        )
        statuses = [
            keyword.value for keyword in value.keywords if keyword.arg == "status_code"  # type: ignore[union-attr]
        ]
        require(
            len(statuses) == 1
            and isinstance(statuses[0], ast.Constant)
            and statuses[0].value in GUARD_REFUSAL_STATUSES,
            "HTTP middleware refusal status is not a fail-closed constant",
        )


def verify_governed_routes(sources: Sources) -> dict[str, tuple[str, str]]:
    """``app/appolon_routes.py``: governed reads authenticate first, statically."""
    tree = sources.load(CONTROL_PLANE_ROUTES_MODULE)
    assert_request_binding(tree, CONTROL_PLANE_ROUTES_MODULE)

    def authentication_binding(node: ast.AsyncFunctionDef) -> tuple[str, str]:
        positional = [*node.args.posonlyargs, *node.args.args]
        request_arguments = [
            (index, argument) for index, argument in enumerate(positional) if argument.arg == "request"
        ]
        require(len(request_arguments) == 1, "governed GET route request binding is missing or ambiguous")
        request_index, request_argument = request_arguments[0]
        require(
            isinstance(request_argument.annotation, ast.Name)
            and request_argument.annotation.id == "Request",
            "governed GET route request parameter is not FastAPI Request",
        )
        default_start = len(positional) - len(node.args.defaults)
        require(request_index < default_start, "governed GET route request parameter has a dependency default")
        statements = list(node.body)
        if (
            statements
            and isinstance(statements[0], ast.Expr)
            and isinstance(statements[0].value, ast.Constant)
            and isinstance(statements[0].value.value, str)
        ):
            statements = statements[1:]
        if not statements:
            raise ContractError("governed GET route body is empty")
        first = statements[0]
        if not isinstance(first, ast.Expr) or not isinstance(first.value, ast.Await):
            raise ContractError("governed GET route must authenticate before executing its body")
        call = first.value.value
        if not isinstance(call, ast.Call) or attribute_path(call.func) != [
            "request",
            "app",
            "state",
            "runtime",
            "tokens",
            "verify",
        ]:
            raise ContractError("governed GET route does not await the runtime token verifier")
        if len(call.args) != 1 or not isinstance(call.args[0], ast.Call):
            raise ContractError("governed GET route does not verify its Authorization header")
        header_call = call.args[0]
        if (
            attribute_path(header_call.func) != ["request", "headers", "get"]
            or len(header_call.args) != 2
            or not all(isinstance(item, ast.Constant) for item in header_call.args)
            or [item.value for item in header_call.args if isinstance(item, ast.Constant)]
            != ["Authorization", ""]
        ):
            raise ContractError("governed GET route does not verify its Authorization header")
        require(
            all(keyword.arg is not None for keyword in call.keywords),
            "governed GET route authentication uses expanded keywords",
        )
        keywords = {item.arg: item.value for item in call.keywords if item.arg}
        require(
            set(keywords) == {"expected_client_id", "required_scope"},
            "governed GET route authentication keywords are not exact",
        )
        client = keywords["expected_client_id"]
        scope = keywords["required_scope"]
        if (
            not isinstance(client, ast.Constant)
            or not isinstance(client.value, str)
            or not isinstance(scope, ast.Constant)
            or not isinstance(scope.value, str)
        ):
            raise ContractError("governed GET route authentication binding is not static")
        return client.value, scope.value

    routes: dict[str, tuple[str, str]] = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        paths: list[str] = []
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "router"
                and decorator.func.attr == "get"
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and isinstance(decorator.args[0].value, str)
            ):
                paths.append(decorator.args[0].value)
        paths = [path for path in paths if path in GOVERNED_READ_PATHS]
        if not paths:
            continue
        require(len(node.decorator_list) == 1, "governed GET route has a handler-replacing decorator")
        for path in paths:
            require(path not in routes, f"duplicate GET route in control-plane routes: {path}")
            if not isinstance(node, ast.AsyncFunctionDef):
                raise ContractError(f"governed GET route must be asynchronous: {path}")
            routes[path] = authentication_binding(node)

    # Route helpers register on the module router exactly once.
    for helper_name, module_name in EXPECTED_ROUTE_HELPERS.items():
        imports = [
            statement
            for statement in tree.body
            if isinstance(statement, ast.ImportFrom)
            and statement.level == 1
            and statement.module == module_name
            and any(i.name == helper_name and i.asname is None for i in statement.names)
        ]
        require(len(imports) == 1, f"route helper import drift: {helper_name}")
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == helper_name
        ]
        require(
            len(calls) == 1
            and len(calls[0].args) == 1
            and not calls[0].keywords
            and isinstance(calls[0].args[0], ast.Name)
            and calls[0].args[0].id == "router",
            f"route helper call is missing or ambiguous: {helper_name}",
        )
    local = sources.local_router_prefixes(CONTROL_PLANE_ROUTES_MODULE)
    require(set(local) == {"router"} and local["router"] == "", "control-plane router definition drifted")
    return routes


def verify_router_registry(sources: Sources) -> None:
    """``app/router_registry.py`` mounts exactly the approved router groups."""
    registry_tree = sources.load(EXPECTED_ROUTER_REGISTRY_MODULE)
    imported: dict[str, tuple[str, str]] = {}
    for statement in registry_tree.body:
        if not isinstance(statement, ast.ImportFrom):
            continue
        module = statement.module or ""
        if statement.level != 0 or not module.startswith("app."):
            continue
        for name in statement.names:
            bound = name.asname or name.name
            if bound not in EXPECTED_REGISTRY_ROUTERS:
                continue
            require(bound not in imported, f"duplicate router registry import: {bound}")
            imported[bound] = (module.removeprefix("app."), name.name)
    require(
        imported == EXPECTED_REGISTRY_ROUTERS,
        "router registry imports drifted from the approved router set",
    )
    side_effect_modules = {
        imported_name.name
        for statement in registry_tree.body
        if isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module == "app"
        for imported_name in statement.names
    }
    require(
        side_effect_modules == EXPECTED_SIDE_EFFECT_ROUTER_MODULES,
        "router registry side-effect router imports drifted",
    )
    rebound = {
        candidate.id
        for candidate in ast.walk(registry_tree)
        if isinstance(candidate, ast.Name)
        and isinstance(candidate.ctx, (ast.Store, ast.Del))
        and candidate.id in EXPECTED_REGISTRY_ROUTERS
    }
    require(not rebound, "router registry rebinds an approved router")
    tuples: dict[str, list[str]] = {}
    for statement in registry_tree.body:
        if isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
            target_name, value = statement.target.id, statement.value
        elif (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
        ):
            target_name, value = statement.targets[0].id, statement.value
        else:
            continue
        if target_name not in EXPECTED_REGISTRY_TUPLES:
            continue
        require(target_name not in tuples, f"router registry tuple is duplicated: {target_name}")
        require(
            isinstance(value, ast.Tuple) and all(isinstance(item, ast.Name) for item in value.elts),
            f"router registry tuple is not a literal tuple of routers: {target_name}",
        )
        names = [item.id for item in value.elts]  # type: ignore[union-attr]
        require(
            len(names) == len(set(names)) and set(names) == EXPECTED_REGISTRY_TUPLES[target_name],
            f"router registry tuple drifted from the approved router set: {target_name}",
        )
        tuples[target_name] = names
    require(set(tuples) == set(EXPECTED_REGISTRY_TUPLES), "router registry tuples are incomplete")
    all_names = [name for names in tuples.values() for name in names]
    require(len(all_names) == len(set(all_names)), "a router is mounted by more than one group")

    # ``_mount`` is the only place ``app.include_router`` is called: one loop
    # over its ``routers`` argument, including exactly the loop variable.
    mounts = [
        node for node in registry_tree.body if isinstance(node, ast.FunctionDef) and node.name == "_mount"
    ]
    require(len(mounts) == 1, "router registry _mount helper is not unique")
    loops = [
        node
        for node in ast.walk(mounts[0])
        if isinstance(node, ast.For)
        and isinstance(node.target, ast.Name)
        and isinstance(node.iter, ast.Name)
        and node.iter.id == "routers"
    ]
    includes = [
        node
        for node in ast.walk(registry_tree)
        if isinstance(node, ast.Call) and attribute_path(node.func) == ["app", "include_router"]
    ]
    require(
        len(loops) == 1
        and len(includes) == 1
        and len(includes[0].args) == 1
        and not includes[0].keywords
        and isinstance(includes[0].args[0], ast.Name)
        and includes[0].args[0].id == loops[0].target.id,  # type: ignore[attr-defined]
        "router registry includes an unapproved router",
    )
    for mounter_name, tuple_name in EXPECTED_REGISTRY_MOUNTERS.items():
        definitions = [
            node
            for node in registry_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == mounter_name
        ]
        require(len(definitions) == 1, f"router registry mounter is not unique: {mounter_name}")
        mount_calls = [
            node
            for node in ast.walk(definitions[0])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_mount"
        ]
        require(
            len(mount_calls) == 1
            and len(mount_calls[0].args) == 2
            and not mount_calls[0].keywords
            and isinstance(mount_calls[0].args[0], ast.Name)
            and mount_calls[0].args[0].id == "app"
            and isinstance(mount_calls[0].args[1], ast.Name)
            and mount_calls[0].args[1].id == tuple_name,
            f"router registry mounter does not mount {tuple_name}: {mounter_name}",
        )


def verify_route_sources(
    sources: Sources,
    *,
    webhook_paths: list[str],
    provider_paths: list[str],
) -> None:
    """No mounted module, helper or health registration may shadow a governed path."""
    all_registered_paths: list[str] = []

    # Control-plane routes: the governed reads plus the dynamic webhook ingress.
    # ``app`` appears only in the error-handler/OpenAPI installers, which
    # register no routes; it is tracked so any route registration on it fails.
    routes_tree = sources.load(CONTROL_PLANE_ROUTES_MODULE)
    all_registered_paths.extend(
        registered_paths(
            routes_tree,
            module_name=CONTROL_PLANE_ROUTES_MODULE,
            receiver_prefixes={"router": "", "app": ""},
            webhook_paths=webhook_paths,
            provider_paths=provider_paths,
            static_names=module_string_constants(routes_tree),
            allow_webhook_dynamic=True,
        )
    )
    # Health surface (registered on ``app`` from literal paths only).
    health_tree = sources.load(HEALTH_MODULE)
    all_registered_paths.extend(
        registered_paths(
            health_tree,
            module_name=HEALTH_MODULE,
            receiver_prefixes={"app": ""},
            webhook_paths=webhook_paths,
            provider_paths=provider_paths,
            static_names=module_string_constants(health_tree),
        )
    )
    # The guard registers exactly the HTTP middleware and nothing else on ``app``.
    guard_tree = sources.load(GUARD_MODULE)
    all_registered_paths.extend(
        registered_paths(
            guard_tree,
            module_name=GUARD_MODULE,
            receiver_prefixes={"app": ""},
            webhook_paths=webhook_paths,
            provider_paths=provider_paths,
            allow_http_middleware=True,
        )
    )
    # Route helpers.
    for helper_name, module_name in EXPECTED_ROUTE_HELPERS.items():
        helper_tree = sources.load(module_name)
        all_registered_paths.extend(
            registered_paths(
                helper_tree,
                module_name=module_name,
                receiver_prefixes={"app": ""},
                webhook_paths=webhook_paths,
                provider_paths=provider_paths,
                static_names=module_string_constants(helper_tree),
            )
        )

    pending_modules = list(
        dict.fromkeys(
            [
                *(module for module, _name in EXPECTED_REGISTRY_ROUTERS.values()),
                *sorted(EXPECTED_SIDE_EFFECT_ROUTER_MODULES),
            ]
        )
    )
    scanned_modules: set[str] = {CONTROL_PLANE_ROUTES_MODULE}
    while pending_modules:
        module_name = pending_modules.pop(0)
        if module_name in scanned_modules:
            continue
        module_tree = sources.load(module_name)
        local = sources.local_router_prefixes(module_name)
        imported_bindings = sources.imported_router_bindings(module_name)
        receiver_names = set(local) | set(imported_bindings)
        require(receiver_names, f"included router module has no router: {module_name}")
        receiver_prefixes = {name: sources.router_prefix(module_name, name) for name in receiver_names}
        for candidate in ast.walk(module_tree):
            if not isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                continue
            if isinstance(candidate.value, ast.Name) and candidate.value.id in receiver_names:
                raise ContractError(f"router alias makes registration ambiguous: {module_name}")
        all_registered_paths.extend(
            registered_paths(
                module_tree,
                module_name=module_name,
                receiver_prefixes=receiver_prefixes,
                webhook_paths=webhook_paths,
                provider_paths=provider_paths,
                static_names=module_string_constants(module_tree),
                allow_provider_dynamic=module_name == "provider_control_api",
            )
        )
        for candidate in ast.walk(module_tree):
            if (
                not isinstance(candidate, ast.Call)
                or not isinstance(candidate.func, ast.Attribute)
                or candidate.func.attr != "include_router"
            ):
                continue
            receiver = attribute_path(candidate.func.value)
            require(
                receiver is not None and len(receiver) == 1 and receiver[0] in receiver_names,
                f"included-router receiver is unresolved: {module_name}",
            )
            if (
                len(candidate.args) != 1
                or candidate.keywords
                or not isinstance(candidate.args[0], ast.Name)
                or candidate.args[0].id not in receiver_names
            ):
                raise ContractError(f"included-router binding is dynamic or ambiguous: {module_name}")
            included_name = candidate.args[0].id
            if included_name in imported_bindings:
                pending_modules.append(imported_bindings[included_name][0])
        scanned_modules.add(module_name)
    for path in GOVERNED_READ_PATHS:
        require(
            all_registered_paths.count(path) == 1,
            f"governed GET route registration is missing or ambiguous: {path}",
        )


def verify_application_sources(
    *,
    webhook_paths: list[str],
    provider_paths: list[str],
) -> dict[str, tuple[str, str]]:
    sources = Sources()
    verify_factory(sources)
    verify_guard(sources)
    verify_router_registry(sources)
    routes = verify_governed_routes(sources)
    verify_route_sources(sources, webhook_paths=webhook_paths, provider_paths=provider_paths)
    return routes


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def main() -> None:
    contract = json.loads(
        (ROOT / "contracts/staging-intake-observability-runtime.v1.json").read_text()
    )
    require(contract["schema_version"] == "1.1", "contract schema version drift")
    release = contract["immutable_release"]
    require(release["source_sha"] == EXPECTED_SOURCE, "release source drift")
    require(release["image_digest"] == EXPECTED_DIGEST, "release digest drift")
    require(
        release["image_reference"].endswith("@" + EXPECTED_DIGEST),
        "release image is not digest-bound",
    )
    require(
        re.fullmatch(r"sha256:[0-9a-f]{64}", release["image_digest"]),
        "release digest is invalid",
    )
    require(
        release["schema_head"] == "0003_immutable_event_ledger",
        "release schema head drift",
    )

    profiles = json.loads((ROOT / "config/runtime-profiles.v1.json").read_text())
    require(profiles["schema_version"] == "1.0", "profile schema version drift")
    matches = [
        item for item in profiles["profiles"] if item["profile_id"] == EXPECTED_PROFILE["profile_id"]
    ]
    require(matches == [EXPECTED_PROFILE], "staging runtime profile drift")
    embedded = release["embedded_runtime_profile"]
    require(
        embedded
        == {
            "profile_id": EXPECTED_PROFILE["profile_id"],
            "database_host": EXPECTED_PROFILE["database"]["host"],
            "database_name": EXPECTED_PROFILE["database"]["name"],
            "database_username": EXPECTED_PROFILE["database"]["username"],
            "database_sslmode": EXPECTED_PROFILE["database"]["sslmode"],
            "redis_host": EXPECTED_PROFILE["redis"]["host"],
            "redis_username": EXPECTED_PROFILE["redis"]["username"],
            "redis_database": EXPECTED_PROFILE["redis"]["database"],
            "redis_tls_required": True,
            "production_activation_allowed": False,
        },
        "embedded runtime profile drift",
    )

    runtime = contract["runtime"]
    require(runtime["environment"] == "staging", "runtime environment drift")
    require(runtime["profile_id"] == EXPECTED_PROFILE["profile_id"], "runtime profile binding drift")
    require(runtime["allow_in_memory_storage"] is False, "in-memory storage must remain disabled")
    require(runtime["host_ports_published"] is False, "host ports must not publish")
    require(runtime["private_network_only"] is True, "runtime must remain private")
    require(
        runtime["dependencies"] == ["postgresql-tls", "redis-tls", "keycloak-jwks"],
        "runtime dependency binding drift",
    )
    require(runtime["nats_dispatch_mode"] == "disabled", "NATS dispatch enabled")
    require(runtime["temporal_worker_mode"] == "disabled", "Temporal worker enabled")
    require(runtime["outbox_dispatch_enabled"] is False, "outbox dispatch enabled")
    require(runtime["production_dialing"] == "DISABLED", "production dialing enabled")
    require(runtime["production_activation_configured"] is False, "production activation configured")

    endpoints = contract["authenticated_read_endpoints"]
    expected_endpoints = {
        ("GET", "/metrics", "monitoring-readonly", "metrics.read", "middleware-api", False),
        ("GET", "/v1/runtime/safety", "monitoring-readonly", "health.read", "middleware-api", False),
    }
    actual = {
        (e["method"], e["path"], e["client_id"], e["scope"], e["audience"], e["public_exposure"])
        for e in endpoints
    }
    require(actual == expected_endpoints and len(endpoints) == 2, "authenticated read endpoint policy drift")
    require(contract["token_policy"]["maximum_lifetime_seconds"] == 300, "token lifetime policy drift")
    require(contract["token_policy"]["minimum_independent_tokens"] == 2, "independent token policy drift")
    require(
        contract["token_policy"]["token_values_in_logs_or_artifacts"] is False,
        "token values may enter evidence",
    )
    effects = contract["runtime_recognized_external_effects"]
    require(
        bool(effects) and all(value is False for value in effects.values()),
        "runtime external effect is enabled",
    )
    require(
        contract["dispatch_controls"]
        == {
            "OUTBOX_DISPATCH_ENABLED": False,
            "NATS_DISPATCH_MODE": "disabled",
            "TEMPORAL_WORKER_MODE": "disabled",
            "PRODUCTION_DIALING": "DISABLED",
        },
        "dispatch control drift",
    )
    require(
        all(value is False for value in contract["defense_in_depth_compatibility_flags"].values()),
        "compatibility effect is enabled",
    )
    require(
        contract["evidence"]["checksum_state"] == "PENDING_RUNTIME_EXECUTION",
        "runtime checksum evidence was asserted from source",
    )
    require(contract["evidence"]["prometheus_target_state"] == "pending", "Prometheus evidence was asserted from source")
    require(contract["evidence"]["blackbox_target_state"] == "pending", "blackbox evidence was asserted from source")
    require(contract["production_authorized"] is False, "production authorized")

    env = parse_env(ROOT / "config/environments/staging.intake-observability.runtime.env.example")
    require(env["APP_ENV"] == "staging", "environment template is not staging")
    require(env["RUNTIME_PROFILE_ID"] == EXPECTED_PROFILE["profile_id"], "environment profile drift")
    require(env["APP_SOURCE_SHA"] == EXPECTED_SOURCE, "environment source drift")
    require(env["IMAGE_DIGEST"] == EXPECTED_DIGEST, "environment digest drift")
    require(env["SCHEMA_HEAD"] == release["schema_head"], "environment schema drift")
    require(env["ALLOW_IN_MEMORY_STORAGE"] == "false", "environment permits in-memory storage")
    assert_database_url(env["DATABASE_URL"])
    assert_redis_url(env["REDIS_URL"])
    require(env["NATS_URL"] == "", "NATS URL must remain unset")
    require(env["NATS_STREAM"] == EXPECTED_PROFILE["nats"]["stream"], "NATS stream drift")
    require(env["NATS_SUBJECT_PREFIX"] == EXPECTED_PROFILE["nats"]["subject_prefix"], "NATS subject drift")
    require(env["NATS_DISPATCH_MODE"] == "disabled", "NATS dispatch enabled")
    require(env["TEMPORAL_ADDRESS"] == "", "Temporal address must remain unset")
    require(env["TEMPORAL_NAMESPACE"] == EXPECTED_PROFILE["temporal"]["namespace"], "Temporal namespace drift")
    require(env["TEMPORAL_TASK_QUEUE"] == EXPECTED_PROFILE["temporal"]["task_queue"], "Temporal task queue drift")
    require(env["TEMPORAL_WORKER_MODE"] == "disabled", "Temporal worker enabled")
    require(env["PRODUCTION_DIALING"] == "DISABLED", "production dialing enabled")
    for name in effects:
        require(env[name] == "false", f"environment effect enabled: {name}")
    require(env["OUTBOX_DISPATCH_ENABLED"] == "false", "outbox dispatch enabled")
    for name in contract["defense_in_depth_compatibility_flags"]:
        require(env[name] == "false", f"compatibility effect enabled: {name}")
    require(WEBHOOK_SECRET_NAMES.issubset(env), "environment webhook secret placeholders are incomplete")
    require(
        all(len(env[name]) >= 32 and env[name].startswith("REPLACE_WITH_") for name in WEBHOOK_SECRET_NAMES),
        "environment webhook secret placeholder is unsafe",
    )

    security_source = (ROOT / "app/security.py").read_text()
    webhook_contract = json.loads((ROOT / "config/api-webhook-contracts.json").read_text(encoding="utf-8"))
    raw_webhooks = webhook_contract.get("webhooks", [])
    require(isinstance(raw_webhooks, list), "dynamic webhook policy is malformed")
    webhook_paths: list[str] = []
    for item in raw_webhooks:
        require(isinstance(item, dict), "dynamic webhook policy is malformed")
        path = item.get("path")
        require(isinstance(path, str) and path.startswith("/"), "dynamic webhook path is invalid")
        webhook_paths.append(path)
    require(
        webhook_paths
        and len(webhook_paths) == len(set(webhook_paths))
        and GOVERNED_READ_PATHS.isdisjoint(webhook_paths),
        "dynamic webhook paths are duplicated or shadow a governed GET route",
    )
    provider_policy = json.loads((ROOT / "config/provider-operation-policy.json").read_text(encoding="utf-8"))
    require(provider_policy.get("schemaVersion") == 1, "provider operation policy version drift")
    raw_provider_operations = provider_policy.get("operations", [])
    require(isinstance(raw_provider_operations, list), "provider operation policy is malformed")
    provider_paths: list[str] = []
    for operation in raw_provider_operations:
        require(isinstance(operation, dict), "provider operation policy is malformed")
        if operation.get("externalEffect") is not True:
            continue
        path = operation.get("route")
        require(isinstance(path, str) and path.startswith("/"), "provider operation route is invalid")
        provider_paths.append(path)
    require(
        provider_paths
        and len(provider_paths) == len(set(provider_paths))
        and GOVERNED_READ_PATHS.isdisjoint(provider_paths),
        "provider operation routes are duplicated or shadow a governed GET route",
    )
    route_bindings = verify_application_sources(
        webhook_paths=webhook_paths,
        provider_paths=provider_paths,
    )
    require(
        route_bindings.get("/metrics") == ("monitoring-readonly", "metrics.read"),
        "metrics authentication binding drift",
    )
    require(
        route_bindings.get("/v1/runtime/safety") == ("monitoring-readonly", "health.read"),
        "runtime safety authentication binding drift",
    )
    require("expires_at - issued_at > 300" in security_source, "token lifetime enforcement is missing")
    workflow_source = (ROOT / ".github/workflows/staging-intake-observability-contract.yml").read_text(
        encoding="utf-8"
    )
    for trigger in ("pull_request", "push"):
        paths = workflow_trigger_paths(workflow_source, trigger)
        require(WORKFLOW_REQUIRED_PATHS <= paths, f"workflow {trigger} paths omit a bound contract source")
    print("MIDDLEWARE_STAGING_INTAKE_OBSERVABILITY_CONTRACT=PASS")


if __name__ == "__main__":
    main()
