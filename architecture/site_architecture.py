"""Build the supplemental site/provider architecture from reviewed data."""

from __future__ import annotations

from typing import Any, cast

from .routes import (
    APPLICATION_ROUTES,
    LEAD_DEDUPLICATION_ORDER,
    LEAD_REQUIRED_METADATA,
    LEAD_SOURCES,
    PRIVATE_ROUTES,
    PROVIDER_ROUTES,
    STACKS,
)
from .workstreams import (
    CANONICAL_CONTRACT_BRANCH,
    DEPENDENCY_EXTRAS,
    POLICIES,
    PROVIDER_COMPONENTS,
    STATUS_OVERRIDES,
    WORKSTREAMS,
)


def workstreams() -> list[dict[str, str]]:
    return [
        {"branch": branch, "category": values[0], "runtime_status": values[1], "purpose": values[2]}
        for branch, values in sorted(WORKSTREAMS.items())
    ]


def dependencies() -> dict[str, list[str]]:
    return {
        branch: [CANONICAL_CONTRACT_BRANCH, *DEPENDENCY_EXTRAS.get(branch, ())]
        for branch in sorted(WORKSTREAMS)
    }


def _link(
    link_id: str,
    source: str,
    target: str,
    transport: str = "internal",
    auth: str = "internal_service_policy",
    reliability: str = "synchronous",
    status: str = "declared",
    contract: str = "contracts/http-conventions.md",
) -> dict[str, str]:
    return {
        "id": link_id,
        "from": source,
        "to": target,
        "transport": transport,
        "auth": auth,
        "reliability": reliability,
        "status": status,
        "contract": contract,
    }


def connections() -> list[dict[str, str]]:
    links: list[dict[str, str]] = []

    for branch in sorted(WORKSTREAMS):
        link_id = "contracts-to-" + branch.replace("/", "-")
        contract = (
            "contracts/lead-intake.schema.json"
            if branch == "core/lead-intake-normalization"
            else "contracts/http-conventions.md"
        )
        runtime = WORKSTREAMS[branch][1]
        status = {
            "source_checkout_not_deployed": "not_deployed",
            "declared_private_scope": "private_only",
            "declared_degraded_scope": "degraded",
            "declared_remote_provider_scope": "declared_remote",
        }.get(runtime, "declared")
        links.append(_link(link_id, CANONICAL_CONTRACT_BRANCH, branch, status=status, contract=contract))

    for site in (
        "site/codestra", "site/codestra-auth", "site/codestra-social",
        "site/codestra-ai", "site/beyvra", "site/booked4seasons", "site/breero",
    ):
        status = "degraded" if WORKSTREAMS[site][1] == "declared_degraded_scope" else "declared"
        links.append(_link(
            "caddy-to-" + site.replace("/", "-"),
            "platform/caddy", site, "https", "public_tls", "synchronous", status,
            "contracts/provider-transport-conventions.md",
        ))

    for site in ("site/klyrow", "site/telnexa", "site/kyqra-crawler"):
        links.append(_link(
            "nginx-to-" + site.replace("/", "-"),
            "platform/nginx-provider", site, "https", "public_tls",
            "synchronous", "declared_remote",
            "contracts/provider-transport-conventions.md",
        ))

    links.extend([
        _link(
            "nginx-to-private-app", "platform/nginx-provider",
            "site/private-app-integration", "loopback_http", "mtls",
            "synchronous", "private_only",
            "contracts/provider-transport-conventions.md",
        ),
        _link(
            "provider-host-to-scrapper-source", "operations/provider-host",
            "site/codestra-business-scrapper", "filesystem",
            "host_operator_policy", "read_only", "not_deployed",
            "contracts/provider-transport-conventions.md",
        ),
        _link(
            "web-form-to-private-gateway", "integration/web-form-intake",
            "integration/private-app-gateway", "https", "service_identity",
            "durable_inbox", "private_only",
            "contracts/lead-intake.schema.json",
        ),
        _link(
            "private-gateway-to-inbox", "integration/private-app-gateway",
            "core/webhook-inbox-replay", "https", "mtls",
            "durable_inbox", "private_only",
            "contracts/lead-intake.schema.json",
        ),
        _link(
            "inbox-to-lead-normalization", "core/webhook-inbox-replay",
            "core/lead-intake-normalization", reliability="durable_inbox",
            contract="contracts/lead-intake.schema.json",
        ),
        _link(
            "lead-normalization-to-outbox", "core/lead-intake-normalization",
            "core/event-ledger-outbox", reliability="transactional_outbox",
            contract="contracts/odoo-lead-command.schema.json",
        ),
        _link(
            "outbox-to-odoo-leads", "core/event-ledger-outbox",
            "integration/odoo-19", "https", "oidc_jwt", "at_least_once",
            contract="contracts/odoo-lead-command.schema.json",
        ),
    ])

    for site in (
        "site/codestra", "site/beyvra", "site/booked4seasons",
        "site/breero", "site/klyrow", "site/telnexa",
    ):
        status = (
            "degraded" if site == "site/booked4seasons"
            else "declared_remote" if site in {"site/klyrow", "site/telnexa"}
            else "declared"
        )
        links.append(_link(
            site.replace("/", "-") + "-forms-to-intake",
            site, "integration/web-form-intake", "https",
            "anti_abuse_and_service_identity", "durable_inbox",
            status, "contracts/lead-intake.schema.json",
        ))

    links.extend([
        _link(
            "kyqra-results-to-lead-normalization", "integration/kyqra",
            "core/lead-intake-normalization", "https", "mtls",
            "durable_inbox", "declared_remote",
            "contracts/lead-intake.schema.json",
        ),
        _link(
            "scrapper-results-to-lead-normalization",
            "integration/codestra-business-scrapper",
            "core/lead-intake-normalization", reliability="durable_inbox",
            status="not_deployed", contract="contracts/lead-intake.schema.json",
        ),
        _link("social-site-to-postiz", "site/codestra-social", "integration/postiz-social"),
        _link("ai-site-to-ai-console", "site/codestra-ai", "integration/codestra-ai-console"),
        _link(
            "application-ops-to-caddy", "operations/application-host",
            "platform/caddy", "docker_api", "host_operator_policy",
            contract="contracts/provider-transport-conventions.md",
        ),
        _link(
            "provider-ops-to-nginx", "operations/provider-host",
            "platform/nginx-provider", "docker_api", "host_operator_policy",
            status="declared_remote",
            contract="contracts/provider-transport-conventions.md",
        ),
        _link(
            "smtp-relay-to-postal", "integration/klyrow-smtp-relay",
            "integration/postal-email", "smtp", "smtp_credentials",
            "store_and_forward", "declared_remote",
            "contracts/provider-transport-conventions.md",
        ),
        _link(
            "billing-to-rabbitmq", "integration/provider-billing",
            "platform/rabbitmq", "amqp", "amqp_tls_identity",
            "at_least_once", "declared_remote",
            "contracts/provider-transport-conventions.md",
        ),
    ])

    for site, components in PROVIDER_COMPONENTS.items():
        for component in components:
            links.append(_link(
                site.replace("/", "-") + "-to-" + component.replace("/", "-"),
                site, component, status="declared_remote",
                contract="contracts/provider-transport-conventions.md",
            ))

    return links


def route_dict(values: tuple[Any, ...]) -> dict[str, Any]:
    hostname, branch, kind, environment, status, accepts_forms, redirect_to, issue = values
    result: dict[str, Any] = {
        "hostname": hostname,
        "branch": branch,
        "kind": kind,
        "environment": environment,
        "status": status,
        "accepts_forms": accepts_forms,
    }
    if redirect_to is not None:
        result["redirect_to"] = redirect_to
    if issue is not None:
        result["issue"] = issue
    return result


def server_stacks() -> dict[str, Any]:
    return {
        "application-server-a": {
            "address": "65.109.65.169",
            "edge_branch": "platform/caddy",
            "operations_branch": "operations/application-host",
            "routes": [route_dict(item) for item in APPLICATION_ROUTES],
        },
        "provider-host": {
            "address": "37.27.128.39",
            "edge_branch": "platform/nginx-provider",
            "operations_branch": "operations/provider-host",
            "routes": [route_dict(item) for item in PROVIDER_ROUTES],
            "private_routes": [
                {"id": item[0], "branch": item[1], "status": item[2], "exposure": item[3]}
                for item in PRIVATE_ROUTES
            ],
            "stacks": [
                {
                    "id": item[1],
                    "branch": item[2],
                    "status": item[3],
                    "components": list(item[4]),
                    **cast(dict[str, Any], item[5]),
                }
                for item in STACKS if item[0] == "provider-host"
            ],
        },
    }


def lead_ingestion() -> dict[str, Any]:
    sources = []
    for item in LEAD_SOURCES:
        (
            source_id, source_kind, source_branch, hostnames, runtime_status,
            edge_branch, pipeline, operation, initial_stage, review_required,
            allow_external_contact,
        ) = item
        sources.append({
            "id": source_id,
            "source_kind": source_kind,
            "source_branch": source_branch,
            "hostnames": list(hostnames),
            "runtime_status": runtime_status,
            "edge_branch": edge_branch,
            "pipeline": list(pipeline),
            "odoo_policy": {
                "operation": operation,
                "initial_stage": initial_stage,
                "review_required": review_required,
                "allow_external_contact": allow_external_contact,
            },
        })

    return {
        "version": 1,
        "write_boundary": "middleware",
        "direct_site_crawler_or_scraper_write_to_odoo": False,
        "canonical_intake_schema": "contracts/lead-intake.schema.json",
        "canonical_odoo_command_schema": "contracts/odoo-lead-command.schema.json",
        "required_metadata": list(LEAD_REQUIRED_METADATA),
        "deduplication_order": list(LEAD_DEDUPLICATION_ORDER),
        "sources": sources,
        "odoo_target": {
            "model": "crm.lead",
            "contact_model": "res.partner",
            "delivery_branch": "integration/odoo-19",
            "review_stage": "review_pending",
            "normal_form_stage": "new",
        },
    }


def architecture() -> dict[str, Any]:
    return {
        "version": 1,
        "canonical_contract_branch": CANONICAL_CONTRACT_BRANCH,
        "runtime_status_overrides": dict(STATUS_OVERRIDES),
        "workstreams": workstreams(),
        "dependencies": dependencies(),
        "connections": connections(),
        "server_stacks": server_stacks(),
        "lead_ingestion": lead_ingestion(),
        "policies": dict(POLICIES),
    }
