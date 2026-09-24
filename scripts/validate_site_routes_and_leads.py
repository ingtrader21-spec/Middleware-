#!/usr/bin/env python3
"""Validate site routes, provider stacks, and form/crawler/scraper delivery to Odoo."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from architecture.site_architecture import architecture  # noqa: E402
BASE_MANIFEST = ROOT / "config" / "integration-branches.json"

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
REQUIRED_APPLICATION_HOSTS = {
    "codestra.co", "www.codestra.co", "auth.codestra.co",
    "social.codestra.co", "ai.codestra.co",
    "beyvra.com", "www.beyvra.com", "platform.beyvra.com",
    "api.beyvra.com", "admin.beyvra.com", "staging.beyvra.com",
    "booked4seasons.com", "www.booked4seasons.com",
    "breero.com", "www.breero.com", "api.breero.com",
    "staging.breero.com", "api-staging.breero.com",
}
REQUIRED_PROVIDER_HOSTS = {
    "klyrow.com", "www.klyrow.com", "app.klyrow.com", "api.klyrow.com",
    "track.klyrow.com", "bounce.klyrow.com",
    "sms.telnexa.co", "api.telnexa.co", "status.telnexa.co",
    "crawler.kyqra.com",
}
REQUIRED_SOURCES = {
    "codestra-public-form", "beyvra-public-form",
    "booked4seasons-public-form", "breero-public-form",
    "klyrow-public-form", "telnexa-public-form",
    "kyqra-crawler-results", "codestra-business-scrapper-results",
}
REQUIRED_LEAD_CHAIN = [
    "integration/private-app-gateway",
    "core/webhook-inbox-replay",
    "core/lead-intake-normalization",
    "core/event-ledger-outbox",
    "integration/odoo-19",
]


def load(path: Path, errors: list[str]) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"cannot load {path.relative_to(ROOT)}: {exc}")
        return None
    if not isinstance(value, dict):
        errors.append(f"{path.relative_to(ROOT)} root must be an object")
        return None
    return value


def contains_in_order(values: list[str], required: list[str]) -> bool:
    position = -1
    for value in required:
        try:
            position = values.index(value, position + 1)
        except ValueError:
            return False
    return True


def validate_schema(
    path: Path,
    *,
    canonical_ref: str,
    envelope_field: str,
    envelope_value: str,
    required_payload_fields: set[str],
    errors: list[str],
) -> None:
    schema = load(path, errors)
    if schema is None:
        return
    all_of = schema.get("allOf")
    if not isinstance(all_of, list) or len(all_of) != 2:
        errors.append(f"{path.relative_to(ROOT)} must extend one canonical envelope")
        return
    if all_of[0] != {"$ref": canonical_ref}:
        errors.append(f"{path.relative_to(ROOT)} canonical reference is invalid")
    specialization = all_of[1]
    if not isinstance(specialization, dict):
        errors.append(f"{path.relative_to(ROOT)} specialization must be an object")
        return
    properties = specialization.get("properties", {})
    if properties.get(envelope_field, {}).get("const") != envelope_value:
        errors.append(f"{path.relative_to(ROOT)} has an invalid envelope type")
    payload = properties.get("payload")
    if not isinstance(payload, dict) or payload.get("type") != "object":
        errors.append(f"{path.relative_to(ROOT)} payload schema is missing")
        return
    required = payload.get("required")
    if not isinstance(required, list):
        errors.append(f"{path.relative_to(ROOT)} payload required must be an array")
        return
    missing = sorted(required_payload_fields - set(required))
    if missing:
        errors.append(
            f"{path.relative_to(ROOT)} payload missing: " + ", ".join(missing)
        )
    if not specialization.get("allOf"):
        errors.append(f"{path.relative_to(ROOT)} must contain conditional safety rules")


def main() -> int:
    errors: list[str] = []
    base_manifest = load(BASE_MANIFEST, errors)
    if base_manifest is None:
        return report(errors)
    data = architecture()

    base_branches = {
        item.get("branch")
        for item in base_manifest.get("workstreams", [])
        if isinstance(item, dict) and isinstance(item.get("branch"), str)
    }
    new_branches = {
        item.get("branch")
        for item in data.get("workstreams", [])
        if isinstance(item, dict) and isinstance(item.get("branch"), str)
    }
    combined = base_branches | new_branches

    hosts = data.get("server_stacks")
    if not isinstance(hosts, dict):
        errors.append("server_stacks must be an object")
        hosts = {}
    if set(hosts) != {"application-server-a", "provider-host"}:
        errors.append("server_stacks must declare application-server-a and provider-host")

    routes: dict[str, dict[str, Any]] = {}
    route_sets: dict[str, set[str]] = {}
    for host_id, host in hosts.items():
        if not isinstance(host, dict):
            errors.append(f"{host_id} must be an object")
            continue
        if host.get("edge_branch") not in combined or host.get("operations_branch") not in combined:
            errors.append(f"{host_id} has unknown edge/operations branch")
        route_sets[host_id] = set()
        for route in host.get("routes", []):
            if not isinstance(route, dict):
                errors.append(f"{host_id} has a non-object route")
                continue
            hostname = route.get("hostname")
            if not isinstance(hostname, str) or not HOST_RE.fullmatch(hostname):
                errors.append(f"{host_id} has invalid hostname {hostname!r}")
                continue
            if hostname in routes:
                errors.append(f"hostname {hostname} has multiple owners")
            routes[hostname] = route
            route_sets[host_id].add(hostname)
            if route.get("branch") not in combined or not str(route.get("branch")).startswith("site/"):
                errors.append(f"{hostname} has invalid site owner")
            if route.get("status") == "degraded" and not str(route.get("issue", "")).strip():
                errors.append(f"degraded route {hostname} has no issue")
            if not isinstance(route.get("accepts_forms"), bool):
                errors.append(f"{hostname} accepts_forms must be boolean")
        for private in host.get("private_routes", []):
            if isinstance(private, dict):
                if "hostname" in private:
                    errors.append(f"{host_id} private route has a public hostname")
                if private.get("branch") not in combined:
                    errors.append(f"{host_id} private route branch is unknown")
        for stack in host.get("stacks", []):
            if not isinstance(stack, dict) or stack.get("branch") not in combined:
                errors.append(f"{host_id} has an invalid stack")
                continue
            for component in stack.get("components", []):
                if component not in combined:
                    errors.append(f"{host_id} stack component is unknown: {component}")

    missing_app = sorted(REQUIRED_APPLICATION_HOSTS - route_sets.get("application-server-a", set()))
    missing_provider = sorted(REQUIRED_PROVIDER_HOSTS - route_sets.get("provider-host", set()))
    if missing_app:
        errors.append("application routes missing: " + ", ".join(missing_app))
    if missing_provider:
        errors.append("provider routes missing: " + ", ".join(missing_provider))

    auth = routes.get("auth.codestra.co", {})
    if auth.get("status") != "active" or auth.get("issue") not in (None, ""):
        errors.append("auth.codestra.co must be active with no recorded issue")
    booked = routes.get("www.booked4seasons.com", {})
    if booked.get("status") != "degraded" or "TLS" not in str(booked.get("issue", "")):
        errors.append("www.booked4seasons.com must remain degraded with TLS failure recorded")

    lead = data.get("lead_ingestion")
    if not isinstance(lead, dict):
        errors.append("lead_ingestion must be an object")
        lead = {}
    if lead.get("version") != 1 or lead.get("write_boundary") != "middleware":
        errors.append("lead-ingestion version/write boundary is invalid")
    if lead.get("direct_site_crawler_or_scraper_write_to_odoo") is not False:
        errors.append("direct site/crawler/scraper Odoo writes must be false")

    sources = lead.get("sources")
    if not isinstance(sources, list):
        errors.append("lead sources must be an array")
        sources = []
    source_ids: list[str] = []
    for source in sources:
        if not isinstance(source, dict):
            errors.append("lead sources contains a non-object")
            continue
        source_id = source.get("id")
        kind = source.get("source_kind")
        branch = source.get("source_branch")
        pipeline = source.get("pipeline")
        policy = source.get("odoo_policy")
        if isinstance(source_id, str):
            source_ids.append(source_id)
        if branch not in combined:
            errors.append(f"{source_id} source branch is unknown")
        if not isinstance(pipeline, list) or not all(isinstance(x, str) for x in pipeline):
            errors.append(f"{source_id} pipeline must be an array")
            continue
        if pipeline and pipeline[0] != branch:
            errors.append(f"{source_id} pipeline must start with source branch")
        if not contains_in_order(pipeline, REQUIRED_LEAD_CHAIN):
            errors.append(f"{source_id} lacks the durable Odoo chain")
        if kind == "public_form" and "integration/web-form-intake" not in pipeline:
            errors.append(f"{source_id} form bypasses web-form intake")
        for hostname in source.get("hostnames", []):
            route = routes.get(hostname)
            if route is None:
                errors.append(f"{source_id} references unknown route {hostname}")
            elif kind == "public_form" and route.get("accepts_forms") is not True:
                errors.append(f"{source_id} route {hostname} is not marked for forms")
        if not isinstance(policy, dict):
            errors.append(f"{source_id} has no Odoo policy")
            continue
        if kind == "public_form":
            if policy.get("initial_stage") != "new" or policy.get("review_required") is not False:
                errors.append(f"{source_id} form lead policy is invalid")
            if policy.get("allow_external_contact") != "only_when_consent_and_suppression_policy_pass":
                errors.append(f"{source_id} form outreach policy is unsafe")
        elif kind in {"crawler_result", "scraper_result"}:
            if policy.get("initial_stage") != "review_pending":
                errors.append(f"{source_id} discovered lead must start review_pending")
            if policy.get("review_required") is not True or policy.get("allow_external_contact") is not False:
                errors.append(f"{source_id} discovered lead policy is unsafe")
        else:
            errors.append(f"{source_id} has invalid source_kind")
        if kind == "scraper_result" and source.get("runtime_status") != "not_deployed":
            errors.append(f"{source_id} scrapper source must remain not_deployed")

    if len(source_ids) != len(set(source_ids)):
        errors.append("lead source IDs contain duplicates")
    missing_sources = sorted(REQUIRED_SOURCES - set(source_ids))
    if missing_sources:
        errors.append("required lead sources missing: " + ", ".join(missing_sources))

    validate_schema(
        ROOT / "contracts" / "lead-intake.schema.json",
        canonical_ref=(
            "https://contracts.codestra.co/platform/event-envelope.v1.schema.json"
        ),
        envelope_field="event_type",
        envelope_value="codestra.lead.intake",
        required_payload_fields={
            "source_kind",
            "source_system",
            "submission_id",
            "provenance",
            "consent",
            "review",
            "data",
        },
        errors=errors,
    )
    validate_schema(
        ROOT / "contracts" / "odoo-lead-command.schema.json",
        canonical_ref=(
            "https://contracts.codestra.co/platform/command-envelope.v1.schema.json"
        ),
        envelope_field="command_type",
        envelope_value="crm.lead.upsert",
        required_payload_fields={
            "lead_source",
            "source_record_id",
            "initial_stage",
            "review_required",
            "allow_external_contact",
            "lead",
        },
        errors=errors,
    )

    for path in (
        ROOT / "contracts" / "provider-transport-conventions.md",
        ROOT / "docs" / "SITE-ARCHITECTURE.md",
    ):
        if not path.is_file():
            errors.append(f"missing architecture file: {path.relative_to(ROOT)}")

    if errors:
        return report(errors)

    print(
        "Site route and Odoo intake validation passed: "
        f"{len(routes)} routes, {len(source_ids)} lead sources, "
        "auth.codestra.co active; remaining Booked4Seasons TLS degradation recorded."
    )
    return 0


def report(errors: list[str]) -> int:
    print("Site route/Odoo intake validation failed:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
