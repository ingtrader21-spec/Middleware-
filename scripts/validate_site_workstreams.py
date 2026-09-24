#!/usr/bin/env python3
"""Validate supplemental site/provider workstreams and communication links."""

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
BASE_CONNECTIVITY = ROOT / "config" / "connectivity-map.json"

BRANCH_RE = re.compile(
    r"^(?:site|integration|platform|operations|core|observability|testing)/"
    r"[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?$"
)
ALLOWED_STATUSES = {
    "declared_active_scope", "declared_remote_provider_scope",
    "declared_private_scope", "declared_degraded_scope",
    "required_shared_primitive", "configured_remote_runtime_not_confirmed",
    "source_checkout_not_deployed",
}
VERIFICATION_STATUSES = {
    "configured_remote_runtime_not_confirmed", "source_checkout_not_deployed",
}
ALLOWED_LINK_STATUS = {
    "declared", "declared_remote", "degraded",
    "private_only", "verification_only", "not_deployed",
}
REQUIRED_NEW = {
    "integration/postiz-social", "integration/codestra-ai-console",
    "platform/nginx-provider", "platform/mariadb",
    "integration/klyrow-smtp-relay", "integration/provider-billing",
    "core/lead-intake-normalization", "integration/private-app-gateway",
    "integration/web-form-intake", "integration/codestra-business-scrapper",
    "operations/provider-host", "operations/application-host",
    "site/klyrow", "site/telnexa", "site/kyqra-crawler",
    "site/private-app-integration", "site/codestra-business-scrapper",
    "site/codestra", "site/codestra-auth", "site/codestra-social",
    "site/codestra-ai", "site/beyvra", "site/booked4seasons", "site/breero",
}
EXPECTED_OVERRIDES = {
    "platform/rabbitmq": "declared_remote_provider_scope",
    "integration/mautic": "declared_remote_provider_scope",
    "integration/postal-email": "declared_remote_provider_scope",
    "integration/jasmin-sms": "declared_remote_provider_scope",
    "integration/kyqra": "declared_remote_provider_scope",
    "integration/beyvra": "declared_active_scope",
}
REQUIRED_LINKS = {
    "web-form-to-private-gateway", "private-gateway-to-inbox",
    "inbox-to-lead-normalization", "lead-normalization-to-outbox",
    "outbox-to-odoo-leads",
}


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


def find_cycle(graph: dict[str, list[str]]) -> list[str] | None:
    state: dict[str, int] = {}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        marker = state.get(node, 0)
        if marker == 2:
            return None
        if marker == 1:
            start = stack.index(node) if node in stack else 0
            return stack[start:] + [node]
        state[node] = 1
        stack.append(node)
        for dep in graph.get(node, []):
            if dep in graph:
                result = visit(dep)
                if result:
                    return result
        stack.pop()
        state[node] = 2
        return None

    for node in graph:
        result = visit(node)
        if result:
            return result
    return None


def main() -> int:
    errors: list[str] = []
    base_manifest = load(BASE_MANIFEST, errors)
    base_connectivity = load(BASE_CONNECTIVITY, errors)
    if base_manifest is None or base_connectivity is None:
        return report(errors)

    data = architecture()
    expected_policies = {
        "branches_start_from_reviewed_main": True,
        "all_new_branches_depend_on_canonical_contracts": True,
        "site_branches_are_not_deployment_branches": True,
        "all_links_require_authentication": True,
        "external_effects_disabled_by_default": True,
        "all_public_forms_use_middleware_intake": True,
        "direct_site_crawler_or_scraper_write_to_odoo": False,
        "crawler_and_scraper_odoo_records_start_review_pending": True,
        "external_contact_disabled_for_discovered_records": True,
    }
    if data.get("version") != 1:
        errors.append("supplemental architecture version must be 1")
    if data.get("canonical_contract_branch") != "core/integration-contracts":
        errors.append("canonical contract branch is incorrect")
    if data.get("policies") != expected_policies:
        errors.append("supplemental policies are incomplete or unsafe")

    base_items = base_manifest.get("workstreams", [])
    base_branches = {
        item.get("branch")
        for item in base_items
        if isinstance(item, dict) and isinstance(item.get("branch"), str)
    }
    base_status = {
        item.get("branch"): item.get("runtime_status")
        for item in base_items
        if isinstance(item, dict) and isinstance(item.get("branch"), str)
    }

    raw_new = data.get("workstreams", [])
    new_branches: list[str] = []
    new_status: dict[str, str] = {}
    for index, item in enumerate(raw_new):
        if not isinstance(item, dict):
            errors.append(f"workstreams[{index}] must be an object")
            continue
        branch = item.get("branch")
        status = item.get("runtime_status")
        purpose = item.get("purpose")
        if not isinstance(branch, str) or not BRANCH_RE.fullmatch(branch):
            errors.append(f"workstreams[{index}].branch is not canonical")
            continue
        new_branches.append(branch)
        if branch in base_branches:
            errors.append(f"{branch} duplicates a base workstream")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{branch} has unsupported status {status!r}")
        else:
            new_status[branch] = status
        if not isinstance(purpose, str) or len(purpose.strip()) < 30:
            errors.append(f"{branch} purpose is too short")

    if len(new_branches) != len(set(new_branches)):
        errors.append("new workstream branches contain duplicates")
    missing = sorted(REQUIRED_NEW - set(new_branches))
    if missing:
        errors.append("required new branches missing: " + ", ".join(missing))

    overrides = data.get("runtime_status_overrides")
    if overrides != EXPECTED_OVERRIDES:
        errors.append("runtime status overrides do not match supplied runtime evidence")
    elif not set(overrides).issubset(base_branches):
        errors.append("runtime status overrides reference unknown base branches")

    combined = base_branches | set(new_branches)
    effective_status: dict[Any, Any] = dict(base_status)
    effective_status.update(EXPECTED_OVERRIDES)
    effective_status.update(new_status)

    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict) or set(dependencies) != set(new_branches):
        errors.append("dependency keys must exactly match new branches")
        dependencies = {}

    graph: dict[str, list[str]] = {}
    for branch in new_branches:
        values = dependencies.get(branch, [])
        if not isinstance(values, list) or not all(isinstance(x, str) for x in values):
            errors.append(f"dependencies for {branch} must be an array")
            values = []
        if len(values) != len(set(values)):
            errors.append(f"dependencies for {branch} contain duplicates")
        if branch in values:
            errors.append(f"{branch} cannot depend on itself")
        unknown = sorted(set(values) - combined)
        if unknown:
            errors.append(f"{branch} has unknown dependencies: " + ", ".join(unknown))
        if "core/integration-contracts" not in values:
            errors.append(f"{branch} must depend on core/integration-contracts")
        graph[branch] = list(values)

    cycle = find_cycle(graph)
    if cycle:
        errors.append("new dependency cycle: " + " -> ".join(cycle))

    base_ids = {
        item.get("id")
        for item in base_connectivity.get("connections", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    links = data.get("connections", [])
    ids: list[str] = []
    connected: set[str] = set()
    for index, link in enumerate(links):
        if not isinstance(link, dict):
            errors.append(f"connections[{index}] must be an object")
            continue
        link_id = link.get("id")
        source = link.get("from")
        target = link.get("to")
        status = link.get("status")
        if not isinstance(link_id, str) or not link_id:
            errors.append(f"connections[{index}].id must be a string")
        else:
            ids.append(link_id)
            if link_id in base_ids:
                errors.append(f"connection {link_id} duplicates a base ID")
        if source not in combined or target not in combined:
            errors.append(f"connection {link_id} references an unknown branch")
        if source in new_status:
            connected.add(source)
        if target in new_status:
            connected.add(target)
        for field in ("transport", "auth", "reliability", "contract"):
            value = link.get(field)
            if not isinstance(value, str) or not value:
                errors.append(f"connection {link_id} has no {field}")
        if status not in ALLOWED_LINK_STATUS:
            errors.append(f"connection {link_id} has invalid status")
        endpoint_statuses = {effective_status.get(source), effective_status.get(target)}
        if endpoint_statuses & VERIFICATION_STATUSES and status not in {"verification_only", "not_deployed"}:
            errors.append(f"connection {link_id} activates verification/not-deployed work")
        if "source_checkout_not_deployed" in endpoint_statuses and status != "not_deployed":
            errors.append(f"connection {link_id} touches not-deployed source")
        contract = link.get("contract")
        if isinstance(contract, str) and not (ROOT / contract).is_file():
            errors.append(f"connection {link_id} references missing contract {contract}")
        if target == "integration/odoo-19" and (
            isinstance(source, str)
            and (source.startswith("site/") or source in {
                "integration/crawlee", "integration/kyqra",
                "integration/codestra-business-scrapper",
            })
        ):
            errors.append(f"connection {link_id} bypasses normalization/outbox")

    if len(ids) != len(set(ids)):
        errors.append("connection IDs contain duplicates")
    missing_connected = sorted(set(new_branches) - connected)
    if missing_connected:
        errors.append("new branches with no connection: " + ", ".join(missing_connected))
    missing_links = sorted(REQUIRED_LINKS - set(ids))
    if missing_links:
        errors.append("required lead links missing: " + ", ".join(missing_links))

    if errors:
        return report(errors)

    print(
        "Supplemental workstream validation passed: "
        f"{len(new_branches)} branches, {len(ids)} links, one acyclic graph."
    )
    return 0


def report(errors: list[str]) -> int:
    print("Supplemental workstream validation failed:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
