#!/usr/bin/env python3
"""Fail closed when Middleware claims authority owned by another repository."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = "appolon1908-hue/codestra-production-platform"
MIDDLEWARE = "ingtrader21-spec/Middleware-"
REFERENCE_CANONICAL = REFERENCE.casefold()
FORBIDDEN_ADAPTER_REPOSITORIES = {
    REFERENCE_CANONICAL,
    MIDDLEWARE.casefold(),
}
IDENTIFIER_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
REPOSITORY_PATTERN = re.compile(r"(?:ingtrader21-spec|appolon1908-hue)/[A-Za-z0-9_.-]+\Z")
EXPECTED = {
    "ai": "appolon1908-hue/Codestra-AI",
    "caddy": "appolon1908-hue/Caddy",
    "djone": "ingtrader21-spec/DJONE",
    "keycloak": "appolon1908-hue/Keycloak",
    "klyrow-email": "appolon1908-hue/klyrow.com",
    "klyrow-web": "appolon1908-hue/klyrow-Website-",
    "kong": "appolon1908-hue/Kong",
    "kyqra-crawler": "appolon1908-hue/kyqra-crawler",
    "marketing": "appolon1908-hue/Codestra-Marketing-",
    "middleware": "ingtrader21-spec/Middleware-",
    "n8n": "appolon1908-hue/N8N",
    "odoo": "appolon1908-hue/Odoo",
    "provisioning": "appolon1908-hue/codestra-provisioning-service",
    "sdk": "appolon1908-hue/SDK-repository",
    "social": "appolon1908-hue/social.codestra.co",
    "telnexa-sms": "appolon1908-hue/telnexa",
    "telnexa-web": "appolon1908-hue/Telnexa-web",
    "vicidial-asterisk": "appolon1908-hue/Vicidialer-Codestra",
}


def fail(message: str) -> None:
    raise SystemExit(f"REPOSITORY_AUTHORITY_ERROR={message}")


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate key: {key}")
        value[key] = item
    return value


def reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_nonstandard_json_constant,
        )
    except (OSError, UnicodeError, ValueError) as error:
        fail(f"invalid_json:{path.name}:{error}")
    if not isinstance(value, dict):
        fail(f"invalid_object:{path.name}")
    return cast(dict[str, Any], value)


def require_list(value: object, message: str) -> list[Any]:
    if not isinstance(value, list):
        fail(message)
    return cast(list[Any], value)


def require_object(value: object, message: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        fail(message)
    return cast(dict[str, Any], value)


def require_string(value: object, message: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(message)
    return cast(str, value)


def require_identifier(value: object, message: str) -> str:
    identifier = require_string(value, message)
    if IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        fail(message)
    return identifier


def require_repository(value: object, message: str) -> str:
    repository = require_string(value, message)
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        fail(message)
    return repository


def require_string_list(value: object, message: str) -> list[str]:
    raw = require_list(value, message)
    items = [require_string(item, message) for item in raw]
    if not items or len(items) != len(set(items)):
        fail(message)
    return items


def validate(root: Path = ROOT) -> tuple[int, int]:
    raw = load_object(root / "config/repository-authorities.v1.json")
    if raw.get("schema_version") != "1.0":
        fail("unsupported_schema")
    policy = require_object(raw.get("policy"), "missing_policy")
    if policy.get("owning_repository_is_principal") is not True:
        fail("owning_repository_rule_disabled")
    if policy.get("central_release_authority") is not False:
        fail("central_release_authority_reintroduced")
    if policy.get("reference_repository") != REFERENCE:
        fail("wrong_reference_repository")

    entries = require_list(raw.get("authorities"), "missing_authorities")
    if not entries:
        fail("missing_authorities")
    by_component: dict[str, str] = {}
    principal_repositories: set[str] = set()
    canonical_principal_repositories: set[str] = set()
    for raw_entry in entries:
        entry = require_object(raw_entry, "invalid_authority_entry")
        component = require_identifier(
            entry.get("component"), "invalid_authority_identity"
        )
        repository = require_repository(
            entry.get("principal_repository"), "invalid_authority_identity"
        )
        require_identifier(entry.get("role"), f"missing_authority_role:{component}")
        if component in by_component:
            fail(f"duplicate_component:{component}")
        canonical_repository = repository.casefold()
        if canonical_repository in canonical_principal_repositories:
            fail(f"duplicate_principal_repository:{repository}")
        if canonical_repository == REFERENCE_CANONICAL:
            fail(f"reference_repo_cannot_be_principal:{component}")
        if not repository.startswith(("ingtrader21-spec/", "appolon1908-hue/")):
            fail(f"non_codestra_principal:{component}")
        by_component[component] = repository
        principal_repositories.add(repository)
        canonical_principal_repositories.add(canonical_repository)

    for component, expected_repository in EXPECTED.items():
        if by_component.get(component) != expected_repository:
            fail(f"wrong_principal:{component}:{by_component.get(component)}")

    references = require_list(
        raw.get("reference_only"), "reference_only_contract_missing"
    )
    if len(references) != 1:
        fail("reference_only_contract_missing")
    reference = require_object(references[0], "reference_only_contract_missing")
    if reference.get("repository") != REFERENCE:
        fail("reference_only_repo_changed")
    require_string_list(reference.get("allowed_uses"), "reference_allowed_uses_invalid")
    require_string_list(
        reference.get("forbidden_uses"), "reference_forbidden_uses_invalid"
    )

    adapter_registry = load_object(root / "config/adapter-registry.v2.json")
    if adapter_registry.get("schema_version") != "2.0":
        fail("adapter_registry_schema_invalid")
    adapters = require_list(
        adapter_registry.get("adapters"), "adapter_registry_missing"
    )
    adapter_repositories: dict[str, str] = {}
    for raw_adapter in adapters:
        adapter = require_object(raw_adapter, "invalid_adapter_entry")
        connector_id = require_identifier(adapter.get("id"), "invalid_adapter_identity")
        repository = require_repository(
            adapter.get("repository"), f"invalid_adapter_repository:{connector_id}"
        )
        if connector_id in adapter_repositories:
            fail(f"duplicate_adapter_id:{connector_id}")
        if adapter.get("direct_n8n") is not False:
            fail(f"direct_n8n_forbidden:{connector_id}")
        if repository not in principal_repositories:
            fail(f"adapter_repository_has_no_principal:{connector_id}:{repository}")
        if repository.casefold() in FORBIDDEN_ADAPTER_REPOSITORIES:
            fail(f"adapter_points_to_nonprincipal:{connector_id}")
        adapter_repositories[connector_id] = repository
    if not adapter_repositories:
        fail("adapter_registry_missing")

    manifest_dir = root / "connectors/manifests"
    seen_connectors: set[str] = set()
    for path in sorted(manifest_dir.glob("*.connector.json")):
        manifest = load_object(path)
        connector_id = require_identifier(
            manifest.get("connector_id"), f"invalid_connector_id:{path.name}"
        )
        repository = require_repository(
            manifest.get("repository"), f"invalid_connector_repository:{connector_id}"
        )
        if path.name != f"{connector_id}.connector.json":
            fail(f"connector_filename_drift:{path.name}:{connector_id}")
        if connector_id in seen_connectors:
            fail(f"duplicate_connector_id:{connector_id}")
        if connector_id not in adapter_repositories:
            fail(f"unregistered_connector_owner:{connector_id}")
        expected_repository = adapter_repositories[connector_id]
        if repository != expected_repository:
            fail(
                f"connector_repository_drift:{connector_id}:"
                f"{repository}:expected:{expected_repository}"
            )
        seen_connectors.add(connector_id)
    if seen_connectors != set(adapter_repositories):
        fail("connector_manifest_inventory_changed")

    text_targets = [
        root / "README.md",
        root / "docs/CI-ENVIRONMENTS-AND-HANDOFF.md",
        root / "docs/REPOSITORY-AUTHORITY-POLICY.md",
    ]
    forbidden = (
        "future shared API-edge Caddy source authority** is `appolon1908-hue/Kong`",
        "Caddy's canonical Git home is\n`appolon1908-hue/codestra-production-platform",
        "central deployment manifest authority",
    )
    for path in text_targets:
        if not path.is_file():
            fail(f"missing_policy_document:{path.relative_to(root)}")
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            fail(f"invalid_policy_document:{path.relative_to(root)}:{error}")
        for needle in forbidden:
            if needle in text:
                fail(f"stale_authority_claim:{path.relative_to(root)}")

    return len(by_component), len(seen_connectors)


def main() -> None:
    authority_count, connector_count = validate()
    print("REPOSITORY_AUTHORITY_POLICY=PASS")
    print("OWNING_REPOSITORY_IS_PRINCIPAL=YES")
    print(f"AUTHORITY_COUNT={authority_count}")
    print(f"CONNECTOR_PRINCIPAL_REPOSITORIES=PASS count={connector_count}")
    print("CODESTRA_PRODUCTION_PLATFORM=REFERENCE_ONLY")
    print("CADDY_PRINCIPAL=appolon1908-hue/Caddy")


if __name__ == "__main__":
    main()
