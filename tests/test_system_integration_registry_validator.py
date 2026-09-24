from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_system_integration_registry.py"


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "system_integration_registry_validator", SCRIPT
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def validator() -> ModuleType:
    return load_validator()


@pytest.fixture
def documents(
    validator: ModuleType,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        validator.load_object(validator.REGISTRY_PATH),
        validator.load_object(validator.AUTHORITY_PATH),
        validator.load_object(validator.ALIAS_PATH),
    )


def system(registry: dict[str, Any], component: str) -> dict[str, Any]:
    return next(item for item in registry["systems"] if item["component"] == component)


def authority(authorities: dict[str, Any], component: str) -> dict[str, Any]:
    return next(
        item for item in authorities["authorities"] if item["component"] == component
    )


def assert_rejected(
    validator: ModuleType,
    registry: dict[str, Any],
    authorities: dict[str, Any],
    aliases: dict[str, Any],
    match: str,
) -> None:
    with pytest.raises(validator.RegistryError, match=match):
        validator.validate(registry, authorities, aliases)


def test_current_registry_passes_and_derives_counts(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = documents
    summary = validator.validate(registry, authorities, aliases)
    adapter_registry = validator.load_object(validator.ADAPTER_PATH)
    assert summary["systems"] == len(registry["systems"])
    assert summary["aliases"] == len(aliases["mappings"])
    assert summary["adapters"] == len(adapter_registry["adapters"]) == 11
    assert summary["cells"] == len({item["cell"] for item in registry["systems"]})


def test_duplicate_repository_id_is_rejected(validator: ModuleType, documents) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    registry["systems"][1]["github_repository_id"] = registry["systems"][0][
        "github_repository_id"
    ]
    assert_rejected(
        validator, registry, authorities, aliases, "duplicate repository id"
    )


def test_repository_id_must_match_independent_authority(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, "middleware")["github_repository_id"] = 999_999_999
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "authoritative repository id mismatch: middleware",
    )


def test_duplicate_current_repository_name_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    registry["systems"][1]["current_repository"] = registry["systems"][0][
        "current_repository"
    ]
    assert_rejected(
        validator, registry, authorities, aliases, "duplicate repository name"
    )


def test_missing_authority_component_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    authorities["authorities"] = authorities["authorities"][:-1]
    assert_rejected(
        validator, registry, authorities, aliases, "component coverage differ"
    )


def test_authority_role_drift_is_rejected(validator: ModuleType, documents) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    authority(authorities, "odoo")["role"] = "untrusted-central-runtime"
    assert_rejected(
        validator, registry, authorities, aliases, "authority role mismatch: odoo"
    )


def test_coordinated_authority_role_drift_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    replacement_role = "central-release-authority"
    system(registry, "platform-infrastructure")["authority_role"] = replacement_role
    authority(authorities, "platform-infrastructure")["role"] = replacement_role
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "approved authority role mismatch: platform-infrastructure",
    )


def test_critical_identity_system_coordinated_reclassification_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    keycloak = system(registry, "keycloak")
    keycloak["lifecycle"] = "deprecated"
    keycloak["cell"] = "product-clients"
    keycloak["integration_mode"] = "product-client"
    keycloak["middleware_relationship"] = "caller"
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "approved system security profile mismatch: keycloak",
    )


def test_authority_repository_name_drift_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    authority(authorities, "n8n")["principal_repository"] = (
        "ingtrader21-spec/Middleware-"
    )
    assert_rejected(
        validator, registry, authorities, aliases, "authority repository mismatch: n8n"
    )


def test_every_authority_requires_stable_repository_id(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    authority(authorities, "middleware").pop("github_repository_id")
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "authority stable repository id missing: middleware",
    )


def test_controlled_rename_id_misbinding_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    authority(authorities, "platform-infrastructure")["github_repository_id"] = 1
    assert_rejected(
        validator, registry, authorities, aliases, "authority repository id mismatch"
    )


def test_alias_target_drift_is_rejected(validator: ModuleType, documents) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    aliases["mappings"][0]["target_repository_after_cutover"] = (
        "appolon1908-hue/other-target"
    )
    assert_rejected(
        validator, registry, authorities, aliases, "registry alias target mismatch"
    )


def test_coordinated_alias_target_drift_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    repository_id = 1350724356
    replacement_target = "appolon1908-hue/Codestra-Docs-Replacement"
    mapping = next(
        item
        for item in aliases["mappings"]
        if item["github_repository_id"] == repository_id
    )
    mapping["target_repository_after_cutover"] = replacement_target
    authority(authorities, "platform-documentation")[
        "target_repository_after_cutover"
    ] = replacement_target
    system(registry, "platform-documentation")["name_aliases"][0]["repository"] = (
        replacement_target
    )
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        f"approved repository rename mismatch: {repository_id}",
    )


def test_alias_target_cannot_collide_with_current_repository(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    repository_id = 1350724356
    target = "ingtrader21-spec/Middleware-"
    alias = next(
        item
        for item in aliases["mappings"]
        if item["github_repository_id"] == repository_id
    )
    alias["target_repository_after_cutover"] = target
    authority(authorities, "platform-documentation")[
        "target_repository_after_cutover"
    ] = target
    system(registry, "platform-documentation")["name_aliases"][0]["repository"] = target
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "alias target collides with a current repository",
    )


def test_alias_target_cannot_collide_with_reference_only_repository(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    repository_id = 1350724356
    target = "appolon1908-hue/codestra-production-platform"
    alias = next(
        item
        for item in aliases["mappings"]
        if item["github_repository_id"] == repository_id
    )
    alias["target_repository_after_cutover"] = target
    authority(authorities, "platform-documentation")[
        "target_repository_after_cutover"
    ] = target
    system(registry, "platform-documentation")["name_aliases"][0]["repository"] = target
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "alias target collides with a reference-only repository",
    )


def test_alias_status_must_remain_prepared_not_renamed(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    aliases["mappings"][0]["status"] = "RENAMED"
    assert_rejected(
        validator, registry, authorities, aliases, "invalid alias mapping status"
    )


def test_n8n_cannot_become_provider_adapter(validator: ModuleType, documents) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    n8n = system(registry, "n8n")
    n8n["cell"] = "communications"
    n8n["integration_mode"] = "provider-adapter"
    n8n["middleware_relationship"] = "target-and-event-source"
    n8n["adapter_id"] = None
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "n8n must remain in the automation cell",
    )


def test_provider_adapter_requires_adapter_binding(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, "telnexa-sms")["adapter_id"] = None
    assert_rejected(
        validator, registry, authorities, aliases, "provider adapter lacks adapter id"
    )


def test_provider_adapter_cannot_bypass_middleware_relationship(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, "klyrow-email")["middleware_relationship"] = "caller"
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "provider adapter bypass relationship",
    )


def test_duplicate_adapter_binding_is_rejected(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, "social")["adapter_id"] = system(registry, "telnexa-sms")[
        "adapter_id"
    ]
    assert_rejected(validator, registry, authorities, aliases, "duplicate adapter id")


def test_invented_adapter_binding_is_rejected(validator: ModuleType, documents) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, "telnexa-sms")["adapter_id"] = "invented-sms-adapter"
    assert_rejected(
        validator, registry, authorities, aliases, "unknown adapter binding"
    )


def test_canonical_adapter_owner_cannot_be_relabelled_as_client(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    telnexa = system(registry, "telnexa-sms")
    telnexa["integration_mode"] = "product-client"
    telnexa["middleware_relationship"] = "caller"
    telnexa["adapter_id"] = None
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "canonical adapter binding mismatch: telnexa-sms",
    )


@pytest.mark.parametrize("component", ["ai", "marketing"])
def test_unbound_canonical_adapter_owner_security_cannot_drift(
    validator: ModuleType, documents, component: str
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    owner = system(registry, component)
    owner["cell"] = "governance"
    owner["integration_mode"] = "documentation-reference"
    owner["middleware_relationship"] = "none"
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        f"canonical adapter owner security classification mismatch: {component}",
    )


@pytest.mark.parametrize("component", ["ai", "marketing", "odoo", "beyvra-backend"])
def test_canonical_adapter_owner_must_remain_active(
    validator: ModuleType, documents, component: str
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, component)["lifecycle"] = "deprecated"
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        f"canonical adapter owner security classification mismatch: {component}",
    )


def test_reference_only_repository_inventory_cannot_be_removed(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    authorities["reference_only"] = []
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "reference-only repository inventory mismatch",
    )


def test_reference_only_repository_policy_cannot_drift(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    authorities["reference_only"][0]["allowed_uses"] = ["central release authority"]
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "reference-only repository allowed_uses drift",
    )


def test_canonical_adapter_ownership_cannot_move_between_repositories(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    adapters = validator.load_object(validator.ADAPTER_PATH)
    next(item for item in adapters["adapters"] if item["id"] == "telnexa-sms")[
        "repository"
    ] = "appolon1908-hue/Codestra-AI"

    with pytest.raises(
        validator.RegistryError, match="canonical adapter ownership mismatch"
    ):
        validator.validate(registry, authorities, aliases, adapters)


def test_canonical_adapter_cannot_bypass_middleware(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    adapters = validator.load_object(validator.ADAPTER_PATH)
    next(item for item in adapters["adapters"] if item["id"] == "ai-provider")[
        "direct_n8n"
    ] = True

    with pytest.raises(
        validator.RegistryError, match="canonical adapter permits direct n8n"
    ):
        validator.validate(registry, authorities, aliases, adapters)


def test_canonical_adapter_command_boundary_cannot_drift(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    adapters = validator.load_object(validator.ADAPTER_PATH)
    next(item for item in adapters["adapters"] if item["id"] == "telnexa-sms")[
        "command_prefixes"
    ] = ["sms.", "telephony."]

    with pytest.raises(
        validator.RegistryError,
        match="canonical adapter security profile mismatch: telnexa-sms",
    ):
        validator.validate(registry, authorities, aliases, adapters)


def test_disabled_legacy_system_cannot_retain_write_relationship(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, "scrapper")["middleware_relationship"] = "caller"
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "disabled system retains Middleware relationship",
    )


def test_unknown_cell_is_rejected(validator: ModuleType, documents) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    system(registry, "marketing")["cell"] = "unreviewed-cross-system-cell"
    assert_rejected(validator, registry, authorities, aliases, "unsupported cell")


def test_fail_closed_policy_cannot_be_disabled(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    registry["policy"]["runtime_certification_is_not_embedded"] = False
    assert_rejected(
        validator, registry, authorities, aliases, "registry policy must fail closed"
    )


def test_hard_coded_inventory_count_is_rejected_as_schema_drift(
    validator: ModuleType, documents
) -> None:
    registry, authorities, aliases = copy.deepcopy(documents)
    registry["repository_count"] = len(registry["systems"])
    assert_rejected(
        validator,
        registry,
        authorities,
        aliases,
        "registry top-level field inventory mismatch",
    )


def test_duplicate_json_keys_are_rejected(
    validator: ModuleType, tmp_path: Path
) -> None:
    ambiguous = tmp_path / "ambiguous.json"
    ambiguous.write_text(
        '{"github_repository_id": 1, "github_repository_id": 2}',
        encoding="utf-8",
    )

    with pytest.raises(validator.RegistryError, match="duplicate JSON key"):
        validator.load_object(ambiguous)
