#!/usr/bin/env python3
"""Validate the stable-ID system integration registry against current authorities."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "config/system-integration-registry.v4.json"
AUTHORITY_PATH = ROOT / "config/repository-authorities.v1.json"
ALIAS_PATH = ROOT / "config/repository-name-aliases.v1.json"
ADAPTER_PATH = ROOT / "config/adapter-registry.v2.json"

# The canonical Middleware repository lives under ingtrader21-spec; the portfolio
# repositories it references are still recorded under the appolon1908-hue owner
# (GitHub redirects them) until each one is converged on its own.
REPOSITORY_RE = re.compile(r"^(?:ingtrader21-spec|appolon1908-hue)/[A-Za-z0-9._-]+$")
REGISTRY_KEYS = {
    "schema_version",
    "identity_key",
    "authority_source",
    "name_alias_source",
    "scope",
    "policy",
    "systems",
}
POLICY_KEYS = {
    "counts_are_derived",
    "repository_names_are_mutable_attributes",
    "repository_ids_are_immutable_identity",
    "release_state_is_not_embedded",
    "runtime_certification_is_not_embedded",
    "middleware_is_cross_system_command_authority",
    "n8n_is_orchestration_only",
    "provider_callbacks_terminate_at_middleware",
    "frontends_hold_no_provider_credentials",
    "documentation_is_not_deployment_authorization",
}
SYSTEM_KEYS = {
    "component",
    "github_repository_id",
    "current_repository",
    "authority_role",
    "lifecycle",
    "cell",
    "integration_mode",
    "middleware_relationship",
    "adapter_id",
    "name_aliases",
}
AUTHORITY_KEYS = {
    "component",
    "principal_repository",
    "role",
    "status",
    "github_repository_id",
    "target_repository_after_cutover",
    "rename_status",
}
ALIAS_MAPPING_KEYS = {
    "github_repository_id",
    "current_repository",
    "target_repository_after_cutover",
    "status",
}
REGISTRY_ALIAS_KEYS = {"repository", "status"}
AUTHORITY_TOP_LEVEL_KEYS = {
    "schema_version",
    "policy",
    "middleware_owned",
    "reference_only",
    "authorities",
}
ALIAS_TOP_LEVEL_KEYS = {
    "schema_version",
    "status",
    "identity_key",
    "historical_evidence_immutable",
    "documentation_authority",
    "mappings",
}
ADAPTER_TOP_LEVEL_KEYS = {"schema_version", "adapters"}
ADAPTER_KEYS = {"id", "cell", "repository", "command_prefixes", "direct_n8n"}
ADAPTER_KEYS_WITH_FORBIDDEN_PREFIXES = ADAPTER_KEYS | {"forbidden_prefixes"}
ALLOWED_CELLS = {
    "middleware-core",
    "edge-identity",
    "automation",
    "communications",
    "product-clients",
    "crawler",
    "legacy-disabled",
    "telephony-restricted",
    "core-control-plane",
    "governance",
    "financial-isolated",
    "planned-control-planes",
}
ALLOWED_LIFECYCLES = {
    "active",
    "deprecated",
    "legacy-migration",
    "planned-name-review",
}
ALLOWED_INTEGRATION_MODES = {
    "middleware-authority",
    "edge-compatibility",
    "gateway-compatibility",
    "identity-compatibility",
    "orchestration-client",
    "business-system-adapter",
    "provider-adapter",
    "public-intake-client",
    "disabled",
    "contract-authority",
    "product-client",
    "product-adapter-nonfinancial",
    "planned-client",
    "infrastructure-coordinator",
    "documentation-reference",
}
ALLOWED_RELATIONSHIPS = {
    "authority",
    "compatibility",
    "identity-authority",
    "caller",
    "target-and-event-source",
    "none",
    "governance",
    "caller-and-target",
}
PROVIDER_CELLS = {
    "communications",
    "crawler",
    "telephony-restricted",
    "core-control-plane",
}

# Independently reviewed immutable GitHub repository identities. Repository names
# are still mutable attributes, but an authority cannot invent or reassign the
# numeric identity of a component.
EXPECTED_REPOSITORY_IDENTITIES = {
    "middleware": (1347559071, "ingtrader21-spec/Middleware-"),
    "caddy": (1350228103, "appolon1908-hue/Caddy"),
    "kong": (1347790742, "appolon1908-hue/Kong"),
    "keycloak": (1347523366, "appolon1908-hue/Keycloak"),
    "n8n": (1347560645, "appolon1908-hue/N8N"),
    "odoo": (1347522940, "appolon1908-hue/Odoo"),
    "telnexa-sms": (1334764612, "appolon1908-hue/telnexa"),
    "telnexa-web": (1346958528, "appolon1908-hue/Telnexa-web"),
    "klyrow-email": (1334863061, "appolon1908-hue/klyrow.com"),
    "klyrow-web": (1346968526, "appolon1908-hue/klyrow-Website-"),
    "kyqra-crawler": (1334792686, "appolon1908-hue/kyqra-crawler"),
    "kyqra-legacy": (1334764212, "appolon1908-hue/kyqra"),
    "vicidial-asterisk": (1347744324, "appolon1908-hue/Vicidialer-Codestra"),
    "provisioning": (1339900477, "appolon1908-hue/codestra-provisioning-service"),
    "sdk": (1349042079, "appolon1908-hue/SDK-repository"),
    "social": (1348783113, "appolon1908-hue/social.codestra.co"),
    "ai": (1351354401, "appolon1908-hue/Codestra-AI"),
    "marketing": (1351352422, "appolon1908-hue/Codestra-Marketing-"),
    "scrapper": (1329513537, "appolon1908-hue/scrapper"),
    "beyvra-backend": (1319831182, "appolon1908-hue/beyvra-backend"),
    "beyvra-frontend": (1320246591, "appolon1908-hue/beyvra-frontend"),
    "moneybee-backend": (1343760409, "appolon1908-hue/Moneybee-Backend"),
    "moneybee-frontend": (1343759743, "appolon1908-hue/Moneybee-frontend-"),
    "breero": (1331354808, "appolon1908-hue/Breero.com"),
    "larim-a-backend": (1343962951, "appolon1908-hue/LARIM-A-Backend"),
    "larim-a-frontend": (1343962199, "appolon1908-hue/LARIM-A-Fornt-end"),
    "booked4seasons": (1332044491, "appolon1908-hue/booked4seasons"),
    "codestra-public-site": (1319808791, "appolon1908-hue/codestra"),
    "restaurant-frontend": (1221155447, "appolon1908-hue/Frontend-Resturant-"),
    "freight-platform-frontend": (
        1343761049,
        "appolon1908-hue/transportaion-Frontend",
    ),
    "social-control-plane": (1351353723, "appolon1908-hue/Codesrea-Social-"),
    "platform-documentation": (1350724356, "appolon1908-hue/documentaions"),
    "platform-infrastructure": (1350724865, "appolon1908-hue/Infustruction-repo"),
    "djone": (1382566617, "ingtrader21-spec/DJONE"),
}
EXPECTED_SYSTEM_SECURITY_PROFILES = {
    "middleware": (
        "cross-system-control-plane",
        "active",
        "middleware-core",
        "middleware-authority",
        "authority",
        None,
    ),
    "caddy": (
        "shared-edge-tls-reverse-proxy",
        "active",
        "edge-identity",
        "edge-compatibility",
        "compatibility",
        None,
    ),
    "kong": (
        "api-gateway-policy-routes-plugins",
        "active",
        "edge-identity",
        "gateway-compatibility",
        "compatibility",
        None,
    ),
    "keycloak": (
        "identity-clients-scopes-token-issuance",
        "active",
        "edge-identity",
        "identity-compatibility",
        "identity-authority",
        None,
    ),
    "n8n": (
        "automation-workflow-source",
        "active",
        "automation",
        "orchestration-client",
        "caller",
        None,
    ),
    "odoo": (
        "odoo-modules-business-crm-source",
        "active",
        "communications",
        "business-system-adapter",
        "target-and-event-source",
        "odoo-19",
    ),
    "telnexa-sms": (
        "jasmin-sms-runtime-billing-webhooks",
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
        "telnexa-sms",
    ),
    "telnexa-web": (
        "telnexa-public-website-onboarding",
        "active",
        "product-clients",
        "public-intake-client",
        "caller",
        None,
    ),
    "klyrow-email": (
        "email-postal-mautic-runtime",
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
        "klyrow-email",
    ),
    "klyrow-web": (
        "klyrow-public-marketing-frontend",
        "active",
        "product-clients",
        "public-intake-client",
        "caller",
        None,
    ),
    "kyqra-crawler": (
        "canonical-crawler-runtime",
        "active",
        "crawler",
        "provider-adapter",
        "target-and-event-source",
        "kyqra-crawler",
    ),
    "kyqra-legacy": (
        "legacy-reference-only",
        "deprecated",
        "legacy-disabled",
        "disabled",
        "none",
        None,
    ),
    "vicidial-asterisk": (
        "voice-contact-center-connector-runtime",
        "active",
        "telephony-restricted",
        "provider-adapter",
        "target-and-event-source",
        "vicidial-restricted",
    ),
    "provisioning": (
        "identity-access-provisioning-runtime",
        "active",
        "core-control-plane",
        "provider-adapter",
        "target-and-event-source",
        "provisioning-service",
    ),
    "sdk": (
        "developer-facing-contracts-sdks-connector-kit",
        "active",
        "governance",
        "contract-authority",
        "governance",
        None,
    ),
    "social": (
        "social-postiz-product-source",
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
        "postly-social",
    ),
    "ai": (
        "ai-provider-product-source",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "marketing": (
        "marketing-provider-product-source",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "scrapper": (
        "legacy-business-scrapper-source-and-migration-evidence",
        "legacy-migration",
        "legacy-disabled",
        "disabled",
        "none",
        None,
    ),
    "beyvra-backend": (
        "independent-product-backend",
        "active",
        "financial-isolated",
        "product-adapter-nonfinancial",
        "caller-and-target",
        "beyvra-nonfinancial",
    ),
    "beyvra-frontend": (
        "independent-product-frontend",
        "active",
        "financial-isolated",
        "product-client",
        "caller",
        None,
    ),
    "moneybee-backend": (
        "independent-product-backend",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "moneybee-frontend": (
        "independent-product-frontend",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "breero": (
        "independent-product",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "larim-a-backend": (
        "independent-product-backend",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "larim-a-frontend": (
        "independent-product-frontend",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "booked4seasons": (
        "independent-product",
        "active",
        "product-clients",
        "public-intake-client",
        "caller",
        None,
    ),
    "codestra-public-site": (
        "public-site-source",
        "active",
        "product-clients",
        "public-intake-client",
        "caller",
        None,
    ),
    "restaurant-frontend": (
        "independent-product-frontend",
        "active",
        "product-clients",
        "public-intake-client",
        "caller",
        None,
    ),
    "freight-platform-frontend": (
        "independent-product-frontend",
        "active",
        "product-clients",
        "product-client",
        "caller",
        None,
    ),
    "social-control-plane": (
        "provider-neutral-social-control-plane-architecture",
        "planned-name-review",
        "planned-control-planes",
        "planned-client",
        "caller",
        None,
    ),
    "platform-documentation": (
        "cross-repository-documentation-authority",
        "active",
        "governance",
        "documentation-reference",
        "governance",
        None,
    ),
    "platform-infrastructure": (
        "shared-infrastructure-and-release-governance",
        "active",
        "governance",
        "infrastructure-coordinator",
        "governance",
        None,
    ),
    "djone": (
        "djone-mixxx-native-control-source",
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
        "djone-mixxx",
    ),
}
EXPECTED_REPOSITORY_RENAMES = {
    1221155447: (
        "appolon1908-hue/Frontend-Resturant-",
        "appolon1908-hue/restaurant-frontend",
        "PREPARED_NOT_RENAMED",
    ),
    1343761049: (
        "appolon1908-hue/transportaion-Frontend",
        "appolon1908-hue/freight-platform-frontend",
        "PREPARED_NOT_RENAMED",
    ),
    1343962199: (
        "appolon1908-hue/LARIM-A-Fornt-end",
        "appolon1908-hue/LARIM-A-Frontend",
        "PREPARED_NOT_RENAMED",
    ),
    1351353723: (
        "appolon1908-hue/Codesrea-Social-",
        "appolon1908-hue/Codestra-Social-Control-Plane",
        "PREPARED_NOT_RENAMED",
    ),
    1350724356: (
        "appolon1908-hue/documentaions",
        "appolon1908-hue/Codestra-Documentation",
        "PREPARED_NOT_RENAMED",
    ),
    1350724865: (
        "appolon1908-hue/Infustruction-repo",
        "appolon1908-hue/Codestra-Infrastructure",
        "PREPARED_NOT_RENAMED",
    ),
}
EXPECTED_AUTHORITY_POLICY = {
    "middleware_repository": "ingtrader21-spec/Middleware-",
    "reference_repository": "appolon1908-hue/codestra-production-platform",
    "reference_repository_role": "historical-runtime-deployment-reconciliation-evidence-only",
    "owning_repository_is_principal": True,
    "central_release_authority": False,
    "cross_repository_coupling": "versioned-contracts-and-release-evidence",
    "repository_identity_key": "github_repository_id",
    "repository_name_migration_manifest": "config/repository-name-aliases.v1.json",
}
EXPECTED_MIDDLEWARE_OWNED = (
    "cross-system command and event contracts",
    "tenant-scoped command ledger and durable integration state",
    "Middleware API and workers",
    "Temporal command orchestration owned by Middleware",
    "trusted provider adapters and read-back/reconciliation logic",
    "Middleware Connector Runtime",
    "cross-repository compatibility contracts",
    "combined cross-repository release evidence",
)
EXPECTED_CANONICAL_ADAPTER_OWNERS = {
    "ai-provider": "appolon1908-hue/Codestra-AI",
    "beyvra-nonfinancial": "appolon1908-hue/beyvra-backend",
    "djone-mixxx": "ingtrader21-spec/DJONE",
    "klyrow-alert-email": "appolon1908-hue/klyrow.com",
    "klyrow-email": "appolon1908-hue/klyrow.com",
    "kyqra-crawler": "appolon1908-hue/kyqra-crawler",
    "marketing-provider": "appolon1908-hue/Codestra-Marketing-",
    "odoo-19": "appolon1908-hue/Odoo",
    "postly-social": "appolon1908-hue/social.codestra.co",
    "provisioning-service": "appolon1908-hue/codestra-provisioning-service",
    "telnexa-sms": "appolon1908-hue/telnexa",
    "vicidial-restricted": "appolon1908-hue/Vicidialer-Codestra",
}
EXPECTED_CANONICAL_ADAPTER_PROFILES = {
    "ai-provider": ("core-communications", "appolon1908-hue/Codestra-AI", ("ai.",), ()),
    "beyvra-nonfinancial": (
        "beyvra-financial",
        "appolon1908-hue/beyvra-backend",
        ("beyvra.operations.",),
        (
            "trade.",
            "order.",
            "wallet.",
            "ledger.",
            "hold.",
            "payment.",
            "withdrawal.",
            "deposit.",
            "transfer.",
            "custody.",
            "chain.",
            "broker.",
            "provider.",
        ),
    ),
    "djone-mixxx": (
        "core-communications",
        "ingtrader21-spec/DJONE",
        ("djone.",),
        (),
    ),
    "klyrow-alert-email": (
        "core-communications",
        "appolon1908-hue/klyrow.com",
        ("observability.alert.",),
        (),
    ),
    "klyrow-email": (
        "core-communications",
        "appolon1908-hue/klyrow.com",
        ("email.",),
        (),
    ),
    "kyqra-crawler": (
        "core-communications",
        "appolon1908-hue/kyqra-crawler",
        ("crawler.",),
        (),
    ),
    "marketing-provider": (
        "core-communications",
        "appolon1908-hue/Codestra-Marketing-",
        ("marketing.",),
        (),
    ),
    "odoo-19": ("core-communications", "appolon1908-hue/Odoo", ("crm.",), ()),
    "postly-social": (
        "core-communications",
        "appolon1908-hue/social.codestra.co",
        ("social.",),
        (),
    ),
    "provisioning-service": (
        "core-communications",
        "appolon1908-hue/codestra-provisioning-service",
        ("provisioning.",),
        (),
    ),
    "telnexa-sms": ("core-communications", "appolon1908-hue/telnexa", ("sms.",), ()),
    "vicidial-restricted": (
        "telephony-private",
        "appolon1908-hue/Vicidialer-Codestra",
        ("telephony.", "telephony-internal."),
        (),
    ),
}
EXPECTED_ADAPTER_BOUND_SYSTEMS = {
    "beyvra-backend": (
        "beyvra-nonfinancial",
        "financial-isolated",
        "product-adapter-nonfinancial",
        "caller-and-target",
    ),
    "djone": (
        "djone-mixxx",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "klyrow-email": (
        "klyrow-email",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "kyqra-crawler": (
        "kyqra-crawler",
        "crawler",
        "provider-adapter",
        "target-and-event-source",
    ),
    "odoo": (
        "odoo-19",
        "communications",
        "business-system-adapter",
        "target-and-event-source",
    ),
    "provisioning": (
        "provisioning-service",
        "core-control-plane",
        "provider-adapter",
        "target-and-event-source",
    ),
    "social": (
        "postly-social",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "telnexa-sms": (
        "telnexa-sms",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "vicidial-asterisk": (
        "vicidial-restricted",
        "telephony-restricted",
        "provider-adapter",
        "target-and-event-source",
    ),
}
EXPECTED_CANONICAL_ADAPTER_OWNER_SECURITY = {
    "ai": ("active", "product-clients", "product-client", "caller"),
    "beyvra-backend": (
        "active",
        "financial-isolated",
        "product-adapter-nonfinancial",
        "caller-and-target",
    ),
    "djone": (
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "klyrow-email": (
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "kyqra-crawler": (
        "active",
        "crawler",
        "provider-adapter",
        "target-and-event-source",
    ),
    "marketing": ("active", "product-clients", "product-client", "caller"),
    "odoo": (
        "active",
        "communications",
        "business-system-adapter",
        "target-and-event-source",
    ),
    "provisioning": (
        "active",
        "core-control-plane",
        "provider-adapter",
        "target-and-event-source",
    ),
    "social": (
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "telnexa-sms": (
        "active",
        "communications",
        "provider-adapter",
        "target-and-event-source",
    ),
    "vicidial-asterisk": (
        "active",
        "telephony-restricted",
        "provider-adapter",
        "target-and-event-source",
    ),
}
EXPECTED_REFERENCE_ONLY_REPOSITORIES = {
    "appolon1908-hue/codestra-production-platform": {
        "allowed_uses": (
            "historical runtime inventory",
            "deployment provenance",
            "rollback evidence",
            "previous Caddy/Kong/runtime configuration reference",
            "migration comparison",
        ),
        "forbidden_uses": (
            "principal source for a component that has its own repository",
            "central release authority",
            "place for new product or provider implementation",
            "place for new Caddy, Kong, Keycloak, n8n, Odoo, provider, SDK or product feature development",
        ),
    }
}

JsonObject = dict[str, Any]


class RegistryError(ValueError):
    """Raised when registry evidence is ambiguous or unsafe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RegistryError(message)


def as_object(value: Any, label: str) -> JsonObject:
    require(isinstance(value, dict), f"{label} must be an object")
    return cast(JsonObject, value)


def as_list(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be a list")
    return cast(list[Any], value)


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_nonstandard_constant(value: str) -> None:
    raise RegistryError(f"non-standard JSON constant: {value}")


def load_object(path: Path) -> JsonObject:
    try:
        value: Any = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_pairs,
            parse_constant=reject_nonstandard_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RegistryError) as exc:
        raise RegistryError(f"cannot read valid JSON: {path}: {exc}") from exc
    return as_object(value, str(path))


def valid_repository(value: Any) -> bool:
    return isinstance(value, str) and bool(REPOSITORY_RE.fullmatch(value))


def positive_repository_id(value: Any) -> bool:
    return type(value) is int and value > 0


def validate(
    registry: JsonObject,
    authorities: JsonObject,
    aliases: JsonObject,
    adapter_registry: JsonObject | None = None,
) -> dict[str, int]:
    require(
        set(registry) == REGISTRY_KEYS, "registry top-level field inventory mismatch"
    )
    require(
        set(authorities) == AUTHORITY_TOP_LEVEL_KEYS,
        "repository authority top-level field inventory mismatch",
    )
    require(
        set(aliases) == ALIAS_TOP_LEVEL_KEYS,
        "repository alias top-level field inventory mismatch",
    )
    require(registry.get("schema_version") == "4.0", "registry schema version mismatch")
    require(
        registry.get("identity_key") == "github_repository_id",
        "registry identity key mismatch",
    )
    require(
        registry.get("authority_source") == "config/repository-authorities.v1.json",
        "registry authority source mismatch",
    )
    require(
        registry.get("name_alias_source") == "config/repository-name-aliases.v1.json",
        "registry alias source mismatch",
    )
    require(
        registry.get("scope") == "authority-backed systems on current protected main",
        "registry scope mismatch",
    )

    policy = as_object(registry.get("policy"), "registry policy")
    require(set(policy) == POLICY_KEYS, "registry policy field inventory mismatch")
    for key in sorted(POLICY_KEYS):
        require(policy.get(key) is True, f"registry policy must fail closed: {key}")

    systems_raw = as_list(registry.get("systems"), "registry systems")
    require(bool(systems_raw), "registry systems must not be empty")
    systems: list[JsonObject] = []
    system_by_component: dict[str, JsonObject] = {}
    system_by_id: dict[int, JsonObject] = {}
    repository_names: set[str] = set()
    canonical_repository_names: set[str] = set()
    adapter_ids: set[str] = set()

    for index, raw in enumerate(systems_raw):
        item = as_object(raw, f"registry system {index}")
        require(
            set(item) == SYSTEM_KEYS,
            f"registry system {index} field inventory mismatch",
        )
        component = item.get("component")
        repository_id = item.get("github_repository_id")
        repository = item.get("current_repository")
        role = item.get("authority_role")
        lifecycle = item.get("lifecycle")
        cell = item.get("cell")
        mode = item.get("integration_mode")
        relationship = item.get("middleware_relationship")
        adapter = item.get("adapter_id")
        name_aliases = as_list(
            item.get("name_aliases"), f"registry aliases for {component}"
        )

        if not isinstance(component, str) or not component:
            raise RegistryError(f"invalid component at index {index}")
        require(
            component not in system_by_component, f"duplicate component: {component}"
        )
        if not positive_repository_id(repository_id):
            raise RegistryError(f"invalid repository id for {component}")
        assert isinstance(repository_id, int)
        require(
            repository_id not in system_by_id,
            f"duplicate repository id: {repository_id}",
        )
        if not valid_repository(repository):
            raise RegistryError(f"invalid repository name for {component}")
        assert isinstance(repository, str)
        canonical_repository = repository.casefold()
        require(
            canonical_repository not in canonical_repository_names,
            f"duplicate repository name: {repository}",
        )
        require(
            isinstance(role, str) and bool(role),
            f"invalid authority role for {component}",
        )
        require(
            lifecycle in ALLOWED_LIFECYCLES,
            f"unsupported lifecycle for {component}: {lifecycle}",
        )
        require(cell in ALLOWED_CELLS, f"unsupported cell for {component}: {cell}")
        require(
            mode in ALLOWED_INTEGRATION_MODES,
            f"unsupported integration mode for {component}: {mode}",
        )
        require(
            relationship in ALLOWED_RELATIONSHIPS,
            f"unsupported Middleware relationship for {component}: {relationship}",
        )
        require(
            adapter is None or (isinstance(adapter, str) and bool(adapter)),
            f"invalid adapter id for {component}",
        )
        if isinstance(adapter, str):
            require(adapter not in adapter_ids, f"duplicate adapter id: {adapter}")
            adapter_ids.add(adapter)
        for alias_index, raw_alias in enumerate(name_aliases):
            alias = as_object(raw_alias, f"registry alias {component}[{alias_index}]")
            require(
                set(alias) == REGISTRY_ALIAS_KEYS,
                f"registry alias field inventory mismatch: {component}",
            )
            require(
                valid_repository(alias.get("repository")),
                f"invalid registry alias repository: {component}",
            )
            require(
                alias.get("status") == "PREPARED_NOT_RENAMED",
                f"invalid registry alias status: {component}",
            )

        systems.append(item)
        system_by_component[component] = item
        system_by_id[repository_id] = item
        repository_names.add(repository)
        canonical_repository_names.add(canonical_repository)

    require(
        set(system_by_component) == set(EXPECTED_REPOSITORY_IDENTITIES),
        "registry and authoritative repository identity coverage differ",
    )
    for component, (
        expected_id,
        expected_repository,
    ) in EXPECTED_REPOSITORY_IDENTITIES.items():
        item = system_by_component[component]
        require(
            item.get("github_repository_id") == expected_id,
            f"authoritative repository id mismatch: {component}",
        )
        require(
            item.get("current_repository") == expected_repository,
            f"authoritative repository name mismatch: {component}",
        )

    canonical_adapters = (
        load_object(ADAPTER_PATH) if adapter_registry is None else adapter_registry
    )
    require(
        set(canonical_adapters) == ADAPTER_TOP_LEVEL_KEYS,
        "adapter registry top-level field inventory mismatch",
    )
    require(
        canonical_adapters.get("schema_version") == "2.0",
        "adapter registry schema version mismatch",
    )
    adapter_rows = as_list(
        canonical_adapters.get("adapters"), "canonical adapter registry"
    )
    canonical_adapter_by_id: dict[str, JsonObject] = {}
    for index, raw in enumerate(adapter_rows):
        adapter_row = as_object(raw, f"canonical adapter {index}")
        adapter_id = adapter_row.get("id")
        adapter_repository = adapter_row.get("repository")
        if not isinstance(adapter_id, str) or not adapter_id:
            raise RegistryError(f"invalid canonical adapter id at {index}")
        require(
            adapter_id not in canonical_adapter_by_id,
            f"duplicate canonical adapter id: {adapter_id}",
        )
        expected_profile = EXPECTED_CANONICAL_ADAPTER_PROFILES.get(adapter_id)
        require(
            expected_profile is not None,
            f"unapproved canonical adapter: {adapter_id}",
        )
        assert expected_profile is not None
        expected_fields = (
            ADAPTER_KEYS_WITH_FORBIDDEN_PREFIXES
            if expected_profile[3]
            else ADAPTER_KEYS
        )
        require(
            set(adapter_row) == expected_fields,
            f"canonical adapter field inventory mismatch: {adapter_id}",
        )
        if not valid_repository(adapter_repository):
            raise RegistryError(
                f"canonical adapter repository has no system: {adapter_id}"
            )
        assert isinstance(adapter_repository, str)
        require(
            adapter_repository in repository_names,
            f"canonical adapter repository has no system: {adapter_id}",
        )
        require(
            adapter_row.get("direct_n8n") is False,
            f"canonical adapter permits direct n8n: {adapter_id}",
        )
        canonical_adapter_by_id[adapter_id] = adapter_row

    require(bool(canonical_adapter_by_id), "canonical adapter registry is empty")
    require(
        set(canonical_adapter_by_id) == set(EXPECTED_CANONICAL_ADAPTER_OWNERS),
        "canonical adapter inventory differs from approved ownership",
    )
    for adapter_id, expected_repository in EXPECTED_CANONICAL_ADAPTER_OWNERS.items():
        require(
            canonical_adapter_by_id[adapter_id].get("repository")
            == expected_repository,
            f"canonical adapter ownership mismatch: {adapter_id}",
        )
    for adapter_id, expected_profile in EXPECTED_CANONICAL_ADAPTER_PROFILES.items():
        adapter_row = canonical_adapter_by_id[adapter_id]
        require(
            (
                adapter_row.get("cell"),
                adapter_row.get("repository"),
                tuple(
                    as_list(
                        adapter_row.get("command_prefixes"),
                        f"canonical adapter command prefixes: {adapter_id}",
                    )
                ),
                tuple(
                    as_list(
                        adapter_row.get("forbidden_prefixes", []),
                        f"canonical adapter forbidden prefixes: {adapter_id}",
                    )
                ),
            )
            == expected_profile,
            f"canonical adapter security profile mismatch: {adapter_id}",
        )
    for adapter_id in adapter_ids:
        selected_adapter = canonical_adapter_by_id.get(adapter_id)
        if selected_adapter is None:
            raise RegistryError(f"unknown adapter binding: {adapter_id}")
        owning_system = next(
            item for item in systems if item.get("adapter_id") == adapter_id
        )
        require(
            selected_adapter.get("repository")
            == owning_system.get("current_repository"),
            f"adapter repository mismatch: {adapter_id}",
        )

    require(
        authorities.get("schema_version") == "1.0",
        "repository authority schema version mismatch",
    )
    authority_policy = as_object(
        authorities.get("policy"), "repository authority policy"
    )
    require(
        authority_policy == EXPECTED_AUTHORITY_POLICY,
        "repository authority policy mismatch",
    )
    middleware_owned = as_list(
        authorities.get("middleware_owned"), "middleware-owned scope"
    )
    require(
        tuple(middleware_owned) == EXPECTED_MIDDLEWARE_OWNED,
        "middleware-owned scope mismatch",
    )
    require(
        authority_policy.get("repository_identity_key") == registry.get("identity_key"),
        "authority identity key differs from registry",
    )
    require(
        authority_policy.get("repository_name_migration_manifest")
        == registry.get("name_alias_source"),
        "authority rename manifest differs from registry",
    )

    reference_rows = as_list(
        authorities.get("reference_only"), "reference-only repositories"
    )
    reference_only_names: set[str] = set()
    for index, raw in enumerate(reference_rows):
        reference = as_object(raw, f"reference-only repository {index}")
        require(
            set(reference) == {"repository", "allowed_uses", "forbidden_uses"},
            f"reference-only repository schema drift at {index}",
        )
        repository = reference.get("repository")
        require(
            valid_repository(repository),
            f"invalid reference-only repository at {index}",
        )
        assert isinstance(repository, str)
        canonical_reference = repository.casefold()
        require(
            canonical_reference not in canonical_repository_names,
            f"reference-only repository is also a principal: {repository}",
        )
        require(
            canonical_reference not in reference_only_names,
            f"duplicate reference-only repository: {repository}",
        )
        expected_reference = EXPECTED_REFERENCE_ONLY_REPOSITORIES.get(repository)
        require(
            expected_reference is not None,
            f"unexpected reference-only repository: {repository}",
        )
        assert expected_reference is not None
        for use_kind in ("allowed_uses", "forbidden_uses"):
            uses = as_list(
                reference.get(use_kind),
                f"reference-only repository {use_kind}: {repository}",
            )
            require(
                tuple(uses) == expected_reference[use_kind],
                f"reference-only repository {use_kind} drift: {repository}",
            )
        reference_only_names.add(canonical_reference)
    require(
        reference_only_names
        == {name.casefold() for name in EXPECTED_REFERENCE_ONLY_REPOSITORIES},
        "reference-only repository inventory mismatch",
    )

    authority_rows = as_list(authorities.get("authorities"), "repository authorities")
    authority_by_component: dict[str, JsonObject] = {}
    authority_ids: set[int] = set()
    authority_rename_ids: set[int] = set()
    for index, raw in enumerate(authority_rows):
        authority = as_object(raw, f"authority {index}")
        component = authority.get("component")
        if not isinstance(component, str) or not component:
            raise RegistryError(f"invalid authority component at {index}")
        if "github_repository_id" not in authority:
            raise RegistryError(f"authority stable repository id missing: {component}")
        expected_authority_fields = {
            "component",
            "principal_repository",
            "role",
            "github_repository_id",
        }
        if component == "kyqra-legacy":
            expected_authority_fields.add("status")
        expected_identity = EXPECTED_REPOSITORY_IDENTITIES.get(component)
        if (
            expected_identity is not None
            and expected_identity[0] in EXPECTED_REPOSITORY_RENAMES
        ):
            expected_authority_fields |= {
                "target_repository_after_cutover",
                "rename_status",
            }
        require(
            set(authority) == expected_authority_fields,
            f"authority field inventory mismatch: {component}",
        )
        require(
            component not in authority_by_component,
            f"duplicate authority component: {component}",
        )
        require(
            valid_repository(authority.get("principal_repository")),
            f"invalid authority repository: {component}",
        )
        require(
            isinstance(authority.get("role"), str) and bool(authority.get("role")),
            f"invalid authority role: {component}",
        )
        repository_id = authority.get("github_repository_id")
        if not positive_repository_id(repository_id):
            raise RegistryError(f"invalid authority repository id: {component}")
        assert isinstance(repository_id, int)
        require(
            repository_id not in authority_ids,
            f"duplicate authority repository id: {repository_id}",
        )
        expected = EXPECTED_REPOSITORY_IDENTITIES.get(component)
        if expected is None:
            raise RegistryError(f"unknown authority component: {component}")
        require(
            repository_id == expected[0],
            f"authority repository id mismatch: {component}",
        )
        require(
            authority.get("principal_repository") == expected[1],
            f"authority repository mismatch: {component}",
        )
        require(
            authority.get("role") == EXPECTED_SYSTEM_SECURITY_PROFILES[component][0],
            f"approved authority role mismatch: {component}",
        )
        require(
            authority.get("status")
            == ("deprecated" if component == "kyqra-legacy" else None),
            f"approved authority status mismatch: {component}",
        )
        authority_ids.add(repository_id)
        authority_by_component[component] = authority

        rename_fields = {"target_repository_after_cutover", "rename_status"}
        present_rename_fields = rename_fields & set(authority)
        require(
            not present_rename_fields or present_rename_fields == rename_fields,
            f"partial authority rename binding: {component}",
        )
        if present_rename_fields:
            require(
                valid_repository(authority.get("target_repository_after_cutover")),
                f"invalid authority rename target: {component}",
            )
            require(
                authority.get("rename_status") == "PREPARED_NOT_RENAMED",
                f"invalid authority rename status: {component}",
            )
            authority_rename_ids.add(repository_id)

    require(
        set(authority_by_component) == set(system_by_component),
        "registry and repository-authority component coverage differ",
    )
    for component, item in system_by_component.items():
        authority = authority_by_component[component]
        require(
            authority.get("principal_repository") == item.get("current_repository"),
            f"authority repository mismatch: {component}",
        )
        require(
            authority.get("role") == item.get("authority_role"),
            f"authority role mismatch: {component}",
        )
        require(
            authority.get("github_repository_id") == item.get("github_repository_id"),
            f"authority repository id mismatch: {component}",
        )
        if authority.get("status") == "deprecated":
            require(
                item.get("lifecycle") == "deprecated",
                f"deprecated authority remains active: {component}",
            )

    require(aliases.get("schema_version") == "1.0", "alias schema version mismatch")
    require(
        aliases.get("status") == "PREPARED_NOT_RENAMED",
        "alias manifest status mismatch",
    )
    require(
        aliases.get("identity_key") == registry.get("identity_key"),
        "alias identity key differs from registry",
    )
    require(
        aliases.get("historical_evidence_immutable") is True,
        "alias history immutability must be true",
    )
    require(
        aliases.get("documentation_authority")
        == "appolon1908-hue/documentaions:repository-name-migration.v1.json",
        "alias documentation authority mismatch",
    )
    alias_rows = as_list(aliases.get("mappings"), "repository alias mappings")
    alias_by_id: dict[int, JsonObject] = {}
    alias_current_names: set[str] = set()
    alias_target_names: set[str] = set()
    for index, raw in enumerate(alias_rows):
        mapping = as_object(raw, f"alias mapping {index}")
        require(
            set(mapping) == ALIAS_MAPPING_KEYS,
            f"alias mapping {index} field inventory mismatch",
        )
        repository_id = mapping.get("github_repository_id")
        current_repository = mapping.get("current_repository")
        target_repository = mapping.get("target_repository_after_cutover")
        if not positive_repository_id(repository_id):
            raise RegistryError(f"invalid alias repository id at {index}")
        assert isinstance(repository_id, int)
        require(
            repository_id not in alias_by_id,
            f"duplicate alias repository id: {repository_id}",
        )
        require(
            valid_repository(current_repository),
            f"invalid alias current repository at {index}",
        )
        require(
            valid_repository(target_repository),
            f"invalid alias target repository at {index}",
        )
        assert isinstance(current_repository, str)
        assert isinstance(target_repository, str)
        canonical_current = current_repository.casefold()
        canonical_target = target_repository.casefold()
        require(
            canonical_current not in alias_current_names,
            f"duplicate alias current repository: {current_repository}",
        )
        require(
            canonical_target != canonical_current
            and canonical_target not in canonical_repository_names,
            f"alias target collides with a current repository: {target_repository}",
        )
        require(
            canonical_target not in reference_only_names,
            f"alias target collides with a reference-only repository: {target_repository}",
        )
        require(
            canonical_target not in alias_target_names,
            f"duplicate alias target repository: {target_repository}",
        )
        require(
            mapping.get("status") == "PREPARED_NOT_RENAMED",
            f"invalid alias mapping status at {index}",
        )
        alias_by_id[repository_id] = mapping
        alias_current_names.add(canonical_current)
        alias_target_names.add(canonical_target)

    require(
        set(alias_by_id) == authority_rename_ids,
        "alias mappings and authority rename bindings differ",
    )
    for repository_id, item in system_by_id.items():
        registry_aliases = as_list(
            item.get("name_aliases"),
            f"registry aliases for id {repository_id}",
        )
        selected_mapping = alias_by_id.get(repository_id)
        if selected_mapping is None:
            require(
                not registry_aliases,
                f"unregistered alias attached to repository id {repository_id}",
            )
            continue
        require(
            item.get("current_repository")
            == selected_mapping.get("current_repository"),
            f"alias current name mismatch: {repository_id}",
        )
        require(
            len(registry_aliases) == 1,
            f"registry alias count mismatch: {repository_id}",
        )
        registry_alias = as_object(
            registry_aliases[0],
            f"registry alias for id {repository_id}",
        )
        require(
            registry_alias.get("repository")
            == selected_mapping.get("target_repository_after_cutover"),
            f"registry alias target mismatch: {repository_id}",
        )
        require(
            registry_alias.get("status") == selected_mapping.get("status"),
            f"registry alias status mismatch: {repository_id}",
        )
        component = str(item["component"])
        authority = authority_by_component[component]
        require(
            authority.get("target_repository_after_cutover")
            == selected_mapping.get("target_repository_after_cutover"),
            f"authority alias target mismatch: {component}",
        )
        require(
            authority.get("rename_status") == selected_mapping.get("status"),
            f"authority alias status mismatch: {component}",
        )

    require(
        set(alias_by_id) == set(EXPECTED_REPOSITORY_RENAMES),
        "alias mappings and approved rename inventory differ",
    )
    for repository_id, expected_rename in EXPECTED_REPOSITORY_RENAMES.items():
        mapping = alias_by_id[repository_id]
        require(
            (
                mapping.get("current_repository"),
                mapping.get("target_repository_after_cutover"),
                mapping.get("status"),
            )
            == expected_rename,
            f"approved repository rename mismatch: {repository_id}",
        )

    middleware = system_by_component.get("middleware")
    if middleware is None:
        raise RegistryError("middleware registry row is missing")
    require(
        middleware.get("cell") == "middleware-core",
        "Middleware must remain in middleware-core",
    )
    require(
        middleware.get("integration_mode") == "middleware-authority",
        "Middleware authority mode drift",
    )
    require(
        middleware.get("middleware_relationship") == "authority",
        "Middleware relationship drift",
    )
    require(
        middleware.get("adapter_id") is None,
        "Middleware must not masquerade as a provider adapter",
    )

    n8n = system_by_component.get("n8n")
    if n8n is None:
        raise RegistryError("n8n registry row is missing")
    require(n8n.get("cell") == "automation", "n8n must remain in the automation cell")
    require(
        n8n.get("integration_mode") == "orchestration-client",
        "n8n must remain orchestration-only",
    )
    require(
        n8n.get("middleware_relationship") == "caller",
        "n8n must call Middleware rather than providers",
    )
    require(n8n.get("adapter_id") is None, "n8n must not own a provider adapter")

    for item in systems:
        component = str(item["component"])
        mode = item["integration_mode"]
        lifecycle = item["lifecycle"]
        cell = item["cell"]
        relationship = item["middleware_relationship"]
        adapter = item["adapter_id"]
        if mode == "provider-adapter":
            require(
                lifecycle == "active", f"provider adapter is not active: {component}"
            )
            require(
                cell in PROVIDER_CELLS,
                f"provider adapter is in an invalid cell: {component}",
            )
            require(
                relationship == "target-and-event-source",
                f"provider adapter bypass relationship: {component}",
            )
            require(
                isinstance(adapter, str) and bool(adapter),
                f"provider adapter lacks adapter id: {component}",
            )
        elif mode == "business-system-adapter":
            require(
                cell == "communications",
                f"business-system adapter cell drift: {component}",
            )
            require(
                relationship == "target-and-event-source",
                f"business-system adapter relationship drift: {component}",
            )
            require(
                isinstance(adapter, str) and bool(adapter),
                f"business-system adapter lacks adapter id: {component}",
            )
        elif mode == "product-adapter-nonfinancial":
            require(
                cell == "financial-isolated",
                f"nonfinancial product adapter cell drift: {component}",
            )
            require(
                relationship == "caller-and-target",
                f"nonfinancial product adapter relationship drift: {component}",
            )
            require(
                isinstance(adapter, str) and bool(adapter),
                f"nonfinancial product adapter lacks adapter id: {component}",
            )
        elif mode == "disabled":
            require(
                cell == "legacy-disabled",
                f"disabled system is outside legacy-disabled cell: {component}",
            )
            require(
                relationship == "none",
                f"disabled system retains Middleware relationship: {component}",
            )
            require(
                adapter is None,
                f"disabled system retains provider adapter: {component}",
            )
            require(
                lifecycle in {"deprecated", "legacy-migration"},
                f"disabled system has active lifecycle: {component}",
            )
        elif adapter is not None:
            raise RegistryError(
                f"unexpected adapter binding for integration mode {mode}: {component}"
            )

    for component, adapter_policy in EXPECTED_ADAPTER_BOUND_SYSTEMS.items():
        adapter_id, cell, mode, relationship = adapter_policy
        owner_item = system_by_component[component]
        require(
            owner_item.get("adapter_id") == adapter_id,
            f"canonical adapter binding mismatch: {component}",
        )
        require(
            (
                owner_item.get("cell"),
                owner_item.get("integration_mode"),
                owner_item.get("middleware_relationship"),
            )
            == (cell, mode, relationship),
            f"canonical adapter owner security classification mismatch: {component}",
        )

    canonical_owner_repositories = {
        repository.casefold()
        for repository in EXPECTED_CANONICAL_ADAPTER_OWNERS.values()
    }
    canonical_owner_components = {
        str(item["component"])
        for item in systems
        if str(item["current_repository"]).casefold() in canonical_owner_repositories
    }
    require(
        canonical_owner_components == set(EXPECTED_CANONICAL_ADAPTER_OWNER_SECURITY),
        "canonical adapter owner security inventory mismatch",
    )
    for (
        component,
        expected_security,
    ) in EXPECTED_CANONICAL_ADAPTER_OWNER_SECURITY.items():
        owner_item = system_by_component[component]
        require(
            (
                owner_item.get("lifecycle"),
                owner_item.get("cell"),
                owner_item.get("integration_mode"),
                owner_item.get("middleware_relationship"),
            )
            == expected_security,
            f"canonical adapter owner security classification mismatch: {component}",
        )

    for component, expected_system_profile in EXPECTED_SYSTEM_SECURITY_PROFILES.items():
        item = system_by_component[component]
        require(
            (
                item.get("authority_role"),
                item.get("lifecycle"),
                item.get("cell"),
                item.get("integration_mode"),
                item.get("middleware_relationship"),
                item.get("adapter_id"),
            )
            == expected_system_profile,
            f"approved system security profile mismatch: {component}",
        )

    return {
        "systems": len(systems),
        "aliases": len(alias_by_id),
        "adapters": len(canonical_adapter_by_id),
        "cells": len({str(item["cell"]) for item in systems}),
    }


def main() -> int:
    try:
        summary = validate(
            load_object(REGISTRY_PATH),
            load_object(AUTHORITY_PATH),
            load_object(ALIAS_PATH),
            load_object(ADAPTER_PATH),
        )
    except RegistryError as exc:
        print(f"SYSTEM_INTEGRATION_REGISTRY=FAIL reason={exc}", file=sys.stderr)
        return 1
    print(
        "SYSTEM_INTEGRATION_REGISTRY=PASS "
        f"systems={summary['systems']} aliases={summary['aliases']} "
        f"adapters={summary['adapters']} cells={summary['cells']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
