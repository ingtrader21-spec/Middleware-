import json
from pathlib import Path

from app.commands import CommandPolicyRegistry
from app.core.config import Settings
from app.platform.registry import AdapterRegistry
from app.platform.safety import SafetySwitches


def test_whatsapp_command_family_is_registered_but_disabled_by_default() -> None:
    registry = CommandPolicyRegistry.load()
    policy = registry.resolve("whatsapp.message.send.v1")
    assert policy is not None
    assert policy.target == "evolution-whatsapp"
    assert policy.capability == "WHATSAPP_DELIVERY"
    assert policy.readback_required is True
    assert registry.capabilities["WHATSAPP_DELIVERY"] is False
    adapters = AdapterRegistry(registry)
    adapters.validate()
    assert adapters.owner_for("whatsapp.message.send.v1") is None


def test_whatsapp_safety_gate_requires_external_delivery_and_whatsapp_switch() -> None:
    switches = SafetySwitches.load()
    gate = switches.gates["WHATSAPP_DELIVERY"]
    assert gate.classification == "external_effect"
    assert gate.effect_flags == ("ENABLE_EXTERNAL_DELIVERY", "WHATSAPP_DELIVERY_ENABLED")
    assert gate.umbrella_controls == ("EXTERNAL_DELIVERY_ENABLED",)
    assert gate.campaign_scoped is True
    assert switches.provider_kill_switches["evolution-whatsapp"] is False


def test_whatsapp_runtime_effect_flag_defaults_off() -> None:
    settings = Settings.from_env({"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"})
    assert settings.external_effects["WHATSAPP_DELIVERY_ENABLED"] is False


def test_whatsapp_adapter_ownership_is_synchronized_with_canonical_authority() -> None:
    root = Path(__file__).resolve().parents[1]

    def load(path: str) -> dict:
        return json.loads((root / path).read_text(encoding="utf-8"))

    adapter = next(
        item
        for item in load("config/adapter-registry.v2.json")["adapters"]
        if item["id"] == "evolution-whatsapp"
    )
    manifest = load("connectors/manifests/evolution-whatsapp.connector.json")
    authority = next(
        item
        for item in load("config/repository-authorities.v1.json")["authorities"]
        if item["component"] == "evolution-whatsapp"
    )
    system = next(
        item
        for item in load("config/system-integration-registry.v4.json")["systems"]
        if item["adapter_id"] == "evolution-whatsapp"
    )
    repository = "ingtrader21-spec/Evolution-API"
    assert adapter["repository"] == manifest["repository"] == repository
    assert authority["principal_repository"] == system["current_repository"] == repository
    assert authority["github_repository_id"] == system["github_repository_id"] == 1384467115
    assert adapter["command_prefixes"] == ["whatsapp."]
    assert adapter["direct_n8n"] is False
    assert manifest["enabled_by_default"] is False
    assert manifest["runtime_binding"]["status"] == "UNVERIFIED_TEMPLATE_ONLY"
