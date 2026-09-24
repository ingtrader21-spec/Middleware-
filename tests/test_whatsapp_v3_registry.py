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
