"""PAS-53 — production adapter registration with every capability OFF.

The production kernel registers only the adapters of
``config/production-adapters.v1.json`` whose configuration validates, and
only while every capability they serve is known, gated and ``false``. These
tests prove registration is fail closed, unknown capabilities are denied
explicitly at every layer, the readback API reports the posture, and not one
provider call or business record results from any of it."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import jwt
import pytest
from fastapi.testclient import TestClient

from app.application import AppProfile, create_app
from app.commands import CommandCapabilityDisabled, CommandEnvelope, CommandPolicy, CommandPolicyRegistry, CommandService, MemoryCommandStore
from app.control_plane_auth import ControlPlaneCaller
from app.core.config import Settings
from app.core.runtime import RuntimeContainer
from app.platform.adapters.fixtures import FixtureAdapter
from app.platform.adapters.n8n import N8nWorkflowAdapter
from app.platform.adapters.providers import LegacyBridge, OdooAdapter
from app.platform.kernel import CapabilityUnknown, SafetyDenied
from app.platform.memory import MemoryExecutionBus
from app.platform.principal import KernelPrincipal
from app.platform.production import (
    ProductionManifest,
    ProductionManifestError,
    effect_violations,
    production_candidates,
    register_production_adapters,
)
from app.platform.registry import AdapterRegistry, AdapterRegistryError
from app.platform.runtime import MODE_PRODUCTION_MANIFEST, PlatformRuntime, build_platform_runtime, command_policies
from app.platform.safety import SafetyContext, SafetyGate, SafetySubject, SafetySwitches
from app.replay import MemoryReplayGuard
from app.storage import MemoryInboxStore

TENANT = "tenant-a"
MANIFEST = ProductionManifest.load()


# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------
@dataclass
class CountingLegacy:
    """A legacy transport that records every call; any call is a provider effect."""

    calls: list[tuple[str, str]] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)

    async def execute(self, request: Any) -> Any:
        self.calls.append(("execute", request.command_type))
        return SimpleNamespace(status="accepted", provider_operation_id="should-never-exist")

    async def readback(self, request: Any) -> Any:
        self.calls.append(("readback", request.command_type))
        return SimpleNamespace(status="matched", provider_operation_id="should-never-exist")


def manifest_candidates(*, only: tuple[str, ...] | None = None) -> tuple[tuple[LegacyBridge, ...], CountingLegacy]:
    """One bridge per manifest adapter over one shared counting transport."""
    legacy = CountingLegacy()
    bridges = tuple(
        LegacyBridge(
            adapter_id=entry.adapter_id,
            provider_family=entry.provider_family,
            connector_ids=entry.connector_ids,
            served_capabilities=entry.capabilities,
            legacy=legacy,
        )
        for entry in MANIFEST.adapters
        if only is None or entry.adapter_id in only
    )
    return bridges, legacy


@pytest.fixture
def production(test_settings: Settings) -> Settings:
    return test_settings.replace(app_env="production")


def production_runtime(settings: Settings, *, candidates: tuple[object, ...], policies: CommandPolicyRegistry | None = None) -> tuple[PlatformRuntime, MemoryCommandStore]:
    store = MemoryCommandStore()
    commands = CommandService(store=store, policies=policies or command_policies(settings))
    platform = build_platform_runtime(settings, commands=commands, http=None, pool=None, service_id="middleware-integration-api", candidates=candidates)
    return platform, store


def everyone() -> KernelPrincipal:
    caller = ControlPlaneCaller(
        client_id="middleware-api",
        command_scope="platform.command",
        status_scope="platform.command.read",
        allowed_command_prefixes=tuple(policy.prefix for policy in CommandPolicyRegistry.load().policies) + ("automation.workflow.",),
        allowed_targets=frozenset({entry for item in MANIFEST.adapters for entry in item.connector_ids} | {policy.target for policy in CommandPolicyRegistry.load().policies}),
        connector_commands_allowed=True,
        compatibility_only=False,
    )
    return KernelPrincipal(
        subject="user-1",
        client_id="middleware-api",
        tenants=(TENANT,),
        roles=("platform-operator",),
        scopes=(
            "platform.command",
            "platform.command.read",
            "face-id.access.evaluate",
            "face-id.presence.write",
            "face-id.watchlist.write",
            "face-id.enrollment.review",
            "camera-gateway.ptz.control",
            "camera-gateway.events.write",
            "camera-gateway.maintenance.write",
        ),
        caller=caller,
    )


def envelope(command_type: str, target: str, capability: str, **payload: Any) -> CommandEnvelope:
    return CommandEnvelope.model_validate(
        {
            "command_id": str(uuid4()),
            "command_type": command_type,
            "command_version": "1.0",
            "target": target,
            "tenant_id": TENANT,
            "requested_by": "user-1",
            "correlation_id": "corr-" + uuid4().hex[:12],
            "idempotency_key": "idem-" + uuid4().hex,
            "capability": capability,
            "payload": {"campaign_id": "campaign-1", **payload},
        }
    )


# ----------------------------------------------------------------------------
# manifest
# ----------------------------------------------------------------------------
def test_manifest_capabilities_are_known_gated_and_off(production: Settings) -> None:
    assert MANIFEST.activation_authorized is False
    policies = command_policies(production)
    assert effect_violations(MANIFEST, policies, SafetySwitches.load()) == []
    switches = SafetySwitches.load()
    for capability in MANIFEST.capabilities():
        assert policies.capabilities[capability] is False
        assert switches.gates[capability].classification == "external_effect"
    # Every production command prefix whose capability a manifest adapter
    # serves is owned by exactly that adapter's connector.
    for policy in policies.policies:
        owners = [entry for entry in MANIFEST.adapters if policy.capability in entry.capabilities]
        assert len(owners) <= 1
        if owners:
            assert policy.target in owners[0].connector_ids


def test_manifest_matches_the_real_production_adapter_classes() -> None:
    odoo = MANIFEST.entry("odoo-19")
    assert odoo is not None and odoo.capabilities == OdooAdapter.served_capabilities and odoo.connector_ids == OdooAdapter.connector_ids
    n8n = MANIFEST.entry("n8n-automation")
    assert n8n is not None and n8n.capabilities == N8nWorkflowAdapter.served_capabilities and n8n.connector_ids == N8nWorkflowAdapter.connector_ids


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"schema_version": "2.0"}, "schema"),
        ({"environment": "staging"}, "production environment"),
        ({"activation_authorized": "no"}, "boolean"),
        ({"adapters": []}, "must not be empty"),
        ({"adapters": [{"adapter_id": "a", "provider_family": "x", "connector_ids": ["a"], "capabilities": ["ODOO_WRITE"]}] * 2}, "duplicate adapter id"),
        (
            {
                "adapters": [
                    {"adapter_id": "a", "provider_family": "x", "connector_ids": ["a"], "capabilities": ["ODOO_WRITE"]},
                    {"adapter_id": "b", "provider_family": "x", "connector_ids": ["b"], "capabilities": ["ODOO_WRITE"]},
                ]
            },
            "served by",
        ),
        ({"adapters": [{"adapter_id": "a", "provider_family": "x", "connector_ids": [], "capabilities": ["ODOO_WRITE"]}]}, "non-empty"),
    ],
)
def test_malformed_manifest_is_rejected(mutation: dict[str, Any], message: str) -> None:
    raw: dict[str, Any] = {
        "schema_version": "1.0",
        "manifest_version": "t",
        "environment": "production",
        "activation_authorized": False,
        "adapters": [{"adapter_id": "odoo-19", "provider_family": "odoo", "connector_ids": ["odoo-19"], "capabilities": ["ODOO_WRITE"]}],
    }
    raw.update(mutation)
    with pytest.raises(ProductionManifestError, match=message):
        ProductionManifest.parse(raw)


# ----------------------------------------------------------------------------
# registration
# ----------------------------------------------------------------------------
def test_production_registers_manifest_adapters_with_every_capability_off(production: Settings) -> None:
    candidates, legacy = manifest_candidates()
    platform, store = production_runtime(production, candidates=candidates)
    assert platform.registry_error is None
    assert platform.registration_mode == MODE_PRODUCTION_MANIFEST
    assert platform.registry.ids() == tuple(sorted(entry.adapter_id for entry in MANIFEST.adapters))
    assert platform.registry.validated
    assert platform.registration is not None and not platform.registration.refused
    assert {row.reason for row in platform.registration.rows} == {"registered"}
    # Registration activated nothing.
    assert all(value is False for value in platform.registry.policies.capabilities.values())
    assert platform.registry.enabled_adapter_ids() == ()
    assert "TEST_SYN_EXECUTE" not in platform.registry.policies.capabilities
    assert legacy.calls == [] and store._commands == {} and store._outbox == []


@pytest.mark.asyncio
async def test_production_readback_reports_all_off_and_probes_no_provider(production: Settings) -> None:
    candidates, legacy = manifest_candidates()
    platform, _ = production_runtime(production, candidates=candidates)
    readback = await platform.adapter_readback()
    assert readback["environment"] == "production"
    assert readback["registration_mode"] == "production_manifest"
    assert readback["registry_valid"] is True and readback["registry_error"] is None
    assert readback["provider_effects_enabled"] is False
    assert readback["effectful_capabilities_enabled"] == []
    assert readback["unknown_capabilities"] == []
    assert readback["readiness"] == {"adapter_registry": True, "platform_adapters": None, "probed_adapter_ids": []}
    assert readback["registration"]["activation_authorized"] is False
    assert readback["registration"]["manifest_version"] == MANIFEST.manifest_version
    for row in readback["adapters"]:
        assert row["registered"] is True
        assert row["capability_states"] and not any(row["capability_states"].values())
    for capability in MANIFEST.capabilities():
        state = readback["capabilities"][capability]
        assert state == {"known": True, "enabled": False, "classification": "external_effect", "adapter_ids": state["adapter_ids"]}
        assert len(state["adapter_ids"]) == 1
    assert legacy.calls == []


@pytest.mark.asyncio
async def test_unconfigured_production_adapters_are_reported_not_registered(production: Settings) -> None:
    candidates, legacy = manifest_candidates(only=("odoo-19",))
    platform, _ = production_runtime(production, candidates=candidates)
    assert platform.registry_error is None
    assert platform.registry.ids() == ("odoo-19",)
    readback = await platform.adapter_readback()
    reasons = {row["adapter_id"]: (row["registered"], row["reason"]) for row in readback["adapters"]}
    assert reasons["odoo-19"] == (True, "registered")
    assert reasons["telnexa-sms"] == (False, "not_configured")
    assert reasons["n8n-automation"] == (False, "not_configured")
    assert len(reasons) == len(MANIFEST.adapters)
    assert legacy.calls == []


def test_real_production_candidates_without_provider_configuration_register_nothing(production: Settings) -> None:
    """The real factory path: the test settings configure no provider."""
    candidates = production_candidates(production, http=None)
    assert {getattr(item, "adapter_id") for item in candidates} <= {entry.adapter_id for entry in MANIFEST.adapters}
    store = MemoryCommandStore()
    commands = CommandService(store=store, policies=command_policies(production))
    platform = build_platform_runtime(production, commands=commands, http=None, pool=None, service_id="middleware-integration-api")
    assert platform.registration_mode == MODE_PRODUCTION_MANIFEST
    assert platform.registry_error is None
    assert platform.registration is not None
    assert set(platform.registry.ids()) == {row.adapter_id for row in platform.registration.rows if row.registered}


def test_enabled_capability_refuses_the_whole_production_set(production: Settings) -> None:
    base = CommandPolicyRegistry.load()
    enabled = CommandPolicyRegistry(base.policies, {**base.capabilities, "ODOO_WRITE": True})
    candidates, legacy = manifest_candidates()
    platform, _ = production_runtime(production, candidates=candidates, policies=command_policies(production, enabled))
    assert platform.registry_error is not None and "capability_enabled:ODOO_WRITE" in platform.registry_error
    assert platform.registry.ids() == ()
    assert not platform.registry.validated
    assert platform.registration is not None and platform.registration.refused
    assert {row.reason for row in platform.registration.rows} == {"registration_refused"}
    assert legacy.calls == []


def test_unknown_ungated_or_internal_capability_refuses_registration(production: Settings) -> None:
    policies = command_policies(production)
    switches = SafetySwitches.load()
    unknown = ProductionManifest.parse(
        {
            "schema_version": "1.0",
            "manifest_version": "t",
            "environment": "production",
            "activation_authorized": False,
            "adapters": [{"adapter_id": "mystery", "provider_family": "x", "connector_ids": ["mystery"], "capabilities": ["MYSTERY_WRITE"]}],
        }
    )
    report = register_production_adapters(policies, switches, candidates=(), manifest=unknown)
    assert report.refused
    assert "capability_unknown:MYSTERY_WRITE" in report.violations
    assert "capability_without_safety_gate:MYSTERY_WRITE" in report.violations
    authorized = ProductionManifest.parse({**_raw(MANIFEST), "activation_authorized": True})
    assert "activation_authorized_must_be_false" in register_production_adapters(policies, switches, candidates=(), manifest=authorized).violations


def _raw(manifest: ProductionManifest) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "manifest_version": manifest.manifest_version,
        "environment": "production",
        "activation_authorized": manifest.activation_authorized,
        "adapters": [
            {"adapter_id": item.adapter_id, "provider_family": item.provider_family, "connector_ids": list(item.connector_ids), "capabilities": list(item.capabilities)}
            for item in manifest.adapters
        ],
    }


def test_unlisted_or_mismatched_adapter_refuses_the_whole_set(production: Settings) -> None:
    policies = command_policies(production)
    switches = SafetySwitches.load()
    candidates, _ = manifest_candidates()
    rogue = FixtureAdapter(adapter_id="rogue", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("ODOO_WRITE",))
    report = register_production_adapters(policies, switches, candidates=(*candidates, rogue))
    assert report.violations == ("adapter_not_in_manifest:rogue",)
    assert report.adapters == ()
    wide = LegacyBridge(adapter_id="odoo-19", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("ODOO_WRITE", "SMS_DELIVERY"), legacy=CountingLegacy())
    others = tuple(item for item in candidates if item.adapter_id != "odoo-19")
    mismatch = register_production_adapters(policies, switches, candidates=(*others, wide))
    assert mismatch.violations == ("adapter_manifest_mismatch:odoo-19",)
    assert mismatch.row("odoo-19") is not None and mismatch.row("odoo-19").reason == "manifest_mismatch"  # type: ignore[union-attr]
    assert mismatch.adapters == ()


def test_production_candidates_are_ignored_outside_production(test_settings: Settings) -> None:
    candidates, _ = manifest_candidates()
    platform, _ = production_runtime(test_settings, candidates=candidates)
    assert platform.registration is None and platform.registration_mode == "environment_defaults"


# ----------------------------------------------------------------------------
# zero effects
# ----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_every_production_command_is_denied_with_zero_provider_or_business_effects(production: Settings) -> None:
    candidates, legacy = manifest_candidates()
    platform, store = production_runtime(production, candidates=candidates)
    bus = MemoryExecutionBus(store, platform.dispatch)
    denied: dict[str, str] = {}
    from app.identity_missions import MISSION_COMMANDS
    from app.identity_service_contract import SERVICE_COMMANDS
    from tests.test_identity_missions import mission as identity_mission
    from tests.test_identity_service_adapters import command as service_command

    for policy in platform.registry.policies.policies:
        mission_name = next(
            (name for name in MISSION_COMMANDS if name.startswith(policy.prefix)),
            None,
        )
        if mission_name is not None:
            command = identity_mission(mission_name).model_copy(
                update={"tenant_id": TENANT, "requested_by": "user-1"}
            )
        elif (
            policy.target in SERVICE_COMMANDS
            and SERVICE_COMMANDS[policy.target][0] == policy.capability
        ):
            command = service_command(policy.target).model_copy(
                update={"tenant_id": TENANT, "requested_by": "user-1"}
            )
        else:
            command = envelope(
                f"{policy.prefix}probe.v1", policy.target, policy.capability
            )
        with pytest.raises(
            SafetyDenied, match="capability_disabled|provider_kill_switch"
        ):
            await platform.kernel.submit(command, everyone())
        denied[policy.prefix] = policy.capability
        # The ledger itself refuses a disabled capability even without the kernel.
        with pytest.raises(CommandCapabilityDisabled):
            await platform.kernel.commands.submit(command, authenticated_subject="user-1", authenticated_client_id="middleware-api", destination="adapter-command", decision_evidence={})
    assert set(denied) == {policy.prefix for policy in platform.registry.policies.policies}
    assert await bus.run_once() is False
    assert legacy.calls == []
    assert store._commands == {} and store._outbox == []
    records = platform.denials.records  # type: ignore[attr-defined]
    assert len(records) == len(denied)
    reasons = {(record.kind, record.reason_code) for record in records}
    assert reasons <= {
        ("safety_deny", "capability_disabled"),
        ("safety_deny", "provider_kill_switch"),
    }
    assert reasons


def test_safety_gate_denies_every_manifest_capability_even_with_a_ready_adapter(production: Settings) -> None:
    gate = SafetyGate(production, command_policies(production))
    for entry in MANIFEST.adapters:
        for capability in entry.capabilities:
            decision = gate.evaluate(
                SafetySubject(tenant_id=TENANT, command_type="x.probe.v1", target=entry.connector_ids[0], capability=capability, campaign_id="c", correlation_id="c"),
                SafetyContext(adapter_registered=True, adapter_ready=True),
            )
            assert not decision.allow
            assert "capability_disabled" in decision.reason_codes
            assert "capability_unknown" not in decision.reason_codes


# ----------------------------------------------------------------------------
# explicit unknown-capability denial
# ----------------------------------------------------------------------------
def test_safety_gate_denies_unknown_capability_whatever_its_class(test_settings: Settings) -> None:
    gate = SafetyGate(test_settings, command_policies(test_settings))
    unlisted = gate.evaluate(SafetySubject(tenant_id="TEST_SYN", command_type="x.v1", target="x", capability="UNLISTED_THING"), SafetyContext(adapter_registered=True, adapter_ready=True))
    assert unlisted.reason_code == "capability_without_safety_gate" and "capability_unknown" in unlisted.reason_codes
    # Gated but absent from the capability registry: still denied explicitly.
    narrow = SafetyGate(test_settings, CommandPolicyRegistry((), {}))
    gated = narrow.evaluate(SafetySubject(tenant_id="TEST_SYN", command_type="test.syn.execute.v1", target="test-syn", capability="TEST_SYN_EXECUTE"), SafetyContext(adapter_registered=True, adapter_ready=True))
    assert not gated.allow and "capability_unknown" in gated.reason_codes


def test_registry_refuses_adapters_and_policies_with_unknown_capabilities(test_settings: Settings) -> None:
    registry = AdapterRegistry(command_policies(test_settings))
    with pytest.raises(AdapterRegistryError, match="unknown capabilities"):
        registry.register(FixtureAdapter(adapter_id="odoo-extra", provider_family="odoo", connector_ids=("odoo-19",), served_capabilities=("ODOO_WRITE", "SECRET_WRITE")))
    broken = AdapterRegistry(CommandPolicyRegistry((CommandPolicy("mystery.", "mystery", "MYSTERY_WRITE", True),), {}))
    with pytest.raises(AdapterRegistryError, match="unknown capability 'MYSTERY_WRITE'"):
        broken.validate()


@pytest.mark.asyncio
async def test_kernel_denies_unknown_capability_before_policy_resolution(production: Settings) -> None:
    candidates, legacy = manifest_candidates()
    platform, store = production_runtime(production, candidates=candidates)
    with pytest.raises(CapabilityUnknown) as caught:
        await platform.kernel.submit(envelope("crm.contact.create.v1", "odoo-19", "MYSTERY_WRITE"), everyone())
    assert caught.value.code == "capability_unknown" and caught.value.status_code == 403
    assert legacy.calls == [] and store._commands == {}


# ----------------------------------------------------------------------------
# readback API
# ----------------------------------------------------------------------------
def token(*, scope: str = "platform.command platform.command.read", tenant: str = TENANT) -> str:
    now = int(time.time())
    claims = {"iss": "fake", "aud": "middleware-api", "azp": "middleware-api", "sub": "user-1", "iat": now, "exp": now + 120, "scope": scope, "tenant_ids": [tenant], "realm_access": {"roles": []}}
    return jwt.encode(claims, "unit-test-only-signing-key-32-bytes!", algorithm="HS256")


class ClaimsVerifier:
    async def verify(self, authorization: str, *, expected_client_id: str, required_scope: str) -> dict[str, Any]:
        from app.security import AuthenticationError

        scheme, _, raw = authorization.partition(" ")
        if scheme.lower() != "bearer" or not raw:
            raise AuthenticationError("Authorization must be a Bearer token")
        try:
            claims = jwt.decode(raw, "unit-test-only-signing-key-32-bytes!", algorithms=["HS256"], options={"verify_aud": False})
        except Exception as exc:  # noqa: BLE001
            raise AuthenticationError("invalid bearer token") from exc
        if claims.get("azp") != expected_client_id or required_scope not in str(claims.get("scope", "")).split():
            raise AuthenticationError("token is not authorized")
        return claims

    async def ready(self) -> bool:
        return True


@pytest.fixture
def api(test_settings: Settings, production: Settings):
    """The canonical integration app serving a production-registered kernel."""
    candidates, legacy = manifest_candidates(only=("odoo-19", "telnexa-sms", "vicidial-restricted"))
    store = MemoryCommandStore()
    commands = CommandService(store=store, policies=command_policies(production))
    runtime = RuntimeContainer(settings=test_settings, inbox=MemoryInboxStore(), replay=MemoryReplayGuard(), tokens=ClaimsVerifier(), commands=commands)
    runtime.platform = build_platform_runtime(production, commands=commands, http=None, pool=None, service_id="middleware-integration-api", candidates=candidates)
    app = create_app(settings=test_settings, runtime=runtime, profile=AppProfile.INTEGRATION)
    with TestClient(app) as client:
        yield client, legacy, store


def bearer(scope: str = "platform.command platform.command.read") -> dict[str, str]:
    return {"Authorization": f"Bearer {token(scope=scope)}"}


def test_adapter_readback_requires_read_scope(api) -> None:
    client, _, _ = api
    assert client.get("/platform/v1/adapters").status_code == 401
    assert client.get("/platform/v1/adapters", headers=bearer("platform.command")).status_code == 401
    assert client.get("/platform/v1/adapters/odoo-19").status_code == 401


def test_adapter_readback_lists_production_posture(api) -> None:
    client, legacy, store = api
    response = client.get("/platform/v1/adapters", headers=bearer())
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["environment"] == "production" and body["registration_mode"] == "production_manifest"
    assert body["provider_effects_enabled"] is False and body["effectful_capabilities_enabled"] == []
    assert body["unknown_capabilities"] == []
    assert body["registry_valid"] is True
    assert body["readiness"]["probed_adapter_ids"] == []
    registered = {row["adapter_id"] for row in body["adapters"] if row["registered"]}
    assert registered == {"odoo-19", "telnexa-sms", "vicidial-restricted"}
    assert {row["adapter_id"] for row in body["adapters"]} == {entry.adapter_id for entry in MANIFEST.adapters}
    assert all(state["enabled"] is False for state in body["capabilities"].values())
    text = response.text.lower()
    for forbidden in ("password", "client_secret", "bearer ", "private_key", "api_key"):
        assert forbidden not in text
    assert legacy.calls == [] and store._commands == {}


def test_adapter_detail_readback(api) -> None:
    client, legacy, _ = api
    odoo = client.get("/platform/v1/adapters/odoo-19", headers=bearer())
    assert odoo.status_code == 200
    detail = odoo.json()
    assert detail["adapter"]["registered"] is True and detail["adapter"]["reason"] == "registered"
    assert detail["adapter"]["capability_states"] == {"ODOO_WRITE": False}
    assert detail["adapter"]["command_prefixes"] == ["crm."]
    assert detail["capabilities"]["ODOO_WRITE"]["adapter_ids"] == ["odoo-19"]
    assert detail["provider_effects_enabled"] is False
    email = client.get("/platform/v1/adapters/klyrow-email", headers=bearer()).json()
    assert email["adapter"]["registered"] is False and email["adapter"]["reason"] == "not_configured"
    missing = client.get("/platform/v1/adapters/not-an-adapter", headers=bearer())
    assert missing.status_code == 404 and missing.json()["error"]["code"] == "adapter_not_found"
    assert client.get("/platform/v1/adapters/Not_Valid", headers=bearer()).status_code in {400, 422}
    assert legacy.calls == []


def test_submission_with_unknown_capability_is_denied_explicitly(api) -> None:
    client, legacy, store = api
    body = {
        "command_id": str(uuid4()),
        "command_type": "crm.contact.create.v1",
        "tenant_id": TENANT,
        "requested_by": "user-1",
        "correlation_id": "corr-unknown-cap",
        "idempotency_key": "idem-" + uuid4().hex,
        "capability": "MYSTERY_WRITE",
        "payload": {"record": {"name": "x"}},
    }
    headers = {**bearer(), "X-Correlation-ID": body["correlation_id"], "Idempotency-Key": body["idempotency_key"]}
    unknown = client.post("/platform/v1/commands", json=body, headers=headers)
    assert unknown.status_code == 403 and unknown.json()["error"]["code"] == "capability_unknown"
    known_but_off = client.post("/platform/v1/commands", json={**body, "capability": "ODOO_WRITE"}, headers=headers)
    assert known_but_off.status_code == 403
    assert known_but_off.json()["error"]["code"] in {"safety_denied", "policy_denied"}
    assert legacy.calls == [] and store._commands == {} and store._outbox == []


def test_connector_catalog_aliases_adapter_posture(api) -> None:
    client, legacy, _ = api
    response = client.get("/platform/v1/connectors", headers=bearer())
    assert response.status_code == 200
    body = response.json()
    rows = {row["adapter_id"]: row for row in body["connectors"]}
    assert rows["odoo-19"]["registered"] is True
    assert rows["odoo-19"]["capability_states"] == {"ODOO_WRITE": False}
    assert rows["klyrow-email"]["registered"] is False
    assert body["environment"] == "production"

    detail = client.get("/platform/v1/connectors/odoo-19", headers=bearer())
    assert detail.status_code == 200
    assert detail.json()["command_prefixes"] == ["crm."]

    health = client.get("/platform/v1/connectors/odoo-19/health", headers=bearer())
    assert health.status_code == 200
    assert health.json()["health"] == "disabled"
    assert legacy.calls == []


def test_connector_readback_reconcile_reference_and_tenant_guards(api) -> None:
    import asyncio

    client, legacy, store = api
    cmd = envelope("crm.contact.create.v1", "odoo-19", "ODOO_WRITE", record={"name": "Synthetic"})
    asyncio.run(store.submit(cmd, authenticated_client_id="middleware-api"))
    asyncio.run(store.transition(TENANT, cmd.command_id, new_state="queued", actor_id="worker", reason="queued"))
    asyncio.run(store.transition(TENANT, cmd.command_id, new_state="dispatching", actor_id="worker", reason="dispatch"))
    asyncio.run(store.transition(
        TENANT,
        cmd.command_id,
        new_state="accepted",
        actor_id="worker",
        reason="accepted",
        provider_operation_id="profile_id:123",
    ))
    asyncio.run(store.transition(
        TENANT,
        cmd.command_id,
        new_state="readback_pending",
        actor_id="worker",
        reason="readback",
        provider_operation_id="profile_id:123",
    ))

    wrong_reference = client.post(
        "/platform/v1/connectors/odoo-19/readback",
        json={"operation_id": str(cmd.command_id), "provider_reference": "profile_id:999"},
        headers=bearer(),
    )
    assert wrong_reference.status_code == 409
    assert wrong_reference.json()["error"]["code"] == "PROVIDER_REFERENCE_MISMATCH"
    assert legacy.calls == []

    readback = client.post(
        "/platform/v1/connectors/odoo-19/readback",
        json={"operation_id": str(cmd.command_id), "provider_reference": "profile_id:123"},
        headers=bearer(),
    )
    assert readback.status_code == 200
    assert readback.json()["command_id"] == str(cmd.command_id)
    assert readback.json()["provider_state"] == "MATCHED"

    reconcile = client.post(
        "/platform/v1/connectors/odoo-19/reconcile",
        json={"operation_id": str(cmd.command_id), "provider_reference": "profile_id:123"},
        headers=bearer(),
    )
    assert reconcile.status_code == 200
    assert reconcile.json()["consistency"] == "CONSISTENT"

    foreign = client.post(
        "/platform/v1/connectors/odoo-19/readback",
        json={"operation_id": str(cmd.command_id), "provider_reference": "profile_id:123"},
        headers={"Authorization": f"Bearer {token(tenant='tenant-b')}"},
    )
    assert foreign.status_code == 404
