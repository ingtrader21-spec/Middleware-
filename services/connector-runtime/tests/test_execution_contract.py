from __future__ import annotations
import asyncio
import pytest
from codestra_connector_runtime.execution import (
    Connector, ConnectorCapability, ConnectorDescriptor, ConnectorFailure,
    ConnectorRegistry, ConnectorResult, EffectClass, ExecutionContext,
)

class FakeConnector(Connector):
    descriptor = ConnectorDescriptor(
        connector_id="fake", provider="synthetic", version="1.0.0",
        capabilities=(
            ConnectorCapability("read", EffectClass.READ),
            ConnectorCapability("write", EffectClass.WRITE, cancellable=True),
            ConnectorCapability("slow", EffectClass.READ),
            ConnectorCapability("boom", EffectClass.READ),
        ),
        environments=frozenset({"development"}),
        dependencies=("synthetic-store",),
    )
    async def execute(self, operation, payload, context):
        if operation == "slow":
            await asyncio.sleep(.05)
        if operation == "boom":
            raise RuntimeError("secret provider detail")
        return ConnectorResult(True, "succeeded", {"operation": operation})
    async def health(self, context):
        return ConnectorResult(True, "healthy")

def context(**changes):
    values = dict(tenant_id="tenant-a", environment="development", correlation_id="corr", actor_id="actor", timeout_seconds=1, effects_allowed=False)
    values.update(changes)
    return ExecutionContext(**values)

@pytest.mark.asyncio
async def test_registry_discovers_and_executes_read_capability():
    registry = ConnectorRegistry(); registry.register(FakeConnector())
    assert registry.descriptors(context())[0].dependencies == ("synthetic-store",)
    result = await registry.execute("fake", "read", {}, context())
    assert result.ok and result.operation == "read"

@pytest.mark.asyncio
async def test_effects_fail_closed_and_environment_is_restricted():
    registry = ConnectorRegistry(); registry.register(FakeConnector())
    with pytest.raises(ConnectorFailure) as exc:
        await registry.execute("fake", "write", {}, context())
    assert exc.value.error.code == "EFFECT_DISABLED"
    with pytest.raises(ConnectorFailure) as exc:
        registry.get("fake", context(environment="production"))
    assert exc.value.error.code == "ENVIRONMENT_NOT_ALLOWED"

@pytest.mark.asyncio
async def test_timeout_and_provider_error_are_normalized():
    registry = ConnectorRegistry(); registry.register(FakeConnector())
    with pytest.raises(ConnectorFailure) as exc:
        await registry.execute("fake", "slow", {}, context(timeout_seconds=.001))
    assert exc.value.error.code == "PROVIDER_TIMEOUT" and exc.value.error.retryable
    with pytest.raises(ConnectorFailure) as exc:
        await registry.execute("fake", "boom", {}, context())
    assert exc.value.error.code == "PROVIDER_ERROR"
    assert "secret provider detail" not in exc.value.error.message

@pytest.mark.asyncio
async def test_cancellation_propagates():
    registry = ConnectorRegistry(); registry.register(FakeConnector())
    task = asyncio.create_task(registry.execute("fake", "slow", {}, context()))
    await asyncio.sleep(.001); task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
