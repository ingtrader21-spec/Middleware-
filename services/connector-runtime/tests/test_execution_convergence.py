import pytest
from codestra_connector_runtime.execution import (
    Connector, ConnectorCapability, ConnectorDescriptor, ConnectorFailure,
    ConnectorRegistry, ConnectorResult, EffectClass, ExecutionContext,
)

class C(Connector):
    descriptor = ConnectorDescriptor(
        connector_id="c1", provider="p", version="1", implementation_version="build-1",
        capabilities=(ConnectorCapability("send", EffectClass.COMMUNICATION),),
        environments=frozenset({"test"}), tenants=frozenset({"t1"}), denied_tenants=frozenset({"blocked"}),
        dependencies=("PostgreSQL", "OpenBao"), configuration_references=("secretref://c1",), enabled=True,
    )
    async def execute(self, operation, payload, context):
        return ConnectorResult(True, "accepted", provider_reference="ref-1", provider_status="ACCEPTED")
    async def health(self, context): return ConnectorResult(True, "healthy")

def ctx(**kw):
    v=dict(tenant_id="t1", environment="test", correlation_id="corr", actor_id="actor",
           command_id="cmd", causation_id="cause", operation="send", connector_id="c1",
           effects_allowed=True)
    v.update(kw); return ExecutionContext(**v)

@pytest.mark.asyncio
async def test_registry_lookup_and_normalized_result():
    r=ConnectorRegistry(); r.register(C())
    assert r.find_by_provider("p")[0].descriptor.connector_id == "c1"
    assert r.resolve_operation("send", ctx()).descriptor.connector_id == "c1"
    assert r.is_available("c1", ctx())
    out=await r.execute("c1","send",{},ctx())
    assert (out.connector_id,out.connector_version,out.operation,out.command_id)==("c1","1","send","cmd")
    assert out.provider_reference=="ref-1"

def test_duplicate_tenant_environment_and_disabled_fail_closed():
    r=ConnectorRegistry(); r.register(C())
    with pytest.raises(ValueError): r.register(C())
    for changed,code in [({"tenant_id":"other"},"TENANT_NOT_ALLOWED"),({"environment":"production"},"ENVIRONMENT_NOT_ALLOWED")]:
        with pytest.raises(ConnectorFailure) as exc: r.get("c1",ctx(**changed))
        assert exc.value.error.code==code
