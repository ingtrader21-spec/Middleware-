"""Canonical connector catalog projections over the one AdapterRegistry."""
from __future__ import annotations
from typing import Any
from app.platform.adapter import AdapterContext

class ConnectorCatalogError(RuntimeError):
    code="connector_unavailable"

def _row(runtime, connector_id: str) -> tuple[dict[str,Any], str]:
    for adapter in runtime.registry.describe():
        if connector_id in adapter["connector_ids"]:
            return adapter, adapter["adapter_id"]
    raise ConnectorCatalogError(f"connector {connector_id!r} is not registered")

async def describe_connector(runtime, connector_id: str) -> dict[str,Any]:
    row, adapter_id=_row(runtime,connector_id)
    enabled=any(runtime.registry.policies.capabilities.get(c) is True for c in row["capabilities"])
    context=AdapterContext(tenant_id="catalog",command_id="catalog",correlation_id="catalog",
        attempt=0,timeout_seconds=runtime.settings.readiness_timeout_seconds,
        environment=runtime.settings.app_env,deployment_sha=runtime.settings.source_sha,http=runtime.dispatch.http)
    readiness=(await runtime.registry.readiness(context))[adapter_id]
    return {**row,"connector_id":connector_id,"enabled":enabled,
        "health":"healthy" if readiness.ready else "unavailable",
        "readiness":{"ready":readiness.ready,"detail":readiness.detail},
        "environment":runtime.settings.app_env,
        "effect_classification":{c:runtime.safety.classification(c) for c in row["capabilities"]}}

async def list_connectors(runtime) -> list[dict[str,Any]]:
    result=[]
    for row in runtime.registry.describe():
        for connector_id in row["connector_ids"]:
            result.append(await describe_connector(runtime,connector_id))
    return sorted(result,key=lambda x:x["connector_id"])

async def connector_readback(runtime, commands, *, tenant_id, connector_id, operation_id):
    operation=await commands.get(tenant_id,operation_id)
    row, adapter_id=_row(runtime,connector_id)
    if operation.target != connector_id:
        raise ConnectorCatalogError("operation belongs to a different connector")
    adapter=runtime.registry.adapter(adapter_id)
    envelope=await commands.load_envelope(tenant_id,operation_id)
    attempt=await commands.latest_attempt(tenant_id,operation_id)
    context=runtime.dispatch.context(operation,attempt=attempt,timeout=runtime.dispatch.bus.default_timeout_seconds,payload=envelope.payload)
    result=await adapter.readback(operation,context)
    return {"connector_id":connector_id,"operation_id":str(operation_id),"provider_reference":result.provider_operation_id or operation.provider_operation_id,"local_state":operation.state,"remote_state":result.status.value,"consistency_status":result.status.value,"retry_recommendation":"reconcile" if result.status.value in {"UNAVAILABLE","MISMATCH"} else "none","correlation_id":operation.correlation_id,"timestamp":operation.updated_at.isoformat()}

async def connector_reconcile(runtime, commands, *, tenant_id, connector_id, operation_id):
    operation=await commands.get(tenant_id,operation_id)
    row, adapter_id=_row(runtime,connector_id)
    if operation.target != connector_id:
        raise ConnectorCatalogError("operation belongs to a different connector")
    adapter=runtime.registry.adapter(adapter_id)
    envelope=await commands.load_envelope(tenant_id,operation_id)
    attempt=await commands.latest_attempt(tenant_id,operation_id)
    context=runtime.dispatch.context(operation,attempt=attempt,timeout=runtime.dispatch.bus.default_timeout_seconds,payload=envelope.payload)
    result=await adapter.reconcile(operation,context)
    return {"connector_id":connector_id,"operation_id":str(operation_id),"provider_reference":result.provider_operation_id or operation.provider_operation_id,"local_state":operation.state,"remote_state":result.status.value,"consistency_status":result.status.value,"proposed_repair":"complete" if result.status.value=="MATCHED" else "reconciliation_required","retry_recommendation":"bounded_reconcile" if result.status.value in {"UNAVAILABLE","MISMATCH"} else "none","correlation_id":operation.correlation_id,"timestamp":operation.updated_at.isoformat()}