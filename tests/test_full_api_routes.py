from fastapi.testclient import TestClient
from app.commands import CommandService, MemoryCommandStore
from app.main import create_app
from app.replay import MemoryReplayGuard
from app.core.runtime import RuntimeContainer as Runtime
from app.storage import MemoryInboxStore
from tests.test_commands import CommandTokenVerifier, enabled_policy
from tests.test_commands import command_payload
from tests.conftest import make_event, signed_headers
from app.contracts import ROUTE_BY_PATH

REQUIRED={
"/v1/inbox","/v1/inbox/{record_id}","/v1/inbox/{record_id}/events","/v1/inbox/{record_id}/reprocess","/v1/inbox/{record_id}/quarantine","/v1/inbox/{record_id}/release",
"/v1/outbox","/v1/outbox/{record_id}","/v1/outbox/{record_id}/attempts","/v1/outbox/{record_id}/cancel","/v1/outbox/{record_id}/retry","/v1/outbox/{record_id}/reconcile","/v1/reconciliation/operations/{record_id}/request",
"/v1/system/capabilities","/v1/system/safety-state","/v1/system/readiness","/v1/policy/effective","/v1/policy/decisions","/v1/reconciliation/operations","/v1/audit/events","/v1/providers/status",
"/v1/integrations/n8n/operations","/v1/integrations/n8n/operations/{operation_id}/cancel","/v1/integrations/n8n/operations/{operation_id}/reconcile",
"/v1/communication/messages","/v1/communication/messages/{messageId}",
"/v1/email/commands","/v1/sms/commands","/v1/telephony/commands","/v1/social/commands","/v1/marketing/commands","/v1/ai/commands","/v1/webhooks/{connector_id}/{endpoint_key}/{webhook_id}","/webhooks/vicidial/call-result/{webhook_id}"}

def _app(test_settings):
    commands=CommandService(MemoryCommandStore(),enabled_policy())
    # REQUIRED includes the deprecated /v1/integrations/n8n/* aliases (monolith only).
    return create_app(settings=test_settings,runtime=Runtime(settings=test_settings,inbox=MemoryInboxStore(),replay=MemoryReplayGuard(),tokens=CommandTokenVerifier(),commands=commands),legacy_monolith=True)

def test_required_control_routes_are_registered(test_settings):
    assert REQUIRED <= set(_app(test_settings).openapi()["paths"])

def test_system_safety_is_authenticated_and_fail_closed(test_settings):
    with TestClient(_app(test_settings)) as client:
        assert client.get("/v1/system/capabilities",headers={"X-Tenant-ID":"tenant-1"}).status_code==401
        response=client.get("/v1/system/capabilities",headers={"Authorization":"Bearer legacy-status-token","X-Tenant-ID":"tenant-1"})
        assert response.status_code==200
        body=response.json()
        assert body["CALLS_PLACED"]==0
        assert all(body[key] is False for key in ("LIVE_ADVERTISING_ENABLED","EXTERNAL_DELIVERY_ENABLED","SOCIAL_PUBLISHING_ENABLED","EXTERNAL_MODEL_CALLS_ENABLED","LIVE_SMS_DELIVERY","LIVE_EMAIL_DELIVERY","LIVE_PSTN_DIALING","N8N_EXTERNAL_PROVIDER_WRITES","PRODUCTION_DIALING"))

def test_system_capabilities_report_effective_umbrella_state(test_settings):
    settings=test_settings.replace(umbrella_live_advertising_enabled=True)
    with TestClient(_app(settings)) as client:
        response=client.get("/v1/system/capabilities",headers={"Authorization":"Bearer legacy-status-token","X-Tenant-ID":"tenant-1"})
    assert response.status_code==200
    assert response.json()["LIVE_ADVERTISING_ENABLED"] is True
    assert response.json()["evidence"]=="effective_runtime"

def test_policy_decision_never_treats_umbrella_switch_as_a_grant(test_settings):
    settings=test_settings.replace(umbrella_live_advertising_enabled=True)
    headers={
        "Authorization":"Bearer legacy-command-token",
        "X-Tenant-ID":"tenant-1",
        "X-Correlation-ID":"policy-decision-test",
        "Idempotency-Key":"policy-decision-test",
    }
    with TestClient(_app(settings)) as client:
        response=client.post(
            "/v1/policy/decisions",
            json={
                "capability":"LIVE_ADVERTISING_ENABLED",
                "proposed_action":"start an advertising campaign",
            },
            headers=headers,
        )
    assert response.status_code==200
    assert response.json()["decision"]=="DENY"

def test_runtime_safety_openapi_publishes_typed_v11_schema(test_settings):
    schema=_app(test_settings).openapi()
    response=schema["paths"]["/v1/runtime/safety"]["get"]["responses"]["200"]
    model=response["content"]["application/json"]["schema"]
    assert model["$ref"]=="#/components/schemas/RuntimeSafetyReadback"
    component=schema["components"]["schemas"]["RuntimeSafetyReadback"]
    assert "umbrella_controls" in component["required"]
    assert component["additionalProperties"] is False

def test_generic_provider_webhook_preserves_signature_and_replay_controls(test_settings,runtime):
    path="/v1/webhooks/odoo/events/webhook-1"
    route=ROUTE_BY_PATH["/api/v1/odoo/events"]
    event=make_event(producer=route.producer_client_id,event_type=sorted(route.event_types)[0])
    body,headers=signed_headers(path=path,producer=route.producer_client_id,scope=route.required_scope,event=event)
    with TestClient(create_app(settings=test_settings,runtime=runtime)) as client:
        first=client.post(path,content=body,headers=headers)
        assert first.status_code==202
        replay=client.post(path,content=body,headers=headers)
        assert replay.status_code==200 and replay.json()["duplicate"] is True
        unsigned=dict(headers)
        unsigned["X-Codestra-Signature"]="sha256="+"0"*64
        assert client.post(path,content=body,headers=unsigned).status_code==401

def test_odoo_domain_command_reuses_durable_operation_and_scope_controls(test_settings):
    body=command_payload()
    headers={"Authorization":"Bearer legacy-command-token","X-Tenant-ID":"tenant-1","X-Correlation-ID":body["correlation_id"],"Idempotency-Key":body["idempotency_key"]}
    with TestClient(_app(test_settings)) as client:
        submitted=client.post("/v1/odoo/commands",json=body,headers=headers)
        assert submitted.status_code==202
        read={"Authorization":"Bearer legacy-status-token","X-Tenant-ID":"tenant-1"}
        assert client.get(f"/v1/odoo/operations/{body['command_id']}",headers=read).status_code==200
        assert client.get(f"/v1/email/operations/{body['command_id']}",headers=read).status_code==404
        missing_version=client.post(f"/v1/odoo/operations/{body['command_id']}/cancel",json={"reason":"operator_requested"},headers={**headers,"Idempotency-Key":"domain-cancel-key"})
        assert missing_version.status_code==400
