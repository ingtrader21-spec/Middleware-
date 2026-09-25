from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from tests.test_campaign_recycling_engine import FakeConn, FakePool, NOW
from app.core.campaign_recycling import (
    PostgresCampaignRecyclingStore,
    CampaignRecyclingConflict,
)


@pytest.mark.asyncio
async def test_journey_cursor_continues_both_streams_and_is_tenant_bound():
    conn = FakeConn()
    conn.fetchrow_results = [{"state": "ELIGIBLE", "version": 3}]
    conn.fetch_results = [[{"version": 3}, {"version": 2}], [], [], []]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    page = await store.journey(tenant_id="tenant-1", lead_id="100-L-00000001", limit=1)
    assert page["lifecycle"] == [{"version": 3}]
    assert page["next_cursor"]
    conn.fetch_results = [[{"version": 2}], [], [], []]
    page2 = await store.journey(
        tenant_id="tenant-1",
        lead_id="100-L-00000001",
        limit=1,
        cursor=page["next_cursor"],
    )
    assert page2["lifecycle"] == [{"version": 2}]
    assert page2["next_cursor"] is None
    sql, args = [
        (s, a) for _, s, a in conn.executed if "FROM mcr_lead_lifecycle_events" in s
    ][-1]
    assert "version <" in sql
    assert 3 in args
    with pytest.raises(CampaignRecyclingConflict, match="cursor"):
        await store.journey(
            tenant_id="tenant-2", lead_id="100-L-00000001", cursor=page["next_cursor"]
        )


@pytest.mark.asyncio
async def test_journey_exact_limit_is_not_truncated():
    conn = FakeConn()
    conn.fetch_results = [[{"version": 1}], [], [], []]
    page = await PostgresCampaignRecyclingStore(FakePool(conn)).journey(
        tenant_id="t", lead_id="l", limit=1
    )
    assert page["truncated"] is False


def api(monkeypatch, *, scope="leads.journey.read", tenant="tenant-1"):
    from app.api.v1 import leads_journey as module
    from app.security import AuthorizationError

    async def authenticate(request, *, required_scope):
        if scope != required_scope:
            raise AuthorizationError("scope denied")
        return SimpleNamespace(
            scopes=(scope,), authorized_for=lambda value: value == tenant
        )

    monkeypatch.setattr(module, "authenticate", authenticate)
    app = FastAPI()
    app.include_router(module.router)
    store = SimpleNamespace(
        journey=AsyncMock(
            return_value={
                "current": {"state": "NEW", "version": 1},
                "lifecycle": [],
                "channel_health": [],
                "suppressions": [],
                "exposures": [],
                "next_cursor": None,
            }
        )
    )

    async def get_store():
        return store

    app.dependency_overrides[module.get_store] = get_store
    return app, store


HEADERS = {"X-Tenant-ID": "tenant-1", "X-Correlation-ID": "corr-read-1"}


@pytest.mark.asyncio
async def test_read_response_and_missing_lead(monkeypatch):
    app, store = api(monkeypatch)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/platform/v1/leads/100-L-00000001/journey", headers=HEADERS
        )
        assert response.status_code == 200
        assert response.json()["lifecycle_state"] == "NEW"
        assert response.json()["next_cursor"] is None
        assert response.headers["X-Correlation-ID"] == HEADERS["X-Correlation-ID"]
        store.journey.return_value["current"] = None
        response = await client.get(
            "/platform/v1/leads/100-L-00000001/journey", headers=HEADERS
        )
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "query,headers,status",
    [
        ("?limit=0", HEADERS, 400),
        ("?limit=201", HEADERS, 400),
        ("?limit=no", HEADERS, 400),
        ("?limit=1&limit=2", HEADERS, 400),
        ("", {**HEADERS, "X-Tenant-ID": "tenant-2"}, 403),
        ("", {"X-Tenant-ID": "tenant-1"}, 400),
    ],
)
async def test_invalid_requests_never_read(monkeypatch, query, headers, status):
    app, store = api(monkeypatch)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/platform/v1/leads/100-L-00000001/journey" + query, headers=headers
        )
    assert response.status_code == status
    assert set(response.json()["error"]) == {
        "code",
        "message",
        "correlation_id",
        "retryable",
        "details",
    }
    store.journey.assert_not_awaited()


@pytest.mark.asyncio
async def test_scope_denied(monkeypatch):
    app, store = api(monkeypatch, scope="campaign.engine.read")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/platform/v1/leads/100-L-00000001/journey", headers=HEADERS
        )
    assert response.status_code == 403
    store.journey.assert_not_awaited()


@pytest.mark.asyncio
async def test_next_action_without_candidate_authority_fails_closed(monkeypatch):
    app, _ = api(monkeypatch, scope="campaign.engine.read")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get(
            "/platform/v1/leads/100-L-00000001/next-action", headers=HEADERS
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "dependency_unavailable"


@pytest.mark.asyncio
async def test_populated_readback_uses_frozen_transition_and_exposure_schemas(monkeypatch):
    from tests.test_campaign_recycling_contracts import _transition, _health, _exposure
    app, store = api(monkeypatch)
    transition = _transition()
    transition['version'] = transition.pop('lifecycle_version')
    for key in ('schema_version', 'tenant_id', 'lead_id'):
        transition.pop(key)
    health = _health()
    health['evidence_hash'] = health.pop('evidence')['evidence_hash']
    health['updated_at'] = health['recorded_at']
    for key in ('schema_version', 'tenant_id', 'lead_id', 'suppression', 'cross_channel_effect'):
        health.pop(key)
    exposure = _exposure()
    for key in ('schema_version', 'tenant_id', 'lead_id'):
        exposure.pop(key)
    store.journey.return_value.update(lifecycle=[transition], channel_health=[health], exposures=[exposure])
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        response = await client.get('/platform/v1/leads/100-L-00000001/journey', headers=HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['transitions'][0]['tenant_id'] == 'tenant-1'
    assert body['transitions'][0]['lifecycle_version'] == 4
    assert body['channel_health'][0]['state'] == 'hard_bounce'
    assert body['exposures'][0]['exposure_id'] == exposure['exposure_id']


@pytest.mark.asyncio
@pytest.mark.parametrize('cursor', ['', '!', 'e30', 'a' * 501])
async def test_invalid_cursor_rejected_before_sql(cursor):
    conn = FakeConn()
    with pytest.raises(CampaignRecyclingConflict, match='cursor'):
        await PostgresCampaignRecyclingStore(FakePool(conn)).journey(tenant_id='t', lead_id='l', cursor=cursor)
    assert conn.executed == []


@pytest.mark.asyncio
async def test_exposure_tie_cursor_uses_uuid_and_timestamp():
    from uuid import UUID
    conn = FakeConn()
    exposure = {'reserved_at': NOW, 'exposure_id': UUID(int=1)}
    conn.fetch_results = [[], [], [], [exposure, {**exposure, 'exposure_id': UUID(int=2)}]]
    store = PostgresCampaignRecyclingStore(FakePool(conn))
    page = await store.journey(tenant_id='t', lead_id='l', limit=1)
    assert page['exposures'] == [exposure]
    await store.journey(tenant_id='t', lead_id='l', limit=1, cursor=page['next_cursor'])
    sql, args = [(s, a) for _, s, a in conn.executed if 'FROM mcr_exposures' in s][-1]
    assert 'exposure_id > $5' in sql
    assert args == ('t', 'l', 2, NOW, UUID(int=1), False)
    assert all(kind != 'execute' for kind, _, _ in conn.executed)


@pytest.mark.asyncio
async def test_real_auth_dependency_enforces_registered_caller_and_scope(monkeypatch):
    from app.api.v1 import leads_journey as module
    from app.platform.principal import authenticate
    from app.security import AuthenticationError
    app, store = api(monkeypatch)
    monkeypatch.setattr(module, 'authenticate', authenticate)
    verifier = AsyncMock(return_value={'sub':'reader', 'azp':'kong-gateway', 'tenant_id':'tenant-1', 'scope':'leads.journey.read'})
    app.state.runtime = SimpleNamespace(tokens=SimpleNamespace(verify=verifier),settings=SimpleNamespace(app_env='test'))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        missing = await client.get('/platform/v1/leads/100-L-00000001/journey', headers=HEADERS)
        assert missing.status_code == 401
        valid = await client.get('/platform/v1/leads/100-L-00000001/journey', headers={**HEADERS,'Authorization':'Bearer test-token'})
        assert valid.status_code == 200
        assert verifier.call_args.kwargs == {'expected_client_id':'kong-gateway', 'required_scope':'leads.journey.read'}
        verifier.side_effect = AuthenticationError('invalid token')
        denied = await client.get('/platform/v1/leads/100-L-00000001/journey', headers={**HEADERS,'Authorization':'Bearer test-token'})
        assert denied.status_code == 401
    assert store.journey.await_count == 1


def test_openapi_preserves_scopes_parameters_and_canonical_errors(monkeypatch):
    from app.api.v1.leads_journey import install_leads_openapi
    app, _ = api(monkeypatch)
    install_leads_openapi(app)
    spec = app.openapi()
    for name, scope in [('journey', 'leads.journey.read'), ('next-action', 'campaign.engine.read')]:
        operation = spec['paths']['/platform/v1/leads/{lead_id}/' + name]['get']
        assert operation['security'] == [{'codestraOAuth': [scope]}]
        params = [(item['in'], item['name']) for item in operation['parameters']]
        assert len(params) == len(set(params))
        assert '422' not in operation['responses']
        for code in ['400', '401', '403', '404', '503']:
            response = operation['responses'][code]
            assert response['content']['application/json']['schema']['required'] == ['error']
            assert 'X-Correlation-ID' in response['headers']
    assert 'codestraOAuth' in spec['components']['securitySchemes']


@pytest.mark.asyncio
async def test_inconsistent_projection_returns_safe_unavailable(monkeypatch):
    app, store = api(monkeypatch)
    store.journey.return_value['current']['state'] = 'INVENTED'
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as client:
        response = await client.get('/platform/v1/leads/100-L-00000001/journey', headers=HEADERS)
    assert response.status_code == 503
    assert 'INVENTED' not in response.text


@pytest.mark.parametrize('field,value', [
    (0, True), (0, 1.0), (2, True), (2, -1), (2, 2**63),
    (3, 12), (3, False), (3, ''), (3, '2026-09-24T12:00:00'),
    (4, 12), (4, False), (4, ''), (5, 1),
])
@pytest.mark.asyncio
async def test_cursor_rejects_invalid_field_types_before_sql(field, value):
    import base64
    import json
    from app.core.journey_cursor import scope_key

    fields = [1, scope_key('t', 'l'), 2, None, None, True]
    fields[field] = value
    cursor = base64.urlsafe_b64encode(json.dumps(fields).encode()).decode().rstrip('=')
    conn = FakeConn()
    with pytest.raises(CampaignRecyclingConflict, match='cursor'):
        await PostgresCampaignRecyclingStore(FakePool(conn)).journey(
            tenant_id='t', lead_id='l', cursor=cursor,
        )
    assert conn.executed == []


@pytest.mark.asyncio
async def test_next_action_authority_boundary_uses_only_read_engine(monkeypatch):
    from app.core import journey_readback as boundary
    from app.core.campaign_recycling import LeadSnapshot, PolicyProfile
    from unittest.mock import Mock

    inputs = boundary.NextActionInputs(
        snapshot=LeadSnapshot('tenant-1', '100-L-00000001', 'NEW', 1, {}),
        candidates=(), policy=PolicyProfile.load('test'), evaluated_at=NOW,
        kill_switch_open=True, evidence_stale_or_conflicting=True,
    )
    authority = SimpleNamespace(load=AsyncMock(return_value=inputs))
    evaluate = Mock(return_value=object())
    monkeypatch.setattr(boundary.CampaignRecyclingEngine, 'evaluate', evaluate)
    result = await boundary.evaluate_next_action(
        authority, tenant_id='tenant-1', lead_id='100-L-00000001', channel='email',
    )
    assert result is evaluate.return_value
    evaluate.assert_called_once_with(
        inputs.snapshot, (), mode='read', now=NOW, kill_switch_open=True,
        evidence_stale_or_conflicting=True,
    )
    evaluate.reset_mock()
    with pytest.raises(boundary.ReadbackUnavailable):
        await boundary.evaluate_next_action(authority, tenant_id='other', lead_id='100-L-00000001')
    evaluate.assert_not_called()
