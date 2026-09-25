import hashlib
import hmac
import json
import time
from datetime import UTC, datetime
from types import SimpleNamespace

import asyncpg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import campaign_recycling as api
from app.core import campaign_recycling_readback as readback
from app.core.campaign_recycling import (
    CampaignRecyclingConflict,
    CampaignRecyclingIdempotencyConflict,
    CampaignRecyclingLifecycleConflict,
    CampaignRecyclingNotFound,
    ChannelHealth,
    LeadSnapshot,
    PolicyProfile,
    delivery_event_payload_hash,
)
from app.core.config import ConfigurationError
from app.core.jwt_auth import JWTAuthError

TENANT = 'TEST_SYN_TENANT'
LEAD = '100-L-00000001'
SECRET = b'k' * 32
CURSOR_KEY = 'c' * 32
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
ENVELOPE = {'code', 'message', 'correlation_id', 'retryable', 'details'}
HEADERS = {'Authorization': 'Bearer test', 'X-Tenant-ID': TENANT,
           'X-Correlation-ID': 'corr-test'}
STATUS = '/platform/v1/campaign-engine/status'
EVENTS = '/platform/v1/delivery-events'
SUPPRESSIONS = '/platform/v1/suppressions'
JOURNEY = f'/platform/v1/leads/{LEAD}/journey'
OPERATION_PATHS = {
    'campaign_engine_status': ('get', STATUS),
    'campaign_engine_plan': ('post', '/platform/v1/campaign-engine/plan'),
    'campaign_engine_execute': ('post', '/platform/v1/campaign-engine/execute'),
    'lead_journey_read': ('get', JOURNEY),
    'lead_next_action_read': ('get', f'/platform/v1/leads/{LEAD}/next-action'),
    'campaign_eligible_leads_read': (
        'get', '/platform/v1/campaigns/klyrow:test-syn-mcr/eligible-leads?campaign_version=1'),
    'delivery_event_ingest': ('post', EVENTS),
    'suppression_record': ('post', SUPPRESSIONS),
}


class Settings(SimpleNamespace):
    def webhook_secret(self, producer):
        if self.secret is None:
            raise ConfigurationError('missing')
        return self.secret


class FakeStore:
    """Stands in for PostgresCampaignRecyclingStore; records every call."""

    calls: list = []
    constructed: list = []
    delivery_result: object = None
    suppression_result: object = None
    snapshot_result: object = None

    def __init__(self, pool):
        FakeStore.constructed.append(pool)

    async def load_snapshot(self, **kwargs):
        FakeStore.calls.append(('snapshot', kwargs))
        if isinstance(FakeStore.snapshot_result, BaseException):
            raise FakeStore.snapshot_result
        if FakeStore.snapshot_result is not None:
            return FakeStore.snapshot_result
        return LeadSnapshot(
            tenant_id=kwargs['tenant_id'],
            lead_id=kwargs['lead_id'],
            lifecycle_state='ELIGIBLE',
            lifecycle_version=1,
            channel_health={
                'email': ChannelHealth(
                    state='valid', occurred_at=NOW, address_ref='addrref:test-syn'
                )
            },
        )

    async def apply_delivery_event(self, event, *, policy, address_ref=None):
        FakeStore.calls.append(('delivery', event, policy, address_ref))
        if isinstance(FakeStore.delivery_result, BaseException):
            raise FakeStore.delivery_result
        return FakeStore.delivery_result

    async def record_suppression_request(self, **kwargs):
        FakeStore.calls.append(('suppression', kwargs))
        if isinstance(FakeStore.suppression_result, BaseException):
            raise FakeStore.suppression_result
        return FakeStore.suppression_result


@pytest.fixture
def claims():
    return {'aud': 'middleware-api', 'tenant_id': TENANT, 'azp': 'klyrow-gateway',
            'scope': ' '.join(api.OPERATION_SCOPES.values())}


@pytest.fixture
def runtime():
    return SimpleNamespace(pool=object(), settings=Settings(
        secret=SECRET, webhook_max_clock_skew_seconds=300,
        mcr_cursor_signing_key=CURSOR_KEY))


@pytest.fixture
def client(monkeypatch, claims, runtime):
    def validate(token):
        if token != 'test':
            raise JWTAuthError('invalid')
        return claims
    monkeypatch.setattr(api, 'validate_token', validate)
    monkeypatch.setattr(api, 'PostgresCampaignRecyclingStore', FakeStore)
    FakeStore.calls, FakeStore.constructed = [], []
    FakeStore.delivery_result = {'event_id': 'evt-mcr-00000001', 'duplicate': False,
                                 'projection_state': 'applied', 'projection_note': None}
    FakeStore.suppression_result = {
        'suppression_id': '00000000-0000-4000-8000-000000000001', 'duplicate': False,
        'scope': 'channel', 'effective_at': NOW.isoformat()}
    FakeStore.snapshot_result = None
    app = FastAPI()
    app.include_router(api.router)
    app.state.runtime = runtime
    return TestClient(app)


def delivery_event(**overrides):
    value = {
        'schema_version': '1.0', 'event_id': 'evt-mcr-00000001', 'event_type': 'click',
        'automated_suspected': False, 'source': 'klyrow', 'provider': 'postal',
        'tenant_id': TENANT, 'lead_id': LEAD, 'channel': 'email',
        'campaign_id': 'klyrow:cmp-a', 'campaign_version': 1,
        'exposure_idempotency_key': 'mcr1:' + '1' * 64, 'message_id': None,
        'provider_message_id': 'pm-1', 'correlation_id': 'corr-test', 'causation_id': None,
        'occurred_at': '2026-09-24T12:00:00Z', 'received_at': '2026-09-24T12:00:01Z',
        'origin': {'inbox': 'klyrow_delivery_event_inbox', 'inbox_event_id': 'raw-1'},
    }
    value.update(overrides)
    value['payload_hash'] = overrides.get('payload_hash', delivery_event_payload_hash(value))
    return value


def signed(body, *, event=None, timestamp=None, producer='klyrow-gateway', secret=SECRET,
           raw=None, **headers):
    raw = raw if raw is not None else json.dumps(body).encode()
    event_id = event or (body or {}).get('event_id', 'evt-mcr-00000001')
    stamp = str(int(time.time()) if timestamp is None else timestamp)
    canonical = '\n'.join(('v1', 'POST', EVENTS, stamp, event_id, producer,
                           hashlib.sha256(raw).hexdigest())).encode()
    result = {**HEADERS, 'Content-Type': 'application/json',
              'Idempotency-Key': f"{(body or {}).get('source', 'klyrow')}:{event_id}",
              'X-Codestra-Event-ID': event_id, 'X-Codestra-Timestamp': stamp,
              'X-Codestra-Signature': 'v1=' + hmac.new(secret, canonical, hashlib.sha256).hexdigest()}
    result.update(headers)
    return raw, result


def post_event(client, body=None, **kwargs):
    raw, headers = signed(body if body is not None else delivery_event(), **kwargs)
    return client.post(EVENTS, content=raw, headers=headers)


def suppression(**overrides):
    value = {'schema_version': '1.0', 'lead_id': LEAD, 'scope': 'channel',
             'channel': 'email', 'campaign_id': None, 'reason': 'unsubscribe',
             'source': 'operator', 'occurred_at': '2026-09-24T12:00:00Z',
             'evidence': {'kind': 'operator_change', 'evidence_hash': 'a' * 64},
             'requested_by': 'operator:synthetic'}
    value.update(overrides)
    return value


def post_suppression(client, body=None, key='suppress-key-1', **headers):
    return client.post(SUPPRESSIONS, json=body if body is not None else suppression(),
                       headers={**HEADERS, 'Idempotency-Key': key, **headers})


def call(client, operation_id, headers=None):
    if operation_id == 'delivery_event_ingest':
        return post_event(client, **(headers or {}))
    method, path = OPERATION_PATHS[operation_id]
    headers = {**HEADERS, 'Idempotency-Key': 'operation-key-1', **(headers or {})}
    if method == 'get':
        return client.get(path, headers=headers)
    return client.post(path, headers=headers, json={})


def assert_error(response, status, code):
    assert response.status_code == status, response.text
    error = response.json()['error']
    assert set(response.json()) == {'error'} and set(error) == ENVELOPE
    assert error['code'] == code
    assert error['details'] == {}
    assert error['correlation_id'] == response.headers['X-Correlation-ID']
    return error


# --- status, registration, envelope ---------------------------------------------


def test_status_is_frozen(client):
    response = client.get(STATUS, headers=HEADERS)
    assert response.status_code == 200
    assert response.headers['X-Correlation-ID'] == 'corr-test'
    assert response.json()['runtime_status'] == 'contract_only'
    for flag in ('engine_enabled', 'execute_enabled', 'production_authorized'):
        assert response.json()[flag] is False
    assert not any(response.json()['capabilities'].values())
    assert FakeStore.constructed == []


def test_status_ignores_provider_capability_settings(client, runtime):
    runtime.settings.external_effects = True
    runtime.settings.email_delivery_enabled = True
    body = client.get(STATUS, headers=HEADERS).json()
    assert body['production_authorized'] is False and body['execute_enabled'] is False


def test_openapi_registers_exactly_the_frozen_operations(test_settings):
    from app.main import create_app
    from scripts.validate_campaign_recycling_contracts import EXPECTED_OPERATIONS
    schema = create_app(settings=test_settings).openapi()
    markers = ('campaign-engine', 'delivery-events', 'suppressions', '/journey',
               '/next-action', 'eligible-leads')
    registered = {(method, path): operation['operationId']
                  for path, item in schema['paths'].items()
                  if any(marker in path for marker in markers)
                  for method, operation in item.items()}
    assert set(registered) == EXPECTED_OPERATIONS
    assert set(registered.values()) == set(OPERATION_PATHS) == set(api.OPERATION_SCOPES)
    for (method, path), operation_id in registered.items():
        assert OPERATION_PATHS[operation_id][0] == method


@pytest.mark.parametrize('header', ['X-Tenant-ID', 'X-Correlation-ID'])
def test_required_headers(client, header):
    response = client.get(STATUS, headers={k: v for k, v in HEADERS.items() if k != header})
    error = assert_error(response, 400, 'invalid_request')
    assert error['retryable'] is False


@pytest.mark.parametrize('value', ['', 'x' * 181])
def test_invalid_correlation_is_replaced_not_echoed(client, value):
    response = client.get(STATUS, headers={**HEADERS, 'X-Correlation-ID': value})
    assert response.status_code == 400
    assert response.headers['X-Correlation-ID'] != value


@pytest.mark.parametrize('key', [None, 'short', 'k' * 181])
def test_suppression_requires_a_valid_idempotency_key(client, key):
    headers = {**HEADERS} if key is None else {**HEADERS, 'Idempotency-Key': key}
    response = client.post(SUPPRESSIONS, json=suppression(), headers=headers)
    assert_error(response, 400, 'invalid_request')
    assert FakeStore.calls == []


def test_mutations_require_json_content_type(client):
    response = client.post(SUPPRESSIONS, content=json.dumps(suppression()),
                           headers={**HEADERS, 'Idempotency-Key': 'suppress-key-1',
                                    'Content-Type': 'text/plain'})
    assert_error(response, 400, 'invalid_request')


# --- authentication, audience, scope, tenant ------------------------------------


def test_auth_required(client):
    response = client.get(STATUS, headers={k: v for k, v in HEADERS.items() if k != 'Authorization'})
    assert_error(response, 401, 'authentication_required')
    response = client.get(STATUS, headers={**HEADERS, 'Authorization': 'Bearer wrong'})
    assert_error(response, 401, 'authentication_required')


@pytest.mark.parametrize('audience', ['other-api', ['other-api'], None, 'middleware-api-x'])
def test_audience_must_be_middleware_api(client, claims, audience):
    claims['aud'] = audience
    assert_error(client.get(STATUS, headers=HEADERS), 401, 'authentication_required')


def test_audience_list_containing_middleware_api_is_accepted(client, claims):
    claims['aud'] = ['account', 'middleware-api']
    assert client.get(STATUS, headers=HEADERS).status_code == 200


@pytest.mark.parametrize('operation_id', sorted(OPERATION_PATHS))
def test_each_operation_requires_its_exact_scope(client, claims, operation_id):
    required = api.OPERATION_SCOPES[operation_id]
    claims['scope'] = ' '.join(s for s in set(api.OPERATION_SCOPES.values()) if s != required)
    claims['scope'] += ' ' + required + '.extra campaign.engine.*'
    assert_error(call(client, operation_id), 403, 'scope_denied')
    assert FakeStore.constructed == []


def test_scope_claim_must_be_a_space_delimited_string(client, claims):
    claims['scope'] = list(api.OPERATION_SCOPES.values())
    assert_error(client.get(STATUS, headers=HEADERS), 403, 'scope_denied')


@pytest.mark.parametrize('tenant_claims', [
    {'tenant_id': 'other'}, {'tenant_id': '*'}, {'tenant_ids': ['*', TENANT]}, {}])
def test_tenant_must_match_the_authenticated_mapping(client, claims, tenant_claims):
    claims.pop('tenant_id')
    claims.update(tenant_claims)
    assert_error(client.get(STATUS, headers=HEADERS), 403, 'tenant_scope_denied')


def test_tenant_scope(client):
    response = client.get(STATUS, headers={**HEADERS, 'X-Tenant-ID': 'other'})
    assert_error(response, 403, 'tenant_scope_denied')


# --- closed operations ----------------------------------------------------------


def test_execute_cannot_be_activated(client, runtime):
    runtime.settings.external_effects = True
    response = client.post('/platform/v1/campaign-engine/execute', headers={**HEADERS, 'Idempotency-Key': 'execute-1'}, json={
        'schema_version': '1.0', 'plan_id': '00000000-0000-4000-8000-000000000001', 'plan_hash': 'a'*64})
    assert_error(response, 403, 'production_not_authorized')
    assert FakeStore.constructed == [] and FakeStore.calls == []


def test_plan_strict_schema(client):
    response = client.post('/platform/v1/campaign-engine/plan', headers=HEADERS, json={
        'schema_version':'1.0', 'lead_ids':['100-L-00000001'], 'execute':True})
    assert_error(response, 422, 'contract_violation')


@pytest.mark.parametrize('operation_id', [
    'lead_next_action_read', 'campaign_eligible_leads_read'])
def test_reads_fail_closed_while_policy_is_unconfigured(client, monkeypatch, operation_id):
    monkeypatch.setattr(api, '_policy_for_tenant', lambda tenant: PolicyProfile.load('production'))
    assert_error(call(client, operation_id), 503, 'policy_not_configured')


@pytest.mark.parametrize('operation_id', [
    'lead_next_action_read', 'campaign_eligible_leads_read'])
def test_reads_fail_closed_without_certified_campaign_authority(client, monkeypatch, operation_id):
    monkeypatch.setattr(api, '_policy_for_tenant', lambda tenant: PolicyProfile.load('test'))
    monkeypatch.setattr(api, 'candidate_authority_for_tenant', lambda tenant: None)
    error = assert_error(call(client, operation_id), 503, 'dependency_unavailable')
    assert error['retryable'] is True
    assert FakeStore.constructed == []


# --- delivery events --------------------------------------------------------------


def test_delivery_event_is_durably_accepted(client):
    body = delivery_event()
    response = post_event(client, body)
    assert response.status_code == 202, response.text
    assert response.json() == {'accepted': True, 'duplicate': False,
                               'source': 'klyrow', 'event_id': body['event_id']}
    (kind, event, policy, address_ref), = FakeStore.calls
    assert kind == 'delivery' and event == body and address_ref is None
    assert policy.configured is False and policy.production_authorized is False


def test_identical_delivery_replay_is_202_duplicate(client):
    FakeStore.delivery_result = {'event_id': 'evt-mcr-00000001', 'duplicate': True,
                                 'projection_state': 'applied', 'projection_note': None}
    response = post_event(client)
    assert response.status_code == 202
    assert response.json()['duplicate'] is True


def test_delivery_replay_or_evidence_conflict_is_409_without_leaking(client):
    FakeStore.delivery_result = CampaignRecyclingConflict(
        'delivery event identity was reused with different evidence secret-detail')
    response = post_event(client)
    error = assert_error(response, 409, 'replay_conflict')
    assert error['retryable'] is False and 'secret-detail' not in response.text


def test_delivery_lifecycle_race_is_retryable_409(client):
    FakeStore.delivery_result = CampaignRecyclingLifecycleConflict('lost race')
    error = assert_error(post_event(client), 409, 'lifecycle_version_conflict')
    assert error['retryable'] is True


def test_delivery_database_failure_is_503_without_leaking(client):
    FakeStore.delivery_result = asyncpg.PostgresError('password=hunter2')
    response = post_event(client)
    assert_error(response, 503, 'dependency_unavailable')
    assert 'hunter2' not in response.text


def test_delivery_requires_the_shared_durable_pool(client, runtime):
    runtime.pool = None
    assert_error(post_event(client), 503, 'dependency_unavailable')
    assert FakeStore.calls == []


@pytest.mark.parametrize('event_type', ['delivered', 'soft_bounce', 'hard_bounce',
                                        'complaint', 'unsubscribe'])
def test_health_effect_without_certified_address_ref_fails_closed(client, event_type):
    extra = {'bounce_class': 'soft' if event_type == 'soft_bounce' else 'hard'} \
        if 'bounce' in event_type else {}
    body = delivery_event(event_type=event_type, **extra)
    body.pop('automated_suspected')
    body['payload_hash'] = delivery_event_payload_hash(body)
    assert_error(post_event(client, body), 503, 'dependency_unavailable')
    assert FakeStore.constructed == []


def test_payload_hash_must_match_the_canonical_event(client):
    assert_error(post_event(client, delivery_event(payload_hash='f' * 64)),
                 422, 'contract_violation')
    assert FakeStore.calls == []


def test_signature_is_verified_before_the_body_is_parsed(client):
    raw, headers = signed(None, raw=b'{not json', event='evt-mcr-00000001')
    headers['X-Codestra-Signature'] = 'v1=' + '0' * 64
    assert_error(client.post(EVENTS, content=raw, headers=headers), 401, 'signature_invalid')
    raw, headers = signed(None, raw=b'{not json', event='evt-mcr-00000001')
    assert_error(client.post(EVENTS, content=raw, headers=headers), 400, 'invalid_request')


def test_signature_binds_the_raw_body(client):
    raw, headers = signed(delivery_event())
    tampered = raw.replace(b'"click"', b'"reply"')
    assert_error(client.post(EVENTS, content=tampered, headers=headers), 401, 'signature_invalid')


def test_signature_uses_the_principal_credential_only(client):
    assert_error(post_event(client, secret=b'x' * 32), 401, 'signature_invalid')
    assert_error(post_event(client, producer='telnexa-gateway'), 401, 'signature_invalid')


@pytest.mark.parametrize('offset', [-301, 301])
def test_timestamp_outside_window_is_rejected(client, offset):
    response = post_event(client, timestamp=int(time.time()) + offset)
    assert_error(response, 401, 'timestamp_out_of_window')


def test_missing_producer_secret_fails_closed(client, runtime):
    runtime.settings.secret = None
    assert_error(post_event(client), 503, 'dependency_unavailable')


def test_unbounded_clock_window_fails_closed(client, runtime):
    runtime.settings.webhook_max_clock_skew_seconds = 0
    assert_error(post_event(client), 503, 'dependency_unavailable')


def test_non_producer_principal_is_denied(client, claims):
    claims['azp'] = 'n8n-automation'
    assert_error(post_event(client, producer='n8n-automation'), 403, 'scope_denied')


def test_body_source_must_match_the_authenticated_producer(client):
    body = delivery_event(source='telnexa', channel='sms', origin=None)
    assert_error(post_event(client, body), 403, 'scope_denied')
    assert FakeStore.calls == []


def test_body_tenant_must_match_the_header(client):
    assert_error(post_event(client, delivery_event(tenant_id='OTHER_TENANT')),
                 403, 'tenant_scope_denied')


@pytest.mark.parametrize('headers', [
    {'Idempotency-Key': 'klyrow:evt-other-0001'},
    {'X-Correlation-ID': 'corr-other'},
    {'X-Causation-ID': 'cause-1'},
])
def test_delivery_headers_are_bound_to_the_body(client, headers):
    assert_error(post_event(client, **headers), 400, 'invalid_request')


def test_signed_event_id_must_match_the_body(client):
    raw, headers = signed(delivery_event(), event='evt-mcr-00000002')
    headers['Idempotency-Key'] = 'klyrow:evt-mcr-00000001'
    assert_error(client.post(EVENTS, content=raw, headers=headers), 400, 'invalid_request')


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":NaN}', b'[]'])
def test_ambiguous_or_non_object_json_is_rejected(client, raw):
    response = client.post(EVENTS, content=raw, headers=signed(None, raw=raw)[1])
    assert response.status_code in {400, 422}
    assert FakeStore.calls == []


# --- suppressions ---------------------------------------------------------------


def test_suppression_is_recorded_with_exact_tenant_binding(client):
    response = post_suppression(client)
    assert response.status_code == 201, response.text
    assert response.json()['duplicate'] is False
    (kind, kwargs), = FakeStore.calls
    assert kind == 'suppression'
    assert kwargs == {'tenant_id': TENANT, 'idempotency_key': 'suppress-key-1',
                      'request': suppression(), 'correlation_id': 'corr-test'}


def test_identical_suppression_replay_is_200_duplicate(client):
    FakeStore.suppression_result = {**FakeStore.suppression_result, 'duplicate': True}
    response = post_suppression(client)
    assert response.status_code == 200 and response.json()['duplicate'] is True


def test_idempotency_key_reuse_with_a_different_request_is_409(client):
    FakeStore.suppression_result = CampaignRecyclingIdempotencyConflict('different')
    assert_error(post_suppression(client), 409, 'idempotency_conflict')


def test_suppression_for_unknown_lead_is_404(client):
    FakeStore.suppression_result = CampaignRecyclingNotFound('missing')
    assert_error(post_suppression(client), 404, 'lead_not_found')


def test_suppression_lifecycle_race_is_retryable_409(client):
    FakeStore.suppression_result = CampaignRecyclingLifecycleConflict('race')
    assert assert_error(post_suppression(client), 409, 'lifecycle_version_conflict')['retryable']


@pytest.mark.parametrize('body', [
    suppression(scope='global', channel='email'),
    suppression(scope='global', channel=None, source='klyrow_delivery_event'),
    suppression(scope='campaign', channel=None),
    suppression(tenant_id=TENANT),
    suppression(lead_id='not-a-lead'),
])
def test_suppression_contract_is_strict(client, body):
    assert_error(post_suppression(client, body), 422, 'contract_violation')
    assert FakeStore.calls == []


def test_suppression_requires_the_shared_durable_pool(client, runtime):
    runtime.pool = None
    assert_error(post_suppression(client), 503, 'dependency_unavailable')


def test_invalid_store_ack_is_never_disclosed(client):
    FakeStore.suppression_result = {'suppression_id': 'not-a-uuid', 'duplicate': False,
                                    'scope': 'channel', 'effective_at': NOW.isoformat()}
    assert_error(post_suppression(client), 503, 'dependency_unavailable')


# --- journey ----------------------------------------------------------------------


class _Txn:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class JourneyConn:
    def __init__(self, current, transitions=()):
        self.current, self.transitions, self.queries = current, list(transitions), []

    def transaction(self, **kwargs):
        assert kwargs == {'isolation': 'repeatable_read', 'readonly': True}
        return _Txn()

    async def fetchrow(self, sql, *args):
        self.queries.append((sql, args))
        return self.current

    async def fetch(self, sql, *args):
        self.queries.append((sql, args))
        return self.transitions if 'mcr_lead_lifecycle_events' in sql else []


class JourneyPool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        conn = self.conn

        class Acquire:
            async def __aenter__(self):
                return conn

            async def __aexit__(self, *exc):
                return False
        return Acquire()


def transition(version):
    return {'transition_id': f'00000000-0000-4000-8000-00000000000{version}',
            'tenant_id': TENANT, 'lead_id': LEAD, 'version': version,
            'from_state': None if version == 1 else 'NEW',
            'to_state': 'NEW' if version == 1 else 'VALIDATED',
            'reason_code': 'LEAD_REGISTERED' if version == 1 else 'VALIDATION_PASSED',
            'source': 'leads', 'occurred_at': NOW, 'recorded_at': NOW,
            'correlation_id': 'corr-j', 'evidence_hash': 'a' * 64, 'evidence_ref': None}


def test_journey_requires_the_shared_durable_pool(client, runtime):
    runtime.pool = None
    assert_error(client.get(JOURNEY, headers=HEADERS), 503, 'dependency_unavailable')


def test_unknown_lead_journey_is_404_and_tenant_scoped(client, runtime):
    conn = JourneyConn(None)
    runtime.pool = JourneyPool(conn)
    assert_error(client.get(JOURNEY, headers=HEADERS), 404, 'lead_not_found')
    assert all(args[0] == TENANT for _, args in conn.queries)


def test_journey_cursor_is_bound_to_tenant_lead_and_limit(client, runtime):
    runtime.pool = JourneyPool(JourneyConn({'state': 'VALIDATED', 'version': 2}))
    position = {'v': 2, 't': None, 'e': None}
    for tenant, lead, limit in (('OTHER_TENANT', LEAD, 1), (TENANT, '100-L-00000002', 1),
                                (TENANT, LEAD, 2)):
        cursor = readback.encode_cursor(CURSOR_KEY, tenant, lead, limit, position)
        response = client.get(f'{JOURNEY}?limit=1&cursor={cursor}', headers=HEADERS)
        assert_error(response, 400, 'invalid_cursor')
    forged = readback.encode_cursor('d' * 32, TENANT, LEAD, 1, position)
    assert_error(client.get(f'{JOURNEY}?limit=1&cursor={forged}', headers=HEADERS),
                 400, 'invalid_cursor')


@pytest.mark.parametrize('key', ['', 'short-key', 'x' * 31])
def test_missing_or_weak_cursor_key_fails_closed(client, runtime, key):
    runtime.settings.mcr_cursor_signing_key = key
    conn = JourneyConn({'state': 'VALIDATED', 'version': 2}, [transition(2), transition(1)])
    runtime.pool = JourneyPool(conn)
    cursor = readback.encode_cursor(CURSOR_KEY, TENANT, LEAD, 1, {'v': 3, 't': None, 'e': None})
    response = client.get(f'{JOURNEY}?limit=1&cursor={cursor}', headers=HEADERS)
    assert_error(response, 503, 'dependency_unavailable')
    assert conn.queries == []
    # A page that needs a continuation cursor also cannot be issued unsigned.
    assert_error(client.get(f'{JOURNEY}?limit=1', headers=HEADERS), 503, 'dependency_unavailable')


def test_journey_page_issues_a_verifiable_tenant_bound_cursor(client, runtime):
    runtime.pool = JourneyPool(JourneyConn({'state': 'VALIDATED', 'version': 2},
                                           [transition(2), transition(1)]))
    response = client.get(f'{JOURNEY}?limit=1', headers=HEADERS)
    assert response.status_code == 200, response.text
    body = response.json()
    assert [t['lifecycle_version'] for t in body['transitions']] == [2]
    assert readback.decode_cursor(CURSOR_KEY, TENANT, LEAD, 1, body['next_cursor'])['v'] == 2
    with pytest.raises(api.BoundaryError):
        readback.decode_cursor(CURSOR_KEY, 'OTHER_TENANT', LEAD, 1, body['next_cursor'])


@pytest.mark.parametrize('cursor', ['!!!', 'a' * 501, 'AAAA'])
def test_malformed_cursor_is_invalid(client, runtime, cursor):
    runtime.pool = JourneyPool(JourneyConn({'state': 'VALIDATED', 'version': 2}))
    assert_error(client.get(f'{JOURNEY}?cursor={cursor}', headers=HEADERS), 400, 'invalid_cursor')


@pytest.mark.parametrize('query', ['campaign_version=0', 'campaign_version=x',
                                   'campaign_version=1&campaign_version=2', ''])
def test_referenced_integer_parameters_are_validated(client, query):
    response = client.get(f'/platform/v1/campaigns/klyrow:cmp-a/eligible-leads?{query}',
                          headers=HEADERS)
    assert_error(response, 400, 'invalid_request')


def test_raw_vicidial_campaign_ids_are_rejected(client):
    response = client.get('/platform/v1/campaigns/VICI01/eligible-leads?campaign_version=1',
                          headers=HEADERS)
    assert_error(response, 400, 'invalid_request')


# --- synthetic C6/C7 candidate authority and read/plan runtime ------------------


def test_synthetic_next_action_is_real_dry_run_and_redacts_candidates(client):
    response = client.get(
        f'/platform/v1/leads/{LEAD}/next-action',
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['schema_version'] == '1.0'
    assert body['tenant_id'] == TENANT
    assert body['lead_id'] == LEAD
    assert body['mode'] == 'read'
    assert body['dry_run'] is True
    assert body['provider_effects'] == 'none'
    assert body['eligible'] is True
    assert body['selected']['campaign_id'] == 'klyrow:test-syn-mcr'
    assert body['selected']['campaign_version'] == 1
    assert body['selected']['channel'] == 'email'
    assert body['selected']['exposure_idempotency_key'].startswith('mcr1:')
    assert body['candidates_redacted'] is True
    assert body['candidates'] == []
    assert any(call[0] == 'snapshot' for call in FakeStore.calls)


def test_synthetic_next_action_discloses_candidates_only_with_extra_scope(
    client, claims
):
    claims['scope'] += ' campaign.engine.candidates.read'
    response = client.get(
        f'/platform/v1/leads/{LEAD}/next-action',
        headers=HEADERS,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body['candidates_redacted'] is False
    assert len(body['candidates']) == 1
    assert body['candidates'][0]['campaign_id'] == 'klyrow:test-syn-mcr'


def test_synthetic_plan_returns_deterministic_zero_effect_decision(client):
    payload = {
        'schema_version': '1.0',
        'lead_ids': [LEAD],
        'campaign_scope': {
            'campaign_id': 'klyrow:test-syn-mcr',
            'campaign_version': 1,
        },
        'channels': ['email'],
        'policy_version': 'mcr-policy-1.0.0',
    }
    first = client.post(
        '/platform/v1/campaign-engine/plan',
        headers={**HEADERS, 'Content-Type': 'application/json'},
        json=payload,
    )
    second = client.post(
        '/platform/v1/campaign-engine/plan',
        headers={**HEADERS, 'Content-Type': 'application/json'},
        json=payload,
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    a, b = first.json(), second.json()
    assert a['dry_run'] is True and a['provider_effects'] == 'none'
    assert a['policy_version'] == 'mcr-policy-1.0.0'
    assert len(a['decisions']) == 1
    assert a['decisions'][0]['eligible'] is True
    assert a['plan_hash'] == b['plan_hash']
    assert a['plan_id'] == b['plan_id']
    assert a['decisions'][0]['decision_hash'] == b['decisions'][0]['decision_hash']


def test_synthetic_plan_raw_campaign_id_is_rejected_at_contract_boundary(client):
    payload = {
        'schema_version': '1.0',
        'lead_ids': [LEAD],
        'campaign_scope': {'campaign_id': 'TEST_SYN', 'campaign_version': 1},
    }
    response = client.post(
        '/platform/v1/campaign-engine/plan',
        headers={**HEADERS, 'Content-Type': 'application/json'},
        json=payload,
    )
    assert_error(response, 422, 'contract_violation')
    assert not any(call[0] == 'snapshot' for call in FakeStore.calls)


def test_synthetic_eligible_leads_is_bounded_and_cursor_is_query_bound(client):
    path = (
        '/platform/v1/campaigns/klyrow:test-syn-mcr/eligible-leads'
        '?campaign_version=1&limit=1'
    )
    first = client.get(path, headers=HEADERS)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body['dry_run'] is True and body['provider_effects'] == 'none'
    assert len(body['items']) == 1
    assert body['items'][0]['lead_id'] == '100-L-00000001'
    assert body['next_cursor']

    second = client.get(
        path + '&cursor=' + body['next_cursor'],
        headers=HEADERS,
    )
    assert second.status_code == 200, second.text
    assert second.json()['items'][0]['lead_id'] == '100-L-00000002'
    assert second.json()['next_cursor'] is None

    wrong_query = client.get(
        (
            '/platform/v1/campaigns/klyrow:test-syn-mcr/eligible-leads'
            '?campaign_version=1&limit=2&cursor=' + body['next_cursor']
        ),
        headers=HEADERS,
    )
    assert_error(wrong_query, 400, 'invalid_cursor')


def test_synthetic_eligible_leads_version_mismatch_is_not_found(client):
    response = client.get(
        '/platform/v1/campaigns/klyrow:test-syn-mcr/eligible-leads?campaign_version=2',
        headers=HEADERS,
    )
    assert_error(response, 404, 'campaign_not_found')


def test_non_synthetic_tenant_remains_fail_closed(client, monkeypatch):
    monkeypatch.setattr(
        api,
        'validate_token',
        lambda token: {
            'aud': 'middleware-api',
            'tenant_id': 'PROD_TENANT',
            'azp': 'klyrow-gateway',
            'scope': 'campaign.engine.read campaign.engine.plan',
        },
    )
    headers = {
        'Authorization': 'Bearer test',
        'X-Tenant-ID': 'PROD_TENANT',
        'X-Correlation-ID': 'corr-prod',
    }
    response = client.get(
        '/platform/v1/leads/100-L-00000001/next-action',
        headers=headers,
    )
    assert_error(response, 503, 'policy_not_configured')


def test_execute_stays_hard_denied_after_synthetic_read_activation(client):
    payload = {
        'schema_version': '1.0',
        'plan_id': '00000000-0000-4000-8000-000000000010',
        'plan_hash': 'a' * 64,
    }
    response = client.post(
        '/platform/v1/campaign-engine/execute',
        headers={
            **HEADERS,
            'Content-Type': 'application/json',
            'Idempotency-Key': 'execute-key-1',
        },
        json=payload,
    )
    assert_error(response, 403, 'production_not_authorized')
    assert not any(call[0] == 'delivery' for call in FakeStore.calls)
