"""MCR-A HTTP boundary. Registration is not execution authorization.

The frozen contract is the schema authority; the existing core is the policy
and persistence authority. Unavailable dependencies never become empty success.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from uuid import uuid4

import asyncpg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from app.core.campaign_recycling import (
    HEALTH_EVENT_STATE, CampaignRecyclingConflict, CampaignRecyclingError,
    CampaignRecyclingIdempotencyConflict,
    CampaignRecyclingLifecycleConflict, CampaignRecyclingNotFound, PolicyProfile,
    PostgresCampaignRecyclingStore, delivery_event_payload_hash,
)
from app.core.campaign_recycling_contract import (
    API, DeliveryEvent, ExecuteRequest, PlanRequest, SuppressionRequest,
    expand, operation_contract, validator,
)
from app.core.config import settings
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs
from app.security import AuthorizationError, authorize_tenant

LOGGER = logging.getLogger(__name__)
router = APIRouter()
OPERATION_SCOPES = {
    operation['operationId']: operation['security'][0]['codestraOAuth'][0]
    for path in API['paths'].values() for operation in path.values()
}
MODELS = {'campaign_engine_plan': PlanRequest, 'campaign_engine_execute': ExecuteRequest,
          'delivery_event_ingest': DeliveryEvent, 'suppression_record': SuppressionRequest}
# Credential selection is bound to the verified principal, never body input.
PRODUCER_SOURCES = {'klyrow-gateway': 'klyrow', 'telnexa-gateway': 'telnexa',
                    'vicidial-adapter': 'vicidial', 'odoo-integration': 'odoo'}


class BoundaryError(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code


def validate_token(token: str) -> dict:
    kwargs = identity_validator_kwargs(settings.identity)
    kwargs['audience'] = 'middleware-api'
    return KeycloakValidator(**kwargs).validate(token)


def fail(status: int, code: str):
    raise BoundaryError(status, code)


def _store(request: Request) -> PostgresCampaignRecyclingStore:
    pool = getattr(getattr(request.app.state, 'runtime', None), 'pool', None)
    if pool is None:
        fail(503, 'dependency_unavailable')
    return PostgresCampaignRecyclingStore(pool)


async def _ingest_delivery_event(request: Request, body: dict, policy: PolicyProfile):
    if body['event_type'] in HEALTH_EVENT_STATE:
        # Channel-health effects need a certified opaque address_ref, which the
        # frozen normalized contract does not carry. Never synthesize one.
        fail(503, 'dependency_unavailable')
    store = _store(request)
    try:
        result = await store.apply_delivery_event(body, policy=policy)
    except CampaignRecyclingLifecycleConflict:
        fail(409, 'lifecycle_version_conflict')
    except CampaignRecyclingConflict:
        # Identity/digest reuse and exposure evidence mismatches roll back.
        fail(409, 'replay_conflict')
    return 202, {'accepted': True, 'duplicate': result['duplicate'],
                 'source': body['source'], 'event_id': body['event_id']}


async def _record_suppression(request: Request, params: dict, body: dict):
    store = _store(request)
    try:
        result = await store.record_suppression_request(
            tenant_id=params['X-Tenant-ID'], idempotency_key=params['Idempotency-Key'],
            request=body, correlation_id=params['X-Correlation-ID'])
    except CampaignRecyclingNotFound:
        fail(404, 'lead_not_found')
    except CampaignRecyclingIdempotencyConflict:
        fail(409, 'idempotency_conflict')
    except CampaignRecyclingLifecycleConflict:
        fail(409, 'lifecycle_version_conflict')
    except CampaignRecyclingConflict:
        fail(422, 'contract_violation')
    return (200 if result['duplicate'] else 201), result


def _validate_parameters(request: Request, operation: dict) -> dict:
    values = {}
    for reference in operation['parameters']:
        parameter = API['components']['parameters'][reference['$ref'].rsplit('/', 1)[-1]]
        name, location = parameter['name'], parameter['in']
        source = {'header': request.headers, 'path': request.path_params,
                  'query': request.query_params}[location]
        raw = source.get(name)
        if hasattr(source, 'getlist') and len(source.getlist(name)) > 1:
            fail(400, 'invalid_request')
        if raw is None:
            if parameter.get('required'):
                fail(400, 'invalid_request')
            continue
        value = raw
        # Resolve $ref first: CampaignVersion is an integer only after expansion.
        schema = expand(parameter['schema'])
        if schema.get('type') == 'integer':
            if not raw.isascii() or not raw.isdecimal():
                fail(400, 'invalid_request')
            value = int(raw)
        if not Draft202012Validator(schema).is_valid(value):
            fail(400, 'invalid_cursor' if name == 'cursor' else 'invalid_request')
        if location == 'header' and (not raw.strip() or any(ord(c) < 32 or ord(c) == 127 for c in raw)):
            fail(400, 'invalid_request')
        values[name] = value
    return values


def _authenticate(request: Request, operation: dict, tenant: str) -> dict:
    auth = request.headers.get('authorization', '')
    scheme, _, token = auth.partition(' ')
    if scheme.lower() != 'bearer' or not token.strip():
        fail(401, 'authentication_required')
    try:
        claims = validate_token(token.strip())
    except JWTAuthError:
        fail(401, 'authentication_required')
    audience = claims.get('aud')
    if audience != 'middleware-api' and not (isinstance(audience, list) and 'middleware-api' in audience):
        fail(401, 'authentication_required')
    scopes = claims.get('scope', '')
    if not isinstance(scopes, str) or OPERATION_SCOPES[operation['operationId']] not in scopes.split():
        fail(403, 'scope_denied')
    try:
        authorize_tenant(claims, tenant)
    except AuthorizationError:
        fail(403, 'tenant_scope_denied')
    return claims


def _verify_signature(request: Request, raw: bytes, params: dict, claims: dict):
    runtime = getattr(request.app.state, 'runtime', None)
    config = getattr(runtime, 'settings', None)
    producer = claims.get('azp')
    if producer not in PRODUCER_SOURCES:
        fail(403, 'scope_denied')
    if config is None:
        fail(503, 'dependency_unavailable')
    try:
        secret = config.webhook_secret(producer)
    except (ValueError, RuntimeError):
        fail(503, 'dependency_unavailable')
    window = config.webhook_max_clock_skew_seconds
    if not isinstance(window, int) or not 0 < window <= 3600:
        fail(503, 'dependency_unavailable')
    if abs(time.time() - int(params['X-Codestra-Timestamp'])) > window:
        fail(401, 'timestamp_out_of_window')
    canonical = '\n'.join(('v1', 'POST', request.url.path,
        params['X-Codestra-Timestamp'], params['X-Codestra-Event-ID'], producer,
        hashlib.sha256(raw).hexdigest())).encode()
    expected = 'v1=' + hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, params['X-Codestra-Signature']):
        fail(401, 'signature_invalid')


def _json(raw: bytes):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        fail(400, 'invalid_request')


async def dispatch(request: Request, operation: dict, params: dict, claims: dict, body: dict | None):
    operation_id = operation['operationId']
    policy = PolicyProfile.load('production')
    if operation_id == 'campaign_engine_status':
        return 200, {'schema_version': '1.0', 'runtime_status': 'contract_only',
            'engine_enabled': False, 'execute_enabled': False, 'production_authorized': False,
            'policy_version': policy.policy_version, 'policy_configured': policy.configured,
            'capabilities': dict.fromkeys(('EMAIL_DELIVERY','SMS_DELIVERY','WHATSAPP_DELIVERY','PRODUCTION_DIALING'), False)}
    if operation_id == 'campaign_engine_execute':
        # Even unrelated provider capability flags cannot activate this boundary.
        fail(403, 'production_not_authorized')
    if operation_id in {'campaign_engine_plan', 'lead_next_action_read', 'campaign_eligible_leads_read'}:
        if body and body.get('policy_version') not in (None, policy.policy_version):
            fail(409, 'policy_version_mismatch')
        if not policy.configured:
            fail(503, 'policy_not_configured')
        # There is no certified tenant-bound campaign/version/audience readback
        # in RuntimeContainer. Do not infer candidates from the VICIdial registry.
        fail(503, 'dependency_unavailable')
    if operation_id == 'lead_journey_read':
        from app.core.campaign_recycling_readback import journey
        return 200, await journey(request, params)
    if operation_id == 'delivery_event_ingest':
        return await _ingest_delivery_event(request, body, policy)
    if operation_id == 'suppression_record':
        return await _record_suppression(request, params, body)
    fail(503, 'dependency_unavailable')


def _handler(operation: dict):
    async def handle(request: Request):
        supplied = request.headers.get('X-Correlation-ID', '')
        correlation = supplied if 0 < len(supplied) <= 180 and all(32 <= ord(c) < 127 for c in supplied) else str(uuid4())
        request.state.correlation_id = correlation
        code = 'ok'
        try:
            params = _validate_parameters(request, operation)
            claims = _authenticate(request, operation, params['X-Tenant-ID'])
            body = None
            model = MODELS.get(operation['operationId'])
            if model is not None:
                if request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                    fail(400, 'invalid_request')
                raw = await request.body()
                if len(raw) > 1048576:
                    fail(400, 'invalid_request')
                if model is DeliveryEvent:
                    _verify_signature(request, raw, params, claims)
                value = _json(raw)
                if isinstance(value, dict) and value.get('schema_version', '1.0') != '1.0':
                    fail(422, 'unsupported_schema_version')
                try:
                    body = model.model_validate(value).root
                except ValidationError:
                    fail(422, 'contract_violation')
                if model is DeliveryEvent:
                    if body['tenant_id'] != params['X-Tenant-ID']:
                        fail(403, 'tenant_scope_denied')
                    if body['source'] != PRODUCER_SOURCES[claims['azp']]:
                        fail(403, 'scope_denied')
                    if (body['event_id'] != params['X-Codestra-Event-ID'] or
                        params['Idempotency-Key'] != body['source'] + ':' + body['event_id'] or
                        body['correlation_id'] != params['X-Correlation-ID'] or
                        body['causation_id'] != params.get('X-Causation-ID')):
                        fail(400, 'invalid_request')
                    if not hmac.compare_digest(body['payload_hash'], delivery_event_payload_hash(body)):
                        fail(422, 'contract_violation')
            status, payload = await dispatch(request, operation, params, claims, body)
            response = operation['responses'][str(status)]['content']['application/json']['schema']['$ref']
            if not validator(response).is_valid(payload):
                fail(503, 'dependency_unavailable')
        except BoundaryError as exc:
            status, code = exc.status, exc.code
            payload = {'error': {'code': code, 'message': code.replace('_', ' '),
                'correlation_id': correlation,
                'retryable': status == 503 or code == 'lifecycle_version_conflict', 'details': {}}}
        except (asyncpg.PostgresError, CampaignRecyclingError, OSError, TimeoutError):
            status, code = 503, 'dependency_unavailable'
            payload = {'error': {'code': code, 'message': 'required durable dependency unavailable',
                'correlation_id': correlation, 'retryable': True, 'details': {}}}
        # Hash caller-controlled correlation text; never log bodies, paths, IDs,
        # bearer tokens, signatures, addresses, or arbitrary exception messages.
        LOGGER.info('mcr_request operation=%s status=%s code=%s correlation_sha256=%s',
            operation['operationId'], status, code, hashlib.sha256(correlation.encode()).hexdigest())
        return JSONResponse(payload, status_code=status, headers={'X-Correlation-ID': correlation})
    return handle


for _path, _methods in API['paths'].items():
    for _method, _operation in _methods.items():
        router.add_api_route(_path, _handler(_operation), methods=[_method.upper()],
            operation_id=_operation['operationId'], response_model=None,
            openapi_extra=operation_contract(_path, _method))
