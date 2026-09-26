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
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid4, uuid5

import asyncpg
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from app.core.campaign_recycling import (
    HEALTH_EVENT_STATE, CampaignRecyclingConflict, CampaignRecyclingError,
    CampaignRecyclingIdempotencyConflict,
    CampaignRecyclingEngine, CampaignRecyclingLifecycleConflict,
    CampaignRecyclingNotFound, PolicyProfile, PostgresCampaignRecyclingStore,
    canonical_digest, delivery_event_payload_hash, next_action_document,
)
from app.core.campaign_recycling_candidates import (
    CandidateAuthorityNotFound, CandidateCursorError,
    candidate_authority_for_tenant, decode_candidate_cursor,
    encode_candidate_cursor,
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


def _policy_for_tenant(tenant_id: str) -> PolicyProfile:
    # Only the frozen synthetic tenant may use the configured test profile.
    return PolicyProfile.load('test' if tenant_id == 'TEST_SYN_TENANT' else 'production')


def _has_scope(claims: dict, scope: str) -> bool:
    value = claims.get('scope', '')
    return isinstance(value, str) and scope in value.split()


async def _evaluate_lead(
    request: Request,
    *,
    tenant_id: str,
    lead_id: str,
    policy: PolicyProfile,
    mode: str,
    campaign_id: str | None = None,
    campaign_version: int | None = None,
    channels: list[str] | tuple[str, ...] | None = None,
):
    authority = candidate_authority_for_tenant(tenant_id)
    if authority is None:
        fail(503, 'dependency_unavailable')
    candidates, address_refs = authority.candidates_for_lead(
        tenant_id=tenant_id,
        lead_id=lead_id,
        campaign_id=campaign_id,
        campaign_version=campaign_version,
        channels=channels,
    )
    store = _store(request)
    try:
        snapshot = await store.load_snapshot(
            tenant_id=tenant_id,
            lead_id=lead_id,
            address_refs=address_refs,
            policy=policy,
        )
    except CampaignRecyclingNotFound:
        raise
    except CampaignRecyclingConflict:
        fail(503, 'dependency_unavailable')
    decision = CampaignRecyclingEngine(policy).evaluate(
        snapshot,
        candidates,
        mode=mode,
        now=datetime.now(UTC),
    )
    return snapshot, decision


async def _plan(request: Request, params: dict, claims: dict, body: dict, policy: PolicyProfile):
    scope = body.get('campaign_scope') or {}
    campaign_id = scope.get('campaign_id')
    campaign_version = scope.get('campaign_version')
    channels = body.get('channels')
    generated_at = datetime.now(UTC)
    decisions = []
    for lead_id in body['lead_ids']:
        try:
            snapshot, decision = await _evaluate_lead(
                request,
                tenant_id=params['X-Tenant-ID'],
                lead_id=lead_id,
                policy=policy,
                mode='plan',
                campaign_id=campaign_id,
                campaign_version=campaign_version,
                channels=channels,
            )
        except CampaignRecyclingNotFound:
            # Plan has no 404 contract. Missing durable lead state is a dependency
            # failure, never an invented NO_CANDIDATE success.
            fail(503, 'dependency_unavailable')
        decisions.append(
            next_action_document(
                decision,
                snapshot,
                mode='plan',
                evaluated_at=generated_at,
                correlation_id=params['X-Correlation-ID'],
                candidates_redacted=not _has_scope(
                    claims, 'campaign.engine.candidates.read'
                ),
            )
        )
    plan_hash = canonical_digest({
        'tenant_id': params['X-Tenant-ID'],
        'policy_version': policy.policy_version,
        'campaign_scope': scope or None,
        'channels': channels or None,
        'decision_hashes': [item['decision_hash'] for item in decisions],
    })
    return 200, {
        'schema_version': '1.0',
        'plan_id': str(uuid5(NAMESPACE_URL, f'mcr:plan:{plan_hash}')),
        'plan_hash': plan_hash,
        'policy_version': policy.policy_version,
        'dry_run': True,
        'provider_effects': 'none',
        'generated_at': generated_at.isoformat(),
        'expires_at': (generated_at + timedelta(minutes=5)).isoformat(),
        'decisions': decisions,
    }


async def _next_action(request: Request, params: dict, claims: dict, policy: PolicyProfile):
    channels = [params['channel']] if 'channel' in params else None
    try:
        snapshot, decision = await _evaluate_lead(
            request,
            tenant_id=params['X-Tenant-ID'],
            lead_id=params['lead_id'],
            policy=policy,
            mode='read',
            channels=channels,
        )
    except CampaignRecyclingNotFound:
        fail(404, 'lead_not_found')
    return 200, next_action_document(
        decision,
        snapshot,
        mode='read',
        evaluated_at=datetime.now(UTC),
        correlation_id=params['X-Correlation-ID'],
        candidates_redacted=not _has_scope(claims, 'campaign.engine.candidates.read'),
    )


async def _eligible_leads(request: Request, params: dict, policy: PolicyProfile):
    tenant_id = params['X-Tenant-ID']
    authority = candidate_authority_for_tenant(tenant_id)
    if authority is None:
        fail(503, 'dependency_unavailable')
    try:
        members = authority.campaign_members(
            tenant_id=tenant_id,
            campaign_id=params['campaign_id'],
            campaign_version=params['campaign_version'],
            channel=params.get('channel'),
        )
    except CandidateAuthorityNotFound:
        fail(404, 'campaign_not_found')
    limit = params.get('limit', 100)
    runtime = getattr(request.app.state, 'runtime', None)
    config = getattr(runtime, 'settings', None)
    key = getattr(config, 'mcr_cursor_signing_key', '') if config is not None else ''
    try:
        offset = decode_candidate_cursor(
            key,
            params['cursor'],
            tenant_id=tenant_id,
            campaign_id=params['campaign_id'],
            campaign_version=params['campaign_version'],
            channel=params.get('channel'),
            limit=limit,
        ) if 'cursor' in params else 0
    except CandidateCursorError:
        fail(400, 'invalid_cursor')
    page = members[offset:offset + limit]
    items = []
    for membership in page:
        try:
            snapshot, decision = await _evaluate_lead(
                request,
                tenant_id=tenant_id,
                lead_id=membership.lead_id,
                policy=policy,
                mode='read',
                campaign_id=params['campaign_id'],
                campaign_version=params['campaign_version'],
                channels=[params['channel']] if 'channel' in params else None,
            )
        except CampaignRecyclingNotFound:
            fail(503, 'dependency_unavailable')
        if not decision.eligible or decision.selected is None:
            continue
        document = next_action_document(
            decision,
            snapshot,
            mode='read',
            evaluated_at=datetime.now(UTC),
            correlation_id=params['X-Correlation-ID'],
            candidates_redacted=True,
        )
        items.append({
            'lead_id': membership.lead_id,
            'channel': decision.selected.channel,
            'decision_id': document['decision_id'],
            'touch_index': decision.selected.touch_index,
            'exposure_idempotency_key': document['selected']['exposure_idempotency_key'],
        })
    next_cursor = None
    if offset + len(page) < len(members):
        try:
            next_cursor = encode_candidate_cursor(
                key,
                tenant_id=tenant_id,
                campaign_id=params['campaign_id'],
                campaign_version=params['campaign_version'],
                channel=params.get('channel'),
                limit=limit,
                offset=offset + len(page),
            )
        except CandidateCursorError:
            fail(503, 'dependency_unavailable')
    return 200, {
        'schema_version': '1.0',
        'campaign_id': params['campaign_id'],
        'campaign_version': params['campaign_version'],
        'policy_version': policy.policy_version,
        'dry_run': True,
        'provider_effects': 'none',
        'items': items,
        'next_cursor': next_cursor,
    }


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
    if operation_id == 'campaign_engine_status':
        policy = PolicyProfile.load('production')
        return 200, {'schema_version': '1.0', 'runtime_status': 'contract_only',
            'engine_enabled': False, 'execute_enabled': False, 'production_authorized': False,
            'policy_version': policy.policy_version, 'policy_configured': policy.configured,
            'capabilities': dict.fromkeys(('EMAIL_DELIVERY','SMS_DELIVERY','WHATSAPP_DELIVERY','PRODUCTION_DIALING'), False)}

    policy = (
        _policy_for_tenant(params['X-Tenant-ID'])
        if operation_id in {
            'campaign_engine_plan', 'lead_next_action_read',
            'campaign_eligible_leads_read'
        }
        else PolicyProfile.load('production')
    )
    if operation_id == 'campaign_engine_execute':
        # C8 remains fail-closed until a separately approved production gate.
        fail(403, 'production_not_authorized')
    if body and body.get('policy_version') not in (None, policy.policy_version):
        fail(409, 'policy_version_mismatch')
    if operation_id in {
        'campaign_engine_plan', 'lead_next_action_read', 'campaign_eligible_leads_read'
    } and not policy.configured:
        fail(503, 'policy_not_configured')
    if operation_id == 'campaign_engine_plan':
        return await _plan(request, params, claims, body, policy)
    if operation_id == 'lead_next_action_read':
        return await _next_action(request, params, claims, policy)
    if operation_id == 'campaign_eligible_leads_read':
        return await _eligible_leads(request, params, policy)
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


router.add_api_route(
    "/platform/v1/campaign-engine/plan",
    _handler(API["paths"]["/platform/v1/campaign-engine/plan"]["post"]),
    methods=["POST"],
    operation_id=API["paths"]["/platform/v1/campaign-engine/plan"]["post"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract("/platform/v1/campaign-engine/plan", "post"),
)
router.add_api_route(
    "/platform/v1/campaign-engine/execute",
    _handler(API["paths"]["/platform/v1/campaign-engine/execute"]["post"]),
    methods=["POST"],
    operation_id=API["paths"]["/platform/v1/campaign-engine/execute"]["post"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract("/platform/v1/campaign-engine/execute", "post"),
)
router.add_api_route(
    "/platform/v1/leads/{lead_id}/journey",
    _handler(API["paths"]["/platform/v1/leads/{lead_id}/journey"]["get"]),
    methods=["GET"],
    operation_id=API["paths"]["/platform/v1/leads/{lead_id}/journey"]["get"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract("/platform/v1/leads/{lead_id}/journey", "get"),
)
router.add_api_route(
    "/platform/v1/leads/{lead_id}/next-action",
    _handler(API["paths"]["/platform/v1/leads/{lead_id}/next-action"]["get"]),
    methods=["GET"],
    operation_id=API["paths"]["/platform/v1/leads/{lead_id}/next-action"]["get"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract("/platform/v1/leads/{lead_id}/next-action", "get"),
)
router.add_api_route(
    "/platform/v1/campaigns/{campaign_id}/eligible-leads",
    _handler(API["paths"]["/platform/v1/campaigns/{campaign_id}/eligible-leads"]["get"]),
    methods=["GET"],
    operation_id=API["paths"]["/platform/v1/campaigns/{campaign_id}/eligible-leads"]["get"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract(
        "/platform/v1/campaigns/{campaign_id}/eligible-leads", "get"
    ),
)
router.add_api_route(
    "/platform/v1/delivery-events",
    _handler(API["paths"]["/platform/v1/delivery-events"]["post"]),
    methods=["POST"],
    operation_id=API["paths"]["/platform/v1/delivery-events"]["post"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract("/platform/v1/delivery-events", "post"),
)
router.add_api_route(
    "/platform/v1/suppressions",
    _handler(API["paths"]["/platform/v1/suppressions"]["post"]),
    methods=["POST"],
    operation_id=API["paths"]["/platform/v1/suppressions"]["post"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract("/platform/v1/suppressions", "post"),
)
router.add_api_route(
    "/platform/v1/campaign-engine/status",
    _handler(API["paths"]["/platform/v1/campaign-engine/status"]["get"]),
    methods=["GET"],
    operation_id=API["paths"]["/platform/v1/campaign-engine/status"]["get"]["operationId"],
    response_model=None,
    openapi_extra=operation_contract("/platform/v1/campaign-engine/status", "get"),
)
