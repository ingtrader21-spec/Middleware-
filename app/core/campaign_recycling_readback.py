"""Tenant-bound journey projection over the 0068 tables; no writes or caches."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime
from uuid import UUID

from fastapi.encoders import jsonable_encoder

from app.core.campaign_recycling_contract import DOCUMENTS, BASE


def _fail(status, code):
    from app.api.v1.campaign_recycling import fail
    fail(status, code)


def _binding(tenant, lead, limit):
    return hashlib.sha256(json.dumps([tenant, lead, limit], separators=(',', ':')).encode()).hexdigest()


def encode_cursor(key: str, tenant: str, lead: str, limit: int, position: dict) -> str:
    if len(key.encode()) < 32:
        _fail(503, 'dependency_unavailable')
    body = json.dumps({'q': _binding(tenant, lead, limit), **position}, separators=(',', ':')).encode()
    mac = hmac.new(key.encode(), b'mcr-journey-v1\0' + body, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(body + mac).decode().rstrip('=')


def decode_cursor(key: str, tenant: str, lead: str, limit: int, cursor: str) -> dict:
    if len(key.encode()) < 32:
        _fail(503, 'dependency_unavailable')
    try:
        raw = base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True)
        body, supplied = raw[:-32], raw[-32:]
        expected = hmac.new(key.encode(), b'mcr-journey-v1\0' + body, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, supplied):
            raise ValueError()
        result = json.loads(body)
        if result.pop('q') != _binding(tenant, lead, limit):
            raise ValueError()
        if set(result) != {'v', 't', 'e'} or type(result['v']) is not int or result['v'] < 0:
            raise ValueError()
        if (result['t'] is None) != (result['e'] is None):
            raise ValueError()
        if result['t'] is not None:
            datetime.fromisoformat(result['t'])
            UUID(result['e'])
        return result
    except (ValueError, KeyError, TypeError):
        _fail(400, 'invalid_cursor')


async def journey(request, params):
    runtime = getattr(request.app.state, 'runtime', None)
    pool = getattr(runtime, 'pool', None)
    if pool is None:
        _fail(503, 'dependency_unavailable')
    tenant, lead = params['X-Tenant-ID'], params['lead_id']
    limit = params.get('limit', 100)
    config = getattr(runtime, 'settings', None)
    key = getattr(config, 'mcr_cursor_signing_key', '')
    position = decode_cursor(key, tenant, lead, limit, params['cursor']) if 'cursor' in params else {'v': 9223372036854775807, 't': None, 'e': None}
    async with pool.acquire() as conn:
        async with conn.transaction(isolation='repeatable_read', readonly=True):
            current = await conn.fetchrow('SELECT state,version FROM mcr_lead_lifecycle_current WHERE tenant_id=$1 AND lead_id=$2', tenant, lead)
            if current is None:
                _fail(404, 'lead_not_found')
            transitions = await conn.fetch('''SELECT * FROM mcr_lead_lifecycle_events
                WHERE tenant_id=$1 AND lead_id=$2 AND version < $3
                ORDER BY version DESC LIMIT $4''', tenant, lead, position['v'], limit + 1)
            exposures = await conn.fetch('''SELECT * FROM mcr_exposures
                WHERE tenant_id=$1 AND lead_id=$2
                AND ($3::timestamptz IS NULL OR (reserved_at,exposure_id) < ($3,$4::uuid))
                ORDER BY reserved_at DESC,exposure_id DESC LIMIT $5''', tenant, lead,
                datetime.fromisoformat(position['t']) if position['t'] else None,
                UUID(position['e']) if position['e'] else None, limit + 1)
            health = await conn.fetch('''SELECT * FROM mcr_channel_health
                WHERE tenant_id=$1 AND lead_id=$2 ORDER BY channel,address_ref''', tenant, lead)
            suppressions = await conn.fetch('''SELECT * FROM mcr_suppressions
                WHERE tenant_id=$1 AND lead_id=$2 ORDER BY occurred_at DESC,suppression_id''', tenant, lead)
    more = len(transitions) > limit or len(exposures) > limit
    transitions, exposures = transitions[:limit], exposures[:limit]
    next_cursor = None
    if more:
        next_cursor = encode_cursor(key, tenant, lead, limit, {
            'v': transitions[-1]['version'] if transitions else position['v'],
            't': exposures[-1]['reserved_at'].isoformat() if exposures else position['t'],
            'e': str(exposures[-1]['exposure_id']) if exposures else position['e'],
        })
    def project(row, name):
        keys = DOCUMENTS[BASE + name + '.v1.schema.json']['properties']
        return {'schema_version':'1.0', **{k:v for k,v in dict(row).items() if k in keys}}
    lifecycle = [project({**dict(row), 'lifecycle_version': row['version']}, 'lifecycle') for row in transitions]
    health_documents = []
    for row in health:
        document = project(row, 'channel-health')
        source = row['source']
        kinds = {'lead_validation':'validation_result', 'dialing_eligibility':'dialing_state',
                 'operator':'operator_change', 'data_subject_request':'data_subject_request',
                 'whatsapp_consent':'consent_proof'}
        kind = kinds.get(source)
        if kind is None and ('delivery_event' in source or source.startswith('inbound_')):
            kind = 'delivery_event'
        if kind is None:
            # 0068 did not persist evidence.kind. Never invent missing provenance.
            _fail(503, 'dependency_unavailable')
        document.update(evidence={'kind':kind, 'evidence_hash':row['evidence_hash']},
                        suppression=None, cross_channel_effect='none')
        if row['state'] in {'complained','unsubscribed','suppressed'}:
            reason = {'complained':'complaint', 'unsubscribed':'unsubscribe'}.get(row['state'])
            suppression = next((s for s in suppressions if
                s['scope'] in {'global','channel'} and
                (s['scope'] == 'global' or s['channel'] == row['channel']) and
                (reason is None or s['reason'] == reason)), None)
            if suppression is None:
                _fail(503, 'dependency_unavailable')
            document['suppression'] = {k:suppression[k] for k in ('suppression_id','scope','reason','occurred_at','campaign_id')}
        health_documents.append(document)
    return jsonable_encoder({'schema_version':'1.0', 'lead_id':lead,
        'lifecycle_state':current['state'], 'lifecycle_version':current['version'],
        'transitions':lifecycle, 'channel_health':health_documents,
        'exposures':[project(row, 'exposure-ledger') for row in exposures], 'next_cursor':next_cursor})
