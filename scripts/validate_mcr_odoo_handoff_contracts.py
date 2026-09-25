#!/usr/bin/env python3
"""Offline MCR-E contract verifier, never a runtime or a token verifier.

All decisions below are pure conformance checks over supplied fixtures. They
perform no HTTP, SQL, queue, authentication, or provider operation. Production
admission must use verified server-side context and a durable command kernel;
this module must not be imported by runtime routes or workers.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'contracts/campaign-recycling'
BASE = 'https://contracts.codestra.co/campaign-recycling/'
SCHEMAS = ('odoo-handoff-command.v1.schema.json', 'odoo-handoff-readback.v1.schema.json')
NATURAL = ('tenant_id', 'lead_id', 'campaign_id', 'campaign_version',
           'lifecycle_version', 'policy_version', 'handoff')
READBACK = (*NATURAL, 'command_id', 'correlation_id', 'idempotency_key', 'payload_hash')


def digest(value: Any) -> str:
    """Same sorted, compact, Unicode JSON convention as lead_automation.canonical_hash."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def load(name: str) -> dict[str, Any]:
    return json.loads((DIRECTORY / name).read_text())


def validator(name: str) -> Draft202012Validator:
    # Explicit local registry: an unresolved reference fails, never fetches a URL.
    registry = Registry()
    paths = [DIRECTORY / n for n in SCHEMAS]
    paths += [DIRECTORY / 'lifecycle.v1.schema.json',
              ROOT / 'contracts/platform/command-envelope.v1.schema.json']
    for path in paths:
        document = json.loads(path.read_text())
        registry = registry.with_resource(document['$id'], Resource.from_contents(document))
    return Draft202012Validator(load(name), registry=registry, format_checker=FormatChecker())


def flattened(command: dict[str, Any]) -> dict[str, Any]:
    return {**command['payload'], **{k: v for k, v in command.items() if k != 'payload'}}


def idempotency_key(command: dict[str, Any]) -> str:
    values = flattened(command)
    return 'mcrodoo1:' + digest({key: values[key] for key in NATURAL})


def command_errors(command: Any) -> list[str]:
    errors = [error.message for error in validator(SCHEMAS[0]).iter_errors(command)]
    if not errors and command['idempotency_key'] != idempotency_key(command):
        errors.append('idempotency_key_mismatch')
    return errors


def replay_decision(original: dict[str, Any], candidate: dict[str, Any]) -> str:
    if command_errors(original) or command_errors(candidate):
        return 'invalid_contract'
    if original['tenant_id'] != candidate['tenant_id']:
        return 'tenant_conflict'
    if original['idempotency_key'] != candidate['idempotency_key']:
        return 'distinct_handoff'
    # Retry request IDs may differ, but a replay returns the original command ID.
    # Correlation and authenticated requested_by remain immutable for auditability.
    before = {k: v for k, v in original.items() if k != 'command_id'}
    after = {k: v for k, v in candidate.items() if k != 'command_id'}
    return 'duplicate' if before == after else 'idempotency_conflict'


def reconcile(command: dict[str, Any], receipt: Any) -> str:
    if command_errors(command) or list(validator(SCHEMAS[1]).iter_errors(receipt)):
        return 'reconciliation_required'
    expected = {**flattened(command), 'payload_hash': digest(command['payload'])}
    if any(receipt[key] != expected[key] for key in READBACK):
        return 'reconciliation_required'
    if receipt['status'] == 'applied':
        if receipt['observed_lifecycle_version'] != expected['lifecycle_version']:
            return 'reconciliation_required'
        return 'completed'
    if receipt['status'] == 'accepted':
        return 'readback_pending'
    if receipt['status'] == 'rejected':
        return 'dead_lettered'
    return 'reconciliation_required'


def admission(command: Any, *, verified: bool, tenant: str, scopes: list[str]) -> str:
    """Model trust decisions; verified is a test fixture, NEVER request-body auth."""
    if verified is not True:
        return 'unauthorized'
    if command_errors(command):
        return 'invalid_contract'
    if tenant != command['tenant_id'] or 'crm.handoff.write' not in scopes:
        return 'forbidden'
    return 'contract_only'  # No flag or supplied credential can enable an effect.


def retry_decision(outcome: str, *, attempts: int, age_seconds: int,
                   max_attempts: int | None, max_age_seconds: int | None) -> str:
    """Bounded retry classification; caller-supplied outcomes are not evidence."""
    if any(type(n) is not int or n <= 0 for n in (max_attempts, max_age_seconds)):
        return 'policy_blocked'
    if type(attempts) is not int or attempts < 1 or type(age_seconds) is not int or age_seconds < 0:
        return 'policy_blocked'
    if attempts >= max_attempts or age_seconds >= max_age_seconds:
        return 'dead_lettered'
    if outcome == 'proven_not_applied':
        return 'retry_wait'
    if outcome == 'accepted':
        return 'readback_pending'
    if outcome in ('unauthorized', 'forbidden', 'invalid_contract', 'rejected'):
        return 'dead_lettered'
    return 'reconciliation_required'


def example_command() -> dict[str, Any]:
    command = {
        'command_id': '00000000-0000-4000-8000-000000000001',
        'command_type': 'crm.lifecycle.handoff', 'command_version': '1.0',
        'target': 'odoo-19', 'capability': 'ODOO_WRITE',
        'tenant_id': 'TEST_SYN_TENANT', 'requested_by': 'middleware-mcr-fixture',
        'correlation_id': 'mcr-e-offline-20260924',
        'payload': {
            'schema_version': '1.0', 'lead_id': '10000-L-00000001',
            'campaign_id': 'klyrow:cmp_test_syn', 'campaign_version': 1,
            'lifecycle_version': 2, 'policy_version': 'staging-fixture-v1',
            'handoff': 'accepted', 'lifecycle_state': 'ELIGIBLE',
            'signal': 'policy_accepted', 'evidence_source': 'middleware',
            'evidence_id': 'synthetic-policy-decision-1', 'evidence_hash': 'a' * 64,
            'occurred_at': '2026-09-24T12:00:00Z',
            'dry_run': True, 'allow_external_contact': False,
        },
    }
    command['idempotency_key'] = idempotency_key(command)
    return command


def example_readback(command: dict[str, Any]) -> dict[str, Any]:
    values = {**flattened(command), 'payload_hash': digest(command['payload'])}
    return {'schema_version': '1.0', **{k: values[k] for k in READBACK},
            'status': 'applied', 'odoo_record_id': 1,
            'observed_lifecycle_version': command['payload']['lifecycle_version'],
            'observed_at': '2026-09-24T12:01:00Z'}


def validate() -> list[str]:
    errors = []
    for name in SCHEMAS:
        Draft202012Validator.check_schema(load(name))
    authority = load('odoo-handoff-authority.v1.json')
    for key, expected in {
        'runtime_status': 'contract_only', 'command_type': 'crm.lifecycle.handoff',
        'command_authority': 'middleware', 'outbox_authority': 'middleware',
        'crm_authority': 'odoo', 'lifecycle_authority': 'leads', 'conversion_authority': 'odoo',
        'runtime_enabled': False, 'provider_calls_enabled': False,
        'direct_database_writes_allowed': False, 'n8n_pre_acceptance_allowed': False,
        'external_contact_allowed': False,
        'idempotency_identity': list(NATURAL), 'readback_identity': list(READBACK),
        'scopes': {'submit': 'crm.handoff.write', 'read': 'crm.handoff.read',
                   'reconcile': 'crm.handoff.reconcile'},
    }.items():
        if authority.get(key) != expected:
            errors.append(f'authority mismatch: {key}')
    for name in ('max_attempts', 'max_age_seconds', 'base_delay_seconds', 'max_delay_seconds'):
        if authority['retry'].get(name) is not None:
            errors.append(f'contract-only retry policy must be unset: {name}')
    for path in authority['reuse']:
        if not (ROOT / path).is_file():
            errors.append(f'missing reused authority: {path}')
    command = example_command()
    errors.extend(command_errors(command))
    if reconcile(command, example_readback(command)) != 'completed':
        errors.append('valid synthetic readback rejected')
    # Catch removal of the schema's effect barriers independently of admission().
    for field, value in [('dry_run', False), ('allow_external_contact', True), ('signal', 'open')]:
        changed = json.loads(json.dumps(command))
        changed['payload'][field] = value
        if not command_errors(changed):
            errors.append(f'unsafe payload accepted: {field}')
    api = yaml.safe_load((DIRECTORY / 'odoo-handoff.openapi.yaml').read_text())
    if api['openapi'] != '3.1.0' or api['info'].get('x-codestra-implemented') is not False:
        errors.append('OpenAPI must remain unimplemented 3.1.0')
    operations = {
        ('post', '/platform/v1/crm/handoffs'): 'crm.handoff.write',
        ('get', '/platform/v1/crm/handoffs/{command_id}'): 'crm.handoff.read',
        ('post', '/platform/v1/crm/handoffs/{command_id}/reconcile'): 'crm.handoff.reconcile',
    }
    actual = {(method, path) for path, item in api['paths'].items() for method in item}
    if actual != set(operations):
        errors.append('OpenAPI operation set mismatch')
    for (method, path), scope in operations.items():
        op = api['paths'].get(path, {}).get(method, {})
        if op.get('security') != [{'codestraOAuth': [scope]}]:
            errors.append(f'OpenAPI scope mismatch: {path}')
        if op.get('x-codestra-implemented') is not False or op.get('x-codestra-effects') != 'none':
            errors.append(f'OpenAPI effect gate mismatch: {path}')
        headers = {p['name'] for p in op.get('parameters', []) if p.get('in') == 'header' and p.get('required') is True}
        required = {'X-Tenant-ID', 'X-Correlation-ID', 'X-Causation-ID'}
        if method == 'post':
            required.add('Idempotency-Key')
        if not required <= headers:
            errors.append(f'OpenAPI missing metadata: {path}')
        if not {'401', '403', '409', '422', '503'} <= op.get('responses', {}).keys():
            errors.append(f'OpenAPI missing failure responses: {path}')
    # No new MCR handoff dispatch entry point may be smuggled into this mission.
    for directory in ('app', 'middleware'):
        for path in (ROOT / directory).rglob('*.py'):
            source = path.read_text()
            if 'crm.lifecycle.handoff' in source or '/platform/v1/crm/handoffs' in source:
                errors.append(f'contract-only handoff registered in runtime: {path.relative_to(ROOT)}')
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print('\n'.join(errors))
        return 1
    print('MCR-E handoff contracts valid; offline only; no runtime/provider/database effects')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
