"""Offline contract conformance; no Odoo, database, or deployed staging access."""
from copy import deepcopy

import pytest

from scripts import validate_mcr_odoo_handoff_contracts as handoff


@pytest.fixture
def command():
    return handoff.example_command()


def test_repository_contracts():
    assert handoff.validate() == []


@pytest.mark.parametrize('kind,state,signal,source', [
    ('accepted', 'ELIGIBLE', 'policy_accepted', 'middleware'),
    ('engaged', 'ENGAGED', 'reply', 'middleware'),
    ('engaged', 'ENGAGED', 'click', 'middleware'),
    ('conversion', 'CONVERTED', 'conversion', 'odoo'),
])
def test_lifecycle_handoffs(command, kind, state, signal, source):
    command['payload'].update(handoff=kind, lifecycle_state=state,
                              signal=signal, evidence_source=source)
    command['idempotency_key'] = handoff.idempotency_key(command)
    assert handoff.command_errors(command) == []


@pytest.mark.parametrize('field,value', [
    ('handoff', 'delivered'), ('signal', 'open'), ('signal', 'accepted'),
    ('lifecycle_state', 'SUPPRESSED'), ('lifecycle_version', 0),
    ('campaign_version', 0), ('campaign_id', 'odoo:123'),
    ('lead_id', '123'), ('dry_run', False), ('allow_external_contact', True),
    ('evidence_hash', 'not-a-digest'), ('occurred_at', 'yesterday'),
    ('evidence_source', 'n8n'), ('arbitrary_stage', 'won'),
])
def test_invalid_payload_fails_closed(command, field, value):
    command['payload'][field] = value
    assert handoff.command_errors(command)


@pytest.mark.parametrize('field', ['tenant_id', 'lead_id', 'correlation_id',
                                   'campaign_version', 'lifecycle_version', 'policy_version'])
def test_missing_identity_rejected(command, field):
    target = command if field in ('tenant_id', 'correlation_id') else command['payload']
    del target[field]
    assert handoff.command_errors(command)


def test_conversion_cannot_assert_non_odoo_truth(command):
    command['payload'].update(handoff='conversion', lifecycle_state='CONVERTED', signal='conversion')
    assert handoff.command_errors(command)


def test_stable_key_and_conflicting_replays(command):
    original = deepcopy(command)
    assert handoff.replay_decision(original, command) == 'duplicate'
    command['command_id'] = '00000000-0000-4000-8000-000000000002'
    assert handoff.replay_decision(original, command) == 'duplicate'
    command['payload']['evidence_hash'] = 'b' * 64
    assert handoff.replay_decision(original, command) == 'idempotency_conflict'


@pytest.mark.parametrize('field', ['tenant_id', 'lead_id', 'campaign_id', 'campaign_version',
                                   'lifecycle_version', 'handoff', 'policy_version'])
def test_key_is_scoped_to_business_identity(command, field):
    before = handoff.idempotency_key(command)
    target = command if field == 'tenant_id' else command['payload']
    target[field] = str(target[field]) + '-other'
    assert handoff.idempotency_key(command) != before


@pytest.mark.parametrize('field', ['tenant_id', 'lead_id', 'command_id', 'correlation_id',
                                   'campaign_id', 'campaign_version', 'lifecycle_version',
                                   'policy_version', 'idempotency_key', 'payload_hash', 'handoff'])
def test_readback_requires_exact_identity(command, field):
    receipt = handoff.example_readback(command)
    assert handoff.reconcile(command, receipt) == 'completed'
    receipt[field] = 'different'
    assert handoff.reconcile(command, receipt) == 'reconciliation_required'


@pytest.mark.parametrize('status,result', [('accepted', 'readback_pending'),
    ('not_found', 'reconciliation_required'), ('unknown', 'reconciliation_required'),
    ('rejected', 'dead_lettered')])
def test_acceptance_is_not_completion(command, status, result):
    receipt = handoff.example_readback(command)
    receipt.update(status=status, odoo_record_id=None, observed_lifecycle_version=None)
    assert handoff.reconcile(command, receipt) == result


def test_version_drift_and_malformed_readback(command):
    receipt = handoff.example_readback(command)
    receipt['observed_lifecycle_version'] += 1
    assert handoff.reconcile(command, receipt) == 'reconciliation_required'
    assert handoff.reconcile(command, {}) == 'reconciliation_required'
    assert handoff.reconcile(command, None) == 'reconciliation_required'


@pytest.mark.parametrize('verified,tenant,scopes,expected', [
    (False, 'TEST_SYN_TENANT', ['crm.handoff.write'], 'unauthorized'),
    (True, 'other', ['crm.handoff.write'], 'forbidden'),
    (True, 'TEST_SYN_TENANT', [], 'forbidden'),
    (True, 'TEST_SYN_TENANT', ['crm.handoff.read'], 'forbidden'),
    (True, 'TEST_SYN_TENANT', ['crm.handoff.write'], 'contract_only'),
])
def test_auth_and_effect_gate(command, verified, tenant, scopes, expected):
    assert handoff.admission(command, verified=verified, tenant=tenant, scopes=scopes) == expected


@pytest.mark.parametrize('outcome,attempts,age,expected', [
    ('timeout', 1, 0, 'reconciliation_required'),
    ('502', 1, 0, 'reconciliation_required'),
    ('not_found', 1, 0, 'reconciliation_required'),
    ('accepted', 1, 0, 'readback_pending'),
    ('proven_not_applied', 1, 0, 'retry_wait'),
    ('proven_not_applied', 3, 0, 'dead_lettered'),
    ('proven_not_applied', 1, 3600, 'dead_lettered'),
    ('unauthorized', 1, 0, 'dead_lettered'),
    ('invented', 1, 0, 'reconciliation_required'),
])
def test_retry_discipline(outcome, attempts, age, expected):
    assert handoff.retry_decision(outcome, attempts=attempts, age_seconds=age,
                                  max_attempts=3, max_age_seconds=3600) == expected


@pytest.mark.parametrize('limit', [None, 0, -1, True])
def test_missing_or_invalid_retry_policy_blocks(limit):
    assert handoff.retry_decision('proven_not_applied', attempts=1, age_seconds=0,
                                  max_attempts=limit, max_age_seconds=3600) == 'policy_blocked'


def test_staging_fixture_has_zero_effects(command, monkeypatch):
    import socket

    def prohibited(*args, **kwargs):
        raise AssertionError('network prohibited in offline evidence')

    monkeypatch.setattr(socket.socket, 'connect', prohibited)
    monkeypatch.setattr(socket, 'create_connection', prohibited)
    assert handoff.admission(command, verified=True, tenant=command['tenant_id'],
                             scopes=['crm.handoff.write']) == 'contract_only'
    assert handoff.validate() == []
