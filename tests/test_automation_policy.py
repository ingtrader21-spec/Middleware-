from __future__ import annotations

import json

import pytest

from app.automation_policy import (
    DEFAULT_POLICY_PATH,
    AutomationAuthorizationError,
    AutomationPolicy,
    AutomationPolicyError,
)


def _claims(client_id: str, scopes: str | list[str]) -> dict[str, object]:
    return {
        "iss": "https://auth.codestra.co/realms/codestra",
        "aud": "middleware-api",
        "azp": client_id,
        "scope": scopes,
    }


def test_operation_policy_has_exact_authorization_shape() -> None:
    policy = AutomationPolicy.from_path()

    assert len(policy.clients) == 10
    assert len(policy.operations) == 13
    assert len(policy.command_families) == 18
    assert policy.scope_resolution == "client_scopes_are_exact_no_implicit_union"
    assert policy.authoritative_context["tenant"] == "automation_job.tenant_id"
    assert policy.authoritative_context["actor"] == "automation_job.actor_context"
    assert policy.invariants == {
        "generic_execute_scope_allowed": False,
        "generic_command_scope_allowed": False,
        "client_can_claim_other_family": False,
        "caller_tenant_authoritative": False,
        "caller_actor_authoritative": False,
        "active_lease_required_for_steps_and_commands": True,
        "public_provider_callbacks_to_n8n": False,
        "workflow_activation_enables_capability": False,
        "live_apply_authorized": False,
    }


def test_each_command_family_accepts_only_its_exact_owner_and_scope() -> None:
    policy = AutomationPolicy.from_path()

    for family in policy.command_families:
        workflow_family = sorted(family.workflow_families)[0]
        authorized = policy.authorize_command(
            _claims(family.client_id, family.scope),
            command_type=f"{family.prefix}contract-test",
            workflow_family=workflow_family,
        )
        assert authorized == family

        other_client = next(
            client_id
            for client_id in policy.clients
            if client_id != family.client_id
            and family.scope not in policy.clients[client_id].scopes
        )
        with pytest.raises(AutomationAuthorizationError):
            policy.authorize_command(
                _claims(other_client, next(iter(policy.clients[other_client].scopes))),
                command_type=f"{family.prefix}contract-test",
                workflow_family=workflow_family,
            )


def test_client_cannot_claim_another_workflow_family() -> None:
    policy = AutomationPolicy.from_path()

    with pytest.raises(AutomationAuthorizationError, match="another workflow family"):
        policy.authorize_job_family(
            _claims("n8n-identity-automation", "automation.job.claim"),
            required_scope="automation.job.claim",
            workflow_family="crm",
        )


def test_token_scope_is_a_subset_of_the_exact_client_registry() -> None:
    policy = AutomationPolicy.from_path()

    with pytest.raises(AutomationAuthorizationError, match="not declared"):
        policy.authorize_token(
            _claims(
                "n8n-crm-automation",
                "automation.command.crm automation.command.messaging",
            ),
            required_scope="automation.command.crm",
        )


def test_generic_wildcard_and_duplicate_machine_scopes_are_denied() -> None:
    policy = AutomationPolicy.from_path()

    for scopes in (
        "automation.command.crm automation.command",
        "automation.command.crm automation.*",
        "automation.command.crm *",
        ["automation.command.crm", "automation.command.crm"],
    ):
        with pytest.raises(AutomationAuthorizationError):
            policy.authorize_token(
                _claims("n8n-crm-automation", scopes),
                required_scope="automation.command.crm",
            )


def test_policy_rechecks_issuer_and_single_audience() -> None:
    policy = AutomationPolicy.from_path()
    valid = _claims("n8n-crm-automation", "automation.command.crm")

    with pytest.raises(AutomationAuthorizationError, match="issuer"):
        policy.authorize_token(
            {**valid, "iss": "https://gateway.invalid/realm"},
            required_scope="automation.command.crm",
        )
    with pytest.raises(AutomationAuthorizationError, match="audience"):
        policy.authorize_token(
            {**valid, "aud": ["middleware-api", "another-api"]},
            required_scope="automation.command.crm",
        )


def test_operations_and_platform_clients_have_no_command_authority() -> None:
    policy = AutomationPolicy.from_path()

    for client_id in ("n8n-platform-runtime", "n8n-operations-automation"):
        assert policy.client(client_id).command_prefixes == ()
        with pytest.raises(AutomationAuthorizationError):
            policy.authorize_command(
                _claims(client_id, "automation.job.claim"),
                command_type="crm.lead.upsert",
                workflow_family="crm",
            )


def test_security_invariant_change_fails_policy_construction() -> None:
    raw = json.loads(DEFAULT_POLICY_PATH.read_text(encoding="utf-8"))
    raw["invariants"]["caller_tenant_authoritative"] = True

    with pytest.raises(AutomationPolicyError, match="invariant set drift"):
        AutomationPolicy.from_mapping(raw)
