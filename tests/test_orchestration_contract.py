from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.api.v1.orchestration import LeadSyncIntent, ProvisioningIntent


def provisioning(**overrides):
    values = {
        "request_uid": "synthetic-1",
        "operation": "provision",
        "business_unit": "TST",
        "subject_reference": "user:synthetic-1",
        "department_reference": "department:sdr",
        "team_reference": "team:test",
        "supervisor_reference": "user:synthetic-supervisor",
        "campaign_references": ["campaign:test"],
        "requested_resources": ["odoo", "keycloak", "vicidial", "endpoint"],
        "correlation_id": "corr-1",
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15),
    }
    values.update(overrides)
    return values


def test_provisioning_contract_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ProvisioningIntent(**provisioning(password="must-not-be-accepted"))


def test_provisioning_contract_contains_references_not_secrets():
    model = ProvisioningIntent(**provisioning())
    assert "password" not in model.model_dump()
    assert "secret" not in model.model_dump()


def test_lead_sync_contract_minimizes_customer_data():
    model = LeadSyncIntent(
        source_reference="lead:synthetic-1",
        business_unit="TL",
        campaign_reference="campaign:tl-test",
        list_reference="list:tl-test",
        lead_reference="lead:synthetic-1",
        preferred_language="en",
        correlation_id="corr-lead-1",
    )
    assert set(model.model_dump()) == {
        "source_reference",
        "business_unit",
        "campaign_reference",
        "list_reference",
        "lead_reference",
        "preferred_language",
        "correlation_id",
    }


def test_lead_sync_rejects_customer_fields():
    with pytest.raises(ValidationError):
        LeadSyncIntent(
            source_reference="lead:synthetic-1",
            business_unit="TL",
            campaign_reference="campaign:tl-test",
            list_reference="list:tl-test",
            lead_reference="lead:synthetic-1",
            preferred_language="en",
            correlation_id="corr-lead-1",
            telephone="+10000000000",
        )
