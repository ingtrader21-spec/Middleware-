from uuid import uuid4

import pytest

from app.core.config import settings
from app.social import metrics
from app.social.domain import ProviderName
from app.social.production import (
    PRODUCTION_APPROVED,
    ProductionCanaryPolicy,
    ProductionPublishContext,
    require_provider_health,
)
from app.social.providers import SocialError


def configured_policy(**overrides):
    account_id = overrides.pop("account_id", uuid4())
    tenant_id = overrides.pop("tenant_id", uuid4())
    campaign_id = overrides.pop("campaign_id", uuid4())
    config = settings.model_copy(
        update={
            "social_production_mode": True,
            "social_integration_enabled": True,
            "social_publish_enabled": True,
            "social_production_canary_enabled": True,
            "social_sql_repository_enabled": True,
            "social_worker_enabled": True,
            "social_production_backup_gate_verified": True,
            "social_production_rollback_gate_verified": True,
            "social_production_webhook_gate_verified": True,
            "social_production_monitoring_gate_verified": True,
            "social_production_canary_account_ids": str(account_id),
            "social_production_canary_tenant_ids": str(tenant_id),
            "social_production_canary_campaign_ids": str(campaign_id),
            **overrides,
        }
    )
    context = ProductionPublishContext(
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        account_id=account_id,
        provider=ProviderName.POSTLY,
        classification=PRODUCTION_APPROVED,
        connection_state="connected",
        content_approved=True,
    )
    return ProductionCanaryPolicy(config), context


def test_production_canary_policy_accepts_exact_approved_scope():
    policy, context = configured_policy()
    policy.validate(context)


def test_provider_health_gate_is_truthful():
    require_provider_health({"status": "AVAILABLE", "reachable": True})
    with pytest.raises(SocialError) as error:
        require_provider_health({"status": "UNREACHABLE", "reachable": False})
    assert error.value.code == "SOCIAL_PROVIDER_UNAVAILABLE"


@pytest.mark.parametrize(
    ("change", "code"),
    [
        (
            {"social_production_canary_enabled": False},
            "SOCIAL_PRODUCTION_CANARY_DISABLED",
        ),
        (
            {"social_production_backup_gate_verified": False},
            "SOCIAL_PRODUCTION_CANARY_DISABLED",
        ),
        (
            {"social_production_rollback_gate_verified": False},
            "SOCIAL_PRODUCTION_CANARY_DISABLED",
        ),
        (
            {"social_production_webhook_gate_verified": False},
            "SOCIAL_PRODUCTION_CANARY_DISABLED",
        ),
        (
            {"social_production_monitoring_gate_verified": False},
            "SOCIAL_PRODUCTION_CANARY_DISABLED",
        ),
        (
            {"social_production_canary_account_ids": ""},
            "SOCIAL_PRODUCTION_ACCOUNT_DENIED",
        ),
        (
            {"social_automatic_provider_failover_enabled": True},
            "SOCIAL_PROVIDER_FAILOVER_FORBIDDEN",
        ),
        (
            {"social_automatic_dual_publish_enabled": True},
            "SOCIAL_DUAL_PUBLISH_FORBIDDEN",
        ),
    ],
)
def test_production_canary_policy_denies_missing_gate(change, code):
    policy, context = configured_policy(**change)
    with pytest.raises(SocialError) as error:
        policy.validate(context)
    assert error.value.code == code


def test_production_canary_policy_denies_account_content_and_connection():
    policy, context = configured_policy()
    for changed, code in (
        ({"classification": "UNKNOWN"}, "SOCIAL_PRODUCTION_ACCOUNT_NOT_APPROVED"),
        ({"connection_state": "disconnected"}, "SOCIAL_ACCOUNT_DISCONNECTED"),
        ({"content_approved": False}, "SOCIAL_PRODUCTION_CONTENT_NOT_APPROVED"),
    ):
        invalid = ProductionPublishContext(
            **{
                "tenant_id": context.tenant_id,
                "campaign_id": context.campaign_id,
                "account_id": context.account_id,
                "provider": context.provider,
                "classification": context.classification,
                "connection_state": context.connection_state,
                "content_approved": context.content_approved,
                **changed,
            }
        )
        with pytest.raises(SocialError) as error:
            policy.validate(invalid)
        assert error.value.code == code


def test_production_safety_metrics_exist_without_high_cardinality_labels():
    expected = {
        "production_publish_requests",
        "production_publish_success",
        "production_publish_failures",
        "production_canary_denied",
        "duplicate_prevention",
        "unknown_result",
        "provider_failover_attempt",
        "dual_publish_attempt",
    }
    for name in expected:
        collector = getattr(metrics, name)
        assert not (
            {"account_id", "tenant_id", "campaign_id", "content"}
            & set(collector._labelnames)
        )


def test_production_defaults_remain_off():
    assert settings.social_production_mode is False
    assert settings.social_production_canary_enabled is False
    assert settings.social_production_canary_account_ids == ""
    assert settings.social_automatic_provider_failover_enabled is False
    assert settings.social_automatic_dual_publish_enabled is False


def test_settings_reject_partial_or_unsafe_production_activation():
    partial = settings.model_copy(update={"social_publish_enabled": True})
    with pytest.raises(ValueError, match="switches must agree"):
        partial.validate_safety()
    failover = settings.model_copy(
        update={"social_automatic_provider_failover_enabled": True}
    )
    with pytest.raises(ValueError, match="failover and dual publishing"):
        failover.validate_safety()


def test_settings_accept_only_complete_protected_canary_configuration(tmp_path):
    api_key = tmp_path / "postiz-api-key"
    webhook = tmp_path / "postly-webhook"
    api_key.write_text("synthetic-api-key-material")
    webhook.write_text("synthetic-webhook-secret-material")
    api_key.chmod(0o600)
    webhook.chmod(0o600)
    config = settings.model_copy(
        update={
            "social_production_mode": True,
            "social_integration_enabled": True,
            "social_publish_enabled": True,
            "postiz_publish_enabled": True,
            "postiz_delivery_enabled": True,
            "social_production_canary_enabled": True,
            "social_sql_repository_enabled": True,
            "social_worker_enabled": True,
            "social_production_backup_gate_verified": True,
            "social_production_rollback_gate_verified": True,
            "social_production_webhook_gate_verified": True,
            "social_production_monitoring_gate_verified": True,
            "social_production_canary_account_ids": str(uuid4()),
            "postiz_internal_base_url": "https://postly.internal.invalid",
            "postiz_api_key_file": str(api_key),
            "postly_webhook_secret_file": str(webhook),
        }
    )
    config.validate_safety()


def test_openapi_exposes_dry_run_without_provider_secrets():
    import json

    from app.main import app

    operation = app.openapi()["paths"]["/api/v1/social/posts/{post_id}/publish"]["post"]
    parameter_names = {item["name"] for item in operation["parameters"]}
    assert {"dry_run", "idempotency-key", "x-social-content-approved"} <= {
        item.lower() for item in parameter_names
    }
    schema = json.dumps(app.openapi()).lower()
    assert "postiz_api_key" not in schema
    assert "postly_webhook_secret" not in schema


def test_dry_run_fails_closed_outside_sql_production_mode(monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app

    monkeypatch.setattr(settings, "middleware_secret", "synthetic-phase4-auth")
    response = TestClient(app).post(
        f"/api/v1/social/posts/{uuid4()}/publish?dry_run=true",
        headers={
            "Authorization": "Bearer synthetic-phase4-auth",
            "Idempotency-Key": "synthetic-dry-run",
            "X-Codestra-Permissions": "social.publish",
            "X-Social-Content-Approved": "true",
        },
    )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "SOCIAL_PRODUCTION_CANARY_DISABLED"
