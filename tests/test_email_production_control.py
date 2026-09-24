from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from app.communications import CreateMessageRequest, MessageContent
from app.email_production_control import (
    AuthorizeEmailProduction,
    EmailProductionBlocked,
    EmailProductionControlService,
    EmailProductionPolicy,
    MemoryEmailProductionPolicyStore,
)
from app.main import create_app
from app.core.config import Settings


def _settings(*, enabled: bool = True):
    return SimpleNamespace(
        app_env="production",
        source_sha="a" * 40,
        email_delivery_enabled=enabled,
        production_activation_id="change-prod-20260912",
    )


def _request(*, recipient: str = "owner@example.net", category: str = "transactional"):
    return CreateMessageRequest.model_validate(
        {
            "channel": "email",
            "from": "sender@example.com",
            "to": [recipient],
            "content": MessageContent(
                subject="test", text="production control test"
            ),
            "metadata": {"category": category, "consent": "granted"},
        }
    )


def _active_policy(**updates):
    base = EmailProductionPolicy(
        tenantId="tenant-1",
        enabled=True,
        mode="TRANSACTIONAL_CANARY",
        authorizationState="ACTIVE",
        approvedDomains=["example.com"],
        approvedSenders=["sender@example.com"],
        recipientScope="ALLOWLIST",
        approvedRecipients=["owner@example.net"],
        approvedCategories=["transactional"],
        perMinuteLimit=1,
        perHourLimit=2,
        perDayLimit=3,
        changeId="change-prod-20260912",
        approvedBy="operator-1",
        activatedBy="operator-2",
        productionOwner="operator-1",
        monitoringOwner="operator-1",
        escalationOwner="operator-1",
        rollbackOwner="operator-1",
        killSwitchProcedure="Close the kill switch and preserve callback ingestion.",
        provider="klyrow-postal",
        environment="production",
        approvedReleaseSha="a" * 40,
        authorizationTimestamp=datetime.now(UTC),
        activationTimestamp=datetime.now(UTC),
        validFrom=datetime.now(UTC) - timedelta(minutes=5),
        validUntil=datetime.now(UTC) + timedelta(hours=1),
        killSwitchOpen=True,
    )
    return base.model_copy(update=updates)


def test_transactional_authorization_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="unsupported transactional categories"):
        AuthorizeEmailProduction.model_validate({
            "expectedVersion": 1,
            "mode": "TRANSACTIONAL_PRODUCTION",
            "approvedDomains": ["example.com"],
            "approvedSenders": ["sender@example.com"],
            "recipientScope": "ALLOWLIST",
            "approvedRecipients": ["owner@example.net"],
            "approvedCategories": ["internal-news"],
            "perMinuteLimit": 1, "perHourLimit": 2, "perDayLimit": 3,
            "validFrom": datetime.now(UTC),
            "validUntil": datetime.now(UTC) + timedelta(hours=1),
            "changeId": "change-prod-20260912", "productionOwner": "op",
            "monitoringOwner": "op", "escalationOwner": "op", "rollbackOwner": "op",
            "killSwitchProcedure": "Close the kill switch and preserve callback ingestion.",
            "provider": "klyrow-postal", "environment": "production",
            "approvedReleaseSha": "a" * 40, "reason": "test category closure",
        })


def test_production_control_routes_are_mounted() -> None:
    app = create_app(
        settings=Settings.from_env(
            {"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}
        )
    )
    paths = app.openapi()["paths"]
    for path in (
        "/platform/v1/email/production/status",
        "/platform/v1/email/production/readiness",
        "/platform/v1/email/production/quotas",
        "/platform/v1/email/production/audit",
        "/platform/v1/email/production/authorize",
        "/platform/v1/email/production/activate",
        "/platform/v1/email/production/revoke",
        "/platform/v1/email/production/kill-switch",
    ):
        assert path in paths


@pytest.mark.asyncio
async def test_default_policy_is_fail_closed() -> None:
    service = EmailProductionControlService(
        store=MemoryEmailProductionPolicyStore(), settings=_settings()
    )
    policy = await service.get("tenant-1")
    assert policy.mode == "SAFE"
    assert policy.authorizationState == "NOT_AUTHORIZED"
    assert policy.killSwitchOpen is False
    with pytest.raises(EmailProductionBlocked, match="not active"):
        await service.guard_request("tenant-1", _request(), "sender@example.com")


@pytest.mark.asyncio
async def test_canary_allows_only_authorized_recipient_and_reserves_quota() -> None:
    store = MemoryEmailProductionPolicyStore(
        policies={"tenant-1": _active_policy()}
    )
    service = EmailProductionControlService(store=store, settings=_settings())
    policy, reservation = await service.guard_request(
        "tenant-1", _request(), "sender@example.com"
    )
    assert policy.mode == "TRANSACTIONAL_CANARY"
    assert reservation.units == 1
    assert (await store.quota_status("tenant-1"))["minute"] == 1

    with pytest.raises(EmailProductionBlocked, match="outside production allowlist"):
        await service.guard_request(
            "tenant-1",
            _request(recipient="other@example.net"),
            "sender@example.com",
        )


@pytest.mark.asyncio
async def test_kill_switch_blocks_before_provider_submission() -> None:
    store = MemoryEmailProductionPolicyStore(
        policies={"tenant-1": _active_policy(killSwitchOpen=False)}
    )
    service = EmailProductionControlService(store=store, settings=_settings())
    with pytest.raises(EmailProductionBlocked, match="kill switch is closed"):
        await service.guard_request("tenant-1", _request(), "sender@example.com")
    assert (await store.quota_status("tenant-1"))["minute"] == 0


@pytest.mark.asyncio
async def test_marketing_stays_closed_in_transactional_mode() -> None:
    store = MemoryEmailProductionPolicyStore(
        policies={
            "tenant-1": _active_policy(
                mode="TRANSACTIONAL_PRODUCTION",
                recipientScope="ALLOWLIST",
            )
        }
    )
    service = EmailProductionControlService(store=store, settings=_settings())
    with pytest.raises(EmailProductionBlocked, match="campaign email is not authorized"):
        await service.guard_request(
            "tenant-1",
            _request(category="marketing"),
            "sender@example.com",
        )


def test_current_domain_registry_blocks_activation_until_dkim_closeout() -> None:
    service = EmailProductionControlService(
        store=MemoryEmailProductionPolicyStore(), settings=_settings()
    )
    policy = EmailProductionPolicy(
        tenantId="tenant-1",
        enabled=True,
        mode="TRANSACTIONAL_PRODUCTION",
        authorizationState="AUTHORIZED_NOT_ACTIVE",
        approvedDomains=["codestra.co"],
        approvedSenders=["alerts@codestra.co"],
        recipientScope="ALLOWLIST",
        approvedRecipients=["owner@example.net"],
        approvedCategories=["transactional"],
        perMinuteLimit=1,
        perHourLimit=10,
        perDayLimit=100,
        changeId="change-prod-20260912",
        approvedBy="operator-1",
        productionOwner="operator-1",
        monitoringOwner="operator-1",
        escalationOwner="operator-1",
        rollbackOwner="operator-1",
        killSwitchProcedure="Close the kill switch and preserve callback ingestion.",
        provider="klyrow-postal",
        environment="production",
        approvedReleaseSha="a" * 40,
        authorizationTimestamp=datetime.now(UTC),
        validFrom=datetime.now(UTC) - timedelta(minutes=5),
        validUntil=datetime.now(UTC) + timedelta(hours=1),
    )
    blockers = service.activation_blockers(policy)
    assert "dkim_rotation_incomplete:codestra.co" in blockers
    assert "post_rotation_recheck_incomplete:codestra.co" in blockers
    assert "middleware_send_not_eligible:codestra.co" in blockers
    assert "domain_not_production_ready:codestra.co" in blockers
