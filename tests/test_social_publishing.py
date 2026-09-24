import asyncio
import hashlib
import hmac
import json
import time
from typing import Any
from uuid import uuid4

import pytest

from app.core.config import settings
from app.social.adapters import (
    HootsuiteProviderAdapter,
    PostlyProviderAdapter,
    normalize_status,
)
from app.social.domain import (
    Capability,
    JobType,
    ProviderName,
    ProviderResult,
    SocialPostStatus,
    normalize_network,
)
from app.social.providers import (
    SocialError,
    SocialProviderAdapter,
    SocialProviderRegistry,
)
from app.social.queue import classify_failure, retry_delay
from app.social.service import SocialPublishingService


class FakeAdapter(SocialProviderAdapter):
    def __init__(self, name: ProviderName) -> None:
        self.name = name
        self.calls = 0

    async def health_check(self) -> dict[str, Any]:
        return {"provider": self.name, "status": "AVAILABLE"}

    def get_capabilities(self) -> frozenset[Capability]:
        return frozenset(
            {
                Capability.POST_CREATE,
                Capability.POST_PUBLISH,
                Capability.POST_SCHEDULE,
                Capability.POST_CANCEL,
                Capability.POST_DELETE,
                Capability.WEBHOOK_EVENTS,
            }
        )

    async def create_post(self, post, account_refs, correlation_id):
        self.calls += 1
        return ProviderResult(
            f"{self.name}-external-{self.calls}", SocialPostStatus.DRAFT
        )

    async def publish_post(self, post, correlation_id):
        self.calls += 1
        return ProviderResult(
            f"{self.name}-external-{self.calls}", SocialPostStatus.PUBLISHED
        )


def run(value):
    return asyncio.run(value)


def configured_service() -> tuple[SocialPublishingService, FakeAdapter, FakeAdapter]:
    registry = SocialProviderRegistry()
    postly = FakeAdapter(ProviderName.POSTLY)
    hootsuite = FakeAdapter(ProviderName.HOOTSUITE)
    registry.register(postly)
    registry.register(hootsuite)
    return SocialPublishingService(registry), postly, hootsuite


def create(service: SocialPublishingService, key: str = "create-1"):
    return run(
        service.create_post(
            tenant_id=uuid4(),
            account_ids=(uuid4(),),
            content={"text": "test"},
            campaign_id=None,
            publish_at=None,
            metadata={},
            idempotency_key=key,
            correlation_id="corr",
            request_id="req",
        )
    )


def test_provider_registry_and_capability_resolution():
    registry = SocialProviderRegistry()
    registry.register(FakeAdapter(ProviderName.POSTLY))
    assert (
        registry.require("postly", Capability.POST_CREATE).name is ProviderName.POSTLY
    )
    with pytest.raises(SocialError, match="disabled") as error:
        registry.get("disabled")
    assert error.value.code == "SOCIAL_PROVIDER_DISABLED"


def test_normalization():
    assert normalize_network("Twitter").value == "x"
    assert normalize_network("unexpected").value == "other"
    assert normalize_status("particular-provider-value") is SocialPostStatus.UNKNOWN
    assert normalize_status("published") is SocialPostStatus.PUBLISHED


def test_hootsuite_never_reports_fake_success():
    result = run(HootsuiteProviderAdapter().health_check())
    assert result["status"] in {"NOT_CONFIGURED", "DISABLED"}
    assert result["reachable"] is None
    with pytest.raises(SocialError) as error:
        run(HootsuiteProviderAdapter().create_post(None, [], "corr"))
    assert error.value.code == "SOCIAL_PROVIDER_CAPABILITY_UNSUPPORTED"


def test_default_feature_flags_prevent_real_provider_call(monkeypatch):
    service, postly, _ = configured_service()
    monkeypatch.setattr(settings, "social_integration_enabled", False)
    monkeypatch.setattr(settings, "social_publish_enabled", False)
    with pytest.raises(SocialError) as error:
        create(service)
    assert error.value.code == "SOCIAL_PROVIDER_DISABLED"
    assert postly.calls == 0


def test_provider_switch_preserves_historical_provider(monkeypatch):
    service, postly, hootsuite = configured_service()
    monkeypatch.setattr(settings, "social_integration_enabled", True)
    monkeypatch.setattr(settings, "social_provider", "postly")
    post_a, _, _ = create(service, "a")
    assert post_a.provider is ProviderName.POSTLY
    monkeypatch.setattr(settings, "social_provider", "hootsuite")
    assert service.resolve_provider(post_a) is ProviderName.POSTLY
    post_b, _, _ = create(service, "b")
    assert post_b.provider is ProviderName.HOOTSUITE
    assert post_a.id != post_b.id
    run(
        service.process_job(
            next(
                job.id
                for job in service.repository.jobs.values()
                if job.social_post_id == post_a.id
            )
        )
    )
    run(
        service.process_job(
            next(
                job.id
                for job in service.repository.jobs.values()
                if job.social_post_id == post_b.id
            )
        )
    )
    assert postly.calls == 1
    assert hootsuite.calls == 1


def test_duplicate_publish_idempotency_calls_provider_once(monkeypatch):
    service, postly, _ = configured_service()
    monkeypatch.setattr(settings, "social_integration_enabled", True)
    monkeypatch.setattr(settings, "social_publish_enabled", True)
    monkeypatch.setattr(settings, "social_provider", "postly")
    post, create_job, _ = create(service)
    run(service.process_job(create_job.id))
    baseline = postly.calls
    first, first_created = run(
        service.command(post.id, JobType.PUBLISH, "same-key", "corr", "req")
    )
    second, second_created = run(
        service.command(post.id, JobType.PUBLISH, "same-key", "corr", "req")
    )
    assert first.id == second.id
    assert first_created is True and second_created is False
    run(service.process_job(first.id))
    assert postly.calls == baseline + 1


def test_idempotency_conflict(monkeypatch):
    service, _, _ = configured_service()
    monkeypatch.setattr(settings, "social_integration_enabled", True)
    monkeypatch.setattr(settings, "social_provider", "postly")
    fixed = uuid4()
    kwargs = dict(
        tenant_id=uuid4(),
        account_ids=(uuid4(),),
        content={"text": "one"},
        campaign_id=None,
        publish_at=None,
        metadata={},
        idempotency_key="same",
        correlation_id="corr",
        request_id="req",
        post_id=fixed,
    )
    run(service.create_post(**kwargs))
    kwargs["content"] = {"text": "different"}
    with pytest.raises(SocialError) as error:
        run(service.create_post(**kwargs))
    assert error.value.code == "SOCIAL_IDEMPOTENCY_CONFLICT"


def test_create_retry_without_client_supplied_post_id_is_deduplicated(monkeypatch):
    service, _, _ = configured_service()
    monkeypatch.setattr(settings, "social_integration_enabled", True)
    monkeypatch.setattr(settings, "social_provider", "postly")
    tenant_id = uuid4()
    kwargs = dict(
        tenant_id=tenant_id,
        account_ids=(uuid4(),),
        content={"text": "same request"},
        campaign_id=None,
        publish_at=None,
        metadata={},
        idempotency_key="create-retry",
        correlation_id="corr",
        request_id="req",
    )
    first_post, first_job, first_created = run(service.create_post(**kwargs))
    second_post, second_job, second_created = run(service.create_post(**kwargs))
    assert first_post.id == second_post.id
    assert first_job.id == second_job.id
    assert first_created is True and second_created is False


def test_retry_classification_and_bounded_jitter():
    assert classify_failure(SocialError("temporary", "safe", retryable=True)) == "retry"
    assert classify_failure(SocialError("invalid", "safe")) == "dead_letter"
    assert 20 <= retry_delay(4, 5, 300) <= 40


def test_postly_webhook_signature_replay_window_and_normalization(monkeypatch):
    adapter = PostlyProviderAdapter()
    secret = "synthetic-test-secret"
    monkeypatch.setattr(settings, "postly_webhook_secret", secret)
    now = str(int(time.time()))
    payload = {
        "id": "evt-1",
        "type": "post.published",
        "codestra_subject_id": str(uuid4()),
        "tenant_id": str(uuid4()),
        "provider_post_id": "external-1",
        "token": "must-not-pass",
    }
    body = json.dumps(payload).encode()
    signature = hmac.new(
        secret.encode(), now.encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    run(
        adapter.verify_webhook(
            body, {"x-postly-timestamp": now, "x-postly-signature": signature}
        )
    )
    event = run(adapter.normalize_webhook(payload, "corr"))
    assert event.event_type == "social.post.published"
    assert "token" not in event.payload
    with pytest.raises(SocialError) as error:
        run(
            adapter.verify_webhook(
                body, {"x-postly-timestamp": now, "x-postly-signature": "bad"}
            )
        )
    assert error.value.code == "SOCIAL_WEBHOOK_INVALID_SIGNATURE"


def test_social_api_contract_is_provider_neutral():
    from app.main import app

    paths = set(app.openapi()["paths"])
    required = {
        "/api/v1/social/providers",
        "/api/v1/social/accounts",
        "/api/v1/social/posts",
        "/api/v1/social/posts/{post_id}",
        "/api/v1/social/posts/{post_id}/schedule",
        "/api/v1/social/posts/{post_id}/publish",
        "/api/v1/social/posts/{post_id}/cancel",
        "/api/v1/social/webhooks/{provider}",
    }
    assert required <= paths
    schema = json.dumps(app.openapi()).lower()
    assert "postly_account_id" not in schema
    assert "hootsuite_account_id" not in schema
