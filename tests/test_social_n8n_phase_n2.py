import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.core.n8n_runtime import SocialEventEnvelope
from app.workers.postly_polling import _belongs_to_account, _items, _provider_version
from app.workers.social_n8n_delivery import SOCIAL_ROUTER_CODE, SOCIAL_ROUTER_VERSION


ROOT = Path(__file__).parents[1]
ROUTER = ROOT / "integrations/n8n/social-runtime/CdstSocialEventRouterV1.json"
HANDLERS = ROOT / "integrations/n8n/social-runtime/CdstSocialHandlersV1.json"
MIGRATION = ROOT / "migrations/versions/0039_social_n8n_delivery_runtime.py"


def envelope(**overrides):
    value = {
        "event_id": "event-1",
        "event_type": "social.post.published",
        "event_version": 1,
        "occurred_at": "2026-08-09T00:00:00Z",
        "correlation_id": "correlation-1",
        "tenant_id": "tenant-a",
        "source": "social",
        "provider": "postly",
        "subject_id": "subject-1",
        "payload": {"status": "published"},
    }
    value.update(overrides)
    return value


def test_provider_neutral_contract_rejects_credentials_and_unknown_fields():
    assert SocialEventEnvelope.model_validate(envelope()).source == "social"
    with pytest.raises(ValueError):
        SocialEventEnvelope.model_validate(envelope(payload={"access_token": "x"}))
    with pytest.raises(ValueError):
        SocialEventEnvelope.model_validate(
            envelope(payload={"metadata": {"client_secret": "x"}})
        )
    with pytest.raises(ValueError):
        SocialEventEnvelope.model_validate(envelope(postly_post_id="provider-leak"))


def test_polling_helpers_are_bounded_and_account_scoped(monkeypatch):
    monkeypatch.setattr(settings, "postly_poll_batch_size", 2)
    values = [{"id": 1}, {"id": 2}, {"id": 3}]
    assert len(_items({"posts": values})) == 2
    assert _belongs_to_account({"integrations": [{"id": "account-1"}]}, "account-1")
    assert not _belongs_to_account({"integrations": []}, "account-1")
    assert _provider_version({"status": "published"}) == "published"


def test_phase_n2_defaults_are_fail_closed():
    assert settings.postly_polling_enabled is False
    assert settings.social_n8n_delivery_worker_enabled is False
    assert settings.social_publish_enabled is False
    assert settings.social_odoo_write_enabled is False
    assert SOCIAL_ROUTER_CODE == "CDST_SOCIAL_EVENT_ROUTER"
    assert SOCIAL_ROUTER_VERSION == "1"


def _assert_connected(workflow):
    names = {node["name"] for node in workflow["nodes"]}
    sources = set(workflow["connections"])
    targets = {
        edge["node"]
        for outputs in workflow["connections"].values()
        for branch in outputs["main"]
        for edge in branch
    }
    assert workflow["active"] is False
    assert names
    assert sources | targets == names
    assert len(workflow["nodes"]) >= 2


def test_router_and_handlers_have_nonempty_connected_graphs():
    router = json.loads(ROUTER.read_text())
    handlers = json.loads(HANDLERS.read_text())
    assert len(router) == 1
    assert len(handlers) == 11
    assert all(
        workflow["nodes"][0]["parameters"].get("inputSource") == "passthrough"
        for workflow in handlers
    )
    for workflow in router + handlers:
        _assert_connected(workflow)
    router_text = ROUTER.read_text()
    assert "social-authorize" in router_text
    assert "X-Codestra-Signature" in router_text
    assert "n8n-runtime/results" in router_text
    assert "http://middleware-integration-api:8095" in router_text
    assert '"name": "social-ingress"' in router_text
    assert "CdstSocialDeadLetterV1" in router_text


def test_migration_extends_single_social_head_and_has_durable_state():
    source = MIGRATION.read_text()
    assert 'down_revision = "0038_social_production_canary"' in source
    for table in (
        "social_poll_checkpoints",
        "social_poll_observations",
        "social_n8n_delivery_execution",
        "social_n8n_delivery_attempts",
        "social_n8n_ingress_events",
    ):
        assert table in source


def test_polling_worker_source_has_no_provider_write_operations():
    source = (ROOT / "app/workers/postly_polling.py").read_text()
    for forbidden in ("create_post(", "cancel_post(", "upload_from_url("):
        assert forbidden not in source
