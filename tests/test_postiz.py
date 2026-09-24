import asyncio
import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.integrations.postiz.client import PostizClient
from app.integrations.postiz.exceptions import PostizError
from app.main import app


def test_postiz_routes_are_middleware_owned():
    paths = set(app.openapi()["paths"])
    assert "/api/v1/integrations/postiz/health" in paths
    assert "/api/v1/integrations/postiz/posts" in paths
    assert "/api/v1/integrations/postiz/results" in paths
    assert "/api/v1/integrations/postiz/errors" in paths


def test_postiz_flags_are_safe_by_default():
    assert settings.postiz_delivery_enabled is False
    assert settings.postiz_publish_enabled is False
    assert settings.postiz_media_upload_enabled is False
    assert settings.postiz_analytics_enabled is False


def test_postiz_client_fails_closed_without_provider_configuration(monkeypatch):
    monkeypatch.setattr(settings, "postiz_internal_base_url", "")
    monkeypatch.setattr(settings, "postiz_api_key_file", "")
    with pytest.raises(PostizError) as error:
        asyncio.run(PostizClient().connection_check("test-correlation"))
    assert error.value.code == "not_configured"


def test_n8n_exports_have_no_direct_postiz_or_provider_credentials():
    root = Path(__file__).parents[1] / "integrations/n8n/postiz-social-orchestration"
    for path in root.glob("*.json"):
        payload = json.loads(path.read_text())
        assert payload["active"] is False
        text = path.read_text().lower()
        assert "postiz.com" not in text
        assert "/api/public/v1" not in text
        assert "api_key" not in text
        assert "oauth" not in text
