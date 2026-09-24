"""app.core.config is the single configuration authority: one schema, one policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.core.bootstrap import (
    SERVICE_INTEGRATION_API,
    StartupError,
    validate_configuration,
    validate_startup,
)
from app.core.config import (
    CANONICAL_AUDIENCE,
    CANONICAL_SCHEMA_HEAD,
    PRODUCTION_ISSUER,
    STAGING_ISSUER,
    SYNTHETIC_CI_ISSUER,
    SYNTHETIC_CI_JWKS_URL,
    ConfigurationError,
    Settings,
)
from app.core.jwt_auth import JWTAuthError, KeycloakValidator, identity_validator_kwargs

from .test_security import WEBHOOK_PRODUCERS, staging_env as _staging_env

TEST_ENV = {"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}


def staging_env() -> dict[str, str]:
    env = _staging_env()
    for producer in WEBHOOK_PRODUCERS:
        env["WEBHOOK_SECRET_" + producer.upper().replace("-", "_").replace(".", "_")] = "x" * 32
    return env


def test_from_env_reads_only_the_given_mapping(monkeypatch) -> None:
    monkeypatch.setenv("MIDDLEWARE_SECRET", "process-environment-value")
    settings = Settings.from_env(TEST_ENV)
    assert settings.middleware_secret == ""
    assert settings.database_url == "" and settings.redis_url == ""


def test_compatibility_aliases_map_to_canonical_fields() -> None:
    settings = Settings.from_env(
        {
            **TEST_ENV,
            "KEYCLOAK_JWKS_URI": "https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs",
            "MIDDLEWARE_AUDIENCE": CANONICAL_AUDIENCE,
            "SOURCE_SHA": "c" * 40,
        }
    )
    assert settings.keycloak_jwks_url.endswith("/certs")
    assert settings.audience == CANONICAL_AUDIENCE
    assert settings.source_sha == "c" * 40


def test_invalid_values_raise_configuration_error_not_validation_error() -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env({**TEST_ENV, "ALLOW_IN_MEMORY_STORAGE": "maybe"})
    with pytest.raises(ConfigurationError, match="APP_ENV"):
        Settings.from_env({"APP_ENV": "sandbox", "ALLOW_IN_MEMORY_STORAGE": "true"})
    with pytest.raises(ConfigurationError, match="ALLOW_IN_MEMORY_STORAGE"):
        Settings.from_env({**staging_env(), "ALLOW_IN_MEMORY_STORAGE": "true"})
    with pytest.raises(ConfigurationError, match="DATABASE_URL and REDIS_URL"):
        Settings.from_env({"APP_ENV": "test"})


def test_replace_only_accepts_declared_fields() -> None:
    settings = Settings.from_env(TEST_ENV)
    assert settings.replace(max_request_body_bytes=2048).max_request_body_bytes == 2048
    with pytest.raises(TypeError, match="unknown fields"):
        settings.replace(umbrella_controls={})


def test_identity_is_derived_but_marked_implicit_until_configured() -> None:
    implicit = Settings.from_env(TEST_ENV).identity
    assert implicit.issuer == PRODUCTION_ISSUER
    assert implicit.audience == CANONICAL_AUDIENCE
    assert implicit.explicit is False
    assert implicit.max_token_lifetime_seconds == 300 and implicit.algorithms == ("RS256",)
    staging = Settings.from_env({**staging_env(), "KEYCLOAK_AUDIENCE": CANONICAL_AUDIENCE})
    assert staging.identity.explicit is True
    assert staging.identity.issuer == STAGING_ISSUER


def test_integration_validators_refuse_an_implicit_identity() -> None:
    settings = Settings.from_env(TEST_ENV)
    with pytest.raises(JWTAuthError, match="not configured"):
        identity_validator_kwargs(settings.identity)
    with pytest.raises(JWTAuthError, match="not configured"):
        KeycloakValidator.from_identity(settings.identity)
    explicit = Settings.from_env(
        {
            **TEST_ENV,
            "KEYCLOAK_ISSUER": SYNTHETIC_CI_ISSUER,
            "KEYCLOAK_AUDIENCE": CANONICAL_AUDIENCE,
            "KEYCLOAK_JWKS_URL": SYNTHETIC_CI_JWKS_URL,
            "KEYCLOAK_AUTHORIZED_PARTIES": "agent-ui, odoo-reader",
        }
    )
    kwargs = identity_validator_kwargs(explicit.identity, required_scopes=frozenset({"x.read"}))
    assert kwargs["issuer"] == SYNTHETIC_CI_ISSUER
    assert kwargs["audience"] == CANONICAL_AUDIENCE
    assert kwargs["authorized_parties"] == frozenset({"agent-ui", "odoo-reader"})
    assert kwargs["algorithms"] == ("RS256",)
    validator = KeycloakValidator.from_identity(explicit.identity, authorized_parties=frozenset({"only"}))
    assert validator.authorized_parties == frozenset({"only"})


def test_wildcard_tenant_and_missing_authority_are_rejected_by_the_verifier() -> None:
    from app.security import AuthorizationError, authorize_tenant

    with pytest.raises(AuthorizationError):
        authorize_tenant({"tenant_id": "*"}, "tenant-1")
    with pytest.raises(AuthorizationError):
        authorize_tenant({}, "tenant-1")
    authorize_tenant({"tenant_ids": ["tenant-1", "tenant-2"]}, "tenant-2")


def test_schema_head_and_audience_are_pinned() -> None:
    with pytest.raises(ConfigurationError, match="SCHEMA_HEAD"):
        Settings.from_env({**TEST_ENV, "SCHEMA_HEAD": "0001_initial"})
    with pytest.raises(ConfigurationError, match="KEYCLOAK_AUDIENCE"):
        Settings.from_env({**TEST_ENV, "KEYCLOAK_AUDIENCE": "other"})
    assert Settings.from_env(TEST_ENV).schema_head == CANONICAL_SCHEMA_HEAD


def test_secret_files_are_loaded_without_entering_the_environment(tmp_path: Path) -> None:
    secret = tmp_path / "middleware-secret"
    secret.write_text("file-secret-value\n", encoding="utf-8")
    settings = Settings.from_env({**TEST_ENV, "MIDDLEWARE_SECRET_FILE": str(secret)})
    assert settings.middleware_secret == "file-secret-value"
    with pytest.raises(ConfigurationError, match="secret file"):
        Settings.from_env({**TEST_ENV, "MIDDLEWARE_SECRET_FILE": str(tmp_path / "missing")})


def test_startup_validation_requires_the_service_secrets(tmp_path: Path) -> None:
    settings = Settings.from_env(TEST_ENV)
    with pytest.raises(StartupError, match="authorization configuration is incomplete"):
        validate_startup(SERVICE_INTEGRATION_API, settings=settings, environ={})
    with pytest.raises(StartupError, match="SERVICE_NAME"):
        validate_startup("middleware-api", settings=settings, environ={"SERVICE_NAME": "other"})
    resolved, identity = validate_configuration(settings)
    assert resolved is settings and identity.explicit is False


def test_startup_reports_flags_without_secrets() -> None:
    settings = Settings.from_env({**TEST_ENV, "MIDDLEWARE_SECRET": "unit-test-secret"})
    report = validate_startup("middleware-policy-engine", settings=settings, environ={})
    assert report.canonical_flags == {
        "send_events": False,
        "broad_event_send_enabled": False,
        "broad_event_delivery_enabled": False,
        "production_n8n_enabled": False,
        "n8n_production_workflows_enabled": False,
        "enable_external_delivery": False,
    }
    assert "unit-test-secret" not in str(report.summary)
    assert report.summary["schema_head"] == CANONICAL_SCHEMA_HEAD
