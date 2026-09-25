from __future__ import annotations

import json
import time
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import ConfigurationError, Settings, WEBHOOK_PRODUCERS
from app.security import (
    AuthorizationError,
    KeycloakJwtVerifier,
    RequestValidationError,
    _parse_timestamp,
    authorize_tenant,
    validate_claims,
)




def _machine_token(private_key, settings, *, kid: str, jti: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": settings.issuer,
            "aud": settings.audience,
            "sub": "auth02-subject",
            "azp": "middleware-api",
            "jti": jti,
            "iat": now,
            "exp": now + 120,
            "scope": "platform.command",
        },
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _public_jwk(private_key, *, kid: str) -> dict:
    value = json.loads(
        jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key())
    )
    value.update(kid=kid, use="sig", alg="RS256")
    return value


def test_machine_verifier_rejects_key_removed_after_jwks_refresh(
    monkeypatch: pytest.MonkeyPatch, test_settings: Settings
) -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "auth02-removed-key"
    verifier = KeycloakJwtVerifier(test_settings)
    fetch = Mock(return_value={"keys": [_public_jwk(private, kid=kid)]})
    monkeypatch.setattr(verifier._jwks, "fetch_data", fetch)

    first = _machine_token(private, test_settings, kid=kid, jti="auth02-first")
    assert verifier._verify_sync(
        first,
        expected_client_id="middleware-api",
        required_scope="platform.command",
    )["jti"] == "auth02-first"

    # Simulate the bounded JWKS-set cache expiring/refreshing. Once authority
    # no longer advertises the kid, the old key object must not survive in a
    # separate unbounded per-key cache.
    verifier._jwks.jwk_set_cache.put(None)
    fetch.return_value = {"keys": []}
    fresh = _machine_token(private, test_settings, kid=kid, jti="auth02-revoked")

    with pytest.raises((jwt.PyJWKClientError, jwt.PyJWKSetError)):
        verifier._verify_sync(
            fresh,
            expected_client_id="middleware-api",
            required_scope="platform.command",
        )
    assert fetch.call_count >= 2


def test_machine_verifier_accepts_same_kid_replacement_after_refresh(
    monkeypatch: pytest.MonkeyPatch, test_settings: Settings
) -> None:
    old_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    new_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "auth02-rotated-key"
    verifier = KeycloakJwtVerifier(test_settings)
    fetch = Mock(return_value={"keys": [_public_jwk(old_private, kid=kid)]})
    monkeypatch.setattr(verifier._jwks, "fetch_data", fetch)

    old = _machine_token(old_private, test_settings, kid=kid, jti="auth02-old")
    assert verifier._verify_sync(
        old,
        expected_client_id="middleware-api",
        required_scope="platform.command",
    )["jti"] == "auth02-old"

    verifier._jwks.jwk_set_cache.put(None)
    fetch.return_value = {"keys": [_public_jwk(new_private, kid=kid)]}
    rotated = _machine_token(new_private, test_settings, kid=kid, jti="auth02-new")
    assert verifier._verify_sync(
        rotated,
        expected_client_id="middleware-api",
        required_scope="platform.command",
    )["jti"] == "auth02-new"


def test_machine_verifier_has_no_unbounded_signing_key_cache(
    test_settings: Settings,
) -> None:
    verifier = KeycloakJwtVerifier(test_settings)
    # PyJWT only replaces get_signing_key with functools.lru_cache when
    # cache_keys=True. The bounded JWKS set cache remains enabled separately.
    assert not hasattr(verifier._jwks.get_signing_key, "cache_info")
    assert verifier._jwks.jwk_set_cache is not None


def test_exact_scope_and_azp_are_required() -> None:
    validate_claims(
        {
            "azp": "odoo-integration",
            "scope": "odoo.events.publish other.scope",
            "iat": 100,
            "exp": 400,
        },
        expected_client_id="odoo-integration",
        required_scope="odoo.events.publish",
    )
    with pytest.raises(AuthorizationError):
        validate_claims(
            {"azp": "odoo-integration", "scope": "other.scope", "iat": 100, "exp": 200},
            expected_client_id="odoo-integration",
            required_scope="odoo.events.publish",
        )
    with pytest.raises(AuthorizationError):
        validate_claims(
            {"azp": "wrong-client", "scope": "odoo.events.publish", "iat": 100, "exp": 200},
            expected_client_id="odoo-integration",
            required_scope="odoo.events.publish",
        )


def test_machine_token_lifetime_is_bounded() -> None:
    with pytest.raises(AuthorizationError):
        validate_claims(
            {
                "azp": "odoo-integration",
                "scope": "odoo.events.publish",
                "iat": 100,
                "exp": 401,
            },
            expected_client_id="odoo-integration",
            required_scope="odoo.events.publish",
        )


def test_machine_token_timestamp_claims_must_be_numeric_and_finite() -> None:
    for iat, exp in (("100", 200), (100, "200"), (True, 200), (100, False), (float("nan"), 200), (100, float("inf"))):
        with pytest.raises(AuthorizationError):
            validate_claims(
                {
                    "azp": "odoo-integration",
                    "scope": "odoo.events.publish",
                    "iat": iat,
                    "exp": exp,
                },
                expected_client_id="odoo-integration",
                required_scope="odoo.events.publish",
            )


def test_non_finite_webhook_timestamp_is_rejected() -> None:
    for raw in ("nan", "NaN", "inf", "-inf"):
        with pytest.raises(RequestValidationError):
            _parse_timestamp(raw)


def test_tenant_claim_is_mandatory_and_no_wildcards() -> None:
    authorize_tenant({"tenant_id": "tenant-a"}, "tenant-a")
    authorize_tenant({"tenant_ids": ["tenant-a", "tenant-b"]}, "tenant-b")
    with pytest.raises(AuthorizationError):
        authorize_tenant({}, "tenant-a")
    with pytest.raises(AuthorizationError):
        authorize_tenant({"tenant_id": "*"}, "tenant-a")
    with pytest.raises(AuthorizationError):
        authorize_tenant({"tenant_id": "tenant-b"}, "tenant-a")


def test_external_effect_flags_fail_closed() -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "SEND_EVENTS": "true",
            }
        )


def test_umbrella_controls_default_false_and_reject_malformed_values() -> None:
    settings = Settings.from_env(
        {"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"}
    )
    assert settings.umbrella_controls == {
        "LIVE_ADVERTISING_ENABLED": False,
        "EXTERNAL_DELIVERY_ENABLED": False,
        "SOCIAL_PUBLISHING_ENABLED": False,
        "EXTERNAL_MODEL_CALLS_ENABLED": False,
        "N8N_EXTERNAL_PROVIDER_WRITES": False,
    }
    with pytest.raises(ConfigurationError, match="EXTERNAL_DELIVERY_ENABLED"):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "EXTERNAL_DELIVERY_ENABLED": "missing-is-not-false",
            }
        )


def test_staging_rejects_enabled_umbrella_control() -> None:
    with pytest.raises(ConfigurationError, match="staging umbrella controls"):
        Settings.from_env(
            {**staging_env(), "EXTERNAL_MODEL_CALLS_ENABLED": "true"}
        )


def test_external_delivery_umbrella_is_an_authoritative_kill_switch() -> None:
    with pytest.raises(ConfigurationError, match="EXTERNAL_DELIVERY_ENABLED"):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "ODOO_WRITE": "true",
                "FORM_ODOO_DELIVERY_ENABLED": "true",
                "ODOO_19_BASE_URL": "https://odoo.internal.invalid",
                "ODOO_19_HMAC_SECRET": "s" * 40,
            }
        )


def test_jetstream_dispatch_requires_matching_gate_and_authorization() -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "OUTBOX_DISPATCH_ENABLED": "true",
            }
        )
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "SEND_EVENTS": "true",
                "OUTBOX_DISPATCH_ENABLED": "true",
            }
        )


def production_jetstream_env() -> dict[str, str]:
    """A JetStream activation that satisfies every transport-level rule."""
    env = {
        "APP_ENV": "production",
        "RUNTIME_PROFILE_ID": "codestra-middleware-production-v1",
        "DATABASE_URL": (
            "postgresql://middleware_production:secret@"
            "postgresql.middleware-production.svc.cluster.local:5432/"
            "codestra_production?sslmode=verify-full"
        ),
        "REDIS_URL": (
            "rediss://middleware-production:secret@"
            "redis.middleware-production.svc.cluster.local:6379/0"
        ),
        "NATS_URL": "tls://nats.middleware-production.svc.cluster.local:4222",
        "NATS_STREAM": "CODESTRA_EVENTS",
        "NATS_SUBJECT_PREFIX": "codestra.events",
        "NATS_CREDS_FILE": "/run/secrets/middleware-production-nats.creds",
        "NATS_DISPATCH_MODE": "production",
        "PRODUCTION_ACTIVATION_ID": "CHG-20260828-EVENTS",
        "SEND_EVENTS": "true",
        "OUTBOX_DISPATCH_ENABLED": "true",
        "APP_SOURCE_SHA": "a" * 40,
        "IMAGE_DIGEST": "sha256:" + "b" * 64,
        "BUILD_TIME": "2026-08-28T12:00:00Z",
    }
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32
    return env


# SEND_EVENTS gates the JetStream outbox transport only. The n8n broad-event
# pipeline has its own first switch (BROAD_EVENT_SEND_ENABLED) and its own
# conjunction; the two never imply each other.
BROAD_EVENT_GATES = {
    "BROAD_EVENT_SEND_ENABLED": "true",
    "BROAD_EVENT_DELIVERY_ENABLED": "true",
    "PRODUCTION_N8N_ENABLED": "true",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED": "true",
    "CONTROLLED_BROAD_EVENT_ACTIVATION": "true",
    "BROAD_EVENT_BUSINESS_UNIT_ALLOWLIST": "BU-TEST",
    "BROAD_EVENT_CAMPAIGN_ALLOWLIST": "TEST_SYN",
    "BROAD_EVENT_WORKFLOW_ALLOWLIST": "wf-test",
    "BROAD_EVENT_TYPE_ALLOWLIST": "lead.created",
    "BROAD_EVENT_ACTIVATION_HIGH_WATER_MARK": "2026-08-28T12:00:00Z",
    "BROAD_EVENT_SUBMISSION_LIMIT": "1",
}


def test_production_jetstream_dispatch_requires_approved_identity() -> None:
    settings = Settings.from_env(production_jetstream_env())
    assert settings.outbox_dispatch_enabled is True
    assert settings.production_activation_id == "CHG-20260828-EVENTS"
    assert settings.broad_event_pipeline_enabled is False

    without_activation = production_jetstream_env()
    del without_activation["PRODUCTION_ACTIVATION_ID"]
    with pytest.raises(ConfigurationError, match="PRODUCTION_ACTIVATION_ID"):
        Settings.from_env(without_activation)

    wrong_stream = {**production_jetstream_env(), "NATS_STREAM": "CODESTRA_STAGING_EVENTS"}
    with pytest.raises(ConfigurationError, match="NATS_STREAM"):
        Settings.from_env(wrong_stream)

    plaintext = {
        **production_jetstream_env(),
        "NATS_URL": "nats://nats.middleware-production.svc.cluster.local:4222",
    }
    with pytest.raises(ConfigurationError, match="NATS_URL"):
        Settings.from_env(plaintext)


def test_jetstream_and_broad_event_gates_are_independent() -> None:
    # A single broad-event switch without the rest fails closed regardless of
    # SEND_EVENTS; the full set is refused because the n8n production-workflow
    # effect is not implemented by this runtime.
    with pytest.raises(ConfigurationError, match="broad-event activation"):
        Settings.from_env({**production_jetstream_env(), "BROAD_EVENT_SEND_ENABLED": "true"})
    with pytest.raises(
        ConfigurationError,
        match="not implemented by this runtime: N8N_PRODUCTION_WORKFLOWS_ENABLED",
    ):
        Settings.from_env({**production_jetstream_env(), **BROAD_EVENT_GATES})


def test_staging_uses_an_isolated_jetstream_namespace() -> None:
    env = staging_env()
    env.update(
        {
            "NATS_URL": "tls://nats.middleware-staging.svc.cluster.local:4222",
            "NATS_STREAM": "CODESTRA_STAGING_EVENTS",
            "NATS_SUBJECT_PREFIX": "codestra.staging.events",
            "NATS_CREDS_FILE": "/run/secrets/middleware-staging-nats.creds",
            "NATS_DISPATCH_MODE": "isolated",
            "SEND_EVENTS": "true",
            "OUTBOX_DISPATCH_ENABLED": "true",
        }
    )
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32

    settings = Settings.from_env(env)
    assert settings.nats_dispatch_mode == "isolated"
    assert settings.nats_subject_prefix == "codestra.staging.events"

    with pytest.raises(ConfigurationError, match="NATS_STREAM"):
        Settings.from_env({**env, "NATS_STREAM": "CODESTRA_EVENTS"})


def test_staging_rejects_production_jetstream_namespace() -> None:
    env = staging_env()
    env.update(
        {
            "NATS_URL": "tls://nats.middleware-staging.svc.cluster.local:4222",
            "NATS_STREAM": "CODESTRA_EVENTS",
            "NATS_SUBJECT_PREFIX": "codestra.events",
            "NATS_CREDS_FILE": "/run/secrets/middleware-staging-nats.creds",
            "NATS_DISPATCH_MODE": "isolated",
            "SEND_EVENTS": "true",
            "OUTBOX_DISPATCH_ENABLED": "true",
        }
    )
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32

    with pytest.raises(ConfigurationError):
        Settings.from_env(env)


def test_temporal_test_worker_requires_isolated_local_configuration() -> None:
    settings = Settings.from_env(
        {
            "APP_ENV": "test",
            "ALLOW_IN_MEMORY_STORAGE": "true",
            "TEMPORAL_ADDRESS": "127.0.0.1:7233",
            "TEMPORAL_NAMESPACE": "codestra-test",
            "TEMPORAL_TASK_QUEUE": "codestra-test-critical",
            "TEMPORAL_WORKER_MODE": "isolated",
            "TEMPORAL_ALLOW_INSECURE_TEST_CONNECTION": "true",
        }
    )
    assert settings.temporal_worker_mode == "isolated"

    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "TEMPORAL_ADDRESS": "temporal.example:7233",
                "TEMPORAL_NAMESPACE": "codestra-test",
                "TEMPORAL_TASK_QUEUE": "codestra-test-critical",
                "TEMPORAL_WORKER_MODE": "isolated",
                "TEMPORAL_ALLOW_INSECURE_TEST_CONNECTION": "true",
            }
        )


def test_staging_cannot_use_in_memory_storage() -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": "staging",
                "ALLOW_IN_MEMORY_STORAGE": "true",
            }
        )


def staging_env() -> dict[str, str]:
    return {
        "APP_ENV": "staging",
        "RUNTIME_PROFILE_ID": "codestra-middleware-staging-v1",
        "DATABASE_URL": (
            "postgresql://middleware_staging:secret@"
            "postgresql.middleware-staging.svc.cluster.local:5432/"
            "codestra_staging?sslmode=verify-full"
        ),
        "REDIS_URL": (
            "rediss://middleware-staging:secret@"
            "redis.middleware-staging.svc.cluster.local:6379/14"
        ),
        "NATS_STREAM": "CODESTRA_STAGING_EVENTS",
        "NATS_SUBJECT_PREFIX": "codestra.staging.events",
        "TEMPORAL_NAMESPACE": "codestra-staging",
        "TEMPORAL_TASK_QUEUE": "codestra-staging-critical",
        "KEYCLOAK_ISSUER": "https://auth-staging.codestra.co/realms/codestra",
        "KEYCLOAK_JWKS_URI": "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/certs",
        "APP_SOURCE_SHA": "a" * 40,
        "IMAGE_DIGEST": "sha256:" + "b" * 64,
        "BUILD_TIME": "2026-08-26T23:00:00Z",
    }


def test_staging_requires_immutable_release_identity() -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": "staging",
                "DATABASE_URL": "postgresql://example.invalid/db",
                "REDIS_URL": "redis://example.invalid/0",
            }
        )


def test_staging_requires_every_webhook_secret() -> None:
    env = staging_env()
    with pytest.raises(ConfigurationError):
        Settings.from_env(env)

    for producer in WEBHOOK_PRODUCERS:
        name = "WEBHOOK_SECRET_" + producer.upper().replace("-", "_").replace(".", "_")
        env[name] = "x" * 32
    settings = Settings.from_env(env)
    settings.validate_all_webhook_secrets()


def test_staging_rejects_production_identity_authority() -> None:
    env = staging_env()
    env["KEYCLOAK_ISSUER"] = "https://auth.codestra.co/realms/codestra"
    env["KEYCLOAK_JWKS_URI"] = "https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs"
    with pytest.raises(ConfigurationError, match="staging identity authority"):
        Settings.from_env(env)


def test_production_rejects_staging_identity_authority() -> None:
    with pytest.raises(ConfigurationError, match="production identity authority"):
        Settings.from_env(
            {
                "APP_ENV": "production",
                "KEYCLOAK_ISSUER": "https://auth-staging.codestra.co/realms/codestra",
                "KEYCLOAK_JWKS_URI": "https://auth-staging.codestra.co/realms/codestra/protocol/openid-connect/certs",
            }
        )


def test_runtime_profiles_reject_cross_environment_resources_and_activation() -> None:
    env = staging_env()
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32

    production_database = (
        "postgresql://middleware_production:secret@"
        "postgresql.middleware-production.svc.cluster.local:5432/"
        "codestra_production?sslmode=verify-full"
    )
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        Settings.from_env({**env, "DATABASE_URL": production_database})
    with pytest.raises(ConfigurationError, match="REDIS_URL"):
        Settings.from_env(
            {
                **env,
                "REDIS_URL": (
                    "rediss://middleware-production:secret@"
                    "redis.middleware-production.svc.cluster.local:6379/0"
                ),
            }
        )
    with pytest.raises(ConfigurationError, match="PRODUCTION_ACTIVATION_ID"):
        Settings.from_env(
            {**env, "PRODUCTION_ACTIVATION_ID": "CHG-20260828-PRODUCTION"}
        )


def test_runtime_profile_identity_is_mandatory_and_not_allowed_in_tests() -> None:
    env = staging_env()
    env.pop("RUNTIME_PROFILE_ID")
    with pytest.raises(ConfigurationError, match="RUNTIME_PROFILE_ID"):
        Settings.from_env(env)
    with pytest.raises(ConfigurationError, match="reserved"):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "RUNTIME_PROFILE_ID": "codestra-middleware-staging-v1",
            }
        )


def test_production_compose_profile_is_locked_and_effects_disabled() -> None:
    env = {
        "APP_ENV": "production",
        "RUNTIME_PROFILE_ID": "codestra-middleware-production-compose-v1",
        "DATABASE_URL": (
            "postgresql://appolon_middleware_api:secret@codestra-postgres-1:5432/"
            "codestra_middleware_appolon"
        ),
        "REDIS_URL": "redis://middleware-service:secret@redis:6379/0",
        "NATS_STREAM": "CODESTRA_EVENTS",
        "NATS_SUBJECT_PREFIX": "codestra.events",
        "NATS_DISPATCH_MODE": "disabled",
        "TEMPORAL_NAMESPACE": "codestra-production",
        "TEMPORAL_TASK_QUEUE": "codestra-production-critical",
        "TEMPORAL_WORKER_MODE": "disabled",
        "APP_SOURCE_SHA": "a" * 40,
        "IMAGE_DIGEST": "sha256:" + "b" * 64,
        "BUILD_TIME": "2026-08-30T12:00:00Z",
    }
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32

    settings = Settings.from_env(env)

    assert settings.runtime_profile_id == "codestra-middleware-production-compose-v1"
    assert settings.production_activation_id is None
    assert settings.outbox_dispatch_enabled is False
    assert not any(settings.external_effects.values())


def test_production_compose_profile_rejects_legacy_sqlalchemy_url_and_activation() -> None:
    env = {
        "APP_ENV": "production",
        "RUNTIME_PROFILE_ID": "codestra-middleware-production-compose-v1",
        "DATABASE_URL": (
            "postgresql+asyncpg://appolon_middleware_api:secret@"
            "codestra-postgres-1:5432/codestra_middleware_appolon"
        ),
        "REDIS_URL": "redis://middleware-service:secret@redis:6379/0",
        "APP_SOURCE_SHA": "a" * 40,
        "IMAGE_DIGEST": "sha256:" + "b" * 64,
        "BUILD_TIME": "2026-08-30T12:00:00Z",
    }
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32

    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        Settings.from_env(env)
    with pytest.raises(ConfigurationError, match="PRODUCTION_ACTIVATION_ID"):
        Settings.from_env(
            {
                **env,
                "DATABASE_URL": (
                    "postgresql://appolon_middleware_api:secret@"
                    "codestra-postgres-1:5432/codestra_middleware_appolon"
                ),
                "PRODUCTION_ACTIVATION_ID": "not-authorized",
            }
        )


def test_staging_temporal_is_bound_to_staging_identity_and_credentials() -> None:
    env = staging_env()
    env.update(
        {
            "TEMPORAL_ADDRESS": (
                "temporal.middleware-staging.svc.cluster.local:7233"
            ),
            "TEMPORAL_WORKER_MODE": "isolated",
            "TEMPORAL_SERVER_ROOT_CA_FILE": (
                "/run/secrets/middleware-staging-temporal-ca.pem"
            ),
            "TEMPORAL_CLIENT_CERT_FILE": (
                "/run/secrets/middleware-staging-temporal-client.pem"
            ),
            "TEMPORAL_CLIENT_KEY_FILE": (
                "/run/secrets/middleware-staging-temporal-client-key.pem"
            ),
            "TEMPORAL_TLS_SERVER_NAME": (
                "temporal.middleware-staging.svc.cluster.local"
            ),
        }
    )
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32
    assert Settings.from_env(env).temporal_worker_mode == "isolated"

    with pytest.raises(ConfigurationError, match="TEMPORAL_ADDRESS"):
        Settings.from_env(
            {
                **env,
                "TEMPORAL_ADDRESS": (
                    "temporal.middleware-production.svc.cluster.local:7233"
                ),
            }
        )


def test_locked_profiles_convert_malformed_resource_urls_to_configuration_errors() -> None:
    env = staging_env()
    for producer in WEBHOOK_PRODUCERS:
        env[
            "WEBHOOK_SECRET_"
            + producer.upper().replace("-", "_").replace(".", "_")
        ] = "x" * 32
    with pytest.raises(ConfigurationError, match="DATABASE_URL"):
        Settings.from_env({**env, "DATABASE_URL": "postgresql://host:bad/db"})
    with pytest.raises(ConfigurationError, match="REDIS_URL"):
        Settings.from_env({**env, "REDIS_URL": "rediss://host:bad/14"})


def test_webhook_secret_uses_supplied_environment_mapping() -> None:
    settings = Settings.from_env(
        {
            "APP_ENV": "test",
            "ALLOW_IN_MEMORY_STORAGE": "true",
            "WEBHOOK_SECRET_ODOO_INTEGRATION": "s" * 32,
        }
    )
    assert settings.webhook_secret("odoo-integration") == b"s" * 32


def test_jwks_uri_is_pinned_to_canonical_issuer() -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": "test",
                "ALLOW_IN_MEMORY_STORAGE": "true",
                "KEYCLOAK_JWKS_URI": "http://attacker.invalid/jwks",
            }
        )


def test_ci_readiness_identity_uses_canonical_jwks_url_alias() -> None:
    settings = Settings.from_env(
        {
            "APP_ENV": "test",
            "ALLOW_IN_MEMORY_STORAGE": "true",
            "KEYCLOAK_ISSUER": "https://ci-identity.example.invalid/realm",
            "KEYCLOAK_JWKS_URL": "http://127.0.0.1:8120/certs.json",
        }
    )
    assert settings.issuer == "https://ci-identity.example.invalid/realm"
    assert settings.jwks_uri == "http://127.0.0.1:8120/certs.json"


@pytest.mark.parametrize("environment", ["staging", "production"])
def test_synthetic_ci_identity_is_forbidden_in_deployable_environments(
    environment: str,
) -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(
            {
                "APP_ENV": environment,
                "KEYCLOAK_ISSUER": "https://ci-identity.example.invalid/realm",
                "KEYCLOAK_JWKS_URL": "http://127.0.0.1:8120/certs.json",
            }
        )
