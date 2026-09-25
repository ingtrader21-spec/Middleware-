"""Architecture governance: one authority per concern, enforced on source.

These tests read the repository, not the running application, so a second
Settings class, FastAPI factory, pool, engine, verifier or health surface
fails CI before it can drift. Every allowed exception is named here with its
reason; extending an allowlist is a reviewed architectural decision.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ("app", "workers", "scripts")


def _python_files(*dirs: str) -> list[Path]:
    files: list[Path] = []
    for name in dirs:
        files.extend(sorted((ROOT / name).rglob("*.py")))
    return files


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _files_matching(pattern: str, *dirs: str) -> set[str]:
    regex = re.compile(pattern)
    return {_rel(path) for path in _python_files(*dirs) if regex.search(_read(path))}


# ----------------------------------------------------------------------
# Configuration authority
# ----------------------------------------------------------------------
def test_settings_class_is_defined_once() -> None:
    definitions = {
        _rel(path)
        for path in _python_files("app", "workers")
        if any(
            isinstance(node, ast.ClassDef) and node.name == "Settings"
            for node in ast.parse(_read(path)).body
        )
    }
    assert definitions == {"app/core/config.py"}


def test_legacy_modules_are_pure_shims() -> None:
    shims = {
        "app/config.py": "app.core.config",
        "app/runtime.py": "app.core.runtime",
        "app/appolon_factory.py": "app.application",
    }
    for relative, canonical in shims.items():
        tree = ast.parse(_read(ROOT / relative))
        assert not any(
            isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            for node in tree.body
        ), f"{relative} defines something of its own"
        imports = [
            node.module
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.level == 0
        ]
        assert canonical in imports, f"{relative} does not re-export {canonical}"
        assert "DeprecationWarning" in _read(ROOT / relative)


# Importers still on the app.config shim. The lead-automation workflow gate
# forbids touching vicidial-named files in a PR that changes
# app/api/v1/lead_automation.py, so this one-line import migrates in the next
# release; the shim resolves to the same canonical class meanwhile.
LEGACY_SHIM_IMPORTERS_PENDING = {"app/vicidial_internal_call_adapter.py"}


def test_no_consumer_imports_a_legacy_shim() -> None:
    offenders = _files_matching(
        r"^\s*from (app\.config|app\.runtime|app\.appolon_factory|\.config|\.runtime) import",
        "app",
        "workers",
        "scripts",
        "tests",
    ) - {"app/config.py", "app/runtime.py", "app/appolon_factory.py"}
    # The connector runtime service and the connector SDK own their own
    # ``config``/``runtime`` modules; they are isolated services.
    offenders = {path for path in offenders if not path.startswith(("services/", "middleware/"))}
    assert offenders <= LEGACY_SHIM_IMPORTERS_PENDING, sorted(offenders - LEGACY_SHIM_IMPORTERS_PENDING)


def test_environment_is_read_only_by_configuration_authority() -> None:
    """``os.getenv``/``os.environ`` outside the allowlist would create a second
    configuration authority. The allowlist is a ratchet: it may only shrink."""
    allowed = {
        "app/core/config.py",  # the authority
        "app/core/bootstrap.py",  # SERVICE_NAME / QUEUE_NAME process identity
        "app/entrypoints/runtime.py",  # PORT, LOG_LEVEL, SERVICE_NAME, WORKER_INTERVAL_SECONDS
        # Approved isolated services and workers with their own process contract.
        "app/email/api.py",
        "app/email/runtime.py",
        "app/email/schema.py",
        "app/email/worker.py",
        "app/entrypoints/elevenlabs_egress_gateway.py",
        "app/entrypoints/jetstream_dlq_worker.py",
        "app/qwen_auth_verifier.py",
        # Adapters that read mounted secret paths / provider env by design.
        "app/calling_contract.py",
        "app/klyrow_alert_adapter.py",
        "app/klyrow_email_adapter.py",
        "app/monitoring/backends.py",
        "app/observability_alert_contract.py",
        "app/odoo_provider_adapter.py",
        "app/postly_social_adapter.py",
        "app/telnexa_provider_adapter.py",
        "app/vicidial_internal_call_adapter.py",
        "app/vicidial_odoo_projection_config_base.py",
    }
    actual = _files_matching(r"os\.getenv\(|os\.environ\b", "app")
    assert actual <= allowed, f"new environment readers: {sorted(actual - allowed)}"


# ----------------------------------------------------------------------
# Application factory and route registry
# ----------------------------------------------------------------------
APPROVED_FASTAPI_CONSTRUCTIONS = {
    "app/application.py",  # the single factory
    "app/entrypoints/runtime.py",  # worker_app operational surface
    # Narrow deployed processes that serve a subset of routers on their own port.
    "app/entrypoints/controller_api.py",
    "app/entrypoints/event_gateway.py",
    "app/entrypoints/extension_allocator.py",
    "app/entrypoints/policy_engine.py",
    "app/entrypoints/server_a_agent.py",
    "app/entrypoints/telephony_provisioning.py",
    "app/entrypoints/webphone_session_issuer.py",
    # Isolated services with their own runtime contract.
    "app/email/api.py",
    "app/observability_alerts.py",
    "app/qwen_auth_verifier.py",
    "scripts/generate_integrated_monitoring_openapi.py",
    # In-process no-effect harness: mounts only the Telnexa router with a
    # database sentinel override; never served on a port.
    "scripts/telnexa_callback_harness.py",
}


def test_fastapi_is_constructed_only_by_approved_modules() -> None:
    actual = _files_matching(r"\bFastAPI\(", "app", "workers", "scripts")
    assert actual <= APPROVED_FASTAPI_CONSTRUCTIONS, sorted(actual - APPROVED_FASTAPI_CONSTRUCTIONS)


def test_create_app_is_defined_once() -> None:
    definitions = {
        _rel(path)
        for path in _python_files("app")
        if any(
            isinstance(node, ast.FunctionDef) and node.name == "create_app"
            for node in ast.parse(_read(path)).body
        )
    }
    # The two isolated services keep their own factories; every Middleware
    # process (integration API, canary, monolith) builds from app/application.py.
    assert definitions == {
        "app/application.py",
        "app/observability_alerts.py",
        "app/qwen_auth_verifier.py",
    }


def test_routers_are_mounted_only_through_the_registry() -> None:
    """No module besides the registry includes routers on the canonical app."""
    offenders = {
        _rel(path)
        for path in _python_files("app")
        if re.search(r"\bapp\.include_router\(", _read(path))
    }
    allowed = {
        "app/router_registry.py",
        # Narrow processes assemble their own subset explicitly.
        "app/entrypoints/controller_api.py",
        "app/entrypoints/event_gateway.py",
        "app/entrypoints/extension_allocator.py",
        "app/entrypoints/policy_engine.py",
        "app/entrypoints/server_a_agent.py",
        "app/entrypoints/telephony_provisioning.py",
        "app/entrypoints/webphone_session_issuer.py",
        "app/email/api.py",
        "app/observability_alerts.py",
        "app/qwen_auth_verifier.py",
    }
    assert offenders <= allowed, sorted(offenders - allowed)


def test_every_profile_is_unique_and_nested_in_the_monolith() -> None:
    from app.application import AppProfile, create_app
    from app.core.config import Settings
    from app.router_registry import assert_unique_routes, route_operations

    settings = Settings.from_env({"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"})
    integration = create_app(settings=settings, profile=AppProfile.INTEGRATION)
    control_plane = create_app(settings=settings, profile=AppProfile.CONTROL_PLANE)
    monolith = create_app(settings=settings, profile=AppProfile.MONOLITH)
    for application in (integration, control_plane, monolith):
        assert_unique_routes(application)
    integration_ops = set(route_operations(integration))
    control_plane_ops = set(route_operations(control_plane))
    monolith_ops = set(route_operations(monolith))
    assert integration_ops < monolith_ops
    assert control_plane_ops < monolith_ops
    # Both deployed profiles share the contract-backed canonical routes and
    # the health surface; each adds its own group.
    assert integration_ops & control_plane_ops
    assert integration_ops - control_plane_ops
    assert control_plane_ops - integration_ops
    # The edge-denied aliases exist only on the monolith.
    for denied in (
        ("POST", "/v1/integrations/n8n/commands"),
        ("GET", "/v1/integrations/n8n/operations"),
    ):
        assert denied in monolith_ops
        assert denied not in integration_ops
        assert denied not in control_plane_ops


def test_health_routes_are_registered_only_by_the_health_authority() -> None:
    """Process-level health paths are registered on ``app`` only by
    ``app.core.health`` (routers may expose prefixed sub-resource health)."""
    pattern = re.compile(r"""@app\.get\(\s*["'](/health|/healthz|/health/live|/ready|/readyz|/health/ready|/readiness|/version|/capabilities|/dependencies|/health/dependencies)["']""")
    offenders = {
        _rel(path) for path in _python_files("app") if pattern.search(_read(path))
    }
    allowed = {
        "app/entrypoints/runtime.py",  # worker_app operational surface
        "app/email/api.py",
        "app/observability_alerts.py",
        "app/qwen_auth_verifier.py",
        "app/entrypoints/server_a_agent.py",
        "app/entrypoints/controller_api.py",
    }
    assert offenders <= allowed, sorted(offenders - allowed)


def test_single_request_guard() -> None:
    offenders = {
        _rel(path)
        for path in _python_files("app")
        if re.search(r"""@app\.middleware\(\s*["']http["']\s*\)|app\.middleware\(\s*["']http["']\s*\)\(""", _read(path))
    }
    allowed = {
        "app/core/request_guard.py",
        "app/entrypoints/runtime.py",  # worker_app operational headers
        "app/email/api.py",
        "app/observability_alerts.py",
        "app/qwen_auth_verifier.py",
        "app/entrypoints/server_a_agent.py",
        "app/entrypoints/controller_api.py",
    }
    assert offenders <= allowed, sorted(offenders - allowed)


# ----------------------------------------------------------------------
# Resource ownership
# ----------------------------------------------------------------------
def test_asyncpg_pools_are_opened_only_by_owners() -> None:
    allowed = {
        "app/core/runtime.py",  # the shared pool
        # Store ``connect`` classmethods for standalone workers/scripts.
        "app/automation_v2.py",
        "app/commands.py",
        "app/communications.py",
        "app/realtime.py",
        "app/storage.py",
        "workers/run_outbox.py",
        "scripts/verify_event_ledger.py",
    }
    actual = _files_matching(r"asyncpg\.create_pool\(", *SOURCE_DIRS)
    assert actual <= allowed, sorted(actual - allowed)


def test_sqlalchemy_engine_is_created_only_by_the_session_module() -> None:
    allowed = {
        "app/db/session.py",
        "scripts/migrate_runtime.py",  # NullPool migration engine, closed per run
        "scripts/benchmark_ai_orchestration.py",
    }
    actual = _files_matching(r"create_async_engine\(", *SOURCE_DIRS)
    assert actual <= allowed, sorted(actual - allowed)


def test_jwks_clients_are_created_only_by_the_identity_verifiers() -> None:
    allowed = {
        "app/security.py",
        "app/core/jwt_auth.py",
        "app/email/security.py",  # isolated service
        "scripts/certify_edge_integration.py",  # certification probe
    }
    actual = _files_matching(r"PyJWKClient\(", *SOURCE_DIRS)
    assert actual <= allowed, sorted(actual - allowed)


def test_canonical_identity_is_consumed_through_identity_settings() -> None:
    """Validators bound to the Middleware identity use ``from_identity``; raw
    ``settings.keycloak_*`` construction would create a second identity rule."""
    offenders = _files_matching(r"issuer=settings\.keycloak_issuer", "app")
    assert offenders == set()


# ----------------------------------------------------------------------
# Security invariants that must not regress
# ----------------------------------------------------------------------
@pytest.mark.parametrize(
    "snippet",
    [
        "expires_at - issued_at > 300",  # machine token lifetime
        "raise AuthorizationError(\"token azp does not match producer\")",
    ],
)
def test_security_module_keeps_machine_token_policy(snippet: str) -> None:
    assert snippet in _read(ROOT / "app/security.py")


def test_synthetic_ci_identity_is_never_valid_in_staging_or_production() -> None:
    from app.core.config import (
        SYNTHETIC_CI_ISSUER,
        SYNTHETIC_CI_JWKS_URL,
        ConfigurationError,
        Settings,
    )

    base = {
        "DATABASE_URL": "postgresql://u:p@h/db",
        "REDIS_URL": "rediss://h/0",
        "KEYCLOAK_ISSUER": SYNTHETIC_CI_ISSUER,
        "KEYCLOAK_JWKS_URL": SYNTHETIC_CI_JWKS_URL,
        "APP_SOURCE_SHA": "a" * 40,
        "IMAGE_DIGEST": "sha256:" + "b" * 64,
        "BUILD_TIME": "2026-09-18T00:00:00Z",
    }
    for env in ("staging", "production"):
        with pytest.raises(ConfigurationError):
            Settings.from_env({**base, "APP_ENV": env, "RUNTIME_PROFILE_ID": f"codestra-middleware-{env}-v1"})
    accepted = Settings.from_env({**base, "APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"})
    assert accepted.synthetic_ci_identity is True


def test_bootstrap_rejects_implicit_https_downgrade() -> None:
    from app.core.bootstrap import StartupError, validate_configuration
    from app.core.config import Settings

    settings = Settings.from_env({"APP_ENV": "test", "ALLOW_IN_MEMORY_STORAGE": "true"})
    settings.keycloak_issuer = "http://insecure.example.invalid/realm"
    settings.keycloak_jwks_url = "http://insecure.example.invalid/certs"
    with pytest.raises(StartupError):
        validate_configuration(settings)
