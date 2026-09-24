"""The single startup validation of a Middleware process.

Every API entrypoint, worker and script that hosts application code calls
:func:`validate_startup` exactly once before serving or consuming. It

1. resolves the canonical :class:`~app.core.config.Settings` (which already
   applies the environment policy, the effect gates and the safety rules),
2. re-asserts the identity invariants that must never regress, independent
   of what the configuration authority enforced,
3. applies the per-service requirements that used to be scattered over
   ``app.entrypoints.runtime.validate_runtime`` and the application factories,
4. publishes the canonical fail-closed flag state to Prometheus,

and returns a :class:`StartupReport`. Any defect raises
:class:`StartupError`; nothing degrades, nothing is guessed.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass

from prometheus_client import Gauge

from app.core.config import (
    CANONICAL_AUDIENCE,
    CANONICAL_SCHEMA_HEAD,
    ConfigurationError,
    IdentitySettings,
    Settings,
)

logger = logging.getLogger("codestra.bootstrap")

FEATURE_FLAG_STATE = Gauge(
    "codestra_feature_flag_state",
    "Canonical fail-closed feature flag state",
    ["service", "flag"],
)

# Services and the secrets they cannot start without.
SERVICE_INTEGRATION_API = "middleware-integration-api"
SERVICE_EVENT_GATEWAY = "middleware-event-gateway"
SERVICE_POLICY_ENGINE = "middleware-policy-engine"
SERVICE_CANONICAL_API = "middleware-api"

CANONICAL_FLAGS = (
    "send_events",
    "broad_event_send_enabled",
    "broad_event_delivery_enabled",
    "production_n8n_enabled",
    "n8n_production_workflows_enabled",
    "enable_external_delivery",
)


class StartupError(RuntimeError):
    """The process must not start."""


@dataclass(frozen=True)
class StartupReport:
    service: str
    settings: Settings
    identity: IdentitySettings
    canonical_flags: dict[str, bool]
    schema_head: str

    @property
    def summary(self) -> dict[str, object]:
        """Log-safe description of the validated start (no secrets)."""
        return {
            "service": self.service,
            "app_env": self.settings.app_env,
            "environment": self.settings.environment,
            "runtime_profile_id": self.settings.runtime_profile_id,
            "issuer": self.identity.issuer,
            "audience": self.identity.audience,
            "synthetic_ci_identity": self.settings.synthetic_ci_identity,
            "schema_head": self.schema_head,
            "canonical_flags": dict(self.canonical_flags),
            "external_effects_enabled": sorted(
                name for name, on in self.settings.external_effects.items() if on
            ),
            "umbrella_controls_enabled": sorted(
                name for name, on in self.settings.umbrella_controls.items() if on
            ),
        }


def _assert_identity_invariants(settings: Settings) -> IdentitySettings:
    """Identity rules that hold regardless of how ``settings`` was produced."""
    identity = settings.identity
    if not identity.issuer.startswith("https://") and not settings.synthetic_ci_identity:
        raise StartupError("KEYCLOAK_ISSUER must be an https:// authority")
    if identity.audience != CANONICAL_AUDIENCE:
        raise StartupError(f"KEYCLOAK_AUDIENCE must be {CANONICAL_AUDIENCE}")
    if not identity.jwks_url:
        raise StartupError("KEYCLOAK_JWKS_URL is required")
    if settings.app_env in {"staging", "production"}:
        if settings.synthetic_ci_identity:
            raise StartupError(
                "the synthetic CI identity is never valid in staging/production"
            )
        if identity.issuer != settings.expected_issuer:
            raise StartupError(
                f"KEYCLOAK_ISSUER must match the {settings.app_env} identity authority"
            )
        if not identity.jwks_url.startswith("https://"):
            raise StartupError("KEYCLOAK_JWKS_URL must use https:// in staging/production")
    if identity.max_token_lifetime_seconds != 300 or identity.algorithms != ("RS256",):
        raise StartupError("identity token policy must stay RS256 with a 300-second lifetime")
    return identity


def _assert_service_requirements(
    settings: Settings, service: str, queue: str | None, environ: Mapping[str, str]
) -> None:
    expected = environ.get("SERVICE_NAME")
    if expected and expected != service:
        raise StartupError(f"SERVICE_NAME must be {service}")
    if queue is not None:
        configured = environ.get("QUEUE_NAME", queue)
        if configured != queue:
            raise StartupError(f"QUEUE_NAME must be {queue}")
    if service == SERVICE_EVENT_GATEWAY:
        if not settings.auth_ready:
            raise StartupError("event gateway authorization configuration is incomplete")
        settings.quarantine_fingerprint_secret
        settings.quarantine_encryption_key
    if service in {SERVICE_INTEGRATION_API, SERVICE_POLICY_ENGINE, SERVICE_CANONICAL_API}:
        if not settings.middleware_secret:
            raise StartupError(f"{service} authorization configuration is incomplete")
    if service in {SERVICE_INTEGRATION_API, SERVICE_CANONICAL_API}:
        settings.quarantine_fingerprint_secret
        settings.quarantine_encryption_key
        settings.quarantine_reviewer_secret
    if settings.schema_head != CANONICAL_SCHEMA_HEAD:
        raise StartupError(f"SCHEMA_HEAD must be {CANONICAL_SCHEMA_HEAD}")


def validate_configuration(settings: Settings | None = None) -> tuple[Settings, IdentitySettings]:
    """Resolve and fully validate the configuration an application is built from.

    This is the configuration half of startup validation: environment
    policy, effect gates, safety rules and the identity invariants. It does
    not apply per-service process requirements (secrets a given service
    cannot run without); :func:`validate_startup` adds those when a process
    actually starts serving.
    """
    try:
        resolved = settings if settings is not None else Settings.from_env()
        if settings is not None:
            # An injected Settings may predate its own validation.
            resolved.validate_domain()
            resolved.validate_safety()
    except (ConfigurationError, ValueError) as exc:
        raise StartupError(str(exc)) from exc
    return resolved, _assert_identity_invariants(resolved)


def validate_startup(
    service: str,
    *,
    settings: Settings | None = None,
    queue: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> StartupReport:
    """Validate everything a process needs before it serves; fail closed."""
    env = os.environ if environ is None else environ
    resolved, identity = validate_configuration(settings)
    try:
        _assert_service_requirements(resolved, service, queue, env)
    except (ConfigurationError, ValueError) as exc:
        raise StartupError(str(exc)) from exc

    flags = {name: bool(getattr(resolved, name)) for name in CANONICAL_FLAGS}
    for flag, enabled in flags.items():
        FEATURE_FLAG_STATE.labels(service=service, flag=flag).set(int(enabled))
    report = StartupReport(
        service=service,
        settings=resolved,
        identity=identity,
        canonical_flags=flags,
        schema_head=resolved.schema_head,
    )
    logger.info(
        "startup validated",
        extra={"result": json.dumps(report.summary, sort_keys=True, default=str)},
    )
    return report
