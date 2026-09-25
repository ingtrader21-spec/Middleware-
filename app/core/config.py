"""Canonical Middleware configuration authority.

``from app.core.config import Settings, settings`` is the only configuration
interface for the primary Middleware process. Environment names are read once
here (with the temporary compatibility aliases listed in
``COMPATIBILITY_ENV_ALIASES``); secret files are loaded here; environment
policy (staging/production strictness, synthetic CI identity only in
development/test) is validated in ``validate_domain()``, which
``app.core.bootstrap`` runs at startup and which is fatal there.
"""

import base64
import contextvars
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse, urlsplit

from pydantic import AliasChoices, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, EnvSettingsSource, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_PROFILES_PATH = ROOT / "config" / "runtime-profiles.v1.json"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CANONICAL_SCHEMA_HEAD = "0067_service_catalog_monitoring_state"
PRODUCTION_ISSUER = "https://auth.codestra.co/realms/codestra"
STAGING_ISSUER = "https://auth-staging.codestra.co/realms/codestra"
CANONICAL_AUDIENCE = "middleware-api"
# The only non-real identity the runtime ever accepts, and only for
# APP_ENV in {development, test}; staging/production reject it.
SYNTHETIC_CI_ISSUER = "https://ci-identity.example.invalid/realm"
SYNTHETIC_CI_JWKS_URL = "http://127.0.0.1:8120/certs.json"
WEBHOOK_PRODUCERS = (
    "odoo-integration",
    "n8n-automation",
    "vicidial-adapter",
    "telnexa-gateway",
    "klyrow-gateway",
    "kyqra-gateway",
    "postly-adapter",
)
# Effects this runtime actually implements. Anything else must stay off, so a
# capability cannot be switched on before its handler exists.
SUPPORTED_EXTERNAL_EFFECTS = frozenset(
    {
        "SEND_EVENTS",
        "ODOO_WRITE",
        "FORM_ODOO_DELIVERY_ENABLED",
        "CRAWLER_ODOO_DELIVERY_ENABLED",
        "SCRAPPER_ODOO_DELIVERY_ENABLED",
        "SMS_DELIVERY_ENABLED",
        "EMAIL_DELIVERY_ENABLED",
        "SOCIAL_DELIVERY_ENABLED",
    }
)
EXTERNAL_DELIVERY_EFFECTS = frozenset(
    {
        "ODOO_WRITE",
        "FORM_ODOO_DELIVERY_ENABLED",
        "CRAWLER_ODOO_DELIVERY_ENABLED",
        "SCRAPPER_ODOO_DELIVERY_ENABLED",
        "SMS_DELIVERY_ENABLED",
        "EMAIL_DELIVERY_ENABLED",
    }
)
# System-wide kill switches are a separate contract from implementation-level
# effect gates. They must never be inferred from the lower-level controls.
UMBRELLA_CONTROL_NAMES = (
    "LIVE_ADVERTISING_ENABLED",
    "EXTERNAL_DELIVERY_ENABLED",
    "SOCIAL_PUBLISHING_ENABLED",
    "EXTERNAL_MODEL_CALLS_ENABLED",
    "N8N_EXTERNAL_PROVIDER_WRITES",
)
# Environment name -> Settings field carrying that external-effect flag.
EXTERNAL_EFFECT_FIELDS: dict[str, str] = {
    "SEND_EVENTS": "send_events",
    "ENABLE_EXTERNAL_DELIVERY": "enable_external_delivery",
    "LIVE_WRITE": "live_write",
    "LIVE_WRITES": "live_writes",
    "ODOO_WRITE": "odoo_write",
    "CALLBACK_DISPATCH": "callback_dispatch",
    "N8N_DELIVERY_ENABLED": "n8n_delivery_enabled",
    "VICIDIAL_WRITES_ENABLED": "vicidial_writes_enabled",
    "EXTERNAL_DIAL_ENABLED": "external_dial_enabled",
    "PRODUCTION_CALLBACKS_ENABLED": "production_callbacks_enabled",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED": "n8n_production_workflows_enabled",
    "FORM_ODOO_DELIVERY_ENABLED": "form_odoo_delivery_enabled",
    "CRAWLER_ODOO_DELIVERY_ENABLED": "crawler_odoo_delivery_enabled",
    "SCRAPPER_ODOO_DELIVERY_ENABLED": "scrapper_odoo_delivery_enabled",
    "CRAWLER_EXTERNAL_CONTACT_ENABLED": "crawler_external_contact_enabled",
    "SCRAPPER_EXTERNAL_CONTACT_ENABLED": "scrapper_external_contact_enabled",
    "SMS_DELIVERY_ENABLED": "effect_sms_delivery_enabled",
    "EMAIL_DELIVERY_ENABLED": "effect_email_delivery_enabled",
    "SOCIAL_DELIVERY_ENABLED": "effect_social_delivery_enabled",
    "CRAWLER_EXECUTION_ENABLED": "crawler_execution_enabled",
    "SCRAPPER_EXECUTION_ENABLED": "scrapper_execution_enabled",
    "LIVE_SMS_DELIVERY": "live_sms_delivery",
    "LIVE_EMAIL_DELIVERY": "live_email_delivery",
    "UNRESTRICTED_CRAWLING": "unrestricted_crawling",
}
UMBRELLA_CONTROL_FIELDS: dict[str, str] = {
    "LIVE_ADVERTISING_ENABLED": "umbrella_live_advertising_enabled",
    "EXTERNAL_DELIVERY_ENABLED": "umbrella_external_delivery_enabled",
    "SOCIAL_PUBLISHING_ENABLED": "umbrella_social_publishing_enabled",
    "EXTERNAL_MODEL_CALLS_ENABLED": "umbrella_external_model_calls_enabled",
    "N8N_EXTERNAL_PROVIDER_WRITES": "umbrella_n8n_external_provider_writes",
}
# Legacy environment names still accepted (removed after Mission-2
# certification). Canonical name -> legacy names.
COMPATIBILITY_ENV_ALIASES: dict[str, tuple[str, ...]] = {
    "KEYCLOAK_JWKS_URL": ("KEYCLOAK_JWKS_URI",),
    "KEYCLOAK_AUDIENCE": ("MIDDLEWARE_AUDIENCE",),
}


class ConfigurationError(ValueError):
    """Raised when runtime configuration is unsafe or incomplete."""


def _secret_env_name(producer_client_id: str) -> str:
    return "WEBHOOK_SECRET_" + producer_client_id.upper().replace("-", "_").replace(
        ".", "_"
    )


def _is_absolute_mount_path(path: Path) -> bool:
    value = str(path)
    return (
        path.is_absolute()
        or value.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:[\\/]", value) is not None
    )


def _runtime_profiles() -> dict[str, dict[str, object]]:
    try:
        value = json.loads(RUNTIME_PROFILES_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError("runtime profile registry cannot be loaded") from exc
    if value.get("schema_version") != "1.0":
        raise ConfigurationError("runtime profile registry version is unsupported")
    raw_profiles = value.get("profiles")
    if not isinstance(raw_profiles, list) or len(raw_profiles) < 2:
        raise ConfigurationError(
            "runtime profile registry must declare at least two profiles"
        )
    profiles: dict[str, dict[str, object]] = {}
    for raw in raw_profiles:
        if not isinstance(raw, dict):
            raise ConfigurationError("runtime profile must be an object")
        profile_id = raw.get("profile_id")
        if not isinstance(profile_id, str) or profile_id in profiles:
            raise ConfigurationError(
                "runtime profile identity is invalid or duplicated"
            )
        profiles[profile_id] = raw
    return profiles


# ``Settings.from_env(mapping)`` reads exactly the given mapping instead of
# ``os.environ``; the mapping is installed here for the duration of the build.
_ENV_OVERRIDE: contextvars.ContextVar[Mapping[str, str] | None] = contextvars.ContextVar(
    "middleware_settings_env_override", default=None
)


def _validation_summary(exc: ValidationError) -> str:
    """Name the offending settings without echoing their values."""
    names = sorted({".".join(str(part) for part in error["loc"]) or "settings" for error in exc.errors()})
    reasons = sorted({str(error["msg"]) for error in exc.errors()})
    return "invalid configuration for " + ", ".join(names) + ": " + "; ".join(reasons)


class _MappingEnvSource(EnvSettingsSource):
    """The environment source, redirected to an explicit mapping by ``from_env``.

    The mapping is normalized the way pydantic-settings normalizes
    ``os.environ`` (case folding, empty-value skipping, none-string parsing)
    without importing its private helper, which moved between the 2.7 and
    2.10 releases pinned in the two locked environments.
    """

    def _load_env_vars(self) -> Mapping[str, str | None]:
        override = _ENV_OVERRIDE.get()
        if override is None:
            return super()._load_env_vars()
        loaded: dict[str, str | None] = {}
        for key, value in override.items():
            if self.env_ignore_empty and value == "":
                continue
            name = key if self.case_sensitive else key.lower()
            loaded[name] = (
                None
                if self.env_parse_none_str is not None and value == self.env_parse_none_str
                else value
            )
        return loaded


@dataclass(frozen=True)
class IdentitySettings:
    """The one identity configuration for the Middleware trust boundary.

    ``issuer``/``jwks_url`` always carry a value: the canonical authority for
    the environment when nothing explicit was configured. ``explicit`` says
    whether the operator set them; validators that must not fall back to a
    derived authority (the interactive agent-UI and service-JWT routes)
    check it and fail closed.
    """

    issuer: str
    audience: str
    jwks_url: str
    authorized_parties: frozenset[str]
    jwks_timeout_seconds: int
    explicit: bool = False
    max_token_lifetime_seconds: int = 300
    algorithms: tuple[str, ...] = ("RS256",)


VICIDIAL_PRIVATE_HOSTS = frozenset(
    {
        "authorization.internal.codestra.agency",
        "edge.internal.codestra.agency",
    }
)
VICIDIAL_PRIVATE_PORT = 8443
VICIDIAL_ENDPOINT_ADAPTER_PORT = 8444
VICIDIAL_SECRET_ROOT = Path("/run/secrets/vicidial-mtls")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=None, extra="ignore", populate_by_name=True
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return (init_settings, _MappingEnvSource(settings_cls), file_secret_settings)

    # --- deployment identity (formerly app/config.py) ---------------------------
    app_env: str = "development"
    runtime_profile_id: str | None = None
    app_version: str = "0.1.0"
    # APP_SOURCE_SHA is what Dockerfile.runtime bakes in; SOURCE_SHA is the name
    # the former entrypoint /version handlers read.
    source_sha: str = Field(
        default="unknown",
        validation_alias=AliasChoices("APP_SOURCE_SHA", "SOURCE_SHA", "app_source_sha", "source_sha"),
    )
    image_digest: str = "unknown"
    schema_head: str = CANONICAL_SCHEMA_HEAD
    build_time: str = "unknown"
    release_id: str = "unknown"
    configuration_checksum: str = "unknown"
    jwks_timeout_seconds: int = 3
    readiness_timeout_seconds: int = 3
    # Minimum spacing between in-process attempts to rebuild a runtime whose
    # startup failed; readiness stays closed in between.
    runtime_rebuild_interval_seconds: int = 30
    allow_in_memory_storage: bool = False
    max_request_body_bytes: int = 1_048_576
    webhook_max_clock_skew_seconds: int = 300
    webhook_replay_retention_seconds: int = 86_400
    webhook_secret_odoo_integration: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_SECRET_ODOO_INTEGRATION", "webhook_secret_odoo_integration")
    )
    webhook_secret_n8n_automation: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_SECRET_N8N_AUTOMATION", "webhook_secret_n8n_automation")
    )
    webhook_secret_vicidial_adapter: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_SECRET_VICIDIAL_ADAPTER", "webhook_secret_vicidial_adapter")
    )
    webhook_secret_telnexa_gateway: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_SECRET_TELNEXA_GATEWAY", "webhook_secret_telnexa_gateway")
    )
    webhook_secret_klyrow_gateway: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_SECRET_KLYROW_GATEWAY", "webhook_secret_klyrow_gateway")
    )
    webhook_secret_kyqra_gateway: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_SECRET_KYQRA_GATEWAY", "webhook_secret_kyqra_gateway")
    )
    webhook_secret_postly_adapter: str = Field(
        default="", validation_alias=AliasChoices("WEBHOOK_SECRET_POSTLY_ADAPTER", "webhook_secret_postly_adapter")
    )
    outbox_dispatch_enabled: bool = False
    # External-effect flags (env name == field name unless aliased); see
    # EXTERNAL_EFFECT_FIELDS. Every one defaults to false.
    live_write: bool = False
    live_writes: bool = False
    odoo_write: bool = False
    callback_dispatch: bool = False
    vicidial_writes_enabled: bool = False
    production_callbacks_enabled: bool = False
    form_odoo_delivery_enabled: bool = False
    crawler_odoo_delivery_enabled: bool = False
    scrapper_odoo_delivery_enabled: bool = False
    crawler_external_contact_enabled: bool = False
    scrapper_external_contact_enabled: bool = False
    effect_sms_delivery_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("SMS_DELIVERY_ENABLED", "effect_sms_delivery_enabled")
    )
    effect_email_delivery_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("EMAIL_DELIVERY_ENABLED", "effect_email_delivery_enabled")
    )
    effect_social_delivery_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("SOCIAL_DELIVERY_ENABLED", "effect_social_delivery_enabled")
    )
    crawler_execution_enabled: bool = False
    scrapper_execution_enabled: bool = False
    live_sms_delivery: bool = False
    live_email_delivery: bool = False
    unrestricted_crawling: bool = False
    # Umbrella kill switches (see UMBRELLA_CONTROL_FIELDS); all default false.
    umbrella_live_advertising_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("LIVE_ADVERTISING_ENABLED", "umbrella_live_advertising_enabled")
    )
    umbrella_external_delivery_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("EXTERNAL_DELIVERY_ENABLED", "umbrella_external_delivery_enabled")
    )
    umbrella_social_publishing_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("SOCIAL_PUBLISHING_ENABLED", "umbrella_social_publishing_enabled")
    )
    umbrella_external_model_calls_enabled: bool = Field(
        default=False, validation_alias=AliasChoices("EXTERNAL_MODEL_CALLS_ENABLED", "umbrella_external_model_calls_enabled")
    )
    umbrella_n8n_external_provider_writes: bool = Field(
        default=False, validation_alias=AliasChoices("N8N_EXTERNAL_PROVIDER_WRITES", "umbrella_n8n_external_provider_writes")
    )
    # Odoo 19 CRM lead delivery (Appolon lineage). Distinct from the registry
    # backed ``odoo_base_url`` used by the outbox sync worker.
    odoo_19_base_url: str = Field(
        default="", validation_alias=AliasChoices("ODOO_19_BASE_URL", "odoo_19_base_url")
    )
    odoo_19_hmac_secret: str = Field(
        default="", validation_alias=AliasChoices("ODOO_19_HMAC_SECRET", "odoo_19_hmac_secret")
    )
    odoo_19_tenant_hmac_secrets: str = Field(
        default="", validation_alias=AliasChoices("ODOO_19_TENANT_HMAC_SECRETS", "odoo_19_tenant_hmac_secrets")
    )
    odoo_timeout_seconds: int = Field(
        default=20, validation_alias=AliasChoices("ODOO_19_TIMEOUT_SECONDS", "odoo_timeout_seconds")
    )
    # NATS JetStream
    nats_url: str | None = None
    nats_stream: str = "CODESTRA_EVENTS"
    nats_subject_prefix: str = "codestra.events"
    nats_credentials_file: Path | None = Field(
        default=None, validation_alias=AliasChoices("NATS_CREDS_FILE", "nats_credentials_file")
    )
    nats_dispatch_mode: str = "disabled"
    nats_allow_insecure_test_connection: bool = False
    production_activation_id: str | None = None
    production_dialing: str = "DISABLED"
    # Temporal (not deployed; validated so a stray enablement fails closed)
    temporal_address: str | None = None
    temporal_namespace: str = "codestra-production"
    temporal_task_queue: str = "codestra-production-critical"
    temporal_worker_mode: str = "disabled"
    temporal_server_root_ca_file: Path | None = None
    temporal_client_cert_file: Path | None = None
    temporal_client_key_file: Path | None = None
    temporal_tls_server_name: str | None = None
    temporal_allow_insecure_test_connection: bool = False

    database_url: str = "postgresql+asyncpg://localhost/codestra_middleware"
    database_url_file: str = ""
    database_certification_evidence_dir: str = ""
    # Read-only release certification evidence (release_candidate.json,
    # backup.json, restore_rehearsal.json, rollback.json, seal.json).
    release_certification_evidence_dir: str = ""
    release_certification_max_backup_age_hours: int = Field(default=24, ge=1, le=720)
    redis_url: str = "redis://localhost:6379/2"
    redis_url_file: str = ""
    registry_snapshot_signing_key_file: str = ""
    registry_l1_ttl_seconds: int = 15
    registry_l2_ttl_seconds: int = 60
    registry_stale_grace_seconds: int = 300
    registry_service_issuer: str = ""
    registry_service_audience: str = "codestra-middleware"
    registry_service_jwks_url: str = ""
    registry_service_client_id: str = "codestra-registry-client"
    ingestion_hmac_secret: str = ""
    ingestion_token: str = ""
    middleware_secret: str = ""
    middleware_secret_file: str = ""
    webhook_shared_secret: str = ""
    webhook_shared_secret_file: str = ""
    vicidial_webhook_secret: str = ""
    telnexa_webhook_secret: str = ""
    vicidial_callback_hmac_secret_file: str = ""
    signature_ttl_seconds: int = 300
    request_max_bytes: int = 262144
    database_pool_size: int = 8
    database_max_overflow: int = 4
    database_pool_timeout_seconds: int = 5
    database_command_timeout_seconds: int = 30
    database_pool_recycle_seconds: int = 1800
    health_require_database: bool = False
    enabled_event_types: str = (
        "vicidial.call.started,vicidial.call.connected,vicidial.call.ended"
    )
    allowed_client_instances: str = "vicidial-server-b"
    live_writes_enabled: bool = False
    odoo_write_enabled: bool = False
    allow_non_test_campaigns: bool = False
    campaign_design_enabled: bool = False
    campaign_design_environments: str = "test,staging"
    campaign_design_client_id: str = "odoo-campaign-design"
    odoo_delivery_enabled: bool = False
    n8n_delivery_enabled: bool = False
    n8n_event_delivery_enabled: bool = False
    order_orchestration_enabled: bool = False
    n8n_order_dispatch_enabled: bool = False
    n8n_production_workflows_enabled: bool = False
    automation_actions_enabled: bool = False
    odoo_automation_writes_enabled: bool = False
    vicidial_read_enabled: bool = False
    vicidial_write_enabled: bool = False
    klyrow_write_enabled: bool = False
    telnexa_write_enabled: bool = False
    provisioning_service_invocation_enabled: bool = False
    provisioning_service_base_url: str = ""
    provisioning_service_hmac_secret_file: str = ""
    provisioning_service_timeout_seconds: float = 15.0
    foundation_base_url: str = ""
    foundation_token_url: str = ""
    foundation_audience: str = "codestra-foundation"
    foundation_client_id: str = ""
    foundation_client_secret: str = ""
    foundation_client_secret_file: str = ""
    klyrow_default_domain_claim_id: str = ""
    transfer_control_enabled: bool = False
    vicidial_authorization_url: str = ""
    vicidial_edge_url: str = ""
    vicidial_ca_file: str = ""
    vicidial_client_cert_file: str = ""
    vicidial_client_key_file: str = ""
    vicidial_crl_file: str = ""
    callback_dispatch_enabled: bool = False
    callback_scheduler_enabled: bool = False
    callback_test_syn_enabled: bool = False
    callback_delivery_enabled: bool = False
    callback_allowed_tenant: str = ""
    callback_allowed_campaign: str = ""
    callback_jwt_issuer: str = ""
    callback_jwt_audience: str = "codestra-callback-api"
    callback_jwt_jwks_url: str = ""
    callback_jwt_authorized_parties: str = ""
    callback_email_command_enabled: bool = False
    callback_email_sender_profile_id: str = ""
    callback_email_template_id: str = "codestra.callback.agent-reminder.v1"
    callback_email_policy_hash: str = ""
    callback_websocket_delivery_enabled: bool = False
    callback_websocket_gateway_url: str = ""
    callback_websocket_token_file: str = ""
    messaging_enabled: bool = False
    external_dial_enabled: bool = False
    ai_private_api_enabled: bool = False
    ai_service_id: str = "qwen"
    ai_worker_service_id: str = "qwen-polling-worker"
    ai_worker_source_cidrs: str = "10.40.0.4/32"
    ai_worker_trusted_proxy_cidr: str = "10.250.241.2/32"
    ai_worker_certificate_serial: str = "3008"
    ai_worker_certificate_ip: str = "10.40.0.4"
    ai_worker_spiffe_id: str = "spiffe://codestra.internal/worker/qwen"
    ai_worker_hmac_key_id: str = "qwen-polling-worker-hmac-v1"
    ai_worker_id: str = "qwen-ai-01-worker"
    ai_worker_tenant_id: str = ""
    ai_worker_workspace_id: str = ""
    ai_worker_client_ca_file: str = ""
    ai_hmac_secret_file: str = ""
    ai_audit_log_file: str = ""
    ai_signature_ttl_seconds: int = 300
    ai_rate_limit_per_minute: int = 60
    ai_command_timeout_seconds: int = 10
    ai_job_lease_seconds: int = 60
    ai_job_max_attempts: int = 5
    ai_job_max_context_bytes: int = 131072
    ai_job_max_output_bytes: int = 1048576
    ai_job_project_allowlist: str = ""
    ai_submissions_enabled: bool = False
    ai_orchestration_enabled: bool = False
    ai_worker_claims_enabled: bool = False
    ai_default_max_queued_per_tenant: int = 100
    ai_default_max_running_per_tenant: int = 5
    ai_daily_token_quota: int = 100000
    ai_global_emergency_limit: int = 0
    openai_provider_enabled: bool = False
    openai_worker_service_id: str = "openai-responses-provider"
    openai_worker_id: str = "codestra-openai-01"
    openai_worker_max_concurrency: int = 1
    openai_api_key_file: str = ""
    openai_safety_salt_file: str = ""
    openai_chat_model: str = "gpt-5.6-terra"
    openai_coding_model: str = "gpt-5.6-sol"
    openai_chat_reasoning_effort: str = "low"
    openai_coding_reasoning_effort: str = "medium"
    openai_request_timeout_seconds: float = 120.0
    openai_max_retries: int = 2
    openai_daily_user_token_limit: int = 100000
    openai_daily_project_token_limit: int = 250000
    openai_max_estimated_cost_micro_usd: int = 300000
    elevenlabs_provider_enabled: bool = False
    elevenlabs_base_url: str = "https://api.elevenlabs.io"
    elevenlabs_api_key_file: str = "/run/secrets/elevenlabs-api-key"
    elevenlabs_model_id: str = "eleven_flash_v2_5"
    elevenlabs_canary_voice_id: str = ""
    elevenlabs_browser_output_format: str = "mp3_44100_128"
    elevenlabs_telephony_output_format: str = "ulaw_8000"
    elevenlabs_max_text_characters: int = 1000
    elevenlabs_max_concurrency: int = 1
    elevenlabs_connect_timeout_seconds: float = 10.0
    elevenlabs_read_timeout_seconds: float = 60.0
    elevenlabs_total_timeout_seconds: float = 90.0
    elevenlabs_max_retries: int = 2
    elevenlabs_request_logging_mode: str = "standard"
    controller_approval_signing_key_file: str = ""
    controller_workspace_allowlist: str = (
        "/opt/codestra/middleware,/opt/codestra/worktrees"
    )
    controller_private_enabled: bool = False
    server_a_agent_enabled: bool = False
    server_a_agent_bind: str = "10.40.0.1:9443"
    # SEND_EVENTS gates the NATS JetStream outbox transport (with
    # OUTBOX_DISPATCH_ENABLED and NATS_DISPATCH_MODE). The n8n broad-event
    # pipeline has its own first switch below; the two lineages used to share
    # the SEND_EVENTS name for both, which made either unusable.
    send_events: bool = False
    broad_event_send_enabled: bool = False
    broad_event_delivery_enabled: bool = False
    production_n8n_enabled: bool = False
    enable_external_delivery: bool = False
    controlled_broad_event_activation: bool = False
    broad_event_business_unit_allowlist: str = ""
    broad_event_campaign_allowlist: str = ""
    broad_event_workflow_allowlist: str = ""
    broad_event_type_allowlist: str = ""
    broad_event_activation_high_water_mark: str = ""
    broad_event_submission_limit: int = 0
    n8n_production_target_url: str = ""
    n8n_production_target_identity: str = ""
    n8n_production_image_digest: str = ""
    n8n_production_instance_id: str = ""
    n8n_production_version: str = ""
    n8n_runtime_health_url: str = ""
    webphone_origin_scheme: str = "https"
    webphone_origin_host: str = "phone.codestra.agency"
    webphone_expected_user: str = "preprod"
    webphone_staging_campaign: str = "TEST_SYN"
    webphone_staging_endpoint: str = "6101"
    n8n_workflow_package_sha256: str = ""
    n8n_target_ca_file: str = ""
    n8n_service_issuer: str = ""
    n8n_service_audience: str = "middleware-api"
    n8n_service_jwks_url: str = ""
    n8n_service_client_id: str = "codestra-n8n-production"
    n8n_campaign_service_client_id: str = "codestra-n8n-campaign-crm-production"
    # Optional comma-separated list of n8n service clients accepted on the
    # standard-result routes (submit + readback). Empty falls back to the
    # single client above. Staging certification uses one client per scope.
    n8n_campaign_service_client_ids: str = ""
    middleware_n8n_token_url: str = ""
    middleware_n8n_client_id: str = "codestra-middleware-production"
    middleware_n8n_client_secret_file: str = ""
    middleware_n8n_audience: str = "codestra-n8n-production"
    middleware_n8n_scope: str = "n8n.events.submit"
    odoo_results_client_id: str = "codestra-middleware-odoo-results"
    odoo_results_client_secret_file: str = ""
    odoo_results_ca_file: str = ""
    odoo_service_credential_reference: str = ""
    odoo_service_private_key_file: str = ""
    odoo_result_delivery_enabled: bool = False
    test_syn_odoo_result_delivery_enabled: bool = False
    # Odoo result delivery worker: attempts count dispatches; the reservation
    # lease must exceed the slowest registry route (connect + request) plus a
    # margin, and recovery never re-queues an exhausted delivery.
    odoo_result_delivery_lease_seconds: int = 60
    odoo_result_delivery_retry_limit: int = 3
    # Odoo campaign-control saga (Odoo outbox -> adapter -> actual-state
    # readback). Fail closed: disabled, synthetic adapter only.
    odoo_campaign_saga_enabled: bool = False
    odoo_campaign_saga_adapter: str = "synthetic"
    odoo_campaign_saga_lease_seconds: int = 90
    odoo_campaign_saga_retry_limit: int = 3
    test_syn_odoo_tenant_id: str = "TEST_SYN_TENANT"
    test_syn_odoo_workflow_code: str = "TEST_SYN_ROUTER"
    test_syn_odoo_workflow_version: str = "1"
    test_syn_odoo_event_type: str = "test.synthetic.odoo_result"
    test_syn_odoo_event_id: str = ""
    test_syn_odoo_correlation_id: str = ""
    test_syn_odoo_organization_public_id: str = ""
    test_syn_odoo_business_unit_public_id: str = ""
    test_syn_odoo_campaign_public_id: str = ""
    test_syn_odoo_outbox_public_id: str = ""
    odoo_read_enabled: bool = False
    odoo_sync_worker_enabled: bool = False
    odoo_staging_writes_enabled: bool = False
    odoo_production_writes_enabled: bool = False
    odoo_base_url: str = ""
    odoo_token_url: str = ""
    odoo_client_id: str = "codestra-middleware-staging"
    odoo_client_secret_file: str = ""
    odoo_audience: str = "codestra-odoo-integration"
    odoo_scope: str = ""
    odoo_ca_file: str = ""
    odoo_connect_timeout: float = 5.0
    odoo_read_timeout: float = 15.0
    odoo_max_retries: int = 3
    odoo_sync_worker_id: str = "codestra-middleware-odoo-sync"
    odoo_sync_batch_size: int = 25
    odoo_sync_lease_seconds: int = 60
    odoo_sync_business_units: str = ""
    email_dispatch_enabled: bool = False
    sms_dispatch_enabled: bool = False
    allow_live_email: bool = False
    allow_live_sms: bool = False
    sms_delivery: bool = False
    telnexa_event_ingress_enabled: bool = False
    telnexa_event_api_key: str = ""
    telnexa_event_api_key_file: str = ""
    telnexa_event_hmac_secret: str = ""
    telnexa_event_hmac_secret_file: str = ""
    telnexa_event_signature_ttl_seconds: int = 300
    telnexa_event_request_max_bytes: int = 1_048_576
    klyrow_event_ingress_enabled: bool = False
    klyrow_event_api_key: str = ""
    klyrow_event_api_key_file: str = ""
    klyrow_event_hmac_secret: str = ""
    klyrow_event_hmac_secret_file: str = ""
    klyrow_event_signature_ttl_seconds: int = 300
    klyrow_event_request_max_bytes: int = 1_048_576
    klyrow_odoo_projection_enabled: bool = False
    klyrow_mail_ingress_enabled: bool = False
    klyrow_mail_hmac_secret_file: str = ""
    klyrow_mail_signature_ttl_seconds: int = 300
    klyrow_mail_request_max_bytes: int = 25_000_000
    klyrow_mail_odoo_delivery_enabled: bool = False
    klyrow_mail_odoo_url: str = ""
    klyrow_mail_odoo_database: str = ""
    klyrow_mail_odoo_username: str = ""
    klyrow_mail_odoo_api_key_file: str = ""
    klyrow_mail_odoo_ca_file: str = ""
    klyrow_mail_worker_batch_size: int = 8
    klyrow_mail_worker_lease_seconds: int = 60
    klyrow_mail_worker_max_attempts: int = 8
    ai_enrichment_enabled: bool = False
    qwen_base_url_file: str = ""
    qwen_api_key_file: str = ""
    litellm_base_url_file: str = ""
    litellm_api_key_file: str = ""
    report_delivery_enabled: bool = False
    outbox_worker_enabled: bool = False
    outbox_max_attempts: int = 5
    outbox_base_delay_seconds: int = 5
    outbox_max_delay_seconds: int = 300
    outbox_lease_seconds: int = 60
    odoo_concurrency: int = 4
    n8n_concurrency: int = 8
    n8n_runtime_enabled: bool = False
    n8n_runtime_environment: str = "staging"
    n8n_runtime_base_url: str = ""
    n8n_runtime_hmac_secret_file: str = ""
    n8n_runtime_dispatch_timeout_seconds: float = 10.0
    n8n_runtime_workflow_timeout_seconds: int = 600
    n8n_runtime_max_attempts: int = 5
    redis_runtime_enabled: bool = False
    redis_runtime_environment: str = "staging"
    redis_runtime_prefix: str = "codestra"
    redis_runtime_socket_timeout_seconds: float = 1.0
    recording_concurrency: int = 2
    retention_worker_enabled: bool = True
    retention_delete_enabled: bool = False
    export_upload_enabled: bool = False
    odoo_recording_write_enabled: bool = False
    odoo_recording_hmac_secret: str = ""
    odoo_recording_hmac_secret_file: str = ""
    interaction_result_hmac_secret: str = ""
    interaction_result_hmac_secret_file: str = ""
    # codestra_middleware_bridge (Odoo) -- contacts/notes/tasks/opportunities/
    # tickets thin-adapter target. Same HMAC-over-canonical-headers scheme as
    # that controller's _authenticate(), not the sync.py/OdooRuntimeClient
    # nonce+bearer scheme, which is a different Odoo-facing contract.
    odoo_crm_bridge_base_url: str = ""
    odoo_crm_bridge_hmac_secret: str = ""
    odoo_crm_bridge_hmac_secret_file: str = ""
    odoo_crm_bridge_tenant_id: str = ""
    n8n_recording_workflow_enabled: bool = False
    n8n_recording_binding_enabled: bool = False
    n8n_recording_workflow_active: bool = False
    recording_upload_url_ttl_seconds: int = 300
    recording_playback_url_ttl_seconds: int = 120
    reconciliation_concurrency: int = 1
    keycloak_issuer: str = ""
    keycloak_audience: str = Field(
        default="", validation_alias=AliasChoices("KEYCLOAK_AUDIENCE", "MIDDLEWARE_AUDIENCE", "keycloak_audience")
    )
    # KEYCLOAK_JWKS_URL is canonical; KEYCLOAK_JWKS_URI is a temporary alias
    # (COMPATIBILITY_ENV_ALIASES) so a mid-migration environment cannot lose
    # its JWKS authority.
    keycloak_jwks_url: str = Field(
        default="", validation_alias=AliasChoices("KEYCLOAK_JWKS_URL", "KEYCLOAK_JWKS_URI", "keycloak_jwks_url")
    )
    keycloak_authorized_parties: str = ""
    # Service clients allowed to read campaign state through Middleware
    # (GET /api/v1/integrations/odoo/campaigns/...). Separate from the
    # interactive agent-UI clients in keycloak_authorized_parties; empty means
    # no caller is authorized (fail closed).
    odoo_campaign_reader_client_ids: str = ""
    keycloak_userinfo_url: str = ""
    provisioning_service_url: str = ""
    provisioning_service_token_url: str = ""
    provisioning_service_client_id: str = ""
    provisioning_service_client_secret_file: str = ""
    provisioning_service_ca_file: str = ""
    odoo_identity_lookup_url: str = ""
    odoo_identity_lookup_hmac_file: str = ""
    agent_provisioning_authorized_parties: str = "provisioning-service"
    agent_provisioning_policy_revision: str = "1"
    live_identity_provisioning_enabled: bool = False
    keycloak_lifecycle_admin_base_url: str = ""
    keycloak_lifecycle_realm: str = "codestra"
    keycloak_lifecycle_client_id: str = ""
    keycloak_lifecycle_client_secret_file: str = ""
    keycloak_lifecycle_ca_file: str = ""
    keycloak_lifecycle_approved_attributes: str = (
        "firstName,lastName,phone,employeeId,tenantId"
    )
    keycloak_lifecycle_approved_roles: str = ""
    webrtc_production_policy_path: str = (
        "config/webrtc-production-policy.default-deny.json"
    )
    maintenance_interval_seconds: int = 30
    automation_allowed_campaigns: str = "TEST_SYN"
    automation_environment: str = "test"
    automation_hmac_secret: str = ""
    environment: str = "preproduction"
    publisher_hmac_keys_file: str = ""
    publisher_canary_enabled: bool = False
    breero_ingress_enabled: bool = False
    breero_odoo_delivery_enabled: bool = False
    breero_hmac_identities_file: str = ""
    breero_rate_limit_per_minute: int = 30
    breero_signature_ttl_seconds: int = 300
    breero_request_max_bytes: int = 32768
    breero_odoo_url: str = ""
    breero_odoo_database: str = ""
    breero_odoo_username: str = ""
    breero_odoo_api_key_file: str = ""
    breero_worker_batch_size: int = 8
    breero_worker_lease_seconds: int = 60
    breero_worker_max_attempts: int = 8
    readiness_server_identity: str = "server-a-middleware"
    readiness_approved_source_ip: str = "10.40.0.2"
    readiness_publisher_key_id: str = ""
    readiness_publisher_cert_sha256: str = ""
    readiness_ttl_seconds: int = 60
    readiness_clock_skew_seconds: int = 5
    readiness_request_max_bytes: int = 4096
    readiness_rate_limit_per_minute: int = 10
    deployed_source_sha: str = ""
    runtime_artifact_checksum: str = ""
    quarantine_encryption_key_file: str = ""
    quarantine_encryption_key_version: str = "v1"
    quarantine_fingerprint_secret_file: str = ""
    quarantine_reviewer_secret_file: str = ""
    quarantine_retention_days: int = 90
    quarantine_retention_policy_version: str = "2026-07-26.1"
    quarantine_store_authenticated_raw: bool = True
    quarantine_rate_limit_per_minute: int = 30
    webphone_staging_provisioning_enabled: bool = False
    webphone_keycloak_enabled: bool = False
    webphone_endpoint_adapter_url: str = ""
    extension_allocator_enabled: bool = False
    telephony_provisioning_enabled: bool = False
    telephony_command_worker_enabled: bool = False
    telephony_service_client_id: str = "codestra-middleware-telephony"
    telephony_credential_directory: str = ""
    vicidial_provisioning_enabled: bool = False
    postiz_internal_base_url: str = ""
    postiz_api_key_file: str = ""
    postiz_organization_reference: str = ""
    postiz_timeout_seconds: float = 10.0
    postiz_delivery_enabled: bool = False
    postiz_publish_enabled: bool = False
    postiz_media_upload_enabled: bool = False
    postiz_analytics_enabled: bool = False
    social_integration_enabled: bool = False
    social_publish_enabled: bool = False
    social_provider: str = "disabled"
    social_provider_mode: str = "single"
    social_provider_migration_mode: str = "disabled"
    social_n8n_events_enabled: bool = False
    social_n8n_delivery_worker_enabled: bool = False
    social_n8n_delivery_worker_id: str = "social-n8n-delivery-01"
    social_n8n_delivery_batch_size: int = 8
    social_n8n_delivery_lease_seconds: int = 60
    postly_polling_enabled: bool = False
    postly_poll_interval_seconds: int = 60
    postly_poll_lookback_seconds: int = 300
    postly_poll_batch_size: int = 100
    social_odoo_sync_enabled: bool = False
    social_odoo_write_enabled: bool = False
    social_analytics_sync_enabled: bool = False
    social_sql_repository_enabled: bool = False
    social_worker_enabled: bool = False
    social_worker_id: str = "postly-social-01"
    social_worker_concurrency: int = 1
    social_worker_lease_seconds: int = 60
    social_worker_poll_seconds: float = 1.0
    social_job_max_attempts: int = 5
    social_production_mode: bool = False
    social_production_canary_enabled: bool = False
    social_production_canary_account_ids: str = ""
    social_production_canary_tenant_ids: str = ""
    social_production_canary_campaign_ids: str = ""
    social_production_backup_gate_verified: bool = False
    social_production_rollback_gate_verified: bool = False
    social_production_webhook_gate_verified: bool = False
    social_production_monitoring_gate_verified: bool = False
    social_automatic_provider_failover_enabled: bool = False
    social_automatic_dual_publish_enabled: bool = False
    social_webhook_ttl_seconds: int = 300
    postly_webhook_secret: str = ""
    postly_webhook_secret_file: str = ""
    hootsuite_enabled: bool = False
    hootsuite_client_id_file: str = ""
    hootsuite_client_secret_file: str = ""
    hootsuite_redirect_uri: str = ""
    pjsip_provisioning_enabled: bool = False
    webphone_session_issuer_enabled: bool = False
    agent_websocket_enabled: bool = False
    telephony_reconciliation_enabled: bool = False
    telephony_notifications_enabled: bool = False
    telephony_evidence_enabled: bool = False
    lead_automation_enabled: bool = False
    lead_create_enabled: bool = False
    lead_update_enabled: bool = False
    lead_assignment_enabled: bool = False
    lead_status_change_enabled: bool = False
    lead_callback_create_enabled: bool = False
    n8n_lead_binding_enabled: bool = False
    n8n_result_processing_enabled: bool = False
    odoo_lead_apply_enabled: bool = False
    lead_automation_hmac_secret: str = ""
    sales_lead_intake_enabled: bool = False
    sales_identity_resolution_enabled: bool = False
    sales_odoo_read_only_lookup_enabled: bool = False
    sales_verification_jobs_enabled: bool = False
    scraper_result_ingest_enabled: bool = False
    scraper_middleware_delivery_enabled: bool = False
    scraper_odoo_apply_url: str = ""
    scraper_odoo_company_key: str = "COMPANY-1"
    scraper_odoo_business_unit_key: str = "web-mobile-ai"
    lead_verification_dry_run_only: bool = True
    lead_outreach_enabled: bool = False
    odoo_lead_write_enabled: bool = False
    vicidial_lead_write_enabled: bool = False
    n8n_lead_delivery_enabled: bool = False
    postly_lead_delivery_enabled: bool = False
    hunter_provider_enabled: bool = False
    apollo_provider_enabled: bool = False
    twilio_lookup_provider_enabled: bool = False
    opencorporates_provider_enabled: bool = False
    openai_lead_classification_enabled: bool = False
    vicidial_publication_enabled: bool = False
    outreach_enabled: bool = False
    sales_lead_request_max_bytes: int = 131072
    sales_verification_max_concurrency: int = 4
    sales_scraper_identity: str = ""
    sales_scraper_tenant_id: str = ""
    sales_scraper_campaign_allowlist: str = ""
    sales_scraper_hmac_key_ids: str = ""
    sales_scraper_hmac_keys_directory: str = ""
    sales_scraper_jwt_issuer: str = ""
    sales_scraper_jwt_audience: str = "codestra-scraper-ingress"
    sales_scraper_jwt_jwks_url: str = ""
    sales_scraper_jwt_authorized_parties: str = ""
    sales_scraper_jwt_required_scope: str = "scraper.events.write"
    sales_scraper_jwt_required_role: str = "scraper-publisher"
    sales_scraper_rate_limit_per_minute: int = 60

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        """Build, load secret files and fully validate a Settings instance.

        With ``env`` given, that mapping is the only configuration source
        (``os.environ`` is not consulted); without it the process environment
        is used. Every configuration defect raises ``ConfigurationError``.
        """
        token = _ENV_OVERRIDE.set(dict(env) if env is not None else None)
        try:
            instance = cls()
        except ValidationError as exc:
            raise ConfigurationError(_validation_summary(exc)) from exc
        finally:
            _ENV_OVERRIDE.reset(token)
        if env is not None:
            present = {key.upper() for key in env}
            # The Appolon lineage required an explicit DATABASE_URL/REDIS_URL;
            # keep that contract for callers that build from a mapping.
            if "DATABASE_URL" not in present and "DATABASE_URL_FILE" not in present:
                instance.database_url = ""
            if "REDIS_URL" not in present and "REDIS_URL_FILE" not in present:
                instance.redis_url = ""
        try:
            instance.load_secret_files()
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc
        instance.validate_domain()
        try:
            instance.validate_safety()
        except ValueError as exc:
            raise ConfigurationError(str(exc)) from exc
        return instance

    def replace(self, **changes: object) -> "Settings":
        """Return a copy with the given *fields* changed (test helper).

        Mirrors ``dataclasses.replace`` for the former frozen dataclass:
        only declared fields may be changed; derived views such as
        ``umbrella_controls`` are properties and must be changed through
        their underlying fields. No validation is re-run.
        """
        unknown = sorted(set(changes) - set(type(self).model_fields))
        if unknown:
            raise TypeError(f"Settings.replace() got unknown fields: {', '.join(unknown)}")
        return self.model_copy(update=dict(changes))

    @field_validator(
        "runtime_profile_id",
        "production_activation_id",
        "temporal_address",
        "temporal_tls_server_name",
        "nats_url",
        mode="before",
    )
    @classmethod
    def _empty_string_is_none(cls, value: object) -> object:
        if isinstance(value, str):
            stripped = value.strip()
            return stripped or None
        return value

    @field_validator("app_env", "nats_dispatch_mode", "temporal_worker_mode", mode="before")
    @classmethod
    def _lowercase_mode(cls, value: object) -> object:
        return value.strip().lower() if isinstance(value, str) else value

    @field_validator(
        "keycloak_issuer",
        "app_version",
        "image_digest",
        "schema_head",
        "build_time",
        "release_id",
        "configuration_checksum",
        "keycloak_jwks_url",
        "keycloak_audience",
        "nats_stream",
        "nats_subject_prefix",
        "temporal_namespace",
        "temporal_task_queue",
        "production_dialing",
        "odoo_19_base_url",
        mode="before",
    )
    @classmethod
    def _strip(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator("keycloak_issuer")
    @classmethod
    def _issuer_no_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    @field_validator("jwks_timeout_seconds", "readiness_timeout_seconds")
    @classmethod
    def _bounded_timeout(cls, value: int) -> int:
        if isinstance(value, bool) or not 1 <= value <= 10:
            raise ValueError("timeout must be between 1 and 10 seconds")
        return value

    @field_validator("runtime_rebuild_interval_seconds")
    @classmethod
    def _bounded_rebuild_interval(cls, value: int) -> int:
        if isinstance(value, bool) or not 5 <= value <= 600:
            raise ValueError("runtime rebuild interval must be between 5 and 600 seconds")
        return value

    @field_validator("max_request_body_bytes")
    @classmethod
    def _bounded_body(cls, value: int) -> int:
        if isinstance(value, bool) or not 1_024 <= value <= 10_485_760:
            raise ValueError("MAX_REQUEST_BODY_BYTES must be between 1024 and 10485760")
        return value

    @field_validator("webhook_max_clock_skew_seconds")
    @classmethod
    def _bounded_skew(cls, value: int) -> int:
        if isinstance(value, bool) or not 1 <= value <= 300:
            raise ValueError("WEBHOOK_MAX_CLOCK_SKEW_SECONDS must be between 1 and 300")
        return value

    @field_validator("webhook_replay_retention_seconds")
    @classmethod
    def _bounded_retention(cls, value: int) -> int:
        if isinstance(value, bool) or not 86_400 <= value <= 2_592_000:
            raise ValueError(
                "WEBHOOK_REPLAY_RETENTION_SECONDS must be between 86400 and 2592000"
            )
        return value

    @field_validator("odoo_timeout_seconds")
    @classmethod
    def _bounded_odoo_timeout(cls, value: int) -> int:
        if isinstance(value, bool) or not 1 <= value <= 120:
            raise ValueError("ODOO_19_TIMEOUT_SECONDS must be between 1 and 120")
        return value

    # ------------------------------------------------------------------
    # Identity view (one authority for the Middleware trust boundary)
    # ------------------------------------------------------------------
    @property
    def expected_issuer(self) -> str:
        return STAGING_ISSUER if self.app_env == "staging" else PRODUCTION_ISSUER

    @property
    def issuer(self) -> str:
        return self.keycloak_issuer or self.expected_issuer

    @property
    def jwks_uri(self) -> str:
        return self.keycloak_jwks_url or f"{self.issuer}/protocol/openid-connect/certs"

    @property
    def audience(self) -> str:
        return self.keycloak_audience or CANONICAL_AUDIENCE

    @property
    def authorized_parties(self) -> frozenset[str]:
        return frozenset(
            value.strip()
            for value in self.keycloak_authorized_parties.split(",")
            if value.strip()
        )

    @property
    def synthetic_ci_identity(self) -> bool:
        return (
            self.app_env in {"development", "test"}
            and self.issuer == SYNTHETIC_CI_ISSUER
            and self.jwks_uri == SYNTHETIC_CI_JWKS_URL
        )

    @property
    def identity(self) -> IdentitySettings:
        return IdentitySettings(
            issuer=self.issuer,
            audience=self.audience,
            jwks_url=self.jwks_uri,
            authorized_parties=self.authorized_parties,
            jwks_timeout_seconds=self.jwks_timeout_seconds,
            explicit=bool(
                self.keycloak_issuer and self.keycloak_audience and self.keycloak_jwks_url
            ),
        )

    # ------------------------------------------------------------------
    # Effect gates and umbrella controls
    # ------------------------------------------------------------------
    @property
    def external_effects(self) -> dict[str, bool]:
        return {name: bool(getattr(self, attr)) for name, attr in EXTERNAL_EFFECT_FIELDS.items()}

    @property
    def umbrella_controls(self) -> dict[str, bool]:
        return {name: bool(getattr(self, attr)) for name, attr in UMBRELLA_CONTROL_FIELDS.items()}

    @property
    def webhook_secrets(self) -> dict[str, bytes]:
        return {
            producer: getattr(
                self, _secret_env_name(producer).lower()
            ).encode("utf-8")
            for producer in WEBHOOK_PRODUCERS
        }

    def webhook_secret(self, producer_client_id: str) -> bytes:
        if producer_client_id not in WEBHOOK_PRODUCERS:
            raise ConfigurationError(f"unknown webhook producer: {producer_client_id}")
        secret = self.webhook_secrets.get(producer_client_id, b"")
        if len(secret) < 32:
            raise ConfigurationError(
                f"{_secret_env_name(producer_client_id)} must contain at least 32 bytes"
            )
        return secret

    def validate_all_webhook_secrets(self) -> None:
        for producer in WEBHOOK_PRODUCERS:
            if len(self.webhook_secrets.get(producer, b"")) < 32:
                raise ConfigurationError(
                    f"{_secret_env_name(producer)} must be configured with at least 32 bytes"
                )

    @property
    def odoo_default_hmac_secret(self) -> bytes:
        return self.odoo_19_hmac_secret.encode("utf-8")

    @property
    def odoo_tenant_hmac_secrets(self) -> dict[str, bytes]:
        raw = self.odoo_19_tenant_hmac_secrets.strip()
        if not raw:
            return {}
        try:
            decoded = json.loads(raw)
        except ValueError as exc:
            raise ConfigurationError(
                "ODOO_19_TENANT_HMAC_SECRETS must be a JSON object"
            ) from exc
        if not isinstance(decoded, dict) or not all(
            isinstance(key, str) and isinstance(value, str) and key and value
            for key, value in decoded.items()
        ):
            raise ConfigurationError(
                "ODOO_19_TENANT_HMAC_SECRETS must map tenant IDs to secrets"
            )
        return {key: value.encode("utf-8") for key, value in decoded.items()}

    def odoo_secret_for(self, tenant_id: str) -> bytes:
        return self.odoo_tenant_hmac_secrets.get(tenant_id, self.odoo_default_hmac_secret)

    @property
    def odoo_19_delivery_enabled(self) -> bool:
        """Odoo 19 lead delivery: umbrella switch and the ODOO_WRITE effect."""
        return self.umbrella_external_delivery_enabled and self.odoo_write

    def odoo_source_delivery_enabled(self, provenance_method: str) -> bool:
        gate = {
            "submitted_by_person": "form_odoo_delivery_enabled",
            "crawler_discovery": "crawler_odoo_delivery_enabled",
            "scraper_import": "scrapper_odoo_delivery_enabled",
        }.get(provenance_method)
        if gate is None:
            return False
        return self.odoo_19_delivery_enabled and bool(getattr(self, gate))

    @property
    def social_publishing_enabled(self) -> bool:
        """Effect gate plus its own umbrella switch (not EXTERNAL_DELIVERY_ENABLED)."""
        return self.effect_social_delivery_enabled and self.umbrella_social_publishing_enabled

    @property
    def email_delivery_enabled(self) -> bool:
        return self.effect_email_delivery_enabled and self.umbrella_external_delivery_enabled

    @property
    def sms_delivery_enabled(self) -> bool:
        return self.effect_sms_delivery_enabled and self.umbrella_external_delivery_enabled

    # ------------------------------------------------------------------
    # Environment policy (formerly app/config.py Settings.validate)
    # ------------------------------------------------------------------
    def validate_domain(self) -> None:
        if self.app_env not in {"development", "test", "staging", "production"}:
            raise ConfigurationError("APP_ENV is not recognized")
        if self.app_env in {"staging", "production"} and self.environment not in {
            self.app_env,
            "preproduction",
        }:
            raise ConfigurationError("ENVIRONMENT must match APP_ENV in staging/production")
        synthetic = self.synthetic_ci_identity
        if self.app_env in {"staging", "production"}:
            # Deployed environments trust exactly one authority each.
            if self.issuer != self.expected_issuer:
                raise ConfigurationError(
                    f"KEYCLOAK_ISSUER must match the {self.app_env} identity authority"
                )
            if self.jwks_uri != f"{self.issuer}/protocol/openid-connect/certs":
                raise ConfigurationError("KEYCLOAK_JWKS_URL must match the canonical issuer")
        elif not synthetic:
            # Development/test may point at any TLS authority (a developer's or
            # a disposable CI Keycloak) but never at a plaintext one; the only
            # http:// exception is the approved synthetic CI JWKS fixture.
            if not self.issuer.startswith("https://"):
                raise ConfigurationError("KEYCLOAK_ISSUER must be an https:// authority")
            if not self.jwks_uri.startswith("https://"):
                raise ConfigurationError("KEYCLOAK_JWKS_URL must be an https:// authority")
        if self.audience != CANONICAL_AUDIENCE:
            raise ConfigurationError("KEYCLOAK_AUDIENCE must be middleware-api")
        if self.telnexa_event_ingress_enabled:
            if not self.sms_delivery:
                raise ConfigurationError(
                    "SMS_DELIVERY must be true before enabling Telnexa event ingress"
                )
            if not (self.telnexa_event_api_key or self.telnexa_event_api_key_file):
                raise ConfigurationError(
                    "TELNEXA_EVENT_API_KEY or TELNEXA_EVENT_API_KEY_FILE is required"
                )
            if not (self.telnexa_event_hmac_secret or self.telnexa_event_hmac_secret_file):
                raise ConfigurationError(
                    "TELNEXA_EVENT_HMAC_SECRET or TELNEXA_EVENT_HMAC_SECRET_FILE is required"
                )
        if self.klyrow_event_ingress_enabled:
            if not (self.klyrow_event_api_key or self.klyrow_event_api_key_file):
                raise ConfigurationError(
                    "KLYROW_EVENT_API_KEY or KLYROW_EVENT_API_KEY_FILE is required"
                )
            if not (self.klyrow_event_hmac_secret or self.klyrow_event_hmac_secret_file):
                raise ConfigurationError(
                    "KLYROW_EVENT_HMAC_SECRET or KLYROW_EVENT_HMAC_SECRET_FILE is required"
                )
        if self.klyrow_odoo_projection_enabled and not self.odoo_19_delivery_enabled:
            raise ConfigurationError(
                "Klyrow Odoo projection requires EXTERNAL_DELIVERY_ENABLED and ODOO_WRITE"
            )
        self._validate_environment_profile()
        effects = self.external_effects
        enabled = {name for name, value in effects.items() if value}
        unsupported_enabled = sorted(enabled - SUPPORTED_EXTERNAL_EFFECTS)
        if unsupported_enabled:
            raise ConfigurationError(
                "provider and business effects are not implemented by this runtime: "
                + ", ".join(unsupported_enabled)
            )
        umbrella = self.umbrella_controls
        enabled_umbrella_controls = sorted(name for name, value in umbrella.items() if value)
        if self.app_env == "staging" and enabled_umbrella_controls:
            raise ConfigurationError(
                "staging umbrella controls must remain disabled: "
                + ", ".join(enabled_umbrella_controls)
            )
        enabled_delivery_effects = sorted(enabled & EXTERNAL_DELIVERY_EFFECTS)
        if enabled_delivery_effects and umbrella["EXTERNAL_DELIVERY_ENABLED"] is not True:
            raise ConfigurationError(
                "EXTERNAL_DELIVERY_ENABLED must be true before enabling: "
                + ", ".join(enabled_delivery_effects)
            )
        self._validate_odoo_transport(enabled)
        if "SOCIAL_DELIVERY_ENABLED" in enabled and umbrella["SOCIAL_PUBLISHING_ENABLED"] is not True:
            raise ConfigurationError(
                "SOCIAL_PUBLISHING_ENABLED must be true before enabling: "
                "SOCIAL_DELIVERY_ENABLED"
            )
        if self.production_dialing != "DISABLED":
            raise ConfigurationError("PRODUCTION_DIALING must remain DISABLED")
        self._validate_nats(enabled)
        self._validate_temporal()
        if self.allow_in_memory_storage:
            if self.app_env not in {"test", "development"}:
                raise ConfigurationError(
                    "ALLOW_IN_MEMORY_STORAGE is allowed only in test/development"
                )
        elif not self.database_url or not self.redis_url:
            raise ConfigurationError(
                "DATABASE_URL and REDIS_URL are required unless explicitly using "
                "in-memory storage in test/development"
            )
        if self.schema_head != CANONICAL_SCHEMA_HEAD:
            raise ConfigurationError(f"SCHEMA_HEAD must be {CANONICAL_SCHEMA_HEAD}")
        if self.app_env in {"staging", "production"}:
            if not SHA40.fullmatch(self.source_sha):
                raise ConfigurationError(
                    "APP_SOURCE_SHA must be an exact 40-character SHA"
                )
            if not IMAGE_DIGEST.fullmatch(self.image_digest):
                raise ConfigurationError(
                    "IMAGE_DIGEST must be an immutable sha256 digest"
                )
            if self.build_time in {"", "unknown"}:
                raise ConfigurationError("BUILD_TIME is required in staging/production")
            self.validate_all_webhook_secrets()

    def _validate_nats(self, enabled: set[str]) -> None:
        if self.nats_dispatch_mode not in {"disabled", "isolated", "production"}:
            raise ConfigurationError(
                "NATS_DISPATCH_MODE must be disabled, isolated, or production"
            )
        send_events = "SEND_EVENTS" in enabled
        dispatch_configured = self.nats_dispatch_mode != "disabled"
        if not (self.outbox_dispatch_enabled == send_events == dispatch_configured):
            raise ConfigurationError(
                "OUTBOX_DISPATCH_ENABLED, SEND_EVENTS, and NATS_DISPATCH_MODE "
                "must be enabled or disabled together"
            )
        if not self.outbox_dispatch_enabled:
            if self.nats_allow_insecure_test_connection:
                raise ConfigurationError(
                    "NATS_ALLOW_INSECURE_TEST_CONNECTION requires isolated dispatch"
                )
            return
        if self.nats_dispatch_mode == "production" and self.app_env != "production":
            raise ConfigurationError(
                "production JetStream dispatch requires APP_ENV=production"
            )
        if self.nats_dispatch_mode == "isolated" and self.app_env == "production":
            raise ConfigurationError(
                "isolated JetStream dispatch is forbidden in production"
            )
        parsed_nats = urlparse(self.nats_url or "")
        insecure_local_test = (
            self.nats_allow_insecure_test_connection
            and self.app_env in {"test", "development"}
            and parsed_nats.scheme == "nats"
            and parsed_nats.hostname in {"127.0.0.1", "localhost"}
        )
        if not insecure_local_test and (parsed_nats.scheme != "tls" or not parsed_nats.hostname):
            raise ConfigurationError(
                "NATS_URL must use tls:// with a hostname outside disposable tests"
            )
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{2,63}", self.nats_stream):
            raise ConfigurationError("NATS_STREAM is invalid")
        if not re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9_-]+)+", self.nats_subject_prefix):
            raise ConfigurationError("NATS_SUBJECT_PREFIX is invalid")
        if not insecure_local_test and (
            self.nats_credentials_file is None
            or not _is_absolute_mount_path(self.nats_credentials_file)
        ):
            raise ConfigurationError(
                "NATS_CREDS_FILE must be an absolute mounted credential path"
            )
        if self.nats_dispatch_mode == "isolated":
            expected_environment = "staging" if self.app_env == "staging" else "test"
            expected_stream = f"CODESTRA_{expected_environment.upper()}_EVENTS"
            expected_prefix = f"codestra.{expected_environment}.events"
            if self.nats_stream != expected_stream:
                raise ConfigurationError(
                    f"isolated JetStream must use NATS_STREAM={expected_stream}"
                )
            if self.nats_subject_prefix != expected_prefix:
                raise ConfigurationError(
                    "isolated JetStream subject prefix does not match the environment"
                )
        else:
            if self.nats_stream != "CODESTRA_EVENTS":
                raise ConfigurationError(
                    "production JetStream must use NATS_STREAM=CODESTRA_EVENTS"
                )
            if self.nats_subject_prefix != "codestra.events":
                raise ConfigurationError(
                    "production JetStream must use NATS_SUBJECT_PREFIX=codestra.events"
                )
            if not self.production_activation_id or not re.fullmatch(
                r"[A-Z0-9][A-Z0-9._/-]{7,127}", self.production_activation_id
            ):
                raise ConfigurationError(
                    "PRODUCTION_ACTIVATION_ID must identify the approved activation"
                )

    def _validate_temporal(self) -> None:
        if self.temporal_worker_mode not in {"disabled", "isolated", "production"}:
            raise ConfigurationError(
                "TEMPORAL_WORKER_MODE must be disabled, isolated, or production"
            )
        if self.temporal_worker_mode == "disabled":
            if self.temporal_allow_insecure_test_connection:
                raise ConfigurationError(
                    "TEMPORAL_ALLOW_INSECURE_TEST_CONNECTION requires isolated mode"
                )
            return
        if not self.temporal_address:
            raise ConfigurationError(
                "TEMPORAL_ADDRESS is required when the worker is enabled"
            )
        insecure_temporal_test = (
            self.temporal_allow_insecure_test_connection
            and self.app_env in {"test", "development"}
            and self.temporal_address.startswith(("127.0.0.1:", "localhost:"))
        )
        if self.temporal_worker_mode == "production":
            if self.app_env != "production":
                raise ConfigurationError(
                    "production Temporal mode requires APP_ENV=production"
                )
            expected_namespace = "codestra-production"
            expected_task_queue = "codestra-production-critical"
            if not self.production_activation_id or not re.fullmatch(
                r"[A-Z0-9][A-Z0-9._/-]{7,127}", self.production_activation_id
            ):
                raise ConfigurationError(
                    "production Temporal mode requires PRODUCTION_ACTIVATION_ID"
                )
        else:
            if self.app_env == "production":
                raise ConfigurationError(
                    "isolated Temporal mode is forbidden in production"
                )
            environment = "staging" if self.app_env == "staging" else "test"
            expected_namespace = f"codestra-{environment}"
            expected_task_queue = f"codestra-{environment}-critical"
        if self.temporal_namespace != expected_namespace:
            raise ConfigurationError(
                "Temporal namespace does not match the selected environment"
            )
        if self.temporal_task_queue != expected_task_queue:
            raise ConfigurationError(
                "Temporal task queue does not match the selected environment"
            )
        tls_paths = (
            self.temporal_server_root_ca_file,
            self.temporal_client_cert_file,
            self.temporal_client_key_file,
        )
        if not insecure_temporal_test and any(
            path is None or not _is_absolute_mount_path(path) for path in tls_paths
        ):
            raise ConfigurationError(
                "Temporal requires absolute mounted CA, client certificate, "
                "and client key paths"
            )
        if not insecure_temporal_test and not self.temporal_tls_server_name:
            raise ConfigurationError("TEMPORAL_TLS_SERVER_NAME is required with TLS")

    def _validate_odoo_transport(self, enabled: set[str]) -> None:
        source_scoped = {name for name in enabled if name.endswith("_ODOO_DELIVERY_ENABLED")}
        if source_scoped and "ODOO_WRITE" not in enabled:
            raise ConfigurationError(
                "source-scoped Odoo delivery requires ODOO_WRITE: "
                + ", ".join(sorted(source_scoped))
            )
        # A malformed tenant secret map is a defect even while writes are off.
        self.odoo_tenant_hmac_secrets
        if "ODOO_WRITE" not in enabled:
            return
        if not self.odoo_19_base_url:
            raise ConfigurationError("ODOO_19_BASE_URL is required to write to Odoo")
        if not self.odoo_19_base_url.startswith("https://"):
            raise ConfigurationError("ODOO_19_BASE_URL must be an HTTPS endpoint")
        secrets = [self.odoo_default_hmac_secret, *self.odoo_tenant_hmac_secrets.values()]
        if not any(secrets):
            raise ConfigurationError(
                "ODOO_19_HMAC_SECRET or ODOO_19_TENANT_HMAC_SECRETS is required "
                "to write to Odoo"
            )
        if any(secret and len(secret) < 32 for secret in secrets):
            raise ConfigurationError("Odoo signing secrets must be at least 32 bytes")

    def _validate_environment_profile(self) -> None:
        if self.app_env not in {"staging", "production"}:
            if self.runtime_profile_id is not None:
                raise ConfigurationError(
                    "RUNTIME_PROFILE_ID is reserved for staging/production"
                )
            return
        profiles = _runtime_profiles()
        profile = profiles.get(self.runtime_profile_id or "")
        if profile is None:
            raise ConfigurationError(
                "RUNTIME_PROFILE_ID must select a registered runtime profile"
            )
        if profile.get("environment") != self.app_env:
            raise ConfigurationError("runtime profile does not match APP_ENV")
        self._validate_database_profile(profile["database"])
        self._validate_redis_profile(profile["redis"])
        nats_profile = profile["nats"]
        assert isinstance(nats_profile, dict)
        if self.nats_stream != nats_profile["stream"]:
            raise ConfigurationError("NATS_STREAM does not match the runtime profile")
        if self.nats_subject_prefix != nats_profile["subject_prefix"]:
            raise ConfigurationError(
                "NATS_SUBJECT_PREFIX does not match the runtime profile"
            )
        if self.nats_url is not None:
            try:
                parsed_nats = urlparse(self.nats_url)
                nats_port = parsed_nats.port
            except ValueError as exc:
                raise ConfigurationError("NATS_URL is malformed") from exc
            if (
                parsed_nats.scheme != "tls"
                or parsed_nats.hostname != nats_profile["host"]
                or nats_port != nats_profile["port"]
                or parsed_nats.username is not None
                or parsed_nats.password is not None
                or parsed_nats.path not in {"", "/"}
                or parsed_nats.query
                or parsed_nats.fragment
            ):
                raise ConfigurationError("NATS_URL does not match the runtime profile")
        temporal_profile = profile["temporal"]
        assert isinstance(temporal_profile, dict)
        if self.temporal_namespace != temporal_profile["namespace"]:
            raise ConfigurationError(
                "TEMPORAL_NAMESPACE does not match the runtime profile"
            )
        if self.temporal_task_queue != temporal_profile["task_queue"]:
            raise ConfigurationError(
                "TEMPORAL_TASK_QUEUE does not match the runtime profile"
            )
        if (
            self.temporal_address is not None
            and self.temporal_address != temporal_profile["address"]
        ):
            raise ConfigurationError(
                "TEMPORAL_ADDRESS does not match the runtime profile"
            )
        temporal_host = str(temporal_profile["address"]).rsplit(":", 1)[0]
        if (
            self.temporal_tls_server_name is not None
            and self.temporal_tls_server_name != temporal_host
        ):
            raise ConfigurationError(
                "TEMPORAL_TLS_SERVER_NAME does not match the runtime profile"
            )
        secret_prefix = profile["secret_path_prefix"]
        assert isinstance(secret_prefix, str)
        for credential in (
            self.nats_credentials_file,
            self.temporal_server_root_ca_file,
            self.temporal_client_cert_file,
            self.temporal_client_key_file,
        ):
            normalized = str(credential).replace("\\", "/") if credential is not None else None
            if normalized is not None and not normalized.startswith(secret_prefix):
                raise ConfigurationError(
                    "mounted credential path does not match the runtime profile"
                )
        if (
            profile["production_activation_allowed"] is not True
            and self.production_activation_id is not None
        ):
            raise ConfigurationError(
                "PRODUCTION_ACTIVATION_ID is forbidden by the runtime profile"
            )

    def _validate_database_profile(self, raw_profile: object) -> None:
        assert isinstance(raw_profile, dict)
        try:
            parsed = urlparse(self.database_url or "")
            port = parsed.port
            query = parse_qs(parsed.query, strict_parsing=True) if parsed.query else {}
        except ValueError as exc:
            raise ConfigurationError("DATABASE_URL is malformed") from exc
        if (
            parsed.scheme != raw_profile["scheme"]
            or parsed.hostname != raw_profile["host"]
            or port != raw_profile["port"]
            or unquote(parsed.path.lstrip("/")) != raw_profile["name"]
            or unquote(parsed.username or "") != raw_profile["username"]
            or not parsed.password
            or query
            != ({"sslmode": [raw_profile["sslmode"]]} if raw_profile.get("sslmode") else {})
            or parsed.params
            or parsed.fragment
        ):
            raise ConfigurationError(
                "DATABASE_URL does not match the locked runtime profile"
            )

    def _validate_redis_profile(self, raw_profile: object) -> None:
        assert isinstance(raw_profile, dict)
        try:
            parsed = urlparse(self.redis_url or "")
            port = parsed.port
            database = int(unquote(parsed.path.lstrip("/")))
        except ValueError as exc:
            raise ConfigurationError("REDIS_URL is malformed") from exc
        if (
            parsed.scheme != raw_profile["scheme"]
            or parsed.hostname != raw_profile["host"]
            or port != raw_profile["port"]
            or unquote(parsed.username or "") != raw_profile["username"]
            or not parsed.password
            or database != raw_profile["database"]
            or parsed.query
            or parsed.params
            or parsed.fragment
        ):
            raise ConfigurationError(
                "REDIS_URL does not match the locked runtime profile"
            )

    def validate_safety(self) -> None:
        if self.telnexa_event_ingress_enabled:
            if not self.sms_delivery:
                raise ValueError(
                    "SMS_DELIVERY must be true before enabling Telnexa event ingress"
                )
            if not (
                self.telnexa_event_api_key.strip()
                or self.telnexa_event_api_key_file.strip()
            ):
                raise ValueError(
                    "Telnexa event API key is required when ingress is enabled"
                )
            if not (
                self.telnexa_event_hmac_secret.strip()
                or self.telnexa_event_hmac_secret_file.strip()
            ):
                raise ValueError(
                    "Telnexa event HMAC secret is required when ingress is enabled"
                )
        if self.klyrow_event_ingress_enabled:
            if not (
                self.klyrow_event_api_key.strip()
                or self.klyrow_event_api_key_file.strip()
            ):
                raise ValueError(
                    "Klyrow event API key is required when ingress is enabled"
                )
            if not (
                self.klyrow_event_hmac_secret.strip()
                or self.klyrow_event_hmac_secret_file.strip()
            ):
                raise ValueError(
                    "Klyrow event HMAC secret is required when ingress is enabled"
                )
        if self.social_n8n_delivery_batch_size not in range(1, 26):
            raise ValueError("social n8n delivery batch size must be between 1 and 25")
        if self.social_n8n_delivery_lease_seconds not in range(10, 601):
            raise ValueError("social n8n delivery lease must be between 10 and 600 seconds")
        if self.postly_poll_interval_seconds not in range(30, 3601):
            raise ValueError("Postly polling interval must be between 30 and 3600 seconds")
        if self.postly_poll_lookback_seconds not in range(60, 86401):
            raise ValueError("Postly polling lookback must be between 60 seconds and one day")
        if self.postly_poll_batch_size not in range(1, 501):
            raise ValueError("Postly polling batch size must be between 1 and 500")
        if self.social_worker_concurrency != 1:
            raise ValueError(
                "social worker concurrency must remain 1 in controlled staging"
            )
        broad_event_switches = (
            self.broad_event_send_enabled,
            self.broad_event_delivery_enabled,
            self.production_n8n_enabled,
            self.n8n_production_workflows_enabled,
        )
        production_switches = (
            self.live_writes_enabled,
            self.odoo_write_enabled,
            self.allow_non_test_campaigns,
            self.vicidial_write_enabled,
            self.messaging_enabled,
            self.external_dial_enabled,
            self.enable_external_delivery,
            self.email_dispatch_enabled,
            self.sms_dispatch_enabled,
            self.allow_live_email,
            self.allow_live_sms,
            self.outbox_worker_enabled,
            self.odoo_recording_write_enabled,
            self.n8n_recording_workflow_enabled,
            self.n8n_recording_binding_enabled,
            self.n8n_recording_workflow_active,
            self.telephony_provisioning_enabled,
            self.telephony_command_worker_enabled,
            self.vicidial_provisioning_enabled,
            self.pjsip_provisioning_enabled,
            self.vicidial_publication_enabled,
            self.outreach_enabled,
            not self.lead_verification_dry_run_only,
            self.lead_outreach_enabled,
            self.odoo_lead_write_enabled,
            self.vicidial_lead_write_enabled,
            self.n8n_lead_delivery_enabled,
            self.postly_lead_delivery_enabled,
            self.odoo_production_writes_enabled,
            self.klyrow_odoo_projection_enabled,
            self.social_odoo_write_enabled,
            self.live_identity_provisioning_enabled,
        )
        if any(production_switches):
            raise ValueError("live writes and non-TEST_SYN campaigns are disabled")
        if self.scraper_middleware_delivery_enabled:
            campaigns = {
                value.strip()
                for value in self.sales_scraper_campaign_allowlist.split(",")
                if value.strip()
            }
            if (
                self.environment not in {"test", "staging"}
                or campaigns != {"TEST_SYN"}
                or not self.scraper_odoo_apply_url.startswith(("http://", "https://"))
                or not self.lead_automation_hmac_secret
            ):
                raise ValueError("scraper delivery requires isolated TEST_SYN staging")
        if self.scraper_result_ingest_enabled:
            key_ids = {
                value.strip()
                for value in self.sales_scraper_hmac_key_ids.split(",")
                if value.strip()
            }
            authorized_parties = {
                value.strip()
                for value in self.sales_scraper_jwt_authorized_parties.split(",")
                if value.strip()
            }
            if (
                not self.sales_scraper_identity
                or not self.sales_scraper_tenant_id
                or not self.sales_scraper_campaign_allowlist
                or not self.sales_scraper_hmac_keys_directory
                or not 1 <= len(key_ids) <= 3
                or not self.sales_scraper_jwt_issuer
                or not self.sales_scraper_jwt_audience
                or not self.sales_scraper_jwt_jwks_url
                or self.sales_scraper_identity not in authorized_parties
                or not self.sales_scraper_jwt_required_scope
                or not self.sales_scraper_jwt_required_role
                or self.sales_scraper_rate_limit_per_minute not in range(1, 601)
            ):
                raise ValueError("scraper ingress authentication is incomplete")
            if set(self.sales_scraper_hmac_keys) != key_ids:
                raise ValueError("scraper HMAC key enrollment is inconsistent")
        social_publish_switches = (
            self.social_publish_enabled,
            self.postiz_publish_enabled,
        )
        if any(social_publish_switches):
            if not all(social_publish_switches):
                raise ValueError("social and provider publish switches must agree")
            if not all(
                (
                    self.social_production_mode,
                    self.social_integration_enabled,
                    self.social_production_canary_enabled,
                    self.social_production_backup_gate_verified,
                    self.social_production_rollback_gate_verified,
                    self.social_production_webhook_gate_verified,
                    self.social_production_monitoring_gate_verified,
                    self.social_sql_repository_enabled,
                    self.social_worker_enabled,
                    self.postiz_delivery_enabled,
                    self.social_production_canary_account_ids.strip(),
                )
            ):
                raise ValueError(
                    "production social publishing requires every canary gate"
                )
            if not all(
                (
                    self.postiz_internal_base_url.strip(),
                    self.postiz_api_key_file.strip(),
                    self.postly_webhook_secret_file.strip(),
                )
            ):
                raise ValueError("production Postly secrets and endpoint are required")
            self.postiz_api_key
            self.postly_webhook_verification_secret
        if (
            self.social_automatic_provider_failover_enabled
            or self.social_automatic_dual_publish_enabled
        ):
            raise ValueError(
                "automatic provider failover and dual publishing are forbidden"
            )
        if any(broad_event_switches):
            if not all(broad_event_switches):
                raise ValueError("broad-event activation requires every canonical gate")
            required_scope = (
                self.broad_event_business_unit_allowlist,
                self.broad_event_campaign_allowlist,
                self.broad_event_workflow_allowlist,
                self.broad_event_type_allowlist,
                self.broad_event_activation_high_water_mark,
            )
            if (
                not self.controlled_broad_event_activation
                or not all(value.strip() for value in required_scope)
                or self.broad_event_submission_limit not in range(1, 26)
            ):
                raise ValueError(
                    "broad-event activation requires bounded explicit scope"
                )

    @property
    def broad_event_pipeline_enabled(self) -> bool:
        """Require every internal broad-event gate; external delivery is separate."""
        return all(
            (
                self.broad_event_send_enabled,
                self.broad_event_delivery_enabled,
                self.production_n8n_enabled,
                self.n8n_production_workflows_enabled,
            )
        )

    def load_secret_files(self) -> None:
        """Load runtime secrets without placing their values in environment metadata."""
        mappings = (
            ("database_url", self.database_url_file),
            ("redis_url", self.redis_url_file),
            ("middleware_secret", self.middleware_secret_file),
            # Ingestion deliberately has no legacy shared-secret fallback.
            ("ingestion_hmac_secret", self.vicidial_callback_hmac_secret_file),
            ("odoo_recording_hmac_secret", self.odoo_recording_hmac_secret_file),
            ("interaction_result_hmac_secret", self.interaction_result_hmac_secret_file),
            ("odoo_crm_bridge_hmac_secret", self.odoo_crm_bridge_hmac_secret_file),
        )
        for attribute, filename in mappings:
            if filename:
                path = Path(filename)
                if not path.is_absolute() or not path.is_file():
                    raise ValueError(f"required {attribute} secret file is unavailable")
                value = path.read_text().strip()
                if not value:
                    raise ValueError(f"required {attribute} secret file is empty")
                setattr(self, attribute, value)

    @property
    def sales_scraper_hmac_keys(self) -> dict[str, bytes]:
        directory = Path(self.sales_scraper_hmac_keys_directory)
        if (
            not directory.is_absolute()
            or directory.is_symlink()
            or not directory.is_dir()
            or directory.stat().st_mode & 0o077
            or directory.stat().st_uid != os.geteuid()
        ):
            raise ValueError("sales scraper HMAC key directory is unavailable or unsafe")
        key_ids = [
            value.strip()
            for value in self.sales_scraper_hmac_key_ids.split(",")
            if value.strip()
        ]
        if not 1 <= len(key_ids) <= 3 or len(key_ids) != len(set(key_ids)):
            raise ValueError("sales scraper HMAC trusted-key set is invalid")
        keys: dict[str, bytes] = {}
        for key_id in key_ids:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", key_id):
                raise ValueError("sales scraper HMAC key ID is invalid")
            path = self._protected_secret_path(
                str(directory / f"{key_id}.key"), "sales scraper HMAC"
            )
            if path.stat().st_uid != os.geteuid():
                raise ValueError("sales scraper HMAC secret has an unsafe owner")
            value = path.read_bytes().strip()
            if len(value) < 32:
                raise ValueError("sales scraper HMAC secret is too short")
            keys[key_id] = value
        return keys

    @staticmethod
    def _optional_secret(filename: str, label: str) -> str:
        if not filename:
            return ""
        path = Path(filename)
        if not path.is_absolute() or not path.is_file():
            raise ValueError(f"{label} secret file is unavailable")
        value = path.read_text().strip()
        if not value:
            raise ValueError(f"{label} secret file is empty")
        return value

    @property
    def keycloak_lifecycle_client_secret(self) -> str:
        return self._optional_secret(
            self.keycloak_lifecycle_client_secret_file,
            "Keycloak lifecycle adapter client secret",
        )

    @property
    def qwen_base_url(self) -> str:
        return self._optional_secret(self.qwen_base_url_file, "Qwen base URL")

    @property
    def qwen_api_key(self) -> str:
        return self._optional_secret(self.qwen_api_key_file, "Qwen API key")

    @property
    def litellm_base_url(self) -> str:
        return self._optional_secret(self.litellm_base_url_file, "LiteLLM base URL")

    @property
    def litellm_api_key(self) -> str:
        return self._optional_secret(self.litellm_api_key_file, "LiteLLM API key")

    @property
    def openai_api_key(self) -> str:
        return self._protected_secret(self.openai_api_key_file, "OpenAI API key")

    @property
    def openai_safety_salt(self) -> bytes:
        path = self._protected_secret_path(
            self.openai_safety_salt_file, "OpenAI safety identifier salt"
        )
        value = path.read_bytes()
        if len(value) < 32:
            raise ValueError("OpenAI safety identifier salt is too short")
        return value

    @property
    def elevenlabs_api_key(self) -> str:
        """Load an ASCII API key without ever including it in an error."""
        if self.elevenlabs_api_key_file != "/run/secrets/elevenlabs-api-key":
            raise ValueError("ElevenLabs API key path is not approved")
        return self._protected_text_secret(
            self.elevenlabs_api_key_file, "ElevenLabs API key"
        )

    @classmethod
    def _protected_text_secret(cls, filename: str, label: str) -> str:
        path = cls._protected_secret_path(filename, label)
        metadata = path.stat()
        if (
            metadata.st_uid != os.geteuid()
            or metadata.st_gid != os.getegid()
            or metadata.st_mode & 0o777 != 0o400
        ):
            raise ValueError(f"{label} secret file metadata is unsafe")
        value = path.read_bytes()
        if value.endswith(b"\r\n"):
            value = value[:-2]
        elif value.endswith((b"\r", b"\n")):
            value = value[:-1]
        if not value or b"\x00" in value or any(byte in b" \t\r\n" for byte in value):
            raise ValueError("ElevenLabs API key is malformed")
        try:
            return value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("ElevenLabs API key is malformed") from exc

    @staticmethod
    def _protected_secret_path(filename: str, label: str) -> Path:
        path = Path(filename)
        if (
            not filename
            or not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or path.stat().st_mode & 0o077
        ):
            raise ValueError(f"{label} secret file is unavailable or unsafe")
        return path

    @classmethod
    def _protected_secret(cls, filename: str, label: str) -> str:
        path = cls._protected_secret_path(filename, label)
        value = path.read_text().strip()
        if not value:
            raise ValueError(f"{label} secret file is empty")
        return value

    @property
    def postiz_api_key(self) -> str:
        if not self.postiz_api_key_file:
            return ""
        return self._protected_secret(self.postiz_api_key_file, "Postiz API key")

    @property
    def postly_webhook_verification_secret(self) -> str:
        if self.postly_webhook_secret_file:
            return self._protected_secret(
                self.postly_webhook_secret_file, "Postly webhook"
            )
        if self.social_production_mode:
            return ""
        return self.postly_webhook_secret

    def load_registry_snapshot_key(self) -> bytes:
        path = Path(self.registry_snapshot_signing_key_file)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("registry snapshot signing key file is unavailable")
        value = path.read_bytes().strip()
        if len(value) < 32:
            raise ValueError("registry snapshot signing key is too short")
        return value

    @field_validator("openai_worker_max_concurrency")
    @classmethod
    def validate_openai_worker_max_concurrency(cls, value: int) -> int:
        if value != 1:
            raise ValueError("OpenAI worker concurrency must equal one")
        return value

    @field_validator("elevenlabs_base_url")
    @classmethod
    def validate_elevenlabs_base_url(cls, value: str) -> str:
        if value != "https://api.elevenlabs.io":
            raise ValueError("ElevenLabs base URL must be the approved HTTPS host")
        return value

    @field_validator("elevenlabs_model_id")
    @classmethod
    def validate_elevenlabs_model_id(cls, value: str) -> str:
        if value != "eleven_flash_v2_5":
            raise ValueError("ElevenLabs model is not approved")
        return value

    @field_validator("elevenlabs_canary_voice_id")
    @classmethod
    def validate_elevenlabs_canary_voice_id(cls, value: str) -> str:
        if value and not re.fullmatch(r"[A-Za-z0-9]{1,64}", value):
            raise ValueError("ElevenLabs voice identifier is invalid")
        return value

    @field_validator("elevenlabs_browser_output_format")
    @classmethod
    def validate_elevenlabs_browser_output_format(cls, value: str) -> str:
        if value != "mp3_44100_128":
            raise ValueError("ElevenLabs browser output format is not approved")
        return value

    @field_validator("elevenlabs_telephony_output_format")
    @classmethod
    def validate_elevenlabs_telephony_output_format(cls, value: str) -> str:
        if value != "ulaw_8000":
            raise ValueError("ElevenLabs telephony output format is not approved")
        return value

    @field_validator("elevenlabs_max_concurrency")
    @classmethod
    def validate_elevenlabs_max_concurrency(cls, value: int) -> int:
        if value != 1:
            raise ValueError("ElevenLabs concurrency must equal one")
        return value

    @field_validator("elevenlabs_max_text_characters")
    @classmethod
    def validate_elevenlabs_max_text_characters(cls, value: int) -> int:
        if value != 1000:
            raise ValueError("ElevenLabs text limit must equal 1000")
        return value

    @field_validator(
        "elevenlabs_connect_timeout_seconds",
        "elevenlabs_read_timeout_seconds",
        "elevenlabs_total_timeout_seconds",
    )
    @classmethod
    def validate_elevenlabs_timeout(cls, value: float) -> float:
        if value <= 0 or value > 120:
            raise ValueError("ElevenLabs timeout is invalid")
        return value

    @field_validator("elevenlabs_max_retries")
    @classmethod
    def validate_elevenlabs_max_retries(cls, value: int) -> int:
        if value not in range(0, 3):
            raise ValueError("ElevenLabs retry count is invalid")
        return value

    @field_validator("elevenlabs_request_logging_mode")
    @classmethod
    def validate_elevenlabs_logging_mode(cls, value: str) -> str:
        if value not in {"standard", "zero_retention"}:
            raise ValueError("ElevenLabs request logging mode is invalid")
        return value

    @field_validator("vicidial_authorization_url", "vicidial_edge_url")
    @classmethod
    def validate_vicidial_private_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in VICIDIAL_PRIVATE_HOSTS
            or parsed.port != VICIDIAL_PRIVATE_PORT
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("VICIdial URL must use an approved private HTTPS endpoint")
        return value.rstrip("/")

    @field_validator("n8n_production_target_url")
    @classmethod
    def validate_n8n_production_target_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "n8n.internal.codestra.agency"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/webhook/codestra/v1/events"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("n8n target must be the approved internal webhook")
        return value

    @field_validator("n8n_workflow_package_sha256")
    @classmethod
    def validate_workflow_package_sha256(cls, value: str) -> str:
        if value and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("workflow package identity must be an exact SHA-256")
        return value

    @field_validator("n8n_production_image_digest")
    @classmethod
    def validate_n8n_production_image_digest(cls, value: str) -> str:
        if value and not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
            raise ValueError("n8n image identity must be an exact sha256 digest")
        return value

    @field_validator("telnexa_event_signature_ttl_seconds")
    @classmethod
    def validate_telnexa_signature_ttl(cls, value: int) -> int:
        if isinstance(value, bool) or value not in range(1, 901):
            raise ValueError(
                "Telnexa event signature TTL must be between 1 and 900 seconds"
            )
        return value

    @field_validator("telnexa_event_request_max_bytes")
    @classmethod
    def validate_telnexa_request_max_bytes(cls, value: int) -> int:
        if isinstance(value, bool) or value not in range(1_024, 10_485_761):
            raise ValueError(
                "Telnexa event request size must be between 1024 and 10485760 bytes"
            )
        return value

    @field_validator("klyrow_event_signature_ttl_seconds")
    @classmethod
    def validate_klyrow_signature_ttl(cls, value: int) -> int:
        if isinstance(value, bool) or value not in range(1, 901):
            raise ValueError(
                "Klyrow event signature TTL must be between 1 and 900 seconds"
            )
        return value

    @field_validator("klyrow_event_request_max_bytes")
    @classmethod
    def validate_klyrow_request_max_bytes(cls, value: int) -> int:
        if isinstance(value, bool) or value not in range(1_024, 10_485_761):
            raise ValueError(
                "Klyrow event request size must be between 1024 and 10485760 bytes"
            )
        return value

    @field_validator("webphone_endpoint_adapter_url")
    @classmethod
    def validate_webphone_endpoint_adapter_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "authorization.internal.codestra.agency"
            or parsed.port != VICIDIAL_ENDPOINT_ADAPTER_PORT
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("webphone endpoint adapter must use private HTTPS")
        return value.rstrip("/")

    @field_validator(
        "vicidial_ca_file",
        "vicidial_client_cert_file",
        "vicidial_client_key_file",
        "vicidial_crl_file",
    )
    @classmethod
    def validate_vicidial_secret_path(cls, value: str) -> str:
        if not value:
            return value
        path = Path(value)
        if not path.is_absolute() or path.parent != VICIDIAL_SECRET_ROOT:
            raise ValueError(
                "VICIdial mTLS files must be direct children of the secret mount"
            )
        return value

    @property
    def vicidial_mtls_configured(self) -> bool:
        return all(
            (
                self.vicidial_authorization_url,
                self.vicidial_edge_url,
                self.vicidial_ca_file,
                self.vicidial_client_cert_file,
                self.vicidial_client_key_file,
            )
        )

    @property
    def allowed_campaigns(self) -> frozenset[str]:
        return frozenset(
            value.strip()
            for value in self.automation_allowed_campaigns.split(",")
            if value.strip()
        )

    @property
    def auth_ready(self) -> bool:
        return bool(self.middleware_secret and self.ingestion_hmac_secret)

    @property
    def webphone_identity_ready(self) -> bool:
        return all(
            (
                self.webphone_staging_provisioning_enabled,
                self.keycloak_issuer,
                self.keycloak_audience,
                self.keycloak_jwks_url,
                self.keycloak_authorized_parties,
                self.keycloak_userinfo_url,
                self.provisioning_service_url,
                self.provisioning_service_token_url,
                self.provisioning_service_client_id,
                self.provisioning_service_client_secret_file,
                self.provisioning_service_ca_file,
            )
        )

    @property
    def publisher_hmac_keys(self) -> dict[str, bytes]:
        if not self.publisher_hmac_keys_file:
            return {}
        path = Path(self.publisher_hmac_keys_file)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("publisher key file unavailable")
        values = json.loads(path.read_text())
        if not isinstance(values, dict) or not values:
            raise ValueError("publisher key file invalid")
        return {
            key_id: base64.urlsafe_b64decode(value + "===")
            for key_id, value in values.items()
        }

    @staticmethod
    def _load_binary_secret(filename: str, label: str) -> bytes:
        path = Path(filename)
        if not filename or not path.is_absolute() or not path.is_file():
            raise ValueError(f"{label} file unavailable")
        try:
            value = base64.urlsafe_b64decode(path.read_text().strip() + "===")
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{label} file invalid") from exc
        if len(value) < 32:
            raise ValueError(f"{label} must contain at least 256 bits")
        return value

    @property
    def quarantine_encryption_key(self) -> bytes:
        value = self._load_binary_secret(
            self.quarantine_encryption_key_file, "quarantine encryption key"
        )
        if len(value) != 32:
            raise ValueError("quarantine encryption key must be 256 bits")
        return value

    @property
    def quarantine_fingerprint_secret(self) -> bytes:
        return self._load_binary_secret(
            self.quarantine_fingerprint_secret_file,
            "quarantine fingerprint secret",
        )

    @property
    def quarantine_reviewer_secret(self) -> bytes:
        return self._load_binary_secret(
            self.quarantine_reviewer_secret_file,
            "quarantine reviewer authorization secret",
        )

    @property
    def enabled_events(self) -> frozenset[str]:
        return frozenset(
            x.strip() for x in self.enabled_event_types.split(",") if x.strip()
        )

    @property
    def ingestion_clients(self) -> frozenset[str]:
        return frozenset(
            x.strip() for x in self.allowed_client_instances.split(",") if x.strip()
        )


settings = Settings()
settings.load_secret_files()
if settings.database_url.startswith("postgresql://"):
    settings.database_url = settings.database_url.replace(
        "postgresql://", "postgresql+asyncpg://", 1
    )
settings.validate_safety()
