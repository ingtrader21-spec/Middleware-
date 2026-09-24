from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from app.core.config import Settings
from app.social.domain import ProviderName
from app.social.providers import SocialError


PRODUCTION_APPROVED = "PRODUCTION_APPROVED_CANARY"


def uuid_allowlist(value: str, setting_name: str) -> frozenset[UUID]:
    try:
        return frozenset(
            UUID(item.strip()) for item in value.split(",") if item.strip()
        )
    except ValueError as exc:
        raise SocialError(
            "SOCIAL_PRODUCTION_CONFIGURATION_INVALID",
            f"{setting_name} contains an invalid UUID",
            status_code=503,
        ) from exc


@dataclass(frozen=True, slots=True)
class ProductionPublishContext:
    tenant_id: UUID
    campaign_id: UUID | None
    account_id: UUID
    provider: ProviderName
    classification: str
    connection_state: str
    content_approved: bool


class ProductionCanaryPolicy:
    """Pure fail-closed policy evaluated before a production job is created."""

    def __init__(self, config: Settings) -> None:
        self.config = config

    def validate(self, context: ProductionPublishContext) -> None:
        if not all(
            (
                self.config.social_production_mode,
                self.config.social_integration_enabled,
                self.config.social_publish_enabled,
                self.config.social_production_canary_enabled,
                self.config.social_sql_repository_enabled,
                self.config.social_worker_enabled,
                self.config.social_production_backup_gate_verified,
                self.config.social_production_rollback_gate_verified,
                self.config.social_production_webhook_gate_verified,
                self.config.social_production_monitoring_gate_verified,
            )
        ):
            self._deny("SOCIAL_PRODUCTION_CANARY_DISABLED")
        if self.config.social_automatic_provider_failover_enabled:
            self._deny("SOCIAL_PROVIDER_FAILOVER_FORBIDDEN")
        if self.config.social_automatic_dual_publish_enabled:
            self._deny("SOCIAL_DUAL_PUBLISH_FORBIDDEN")
        accounts = uuid_allowlist(
            self.config.social_production_canary_account_ids,
            "SOCIAL_PRODUCTION_CANARY_ACCOUNT_IDS",
        )
        if not accounts or context.account_id not in accounts:
            self._deny("SOCIAL_PRODUCTION_ACCOUNT_DENIED")
        tenants = uuid_allowlist(
            self.config.social_production_canary_tenant_ids,
            "SOCIAL_PRODUCTION_CANARY_TENANT_IDS",
        )
        if tenants and context.tenant_id not in tenants:
            self._deny("SOCIAL_PRODUCTION_TENANT_DENIED")
        campaigns = uuid_allowlist(
            self.config.social_production_canary_campaign_ids,
            "SOCIAL_PRODUCTION_CANARY_CAMPAIGN_IDS",
        )
        if campaigns and (
            context.campaign_id is None or context.campaign_id not in campaigns
        ):
            self._deny("SOCIAL_PRODUCTION_CAMPAIGN_DENIED")
        if context.classification != PRODUCTION_APPROVED:
            self._deny("SOCIAL_PRODUCTION_ACCOUNT_NOT_APPROVED")
        if context.connection_state != "connected":
            self._deny("SOCIAL_ACCOUNT_DISCONNECTED")
        if not context.content_approved:
            self._deny("SOCIAL_PRODUCTION_CONTENT_NOT_APPROVED")

    @staticmethod
    def _deny(code: str) -> None:
        raise SocialError(code, "Production social publish was denied", status_code=403)


def require_provider_health(health: dict[str, object]) -> None:
    status = str(health.get("status", "")).upper()
    if status not in {"AVAILABLE", "HEALTHY"} or health.get("reachable") is False:
        raise SocialError(
            "SOCIAL_PROVIDER_UNAVAILABLE",
            "Production social provider is not healthy",
            status_code=503,
            retryable=True,
        )
