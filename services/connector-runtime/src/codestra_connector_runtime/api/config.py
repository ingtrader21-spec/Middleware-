"""Fail-closed runtime configuration for the Connector Management API."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, HttpUrl, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RuntimeSettings(BaseSettings):
    """Configuration loaded only from the environment or mounted secret files."""

    model_config = SettingsConfigDict(
        env_prefix="CONNECTOR_RUNTIME_",
        # Deployment platforms conventionally provide upper-case variables.
        # Pydantic field names are lower-case, so strict case matching would
        # silently ignore CONNECTOR_RUNTIME_DATABASE_URL and fail startup.
        case_sensitive=False,
        extra="forbid",
    )

    environment: Literal["development", "staging", "production"] = "development"
    service_name: str = "codestra-connector-runtime"
    release_sha: str = "UNVERIFIED"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    database_url: SecretStr
    keycloak_issuer: HttpUrl = HttpUrl(
        "https://auth.codestra.co/realms/codestra"
    )
    keycloak_jwks_url: HttpUrl = HttpUrl(
        "https://auth.codestra.co/realms/codestra/protocol/openid-connect/certs"
    )
    oauth_audience: str = "codestra-middleware-api"
    allowed_azp: tuple[str, ...] = (
        "connector-management-api",
        "n8n-operations-automation",
    )
    maximum_token_lifetime_seconds: int = Field(default=300, ge=30, le=900)
    jwks_cache_seconds: int = Field(default=300, ge=30, le=3600)

    cursor_hmac_key: SecretStr
    body_encryption_key_file: Path
    webhook_body_root: Path = Path(
        "/var/lib/codestra-connector-runtime/webhook-bodies"
    )
    maximum_management_body_bytes: int = Field(
        default=1_048_576,
        ge=1024,
        le=10_485_760,
    )

    external_effects_enabled: bool = False
    connector_activation_enabled: bool = False
    webhook_ingress_enabled: bool = False
    connector_install_enabled: bool = False
    connector_upgrade_enabled: bool = False
    connector_disable_enabled: bool = False
    webhook_secret_rotation_enabled: bool = False
    webhook_replay_request_enabled: bool = False

    readiness_requires_migration: str = "20260828_0004"

    @field_validator("release_sha")
    @classmethod
    def validate_release_sha(cls, value: str) -> str:
        if value == "UNVERIFIED":
            return value
        if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("release_sha must be UNVERIFIED or a lowercase 40-character SHA")
        return value

    @field_validator("allowed_azp", mode="before")
    @classmethod
    def parse_allowed_azp(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value

    @model_validator(mode="after")
    def fail_closed_in_production(self) -> "RuntimeSettings":
        if self.environment in {"staging", "production"}:
            if self.release_sha == "UNVERIFIED":
                raise ValueError("a verified release SHA is required outside development")
            if not self.body_encryption_key_file.is_absolute():
                raise ValueError("body_encryption_key_file must be absolute")
            if not self.allowed_azp:
                raise ValueError("allowed_azp cannot be empty")
        if self.connector_activation_enabled:
            raise ValueError(
                "normal API connector activation is intentionally unsupported"
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> RuntimeSettings:
    return RuntimeSettings()  # type: ignore[call-arg]
