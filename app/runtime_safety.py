from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.core.config import Settings


class RuntimeSafetyRelease(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_sha: str = Field(min_length=1)
    image_digest: str = Field(min_length=1)
    schema_head: str = Field(min_length=1)
    build_time: str = Field(min_length=1)


class RuntimeSafetyPersistence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    in_memory: bool


class RuntimeSafetyDispatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outbox_enabled: bool
    nats_mode: Literal["disabled", "isolated", "production"]
    temporal_worker_mode: Literal["disabled", "isolated", "production"]


class RuntimeSafetyUmbrellaControls(BaseModel):
    model_config = ConfigDict(extra="forbid")

    LIVE_ADVERTISING_ENABLED: bool
    EXTERNAL_DELIVERY_ENABLED: bool
    SOCIAL_PUBLISHING_ENABLED: bool
    EXTERNAL_MODEL_CALLS_ENABLED: bool
    N8N_EXTERNAL_PROVIDER_WRITES: bool


class RuntimeSafetyReadback(BaseModel):
    """Machine-readable v1.1 response published by the runtime OpenAPI."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.1"]
    service: Literal["middleware-api"]
    environment: Literal["development", "test", "staging", "production"]
    runtime_profile_id: str = Field(min_length=1)
    release: RuntimeSafetyRelease
    persistence: RuntimeSafetyPersistence
    dispatch: RuntimeSafetyDispatch
    external_effects: dict[str, bool] = Field(min_length=1)
    umbrella_controls: RuntimeSafetyUmbrellaControls
    production_dialing: Literal["DISABLED"]
    production_activation_configured: bool
    provider_effects_disabled: bool
    all_external_effects_disabled: bool
    staging_safe: bool


def runtime_safety_readback(settings: Settings) -> dict[str, Any]:
    """Return effective, non-secret controls from the immutable Settings object."""

    effects = dict(sorted(settings.external_effects.items()))
    umbrella_controls = dict(sorted(settings.umbrella_controls.items()))
    provider_effects_disabled = not any(
        enabled for name, enabled in effects.items() if name != "SEND_EVENTS"
    ) and not any(umbrella_controls.values())
    all_effects_disabled = not any(effects.values()) and not any(
        umbrella_controls.values()
    )
    staging_safe = (
        settings.app_env == "staging"
        and not settings.allow_in_memory_storage
        and all_effects_disabled
        and not settings.outbox_dispatch_enabled
        and settings.nats_dispatch_mode == "disabled"
        and settings.temporal_worker_mode == "disabled"
        and settings.production_dialing == "DISABLED"
        and settings.production_activation_id is None
    )
    return {
        "schema_version": "1.1",
        "service": "middleware-api",
        "environment": settings.app_env,
        "runtime_profile_id": settings.runtime_profile_id or "local-unlocked",
        "release": {
            "source_sha": settings.source_sha,
            "image_digest": settings.image_digest,
            "schema_head": settings.schema_head,
            "build_time": settings.build_time,
        },
        "persistence": {
            "in_memory": settings.allow_in_memory_storage,
        },
        "dispatch": {
            "outbox_enabled": settings.outbox_dispatch_enabled,
            "nats_mode": settings.nats_dispatch_mode,
            "temporal_worker_mode": settings.temporal_worker_mode,
        },
        "external_effects": effects,
        "umbrella_controls": umbrella_controls,
        "production_dialing": settings.production_dialing,
        "production_activation_configured": (
            settings.production_activation_id is not None
        ),
        "provider_effects_disabled": provider_effects_disabled,
        "all_external_effects_disabled": all_effects_disabled,
        "staging_safe": staging_safe,
    }
