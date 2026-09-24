"""Monolith entry module.

``app`` is the in-process monolith: every route group of
``app.router_registry`` including the edge-denied legacy aliases.
``create_app`` is the single application factory re-exported for
``uvicorn app.main:create_app --factory`` (the control-plane canary) and for
tests. Nothing else lives here; middleware, health routes and error
handling are owned by ``app.application``.
"""

from __future__ import annotations

from app.application import AppProfile, create_app
from app.core.config import ConfigurationError
from app.core.request_guard import (
    AI_CONSOLE_SELF_AUTHENTICATED_PATHS,
    N8N_TRANSITION_PATH,
    RECORDING_EXPORTER_PATH,
    SELF_AUTHENTICATED_PATHS,
    SIGNED_WEBHOOK_PATHS,
    SOCIAL_WEBHOOK_PATH,
)
from app.core.runtime import RuntimeContainer

__all__ = [
    "AppProfile",
    "AI_CONSOLE_SELF_AUTHENTICATED_PATHS",
    "N8N_TRANSITION_PATH",
    "RECORDING_EXPORTER_PATH",
    "SELF_AUTHENTICATED_PATHS",
    "SIGNED_WEBHOOK_PATHS",
    "SOCIAL_WEBHOOK_PATH",
    "RuntimeContainer",
    "app",
    "create_app",
]

try:
    app = create_app(profile=AppProfile.MONOLITH)
except ConfigurationError as exc:  # pragma: no cover - surfaced by the process entrypoint
    raise RuntimeError(f"monolith configuration is invalid: {exc}") from exc
