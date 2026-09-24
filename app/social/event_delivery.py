from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.social.domain import NormalizedEvent


def n8n_projection(event: NormalizedEvent) -> dict[str, Any] | None:
    """Provider-neutral projection for the existing n8n delivery router."""
    if not settings.social_n8n_events_enabled:
        return None
    return {
        "event_id": str(event.event_id),
        "event_type": event.event_type,
        "event_version": event.event_version,
        "occurred_at": event.occurred_at.isoformat(),
        "correlation_id": event.correlation_id,
        "tenant_id": str(event.tenant_id),
        "source": "social",
        "provider": event.provider.value,
        "subject_id": str(event.subject_id),
        "payload": event.payload,
    }


def odoo_projection(event: NormalizedEvent) -> dict[str, Any] | None:
    """DTO boundary only; production Odoo writes are prohibited and fail closed."""
    if not settings.social_odoo_sync_enabled:
        return None
    if settings.social_odoo_write_enabled:
        raise RuntimeError("production social Odoo writes are disabled")
    return {
        "event_type": event.event_type,
        "subject_id": str(event.subject_id),
        "dry_run": True,
    }
