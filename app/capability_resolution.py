from __future__ import annotations

from collections.abc import Mapping
from typing import Any


_UMBRELLA_CONTROLS = frozenset(
    {
        "LIVE_ADVERTISING_ENABLED",
        "EXTERNAL_DELIVERY_ENABLED",
        "SOCIAL_PUBLISHING_ENABLED",
        "EXTERNAL_MODEL_CALLS_ENABLED",
        "N8N_EXTERNAL_PROVIDER_WRITES",
    }
)

_UMBRELLA_BY_IMPLEMENTATION = {
    "ODOO_WRITE": "EXTERNAL_DELIVERY_ENABLED",
    "FORM_ODOO_DELIVERY_ENABLED": "EXTERNAL_DELIVERY_ENABLED",
    "CRAWLER_ODOO_DELIVERY_ENABLED": "EXTERNAL_DELIVERY_ENABLED",
    "SCRAPPER_ODOO_DELIVERY_ENABLED": "EXTERNAL_DELIVERY_ENABLED",
    "SMS_DELIVERY_ENABLED": "EXTERNAL_DELIVERY_ENABLED",
    "EMAIL_DELIVERY_ENABLED": "EXTERNAL_DELIVERY_ENABLED",
    "LIVE_SMS_DELIVERY": "EXTERNAL_DELIVERY_ENABLED",
    "LIVE_EMAIL_DELIVERY": "EXTERNAL_DELIVERY_ENABLED",
    "SOCIAL_DELIVERY_ENABLED": "SOCIAL_PUBLISHING_ENABLED",
    "N8N_DELIVERY_ENABLED": "N8N_EXTERNAL_PROVIDER_WRITES",
    "N8N_PRODUCTION_WORKFLOWS_ENABLED": "N8N_EXTERNAL_PROVIDER_WRITES",
}


def effective_capability_enabled(
    capabilities: Mapping[str, Any],
    capability: str,
) -> bool:
    """Resolve an implementation capability without truthy coercion.

    An umbrella control is a kill switch, never a grantable capability. A
    lower-level implementation gate must be explicitly true, and its mapped
    umbrella must also be explicitly true. Unknown or malformed evidence
    always fails closed. Legacy top-level booleans are retained only for
    implementation controls that are not duplicated in the runtime section.
    """

    if not isinstance(capability, str) or not capability or len(capability) > 100:
        return False
    if capability in _UMBRELLA_CONTROLS:
        return False

    runtime = capabilities.get("runtime")
    if isinstance(runtime, Mapping) and capability in runtime:
        implementation_enabled = runtime[capability] is True
    else:
        implementation_enabled = capabilities.get(capability) is True
    if not implementation_enabled:
        return False

    umbrella_name = _UMBRELLA_BY_IMPLEMENTATION.get(capability)
    if umbrella_name is None:
        return True
    umbrella = capabilities.get("umbrella_controls")
    return isinstance(umbrella, Mapping) and umbrella.get(umbrella_name) is True
