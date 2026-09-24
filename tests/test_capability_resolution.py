from __future__ import annotations

import pytest

from app.capability_resolution import effective_capability_enabled


def capabilities() -> dict[str, object]:
    return {
        "runtime": {
            "ODOO_WRITE": True,
            "SMS_DELIVERY_ENABLED": False,
            "MALFORMED_RUNTIME": "true",
        },
        "umbrella_controls": {
            "EXTERNAL_DELIVERY_ENABLED": True,
            "LIVE_ADVERTISING_ENABLED": True,
            "MALFORMED_UMBRELLA": 1,
        },
        "LEGACY_BOOLEAN": True,
        "LEGACY_TRUTHY_STRING": "true",
    }


@pytest.mark.parametrize(
    "capability",
    [
        "ODOO_WRITE",
        "LEGACY_BOOLEAN",
    ],
)
def test_effective_capability_resolver_accepts_explicit_implementation_grants(
    capability: str,
) -> None:
    assert effective_capability_enabled(capabilities(), capability) is True


@pytest.mark.parametrize(
    "capability",
    [
        "SMS_DELIVERY_ENABLED",
        "LIVE_ADVERTISING_ENABLED",
        "EXTERNAL_DELIVERY_ENABLED",
        "MALFORMED_RUNTIME",
        "MALFORMED_UMBRELLA",
        "LEGACY_TRUTHY_STRING",
        "UNKNOWN_CAPABILITY",
        "",
    ],
)
def test_effective_capability_resolver_fails_closed(
    capability: str,
) -> None:
    assert effective_capability_enabled(capabilities(), capability) is False


def test_required_umbrella_must_be_enabled_for_implementation_capability() -> None:
    values = capabilities()
    values["umbrella_controls"] = {
        **values["umbrella_controls"],  # type: ignore[dict-item]
        "EXTERNAL_DELIVERY_ENABLED": False,
    }

    assert effective_capability_enabled(values, "ODOO_WRITE") is False


def test_nested_authority_overrides_legacy_top_level_value() -> None:
    values = capabilities()
    values["SMS_DELIVERY_ENABLED"] = True
    values["LIVE_ADVERTISING_ENABLED"] = True

    assert effective_capability_enabled(values, "SMS_DELIVERY_ENABLED") is False
    assert effective_capability_enabled(values, "LIVE_ADVERTISING_ENABLED") is False
