"""AUTH-01 regression: deployed integration must not mount tenantless legacy journals."""

from app import router_registry
from app.api.v1.commands import router as legacy_commands_router
from app.platform.api import router as platform_router


def test_integration_profile_retires_tenantless_legacy_command_router() -> None:
    assert legacy_commands_router not in router_registry.INTEGRATION_ROUTERS
    assert platform_router in router_registry.CANONICAL_ROUTERS


def test_legacy_command_router_cannot_become_canonical_by_accident() -> None:
    assert legacy_commands_router not in router_registry.CANONICAL_ROUTERS
    assert platform_router in router_registry.CANONICAL_ROUTERS
