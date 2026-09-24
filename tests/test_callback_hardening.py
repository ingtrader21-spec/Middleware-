from pathlib import Path

from app.entrypoints.integration_api import app


ROOT = Path(__file__).resolve().parents[1]


def _route_methods(routes, prefix: str = "") -> set[tuple[str, str]]:
    """Flatten routers mounted through ``include_router`` into (path, method)."""
    methods: set[tuple[str, str]] = set()
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            context = getattr(route, "include_context", None)
            methods |= _route_methods(
                original.routes, prefix + (getattr(context, "prefix", "") or "")
            )
            continue
        path = getattr(route, "path", None)
        if path is None:
            continue
        for method in getattr(route, "methods", None) or ():
            methods.add((prefix + path, method))
    return methods


def test_complete_callback_api_surface():
    methods = _route_methods(app.routes)
    required = {
        ("/api/v1/control/callbacks", "POST"),
        ("/api/v1/callbacks/{callback_id}", "GET"),
        ("/api/v1/callbacks/due", "GET"),
        ("/api/v1/control/callbacks/{callback_id}", "PATCH"),
        ("/api/v1/control/callbacks/{callback_id}/snooze", "POST"),
        ("/api/v1/control/callbacks/{callback_id}/reschedule", "POST"),
        ("/api/v1/control/callbacks/{callback_id}/reassign", "POST"),
        ("/api/v1/control/callbacks/{callback_id}/cancel", "POST"),
        ("/api/v1/control/callbacks/{callback_id}/complete", "POST"),
        ("/api/v1/control/callbacks/{callback_id}/call-now", "POST"),
        ("/api/v1/results/callbacks/{callback_id}", "POST"),
    }
    assert required <= methods


def test_postgres_rls_is_forced_and_context_is_transaction_local():
    migration = (
        ROOT / "migrations/versions/0052_callback_rls_hardening.py"
    ).read_text()
    for table in (
        "callback_record",
        "callback_event",
        "callback_delivery",
        "callback_popup_ack",
    ):
        assert f'"{table}"' in migration
    assert "FORCE ROW LEVEL SECURITY" in migration
    assert "current_setting('app.tenant_id'" in migration
    assert "current_setting('app.campaign_ids'" in migration
    assert "current_setting('app.actor_id'" in migration
    assert "current_setting('app.role'" in migration
    assert "NOBYPASSRLS" in migration
    context = (ROOT / "app/core/callback_rls.py").read_text()
    assert "set_config('app.tenant_id', :tenant, true)" in context
    assert "set_config('app.campaign_ids', :campaigns, true)" in context


def test_scheduler_uses_skip_locked_and_requires_tenant():
    source = (ROOT / "app/callback_scheduler.py").read_text()
    assert "with_for_update(skip_locked=True)" in source
    assert "tenant_id and campaign_id are required" in source


def test_no_callback_postal_secret_or_sqlite_production_path():
    callback_sources = "\n".join(
        path.read_text() for path in (ROOT / "app").rglob("*callback*.py")
    )
    assert "POSTAL_API_KEY" not in callback_sources
    assert "sqlite" not in callback_sources.lower()


def test_runtime_image_includes_named_timezone_database():
    requirements = (ROOT / "requirements.lock").read_text()
    assert "tzdata==2026.3" in requirements
