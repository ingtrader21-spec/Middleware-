"""No two handlers may claim the same method+path in either composed app.

FastAPI dispatches to the first match, so a duplicate silently shadows the
later router. app/api/v1/orders.py once registered POST
/api/v1/integrations/n8n/results ahead of the durable JWT handler in
app/api/v1/integrations.py; this test keeps that from recurring.
"""

from collections import Counter

import pytest

from app.entrypoints.integration_api import app as integration_app
from app.main import app as monolith_app


def iter_routes(routes, prefix=""):
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            context = getattr(route, "include_context", None)
            yield from iter_routes(original.routes, prefix + (getattr(context, "prefix", "") or ""))
            continue
        path = getattr(route, "path", None)
        if path is not None:
            for method in getattr(route, "methods", None) or ():
                yield method, prefix + path, getattr(route, "endpoint", None)


# The monolith duplicates that existed since #147 (control.event shadowing
# lead_automation.receive_odoo_event on /events/odoo and being shadowed by
# events.ingest_vicidial on /events/vicidial) were removed with the single
# application factory: the registry refuses any duplicate at build time.
KNOWN_MONOLITH_DUPLICATES: list[tuple[str, str]] = []


@pytest.mark.parametrize(
    "application,known",
    [(monolith_app, KNOWN_MONOLITH_DUPLICATES), (integration_app, [])],
    ids=["main", "integration_api"],
)
def test_no_duplicate_method_path_pairs(application, known):
    table = list(iter_routes(application.routes))
    assert table, "route walk found nothing; included routers were not expanded"
    counts = Counter((method, path) for method, path, _endpoint in table)
    duplicates = sorted(key for key, count in counts.items() if count > 1)
    assert duplicates == sorted(known), duplicates


def test_registry_refuses_duplicate_registrations():
    from fastapi import APIRouter, FastAPI

    from app.router_registry import DuplicateRouteError, assert_unique_routes

    first = APIRouter()
    second = APIRouter()

    @first.get("/api/v1/example")
    async def one():  # pragma: no cover - never called
        return {}

    @second.get("/api/v1/example")
    async def two():  # pragma: no cover - never called
        return {}

    app = FastAPI()
    app.include_router(first)
    app.include_router(second)
    with pytest.raises(DuplicateRouteError, match="GET /api/v1/example"):
        assert_unique_routes(app)


@pytest.mark.parametrize("application", [monolith_app, integration_app], ids=["main", "integration_api"])
def test_n8n_standard_result_route_belongs_to_the_integrations_handler(application):
    owners = {
        endpoint.__module__
        for method, path, endpoint in iter_routes(application.routes)
        if method == "POST" and path == "/api/v1/integrations/n8n/results"
    }
    assert owners == {"app.api.v1.integrations"}
