"""SHADOW_ROUTES=0: no literal route may be captured by an earlier
parameterised route on any application profile.

Starlette dispatches in mount order, so ``GET /api/v1/quarantine/{record_id}``
mounted before ``GET /api/v1/quarantine/events`` used to answer the latter
(a pre-existing defect fixed by constraining the record routes to
``{record_id:uuid}``). This walks every profile the way the router does and
fails on any literal path whose first full match is a different route.
"""

from __future__ import annotations

import pytest
from starlette.routing import Match

from app.application import AppProfile, create_app


def _routes(app):
    def walk(routes):
        for route in routes:
            original = getattr(route, "original_router", None)
            if original is not None:
                yield from walk(original.routes)
                continue
            yield route

    return [route for route in walk(app.routes) if hasattr(route, "matches")]


def _shadowed(app) -> list[str]:
    routes = _routes(app)
    findings: list[str] = []
    for route in routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if path is None or "{" in path or not methods:
            continue
        for method in sorted(methods):
            scope = {"type": "http", "method": method, "path": path, "root_path": "", "headers": []}
            for candidate in routes:
                match, _ = candidate.matches(scope)
                if match is Match.FULL:
                    if candidate is not route:
                        findings.append(f"{method} {path} is answered by {getattr(candidate, 'path', '?')} ({candidate.endpoint.__module__}.{candidate.endpoint.__name__})")
                    break
    return findings


@pytest.mark.parametrize("profile", list(AppProfile), ids=lambda profile: profile.value)
def test_no_literal_route_is_shadowed(profile: AppProfile, test_settings) -> None:
    app = create_app(settings=test_settings, profile=profile)
    assert _shadowed(app) == []


def test_quarantine_events_reach_the_compatibility_reader(test_settings) -> None:
    app = create_app(settings=test_settings, profile=AppProfile.MONOLITH)
    scope = {"type": "http", "method": "GET", "path": "/api/v1/quarantine/events", "root_path": "", "headers": []}
    for route in _routes(app):
        match, _ = route.matches(scope)
        if match is Match.FULL:
            assert route.endpoint.__module__ == "app.compatibility_api"
            return
    raise AssertionError("route not mounted")
