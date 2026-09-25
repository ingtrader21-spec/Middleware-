"""Authenticated integration and control surface (deployed process).

The process serves the single canonical application from
:mod:`app.application` in its integration profile; this module only names
the service and starts uvicorn. Route groups, guard, health and runtime
ownership are defined once in the core.
"""

from __future__ import annotations

from app.application import AppProfile, create_app
from app.core.bootstrap import SERVICE_INTEGRATION_API
from app.entrypoints.runtime import run_api

SERVICE = SERVICE_INTEGRATION_API

app = create_app(profile=AppProfile.CANONICAL_8095, service=SERVICE)


if __name__ == "__main__":
    run_api(app, SERVICE)
