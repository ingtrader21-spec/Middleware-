"""Narrow authenticated webphone session API."""

from fastapi import FastAPI

from app.api.v1.webphone import router
from app.api.v1.agent_realtime import router as realtime_router
from app.entrypoints.runtime import add_api_runtime, run_api

SERVICE = "codestra-webphone-session-issuer"
app = FastAPI(title=SERVICE, routes=[*router.routes, *realtime_router.routes])
add_api_runtime(app, SERVICE)

if __name__ == "__main__":
    run_api(app, SERVICE)
