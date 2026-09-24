"""Codestra canonical policy API runtime."""

from fastapi import FastAPI

from app.api.v1.policy_engine import router
from app.api.internal.authorization import router as internal_authorization_router
from app.entrypoints.runtime import add_api_runtime, run_api


SERVICE = "middleware-policy-engine"
app = FastAPI(title="Codestra Policy Engine", version="1.0.0")
app.include_router(router)
app.include_router(internal_authorization_router)
add_api_runtime(app, SERVICE)


if __name__ == "__main__":
    run_api(app, SERVICE)
