"""Narrow extension inventory and reservation API."""

from fastapi import FastAPI

from app.api.v1.telephony import router
from app.entrypoints.runtime import add_api_runtime, run_api

SERVICE = "codestra-extension-allocator"
OWNED = {
    "/v1/telephony/extensions/audit",
    "/v1/telephony/extensions/pools",
    "/v1/telephony/extensions/availability",
    "/v1/telephony/extensions/reserve",
}
app = FastAPI(
    title=SERVICE,
    routes=[route for route in router.routes if getattr(route, "path", "") in OWNED],
)
add_api_runtime(app, SERVICE)

if __name__ == "__main__":
    run_api(app, SERVICE)
