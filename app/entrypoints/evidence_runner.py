"""Production-safe evidence collector with no external writes."""

from app.core.config import settings
from app.entrypoints.runtime import run_worker


SERVICE = "middleware-evidence-runner"
QUEUE = "middleware.evidence.v1"


async def cycle() -> dict[str, object]:
    return {
        "status": "pass",
        "environment": settings.environment,
        "live_writes_enabled": settings.live_writes_enabled,
        "communications_enabled": settings.messaging_enabled,
        "authorization": "online" if settings.auth_ready else "offline",
    }


if __name__ == "__main__":
    run_worker(SERVICE, QUEUE, cycle)
