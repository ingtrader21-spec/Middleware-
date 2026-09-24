"""Internal VICIdial provisioning adapter runtime."""

from app.core.config import settings
from app.entrypoints.runtime import run_worker

SERVICE = "codestra-vicidial-adapter"
QUEUE = "telephony.vicidial.provisioning"


async def cycle():
    return {
        "result": "kill_switch_closed"
        if not settings.vicidial_provisioning_enabled
        else "ready"
    }


if __name__ == "__main__":
    run_worker(SERVICE, QUEUE, cycle)
