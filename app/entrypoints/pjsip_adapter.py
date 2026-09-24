"""Internal Asterisk/PJSIP provisioning adapter runtime."""

from app.core.config import settings
from app.entrypoints.runtime import run_worker

SERVICE = "codestra-pjsip-adapter"
QUEUE = "telephony.pjsip.provisioning"


async def cycle():
    return {
        "result": "kill_switch_closed"
        if not settings.pjsip_provisioning_enabled
        else "ready"
    }


if __name__ == "__main__":
    run_worker(SERVICE, QUEUE, cycle)
