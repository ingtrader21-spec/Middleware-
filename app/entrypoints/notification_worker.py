"""Notification delivery worker with bounded callback realtime delivery."""

from app.core.config import settings
from app.db.session import SessionFactory
from app.entrypoints.runtime import run_worker
from app.workers.callback_realtime import deliver_callback_popups


SERVICE = "middleware-notification-worker"
QUEUE = "middleware.notification.v1"


async def cycle() -> dict[str, object]:
    if settings.callback_websocket_delivery_enabled:
        if not settings.callback_test_syn_enabled:
            return {"status": "callback-disabled"}
        if (
            settings.callback_allowed_tenant != "COD"
            or settings.callback_allowed_campaign != "TEST_SYN"
        ):
            return {"status": "callback-allowlist-denied"}
        if (
            not settings.callback_websocket_gateway_url
            or not settings.callback_websocket_token_file
        ):
            return {"status": "callback-websocket-unconfigured"}
        async with SessionFactory() as session:
            delivery_result: dict[str, object] = dict(
                await deliver_callback_popups(
                    session,
                    tenant_id="COD",
                    campaign_id="TEST_SYN",
                    gateway_url=settings.callback_websocket_gateway_url,
                    token_file=settings.callback_websocket_token_file,
                )
            )
            return delivery_result
    enabled = settings.messaging_enabled or settings.n8n_delivery_enabled
    return {"status": "idle" if enabled else "disabled"}


if __name__ == "__main__":
    run_worker(SERVICE, QUEUE, cycle)
