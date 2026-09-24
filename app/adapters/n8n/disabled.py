class DisabledN8nAdapter:
    async def deliver(self, _payload: dict) -> None:
        raise RuntimeError("n8n delivery is disabled")
