class DisabledOdooAdapter:
    async def deliver(self, _payload: dict) -> None:
        raise RuntimeError("Odoo delivery is disabled")
