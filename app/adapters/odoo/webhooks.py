"""Canonical Odoo intents produced by provider webhook ingress."""

from __future__ import annotations

from typing import Any


class OdooWebhookAdapter:
    """Build allowlisted Odoo delivery intents; transport remains outbox-owned."""

    @staticmethod
    def log_call_result(payload: dict[str, Any], disposition: str) -> dict[str, Any]:
        return {
            "operation": "log_call_result",
            "call_id": payload["call_id"],
            "phone_number": payload["phone_number"],
            "disposition": disposition,
            "call_time": payload["call_time"],
            "campaign_id": payload["campaign_id"],
            "comments": payload.get("comments"),
        }

    @staticmethod
    def log_inbound_sms(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "operation": "log_inbound_sms",
            "message_id": payload["message_id"],
            "phone_number": payload["from"],
            "body": payload["body"],
            "received_at": payload["received_at"],
            "contact_match": "phone_e164",
            "destination": "contact_chatter",
        }
