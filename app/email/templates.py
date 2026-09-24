from __future__ import annotations

import html
import re
from dataclasses import dataclass

CATEGORIES = {"ACCOUNT", "SECURITY", "TRADING", "FUNDS", "STATEMENTS", "SUPPORT", "SYSTEM"}
TEMPLATES = {
    "ACCOUNT": ["account_verification", "welcome", "password_reset", "password_changed", "email_changed", "account_locked", "account_unlocked"],
    "SECURITY": ["new_login", "suspicious_login", "new_device", "two_factor_changed", "security_settings_changed", "api_key_created", "api_key_revoked"],
    "TRADING": ["order_received", "order_rejected", "order_cancelled", "order_filled", "order_partially_filled", "position_opened", "position_closed", "margin_warning", "margin_call", "risk_alert"],
    "FUNDS": ["deposit_received", "deposit_pending", "deposit_completed", "deposit_failed", "withdrawal_requested", "withdrawal_pending", "withdrawal_approved", "withdrawal_completed", "withdrawal_rejected"],
    "STATEMENTS": ["daily_statement", "monthly_statement", "account_statement_ready"],
    "SUPPORT": ["support_ticket_created", "support_ticket_updated"],
    "SYSTEM": ["maintenance_notice", "service_incident", "service_restored"],
}
TEMPLATE_CATEGORY = {template: category for category, values in TEMPLATES.items() for template in values}
SENDERS = {
    "ACCOUNT": "no-reply@beyvra.com", "SECURITY": "security@beyvra.com",
    "TRADING": "trading@beyvra.com", "FUNDS": "no-reply@beyvra.com",
    "STATEMENTS": "statements@beyvra.com", "SUPPORT": "support@beyvra.com",
    "SYSTEM": "no-reply@beyvra.com",
}
VARIABLE = re.compile(r"{{\s*([a-zA-Z][a-zA-Z0-9_]*)\s*}}")


@dataclass(frozen=True)
class Rendered:
    subject: str
    text: str
    html: str


def render(subject: str, text: str, html_body: str, parameters: dict[str, object], required: list[str]) -> Rendered:
    missing = sorted(set(required) - parameters.keys())
    if missing:
        raise ValueError("missing_template_variables:" + ",".join(missing))
    unknown = sorted(set(parameters) - set(required))
    if unknown:
        raise ValueError("unknown_template_variables:" + ",".join(unknown))
    plain = {key: str(value) for key, value in parameters.items()}
    escaped = {key: html.escape(value, quote=True) for key, value in plain.items()}

    def substitute(value: str, variables: dict[str, str]) -> str:
        return VARIABLE.sub(lambda match: variables[match.group(1)], value)

    return Rendered(substitute(subject, plain), substitute(text, plain), substitute(html_body, escaped))
