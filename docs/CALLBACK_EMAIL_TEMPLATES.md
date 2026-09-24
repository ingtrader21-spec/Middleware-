# Callback Email Templates

Templates are internal-only and campaign configurable: scheduled confirmation, upcoming callback, reassignment, and missed callback supervisor alert. Subject example: `Upcoming Callback – {{ customer_display_name }} – {{ customer_local_time }}`. The body contains campaign, reason, masked phone, previous and assigned agents, and an `Open Callback` URL without credentials. Provider status is tracked as queued, accepted, delivered, bounced or failed; callback validity is independent of email delivery.
