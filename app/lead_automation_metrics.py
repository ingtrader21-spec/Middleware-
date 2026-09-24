from prometheus_client import Counter, Gauge


lead_automation_events_total = Counter(
    "lead_automation_events_total", "Lead automation events", ("environment", "state")
)
lead_automation_policy_denials_total = Counter(
    "lead_automation_policy_denials_total",
    "Policy denials",
    ("environment", "business_unit_key"),
)
lead_automation_consent_blocks_total = Counter(
    "lead_automation_consent_blocks_total", "Consent blocks", ("environment",)
)
lead_automation_dnc_blocks_total = Counter(
    "lead_automation_dnc_blocks_total", "DNC blocks", ("environment",)
)
lead_automation_dispatch_attempts_total = Counter(
    "lead_automation_dispatch_attempts_total",
    "Dispatch attempts",
    ("environment", "result"),
)
lead_automation_results_total = Counter(
    "lead_automation_results_total", "Results", ("environment", "result_code")
)
lead_automation_odoo_apply_total = Counter(
    "lead_automation_odoo_apply_total", "Odoo apply attempts", ("environment", "result")
)
lead_automation_quarantine_total = Counter(
    "lead_automation_quarantine_total", "Quarantines", ("environment", "reason")
)
lead_automation_reconciliation_gaps = Gauge(
    "lead_automation_reconciliation_gaps",
    "Reconciliation gaps",
    ("environment", "gap_type"),
)
lead_automation_outbox_lag_seconds = Gauge(
    "lead_automation_outbox_lag_seconds", "Oldest outbox lag", ("environment",)
)
