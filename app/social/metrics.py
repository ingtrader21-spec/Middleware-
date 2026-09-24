from prometheus_client import Counter, Gauge, Histogram

publish_requests = Counter(
    "social_publish_requests_total",
    "Social publish requests",
    ("provider", "network", "result"),
)
publish_success = Counter(
    "social_publish_success_total",
    "Successful social publishes",
    ("provider", "network"),
)
publish_failures = Counter(
    "social_publish_failures_total",
    "Failed social publishes",
    ("provider", "network", "result"),
)
publish_duration = Histogram(
    "social_publish_duration_seconds", "Social publish latency", ("provider", "network")
)
provider_requests = Counter(
    "social_provider_requests_total", "Provider requests", ("provider", "result")
)
provider_errors = Counter(
    "social_provider_errors_total", "Provider errors", ("provider", "result")
)
provider_rate_limits = Counter(
    "social_provider_rate_limits_total", "Provider rate limits", ("provider",)
)
webhooks_received = Counter(
    "social_webhooks_received_total", "Social webhooks received", ("provider", "result")
)
webhooks_rejected = Counter(
    "social_webhooks_rejected_total", "Social webhooks rejected", ("provider", "result")
)
queue_depth = Gauge("social_queue_depth", "Social queue depth", ("provider",))
jobs_retried = Counter(
    "social_jobs_retried_total", "Social jobs retried", ("provider", "result")
)
jobs_deadletter = Counter(
    "social_jobs_deadletter_total", "Social jobs dead-lettered", ("provider", "result")
)
production_publish_requests = Counter(
    "social_production_publish_requests_total",
    "Production canary publish requests",
    ("provider", "network", "result"),
)
production_publish_success = Counter(
    "social_production_publish_success_total",
    "Successful production canary publishes",
    ("provider", "network"),
)
production_publish_failures = Counter(
    "social_production_publish_failures_total",
    "Failed production canary publishes",
    ("provider", "network", "result"),
)
production_canary_denied = Counter(
    "social_production_canary_denied_total",
    "Denied production canary requests",
    ("reason",),
)
duplicate_prevention = Counter(
    "social_duplicate_prevention_total",
    "Duplicate social operations prevented",
    ("provider", "action"),
)
unknown_result = Counter(
    "social_unknown_result_total",
    "Provider operations with an unknown result",
    ("provider",),
)
provider_failover_attempt = Counter(
    "social_provider_failover_attempt_total",
    "Forbidden automatic provider failover attempts",
    ("source_provider", "target_provider"),
)
dual_publish_attempt = Counter(
    "social_dual_publish_attempt_total",
    "Forbidden dual-publish attempts",
    ("provider",),
)
production_account_connected = Gauge(
    "social_production_account_connected",
    "Connection state of a production canary account",
    ("provider", "network"),
)

poll_cycles = Counter(
    "social_poll_cycles_total", "Postly read-only polling cycles", ("result",)
)
poll_failures = Counter(
    "social_poll_failures_total", "Postly polling failures", ("reason",)
)
poll_events_emitted = Counter(
    "social_poll_events_emitted_total",
    "Normalized events emitted by polling",
    ("event_type",),
)
n8n_delivery_attempts = Counter(
    "social_n8n_delivery_attempts_total", "Social n8n delivery attempts", ("result",)
)
n8n_delivery_success = Counter(
    "social_n8n_delivery_success_total", "Completed social n8n deliveries"
)
n8n_delivery_failure = Counter(
    "social_n8n_delivery_failure_total", "Failed social n8n deliveries", ("reason",)
)
n8n_delivery_deadletter = Counter(
    "social_n8n_delivery_deadletter_total",
    "Dead-lettered social n8n deliveries",
    ("reason",),
)
n8n_callback_rejections = Counter(
    "social_n8n_callback_rejections_total",
    "Rejected social n8n callbacks",
    ("reason",),
)
n8n_duplicate_events = Counter(
    "social_n8n_duplicate_events_total",
    "Deduplicated social n8n events",
    ("event_type",),
)
