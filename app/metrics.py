from prometheus_client import Counter, Gauge, Histogram

ACK = Histogram("codestra_fast_ack_seconds", "Fast ACK total latency")
DB_COMMIT = Histogram("codestra_db_commit_seconds", "Ingress commit latency")
AUTH_FAILURES = Counter(
    "codestra_auth_failures_total", "Authentication failures", ["kind"]
)
SCHEMA_REJECTIONS = Counter("codestra_schema_rejections_total", "Schema rejections")
IDEMPOTENT_REPLAYS = Counter("codestra_idempotent_replays_total", "Idempotent replays")
IDEMPOTENCY_CONFLICTS = Counter(
    "codestra_idempotency_conflicts_total", "Idempotency conflicts"
)
QUEUE_DEPTH = Gauge(
    "codestra_delivery_queue_depth", "Delivery queue depth", ["target", "status"]
)
OLDEST_AGE = Gauge(
    "codestra_delivery_oldest_seconds", "Oldest delivery age", ["target"]
)
DLQ_DEPTH = Gauge("codestra_dlq_depth", "Dead-letter queue depth", ["target"])
RECONCILIATION_GAPS = Gauge(
    "codestra_reconciliation_gaps", "Report-only reconciliation gaps", ["category"]
)

ORDER_RECEIVED = Counter("codestra_orders_received_total", "Orders received")
ORDER_VALIDATED = Counter("codestra_orders_validated_total", "Orders validated")
ORDER_APPROVED = Counter("codestra_orders_approved_total", "Orders approved")
ORDER_DISPATCHED = Counter("codestra_orders_dispatched_total", "Orders dispatched")
ORDER_STARTED = Counter("codestra_orders_started_total", "Orders started")
ORDER_COMPLETED = Counter("codestra_orders_completed_total", "Orders completed")
ORDER_FAILED = Counter("codestra_orders_failed_total", "Orders failed")
ORDER_RETRIED = Counter("codestra_orders_retried_total", "Orders retried")
ORDER_DEAD_LETTERED = Counter("codestra_orders_dead_lettered_total", "Orders dead-lettered")
ORDER_HUMAN_REVIEW = Counter("codestra_orders_human_review_total", "Orders sent to human review")
ORDER_DUPLICATE_SUPPRESSION = Counter("codestra_order_duplicate_suppression_total", "Duplicate orders suppressed")
ORDER_CALLBACK_FAILURE = Counter("codestra_order_callback_failure_total", "Order callback failures")
ORDER_PROGRESS = Counter("codestra_order_progress_total", "Order progress callbacks")
ORDER_SECURITY_RETRY = Counter("codestra_security_failure_retry_total", "Security failures never retried")
ORDER_RECONCILIATION_MISMATCH = Counter("codestra_order_reconciliation_mismatch_total", "Order reconciliation mismatches")
ORDER_QUEUE_DEPTH = Gauge("codestra_order_queue_depth", "Approved-order queue depth")
ORDER_STALE_RUNNING = Gauge("codestra_order_stale_running_total", "Stale running orders")
ORDER_WORKFLOW_DURATION = Histogram("codestra_order_workflow_duration_seconds", "Order workflow duration")
ORDER_QUEUE_DELAY = Histogram("codestra_order_queue_delay_seconds", "Order queue delay")

# Provider metrics deliberately use stable operation/status labels only.
AI_TASKS_RECEIVED = Counter("codestra_ai_tasks_received_total", "AI tasks received", ["task_type", "status"])
AI_TASK_FAILURES = Counter("codestra_ai_task_failures_total", "AI task failures", ["task_type", "failure_class"])
AI_TASK_DURATION = Histogram("codestra_ai_task_duration_seconds", "AI task duration", ["task_type"])
VICIDIAL_COMMANDS_RECEIVED = Counter("codestra_vicidial_commands_received_total", "VICIdial commands received", ["command_type", "status"])
VICIDIAL_COMMAND_FAILURES = Counter("codestra_vicidial_command_failures_total", "VICIdial command failures", ["command_type", "failure_class"])
VICIDIAL_COMMAND_DURATION = Histogram("codestra_vicidial_command_duration_seconds", "VICIdial command duration", ["command_type"])
POSTIZ_COMMANDS_RECEIVED = Counter("codestra_postiz_commands_received_total", "Postiz commands received", ["command_type", "status"])
POSTIZ_COMMAND_FAILURES = Counter("codestra_postiz_command_failures_total", "Postiz command failures", ["command_type", "failure_class"])
POSTIZ_COMMAND_DURATION = Histogram("codestra_postiz_command_duration_seconds", "Postiz command duration", ["command_type"])
CROSS_SYSTEM_QUEUE_DEPTH = Gauge("codestra_cross_system_queue_depth", "Cross-system queue depth")
CROSS_SYSTEM_CALLBACK_FAILURES = Counter("codestra_cross_system_callback_failures_total", "Cross-system callback failures", ["provider"])

# Callback subsystem metrics contain only bounded dimensions; callback/customer IDs
# are deliberately excluded to prevent cardinality and privacy leaks.
CALLBACKS_DUE = Gauge("codestra_callbacks_due", "Callbacks currently due", ["tenant", "campaign"])
CALLBACKS_OVERDUE = Gauge("codestra_callbacks_overdue", "Callbacks overdue", ["tenant", "campaign"])
CALLBACKS_COMPLETED = Counter("codestra_callbacks_completed_total", "Callbacks completed", ["tenant", "campaign"])
CALLBACKS_MISSED = Counter("codestra_callbacks_missed_total", "Callbacks missed", ["tenant", "campaign"])
CALLBACK_EMAIL_DELIVERY = Counter("codestra_callback_email_delivery_total", "Callback email delivery outcomes", ["outcome"])
CALLBACK_POPUP_DELIVERY = Counter("codestra_callback_popup_delivery_total", "Callback popup delivery outcomes", ["outcome"])
CALLBACK_AGENT_RESPONSE_SECONDS = Histogram("codestra_callback_agent_response_seconds", "Agent response latency", ["campaign"])
CROSS_SYSTEM_DEAD_LETTER = Counter("codestra_cross_system_dead_letter_total", "Cross-system dead letters", ["provider"])
CROSS_SYSTEM_RECONCILIATION_MISMATCH = Counter("codestra_cross_system_reconciliation_mismatch_total", "Cross-system reconciliation mismatches", ["provider"])
CROSS_SYSTEM_STALE_EXECUTION = Gauge("codestra_cross_system_stale_execution_total", "Stale cross-system executions")

# Governed n8n/Redis runtime metrics use bounded, non-sensitive labels.
N8N_DISPATCH = Counter("n8n_dispatch_total", "Governed n8n dispatches", ["outcome"])
N8N_DISPATCH_FAILURE = Counter("n8n_dispatch_failure_total", "Failed n8n dispatches", ["failure_class"])
N8N_RESULT = Counter("n8n_result_total", "Authenticated n8n results", ["status"])
N8N_RESULT_FAILURE = Counter("n8n_result_failure_total", "Rejected n8n results", ["reason"])
N8N_EXECUTION_LATENCY = Histogram("n8n_execution_latency", "n8n execution latency in seconds")
N8N_TIMEOUT = Counter("n8n_timeout_total", "Timed out n8n executions")
N8N_RETRY = Counter("n8n_retry_total", "n8n dispatch retries", ["failure_class"])
N8N_DEAD_LETTER = Counter("n8n_dead_letter_total", "Durable n8n dead letters", ["workflow_code"])
REDIS_LATENCY = Histogram("redis_latency", "Redis operation latency in seconds", ["operation"])
REDIS_ERRORS = Counter("redis_errors", "Redis coordination errors", ["operation"])
REDIS_CONNECTED_CLIENTS = Gauge("redis_connected_clients", "Redis connected clients")
REDIS_MEMORY_USAGE = Gauge("redis_memory_usage", "Redis memory usage in bytes")
REDIS_EVICTIONS = Gauge("redis_evictions", "Redis evicted keys")
REDIS_KEYSPACE_HITS = Gauge("redis_keyspace_hits", "Redis keyspace hits")
REDIS_KEYSPACE_MISSES = Gauge("redis_keyspace_misses", "Redis keyspace misses")
