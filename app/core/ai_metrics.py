"""Privacy-safe, bounded-cardinality AI orchestration metrics."""

from prometheus_client import Counter, Gauge, Histogram

COMMANDS = Counter("codestra_ai_commands_total", "AI commands", ("command_type", "outcome"))
JOBS = Counter("codestra_ai_jobs_total", "AI job transitions", ("transition",))
AUTH_FAILURES = Counter("codestra_ai_worker_auth_failures_total", "Worker auth failures", ("reason",))
QUEUE_DEPTH = Gauge("codestra_ai_queue_depth", "Pending AI jobs")
OLDEST_PENDING = Gauge("codestra_ai_oldest_pending_seconds", "Oldest pending AI job")
WORKER_HEARTBEAT_AGE = Gauge("codestra_ai_worker_heartbeat_age_seconds", "Worker heartbeat age")
MODEL_LATENCY = Histogram("codestra_ai_model_latency_seconds", "Model latency", ("profile",))
TOKENS = Counter("codestra_ai_tokens_total", "AI tokens", ("profile",))
QUOTA_REJECTIONS = Counter("codestra_ai_quota_rejections_total", "AI quota rejections", ("reason",))
APPROVAL_WAITING = Gauge("codestra_ai_approval_waiting", "AI proposals awaiting approval")
