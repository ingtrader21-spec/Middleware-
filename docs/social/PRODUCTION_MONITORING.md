# Production social monitoring

Prometheus instrumentation covers production requests, successes, failures, denials, duplicate prevention, unknown results, forbidden failover/dual-publish attempts, account connection state, provider errors, rate limits, webhook acceptance/rejection, queue depth, retries, dead letters, and latency.

Labels are bounded to provider, network, action, result, or safe error code. Account UUIDs, tenant/campaign IDs, content, email, phone, tokens, and API keys are forbidden labels. `monitoring/social-production-alerts.yaml` supplies production rules; it must pass `promtool check rules` and be loaded by the production Prometheus configuration in a separately approved deployment.
