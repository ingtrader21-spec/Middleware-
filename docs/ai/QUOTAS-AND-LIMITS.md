# Quotas and limits

Limits cover queued/running jobs, payload and output bytes, runtime, tokens, retries, per-worker concurrency, daily tokens/compute, and a global emergency limit. Quota evaluation occurs transactionally before enqueue. The claims kill switch defaults off and preserves pending jobs.
