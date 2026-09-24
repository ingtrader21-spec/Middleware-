# OpenAI worker crash recovery

AI submissions are disabled by default with `AI_SUBMISSIONS_ENABLED=false`.
The browser submission and command endpoints return HTTP 503 with
`AI_TEMPORARILY_UNAVAILABLE` before creating a conversation, command, or job.
Status, stream, and cancellation endpoints remain available so existing durable
state can be inspected or cancelled safely.

The OpenAI worker validates its configured concurrency and its enabled database
registration before every claim. Both values must equal one. Invalid, missing,
or conflicting configuration prevents readiness and prevents job claims.
Unexpected failures after a claim are fenced and recorded through the governed
terminal failure path; a lost lease is recovered without executing the job a
second time.

The retired Qwen server is not a rollback target. Its worker registration must
remain absent, and no route may attempt to contact it. Until a newly attested
OpenAI artifact passes its concurrency-one canary, AI stays unavailable while
all non-AI middleware services continue normally.

Activation requires all of the following in one governed deployment:

- `AI_SUBMISSIONS_ENABLED=true`
- `AI_ORCHESTRATION_ENABLED=true`
- `AI_WORKER_CLAIMS_ENABLED=true`
- `OPENAI_PROVIDER_ENABLED=true`
- `OPENAI_WORKER_MAX_CONCURRENCY=1`
- one enabled OpenAI worker registration with `max_concurrency=1`

On any canary failure, disable submissions, claims, and the provider. Preserve
the durable queue for governed recovery; do not redirect to a nonexistent
provider and do not claim that rollback is available.
