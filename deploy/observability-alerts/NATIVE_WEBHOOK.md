# Native Alertmanager compatibility

Native Alertmanager can refresh an OAuth2 client-credentials token and attach
static or file-backed HTTP headers, but cannot calculate a payload-dependent
Idempotency-Key. Its six principal receiver names also differ from the older
single-recipient Middleware envelope.

For POST /v1/integrations/alertmanager/events, set
X-Alertmanager-Native-Webhook: v4 and retain X-Tenant-ID and
X-Source-Deployment. Keycloak must still authenticate the `alertmanager` client with
the middleware-api audience, the correct scope and the fixed tenant.
The service derives an omitted transport key from sanitized validated content,
tenant and deployment and generates an omitted correlation ID for each attempt.
Existing semantic transition deduplication/conflict checks remain authoritative.
Explicit requests without native mode retain their required headers and receiver.

Native mode accepts only the fixed policy receiver or the six receiver names
owned by Codestra-Alertmanager: middleware-default, middleware-heartbeat,
middleware-critical, middleware-high, middleware-warning and
middleware-informational. It normalizes informational to info for the existing
state-only policy. It accepts at most 100 alerts within the existing byte limit;
truncated payloads, missing host/business/owner/runbook metadata, wrong tenant,
wrong workload, unsupported environments and invalid severities remain rejected.

Configure OAuth2 and static/file-backed headers in the principal Alertmanager
repository. Client secret, TLS CA/client material and approved deployment identity
remain file references. Do not reuse the legacy hash-only receiver bearer as a
Keycloak JWT. Do not configure a static Idempotency-Key.
The transport schema is documented at
https://prometheus.io/docs/alerting/latest/configuration/#http_config.

This source change does not deploy the service. Protected image/signature,
schema migration/backup, private TLS ingress and Keycloak prerequisites still
apply. Start with alert delivery disabled, demonstrate a durable incident ID,
repeat the payload to prove deduplication, and then verify a resolved transition.
No provider notification or business mutation is authorized by ingestion alone.
