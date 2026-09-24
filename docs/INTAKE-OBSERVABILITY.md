# Unified intake observability

## Authority

Middleware owns the real application metrics for the canonical forms and surveys path because it is the durable intake and cross-system write boundary. Prometheus owns scraping, recording rules, SLOs and alert evaluation. Grafana owns read-only operational visualization. Loki owns redacted operational logs, Tempo owns traces, OpenTelemetry owns normalization/redaction/sampling, and Blackbox Exporter owns side-effect-free readiness probes.

This work stays in the existing Middleware repository. It does not create a monitoring-specific intake backend or a second forms service.

## Private metrics endpoint

`GET /metrics` requires the existing Keycloak service identity:

```text
client_id = monitoring-readonly
scope     = metrics.read
```

Anonymous access and public exposure are prohibited. The response contains aggregate operational telemetry only; it does not contain a tenant/customer drill-down surface.

## Real request metrics

The FastAPI request boundary records actual status outcomes for:

```text
POST /v1/intake/leads
POST /v1/intake/surveys/responses
```

The exported raw metrics are:

```text
lead_submissions_total
lead_duplicates_total
lead_validation_failures_total
lead_processing_duration_seconds
lead_odoo_delivery_total
lead_odoo_delivery_failures_total
survey_responses_total
survey_validation_failures_total
survey_processing_duration_seconds
intake_inbox_backlog
intake_outbox_backlog
intake_oldest_pending_seconds
intake_backlog_collection_success
intake_rate_limit_rejections_total
intake_spam_rejections_total
```

A successful lead/survey request increments `accepted`; an identical idempotent replay increments `duplicate`; an identity/payload conflict increments `conflict`; bounded contract and payload-size failures increment validation counters; rate limiting and server failure have separate outcomes. Histograms measure end-to-end Middleware request duration.

The Odoo and abuse-control counters contain zero-valued baseline series and explicit worker hooks. They must not report success until the governed worker actually calls those hooks. Fabricating a delivery success to satisfy a dashboard or alert is prohibited.

## Durable backlog collection

Every authenticated metrics scrape refreshes aggregate state from `middleware_inbox` and `middleware_outbox`:

- intake event types only;
- unprocessed inbox rows only;
- non-completed and non-dead-lettered outbox rows only;
- count and oldest pending age;
- destination collapsed into an approved bounded set;
- no tenant, contact, lead, response or customer grouping.

A database failure returns a sanitized dependency error and sets `intake_backlog_collection_success` to zero. The endpoint does not return stale backlog data as a successful fresh collection.

## Labels

Required corporate labels are fixed or deployment-controlled:

```text
codestra_business = platform
application       = integration
service           = middleware-api
environment       = development | test | staging | production
```

Additional dimensions are bounded enumerations such as `channel`, `form_kind`, `survey_kind`, `anonymous`, `result`, `reason`, `delivery_target` and `queue`.

The following must never become metric labels or values:

- tenant, customer, account, contact, lead, response or user identifiers;
- name, email, phone, address or other contact data;
- form ID, survey ID, campaign ID or configured field/question names;
- answers, free text, messages, transcripts, consent text or custom fields;
- request, correlation, trace or idempotency identities;
- attribution/UTM values, raw URLs or query strings;
- credentials, tokens, cookies or provider secrets.

## Prometheus and Blackbox activation

Source configuration is present, but activation remains fail-closed:

```text
prometheusTargetActivation = false
blackboxTargetActivation    = false
stagingEvidencePassed       = false
productionDeploymentApproved = false
```

A target may move from pending only after all of these are proven in staging:

1. exact immutable Middleware image and release identity;
2. private network reachability from Prometheus only;
3. valid `monitoring-readonly` token with `metrics.read` and rejection of missing/wrong credentials;
4. no forbidden label or payload value across successful, duplicate, invalid, conflict and failure cases;
5. PostgreSQL backlog count and oldest-age reconciliation against read-only SQL evidence;
6. `promtool` validation of the merged intake recording and alert rules;
7. bounded-series/cardinality and load evidence;
8. side-effect-free Blackbox readiness endpoint evidence using GET/HEAD only;
9. rollback procedure and target-disable proof.

Merging source does not satisfy those gates and does not authorize deployment, scraping or probing.
