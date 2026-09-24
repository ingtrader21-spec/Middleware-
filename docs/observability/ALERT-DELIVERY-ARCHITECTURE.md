# Codestra observability alert-delivery architecture

## Decision

Normal alerts do not use direct Alertmanager SMTP. The approved path is:

```text
Prometheus
  -> Alertmanager (`alertmanager`)
  -> POST /v1/integrations/alertmanager/events
  -> Middleware durable command ledger and outbox
  -> Temporal command execution
  -> `KlyrowAlertAdapter`
  -> Klyrow private API `/v1/email/messages`
  -> fixed sender `alerts@codestra.co`
  -> fixed recipient `appolon1908@gmail.com`
```

This preserves authentication, tenant policy, idempotency, audit, retries, unknown-outcome reconciliation, and provider read-back.

## Fixed policy

- Tenant: `codestra-platform`
- Alertmanager receiver: `codestra-observability-email`
- Recipient policy: `codestra-observability-admin-v1`
- Sender policy: `codestra-alert-sender-v1`
- Allowed environment: `production`
- Allowed severities: `critical`, `warning`
- Direct SMTP: prohibited in the normal path
- Bulk, campaign, marketing, and arbitrary-recipient delivery: prohibited

## Authentication

`alertmanager` uses Client Credentials with audience `middleware-api` and scopes:

- `alerts.write`
- `alerts.read`

`middleware-alert-delivery` uses Client Credentials with audience `klyrow-email` and scopes:

- `email.message.send`
- `email.message.read`

`klyrow-alert-adapter` publishes delivery events back to Middleware with scopes:

- `observability.alerts.events.write`
- `observability.alerts.read`

All service credentials and mTLS material are injected from OpenBao. No credential belongs in Git, Alertmanager configuration, or the alert payload.

## Durable behavior

Each alert transition becomes one deterministic command. Its identity binds the incoming request idempotency key, alert fingerprint, firing/resolved state, receiver, environment, recipient policy, and start time. A retry of the same transition returns the same operation; changed content with the same identity returns a conflict.

A write timeout is treated as an unknown outcome. The adapter queries `/v1/email/messages/{message_id}` before any retry. A mismatch or unavailable read-back transitions the operation to reconciliation-required; it is never blindly resubmitted.

Delivery callbacks enter the existing durable inbox. Provider read-back remains authoritative for completion.

## Activation

Repository source defaults the capability off. Production activation requires both:

```text
OBSERVABILITY_ALERT_EMAIL_DELIVERY=true
OBSERVABILITY_ALERT_ACTIVATION_ID=<approved change ID>
PRODUCTION_ACTIVATION_ID=<same approved change ID>
```

General email delivery remains disabled. Initial certification permits only one synthetic firing alert and one corresponding resolved notification to the fixed recipient.

## Emergency fallback

A direct Alertmanager-to-SMTP fallback is intentionally not implemented here. It must be a separate reviewed change limited to Watchdog, MiddlewareDown, ObservabilityAlertGatewayDown, CriticalHostDown, and PrimaryAlertDeliveryFailed, with fixed recipient, fixed sender, OpenBao credentials, strict rate limits, and independent evidence.
