# Beyvra identity event boundary

Beyvra performs interactive authentication directly with the canonical
Keycloak realm. Middleware is not a login proxy, password authority, reset
handler, or synchronous dependency of the browser callback.

After the Beyvra backend atomically binds a verified Keycloak issuer and
subject to its local user, its outbox may publish
`identity.account.provisioned` to NATS JetStream. The payload contains only a
SHA-256 identity reference, a Beyvra-local user reference, one application
role, and the `keycloak` authority marker.

The future Middleware worker must consume at least once, deduplicate on
`event_id`, and normalize to `codestra.identity.account.provisioned`. It may
maintain a minimal identity projection. It must not send the event to Odoo or
n8n, and must reject email addresses, passwords, OTPs, reset or authorization
codes, and access, refresh, or ID tokens.

There is deliberately no Beyvra identity HTTP API or webhook in Middleware.
Klyrow delivery, bounce, complaint, and inbound-email callbacks continue to use
the existing signed `/api/v1/klyrow/events` webhook contract. Password-reset
messages remain the documented Keycloak to private Klyrow SECURITY SMTP
exception and never enter this event flow.

This repository currently contains contracts and validators, not authoritative
Middleware worker implementation. Runtime readiness requires imported worker
source, a durable-consumer/replay test, verified NATS TLS and service identity,
a schema fixture, and dead-letter plus observability evidence.

The verification-only route is registered in `config/connectivity-map.json`
as `beyvra-to-workers-identity-events`, using NATS JetStream, TLS service
identity, at-least-once delivery, and the source-event schema in this branch.
