# Codestra Callback Architecture

The middleware `callback_record` is the scheduling control authority. Odoo owns the agent-facing CRM projection and customer context; the middleware owns desired/actual state, versioning, idempotency, event delivery and reconciliation. n8n consumes immutable versioned events and never stores authoritative scheduling state. Kong and Keycloak establish a scoped principal before callback API access. The application WebSocket delivers popups; reconnect reads the durable due queue. Klyrow/Postal only delivers internal agent or supervisor messages. VICIdial/Asterisk is invoked only after an explicit Call Now action and compliance recheck.

Each mutation locks one callback, verifies tenant/campaign/assignment and expected version, updates the aggregate, and inserts its event in the same PostgreSQL transaction. Scheduler workers claim rows with `FOR UPDATE SKIP LOCKED`. Deliveries are unique by callback, version, channel and stage; stale deliveries are cancelled after reschedule.

No email contains credentials. Phone display is masked. Production PSTN, customer email, SMS and non-synthetic campaigns remain disabled during certification.
