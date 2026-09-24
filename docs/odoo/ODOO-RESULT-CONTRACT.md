# Odoo normalized result contract

Middleware mutations originate only from the durable result outbox and terminate at `POST /api/v1/integration/results`. Each request binds tenant, business unit, campaign, originating event, aggregate, schema version, payload hash, optimistic business version, idempotency key, correlation, causation, request ID, timestamp, and trace context.

Result types map to explicit service handlers and field allowlists. Payloads never select a model, table, SQL, method, arbitrary field, URL, or expression. Odoo compliance, DNC, suppression, manual locks, and newer business versions override stale middleware intent. Same key/hash returns the prior result; changed payload returns conflict; concurrent delivery creates one logical mutation.

The current Odoo 19 addon persists normalized reconciliation results in
`codestra.integration.result.inbox` and completes the originating integration
outbox. It does not yet expose the full allowlisted business-domain handlers for
lead/contact/call/callback/recording/transcript/QA/appointment/compliance writes.
Those handlers remain a certification blocker; no unrestricted ORM endpoint may
be introduced as a shortcut.
