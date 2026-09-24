# n8n middleware architecture

Odoo is authoritative business state. Middleware owns authentication, tenant
scope, contracts, idempotency, policy, audit, and all privileged adapters.
n8n executes allowlisted workflows. Redis provides only expiring coordination.
PostgreSQL stores the durable event, execution, result, retry, and dead-letter
record.

The canonical path is:

```text
source -> middleware validation -> PostgreSQL execution/outbox
       -> governed dispatcher -> n8n workflow
       -> authenticated middleware result -> PostgreSQL result
       -> approved middleware Odoo/VICIdial/provider adapter
```

Payloads cannot select a workflow ID or URL. Middleware resolves `event_type`
through `n8n_workflow_registry`. n8n receives no unrestricted Odoo or VICIdial
database credentials. Production gates remain disabled.
