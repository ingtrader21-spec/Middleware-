# Odoo–Middleware runtime architecture

The sole event-ownership model is Odoo transactional outbox claim/lease/acknowledgement. Historical direct-push Odoo ingestion is deprecated and must remain disabled. Odoo is authoritative for CRM/business state; middleware owns transport, normalization, retries, idempotency, replay defense, audit, and adapter orchestration. n8n orchestrates normalized events only. VICIdial is a telephony origin and never writes Odoo storage directly.

```mermaid
sequenceDiagram
  participant O as Odoo 19
  participant OW as Odoo Outbox
  participant SW as Middleware Sync Worker
  participant M as Middleware Gateway
  participant N as n8n/Adapters
  participant RW as Result Worker
  O->>OW: Business transaction + outbox (atomic)
  SW->>OW: Authenticated claim + lease
  SW->>M: Durable normalized intake
  M->>N: Governed orchestration
  N->>M: Normalized result
  M->>RW: Durable result outbox
  RW->>O: Authenticated allowlisted result
  O-->>RW: Idempotent persisted response
  SW->>OW: ACK after durable intake
```

Production writes require `ODOO_PRODUCTION_WRITES_ENABLED=true` and `LIVE_WRITES_ENABLED=true`; both remain false.
