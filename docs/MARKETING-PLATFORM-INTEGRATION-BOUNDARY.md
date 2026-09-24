# Middleware — Marketing Platform Integration Boundary

## Mission
Middleware is the durable integration boundary between Codestra business services and external/internal provider systems. It must not become the owner of marketing, CRM, communication or social business rules.

## Owns
- Provider adapters and transport normalization
- Authenticated webhook ingress
- Idempotency, deduplication and replay protection
- Durable outbox/inbox delivery
- Retry/backoff and dead-letter handling
- Correlation IDs and integration audit metadata
- Provider health and circuit-breaker state
- Translation between canonical Codestra contracts and provider payloads

## Does Not Own
- Campaign strategy, budgets or attribution
- CRM/customer master
- Communication consent policy
- Social publishing business state
- AI prompts/model decisions
- Human approval policy

## Canonical Flows
Marketing -> Middleware -> ad provider
Communication -> Middleware -> messaging provider
Social -> Middleware -> social.codestra.co
Provider webhook -> Middleware -> owning business service -> Odoo/events

## Mandatory Controls
Every mutation must be idempotent and attributable to tenant, actor/service, request ID, correlation ID and source system. Webhooks must be authenticated, timestamp-checked where supported, replay-protected, deduplicated and acknowledged only after durable acceptance.

## Required Integration Contracts
- /v1/integrations/marketing/*
- /v1/integrations/communications/*
- /v1/integrations/social/*
- /v1/integrations/odoo/*
- /v1/webhooks/marketing/*
- /v1/webhooks/communications/*
- /v1/webhooks/social/*

## Deployment Rule
No production provider write is enabled merely because code is merged. Provider writes require explicit environment capability flags, approved credentials, reconciliation tests, observability and rollback evidence.