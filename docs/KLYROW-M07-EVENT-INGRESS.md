# Klyrow M07 event ingress and Odoo projection

Status: source implementation only. Production is **NOT AUTHORIZED**, the production lock remains **NO_GO**, and every new runtime gate defaults to false.

## Boundary

The only supported flow is:

```text
Klyrow durable outbox
  -> POST /api/v1/events/klyrow
  -> Middleware durable inbox + immutable ledger + projection outbox
  -> Middleware Klyrow Odoo projection writer
  -> Odoo
```

Klyrow has no Odoo credential or client. Accepting an event cannot enable email delivery or an Odoo write.

## Authentication and acceptance

The route uses the Telnexa ingress security pattern: a dedicated `klyrow-gateway` Bearer identity plus HMAC-SHA256 over the exact bytes `timestamp + "\n" + event_id + "\n" + "klyrow" + "\n" + raw_json`. `X-Event-Id`, `X-Timestamp`, `X-Signature`, `Idempotency-Key`, and `X-Correlation-Id` are mandatory and bound to the body. The timestamp is fresh for at most 300 seconds by default and the body is read incrementally under a configured size limit.

Middleware returns the exact `202` body `{"operation_id":"op_<digest>","status":"ACCEPTED"}` only after the inbox row, immutable tenant ledger entry, and `odoo-klyrow-projection-v1` outbox row commit together. The operation ID is deterministic for the Klyrow event ID.

An exact event/body replay returns the same `202` and operation ID. If the accepted inbox event exists but its projection intent is missing, that replay recreates exactly one outbox row from the persisted inbox payload. Reusing an event ID with different raw JSON returns `409` and creates no projection. Missing Odoo business entities and proved-absent operations remain in the durable outbox for retry.

## Runtime gates

`KLYROW_EVENT_INGRESS_ENABLED=false` blocks receipt. Enabling it also requires separate OpenBao-rendered `KLYROW_EVENT_API_KEY_FILE` and `KLYROW_EVENT_HMAC_SECRET_FILE` values.

`KLYROW_ODOO_PROJECTION_ENABLED=false` blocks the Odoo handler. The handler is not composed unless that flag is true and both `EXTERNAL_DELIVERY_ENABLED` and `ODOO_WRITE` authorize external delivery. Production keeps all three false until exact-tuple staging certification and the production gate.

The Odoo writer posts signed, idempotent projections to `/codestra/middleware/v1/klyrow/events` and uses `/codestra/middleware/v1/klyrow/events/{operation_id}` for outcome readback. A connection failure before send is safe to retry. Timeouts and ambiguous gateway responses remain reconciliation-required until signed readback proves applied, duplicate, or absent.

## Certification still required

Source merge is not runtime certification. Before any activation, certify the exact Klyrow, Middleware, Odoo, configuration, image, schema, and secret-version tuple in staging. The evidence must include restart persistence, concurrent duplicate races, Odoo outage/backlog/recovery, one logical Odoo record per event, trace/correlation continuity, and reconciliation repair of a deliberately missing projection.
