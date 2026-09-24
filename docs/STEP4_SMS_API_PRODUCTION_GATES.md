# Step 4 SMS API Production Gates

Date: 2026-08-30

The API software is prepared; live SMS remains disabled.

Before activation, all of the following remain mandatory:

- merge and pin the independently reviewed Telnexa/Jasmin provider release;
- replace the in-memory Communications read model and provider-event index with durable tenant-scoped storage;
- bind the Telnexa OAuth2 + mTLS adapter and authoritative `/api/v1/messages/{id}` readback;
- define tenant-to-billing-account resolution without leaking provider-specific requirements into the public API;
- prove the Telnexa callback payloads for DLR, MO, opt-out, and HELP against the committed Middleware allowlist;
- run a cross-repository fake-provider test proving one command produces at most one Telnexa message;
- verify sender, route, destination, carrier, wallet, and bounded canary authorization in Telnexa;
- keep `SMS_DELIVERY`, `SMS_DELIVERY_ENABLED`, and `LIVE_SMS_DELIVERY` false until the owner approves a bounded canary;
- capture rollback, backup/restore, metrics, and reconciliation-backlog evidence.

Middleware must never receive Jasmin credentials or accept raw Jasmin callbacks.
Those controls remain provider-local in Telnexa.
