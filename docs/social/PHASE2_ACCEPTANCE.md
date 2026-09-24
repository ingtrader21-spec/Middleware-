# Phase 2 acceptance

## Passed locally

- Phase 1 exact-SHA CI and provider-neutral baseline;
- durable SQL intent/idempotency/job/audit/outbox transaction;
- database failure before commit produces zero provider calls and zero signal rows;
- atomic job leasing, single provider dispatch, attempt persistence, and IntegrationEvent creation;
- persistent webhook deduplication and normalized event persistence;
- unknown Postly read-timeout fail-closed classification;
- minimal Redis signal contract;
- migration upgrade/downgrade/re-upgrade on disposable PostgreSQL.

## Phase 3A authentication certification

The Postly peer is reachable at `10.40.0.3` over VLAN 4001. The existing
organization API key is installed in the Middleware staging secret convention with
mode `0400` and UID/GID 10001. A real private-route request returned `200`; invalid
and missing credentials returned `401`. Middleware adapter health returned
`AVAILABLE`, and authenticated account discovery returned a valid empty list.

Postly authentication, health, private connectivity, and account-discovery protocol
are certified. Controlled provider writes, schedule/cancel, and signed webhook
round-trip remain blocked because there are zero staging-safe accounts and native
outbound callbacks lack the required signature contract. Publishing remains off.
