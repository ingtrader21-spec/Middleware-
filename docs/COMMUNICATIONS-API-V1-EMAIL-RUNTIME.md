# Communications API v1 — Step 3 Email Runtime

## Authority

This branch implements the Middleware side of the frozen Communications API v1 contract from:

`appolon1908-hue/SDK-repository:feat/communications-api-v1-contracts@63c793e88cca5daecfb5c8a688b8674ab288c522`

Middleware remains the privileged cross-system write/control authority. Klyrow remains the email provider/runtime authority.

## Scope

Implement the canonical email path:

```text
SDK contract
  -> Caddy/Kong
  -> Middleware communications facade
  -> durable command ledger
  -> policy/consent/suppression/idempotency
  -> Klyrow adapter
  -> Klyrow/Postal/Mautic
  -> signed provider event/read-back
  -> Middleware reconciliation/read model
  -> canonical communications events
```

## Required work

1. Map `channel=email` create-message requests to a versioned Middleware command.
2. Preserve tenant, actor, scopes, correlation ID and idempotency key.
3. Reject unverified/unauthorized sender/domain state according to policy.
4. Enforce consent and suppression before provider submission.
5. Persist message intent, command state and outbox atomically where applicable.
6. Translate canonical email payload into the reviewed Klyrow API contract without exposing Postal credentials.
7. Persist provider reference and provider acceptance evidence.
8. Normalize Klyrow delivery/bounce/complaint/suppression events into canonical Communications API v1 events.
9. Implement message read model and event timeline required by the frozen contract.
10. Preserve an indeterminate/reconciliation state when provider outcome cannot be proven.
11. Never retry an uncertain provider submission until read-back/reconciliation proves it safe.
12. Expose provider health/reputation data only through governed read models.

## Required tests

- exact request schema acceptance/rejection
- tenant isolation
- invalid/missing scope denial
- idempotent duplicate with same payload
- conflict on same idempotency key with different payload
- suppression/consent denial before provider effect
- verified sender/domain enforcement
- Klyrow timeout before acceptance
- Klyrow timeout after possible acceptance -> indeterminate/reconciliation, not duplicate send
- provider read-back success/failure
- bounce/complaint/delivery event normalization
- replayed provider event deduplication
- cross-tenant message lookup denial
- kill-switch/safe-mode behavior

## Production boundary

This branch does not authorize production sending. Keep Klyrow safe/production gates unchanged until Step 8 evidence and explicit activation approval.