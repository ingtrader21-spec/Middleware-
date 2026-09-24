# Step 3 Email Security Evidence

Date: 2026-08-30

## Implemented Controls

- Every create/read/cancel path requires bearer verification through the existing runtime token verifier.
- Product caller identity is resolved from the original bearer token model.
- Email send authorization uses the command policy registry for `email.message.send.v1` and target `klyrow-email`.
- Tenant authorization is enforced against `X-Tenant-ID`.
- Actor identity must match the verified token subject when submitting a message.
- Correlation and idempotency headers are required before creating effects.
- Consent and suppression checks run before provider command submission.
- Signed Klyrow webhook ingress updates the canonical read model without adding live provider write access.
- Exact signed callback replays are acknowledged without duplicating timeline
  effects; a reused event identity with changed signed content returns `409`.
- Capability denial occurs before a message or command is stored, so the
  default-disabled `EMAIL_DELIVERY` flag cannot leave a misleading accepted
  intent.

## Production Security Gates Still Required

- Live Keycloak issuer, audience, scope, and caller tests through Kong.
- Secrets from an external secret store.
- Durable communications read-model storage colocated with the already durable
  webhook inbox and replay controls.
- Live negative auth matrix: no token, invalid token, wrong scope, wrong caller, wrong tenant.
