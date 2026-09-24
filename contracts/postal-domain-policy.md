# Postal domain policy

Middleware is the authority for deciding whether a configured Postal domain may be used for application email delivery. Postal remains the SMTP provider; application services must not bypass Middleware and submit directly to Postal.

## Security boundary

- DKIM private keys, SMTP credentials, API credentials, and provider secrets must never be stored in this repository.
- A DNS check marked `pass` is inventory evidence only; it is not authorization to send.
- Any domain whose DKIM private key may have been exposed is blocked until the key is rotated and a fresh Postal DNS check passes after rotation.
- `EMAIL_DELIVERY_ENABLED` and `ENABLE_EXTERNAL_DELIVERY` are both fail-closed controls and remain `false` by default.
- Domain eligibility is evaluated from `config/postal-domain-registry.json` plus the runtime safety flags. Unknown domains fail closed.

## Required send gate

A domain may become eligible only when all of the following are true:

1. The domain exists in the Middleware Postal domain registry.
2. Postal reports SPF, DKIM, MX, and return-path checks as passing after the latest DKIM rotation.
3. `dkim_rotation_required` is false and post-rotation verification is recorded.
4. Middleware policy approval has been recorded for the domain.
5. `EMAIL_DELIVERY_ENABLED=true`.
6. `ENABLE_EXTERNAL_DELIVERY=true`.
7. The request has passed the normal Middleware tenant, authorization, idempotency, suppression, audit, and outbox controls.

Until every gate passes, delivery must remain disabled.

## Booked4Seasons

`booked4seasons.com` is configured in Postal for incoming and outgoing mail, but no completed Postal DNS check is recorded in the supplied inventory. Middleware must treat it as unverified and ineligible until DKIM is rotated and a full Postal DNS check passes.

## Domain names are not application artifacts

SMTP domains are identities/routing configuration, not deployable applications. A Docker registry repository must not be created merely because an SMTP domain exists. Container publication belongs to the actual application or provider adapter source when such source exists and has been reviewed.
