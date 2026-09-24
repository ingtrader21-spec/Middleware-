# Klyrow, Middleware and Odoo on Server A

The September 10 readback found working private TLS and service authentication,
but the production Klyrow callback is routed to the wrong application. Full
Klyrow-to-Odoo processing is not verified.

## Observed connections

| Check | Observed result |
| --- | --- |
| Klyrow worker on 37.27.128.39 to private Server A | 10.40.0.1:18080; verified mTLS and bearer/HMAC authentication |
| Current Caddy callback upstream | 127.0.0.1:18180, `codestra-email-reseller-api-1` |
| Required Middleware receiver | 127.0.0.1:18181 is absent; the current integration API lacks the Klyrow receiver module |
| Required mail-to-Odoo worker | Absent |
| Odoo private health from the existing Middleware results worker | HTTPS 200 with the mounted internal CA |
| Existing results worker service authentication | OAuth token endpoint 200; token obtained; delivery remains disabled |
| Odoo mail integration | `codestra_mail_inbox` installed; `codestra.mail.inbound.event` registered; dedicated mail service account active |
| Dedicated mail credentials | `/etc/codestra/secrets/klyrow-mail/event-hmac` and `odoo-api-key` absent |

The legacy Email Reseller accepts lifecycle callbacks for its own message
records. It does not implement the reviewed Middleware inbound-mail and usage
inboxes. Its healthy response is insufficient evidence for this integration.
The callback authentication check submitted only an empty validation document,
which was rejected before any business event could be persisted.

## Source corrections

The mail worker now loads the mounted internal CA explicitly and requires an
HTTPS origin. Missing trust material stops before credentials are sent.
Redirects and environment proxy settings cannot redirect its RPC credentials.

The Odoo proxy permits `POST /jsonrpc` only from one reserved Middleware
mail-worker address, still inside the private integration CIDR. This route is
closed by default. Set the same `KLYROW_MAIL_RPC_CLIENT_IP` in the worker and
proxy compositions after checking that the address is unused. Keep the existing
results and health routes. Odoo authenticates and authorizes the dedicated
service account; the proxy does not grant application permissions.

## Deployment and reconciliation order

1. Complete review, CI and protected immutable image publication for the exact
   Middleware revision. Preserve the current image/configuration and database
   backup with its restore evidence. Do not patch the running container or use
   a mutable image tag. The current production containers predate this ingress.
2. Provision the existing Klyrow event HMAC into the dedicated mounted file
   without logging its contents. Provision a separate Odoo API key for the
   existing mail service account and verify that account's restricted model
   permissions. The results worker's OAuth secret is not the mail RPC key.
3. Verify migrations 0055 and 0056 against the actual Middleware database and
   apply missing migrations through the release's migration procedure. Read
   back inbox tables and runtime-role privileges before starting consumers.
4. Install only the integration API and dedicated mail worker with the runtime,
   Server A receiver, and `compose.server-a-mail-hold.yaml` compositions. The
   final hold overlay keeps ingress and Odoo delivery disabled during inspection.
   Verify module presence, the loopback listener, secret readability under UID
   10001/group 3999, private CA verification, and Odoo service authentication.
5. Validate the Odoo proxy configuration and the exact reserved worker address.
   Replace only the Klyrow callback upstream in
   `/etc/caddy/conf.d/klyrow-events.caddy` with `127.0.0.1:18181` after the new
   receiver is ready. Preserve the 10.40.0.4 source restriction, mTLS client
   identity, POST-only path, body limit and credential-redacted access logging.
   Keep a restorable prior configuration and read back the active route.
6. Enable only the reviewed Klyrow ingress and mail-to-Odoo delivery controls
   after the preceding checks pass. Other production delivery controls retain
   their current authority. Deploy the reviewed Klyrow outbox recovery source
   through its own protected release process.
7. Use the tenant-scoped Klyrow reconciliation API in dry-run mode first. The
   original 82 provider dead letters included 78 quarantined inbound messages,
   two accepted local-inbox messages, one accepted accounting message and one
   sandbox lifecycle record. Keep quarantined/local records out of Odoo. Review
   the sandbox lifecycle and the separate usage record without relabeling them
   as production or billable delivery.
8. Apply a bounded, reviewed accounting reconciliation page and trace its stable
   event identity through the Middleware inbox and Odoo record acknowledgement.
   Read back the Odoo record and deduplication evidence before processing more
   pages. Neither SMTP acceptance nor an HTTP acknowledgement proves completion.

The Alertmanager receiver permission repair is recorded separately in
Codestra-Alertmanager PR #19. Its successful webhook deltas do not establish
Klyrow alert routing: the private Alertmanager listener, monitoring client
identity and routed Prometheus composition still require deployment/readback.

## Validation

Twenty-one focused ingress, receiver and transport tests pass. Native Caddy
adaptation on Server A accepts both the default closed RPC route and the
single-peer configuration. No mail event, Odoo business record, production image,
ingress route or delivery flag was changed during these checks.
