# Campaign design and provisioning delivery

Odoo owns campaign business inputs and manager approval. Middleware owns the
versioned integration design and reserves identifiers atomically. VICIdial's
restricted adapter owns telephony resources. n8n consumes scoped automation jobs.

## Implemented source boundary

1. Odoo emits a transactional campaign.design.requested.v1 event containing its
   design_request_revision. Retries retain the event identity and payload hash.
2. The preview endpoint authenticates a Keycloak service token against its issuer,
   audience, authorized client, campaign.design.preview scope, environment, and
   business unit and explicit tenant. Request headers must match the body identity and unit.
3. PostgreSQL commits the receipt, immutable design revision, list reservation,
   current pointer, and audit event atomically. Duplicate requests return the
   original manifest; altered replays and out-of-sequence revisions conflict.
4. Middleware returns the nested manifest, revision, and SHA-256 expected by the
   actual Odoo preview validator. All resources and live flags remain disabled.
5. The separate approvals endpoint requires campaign.design.approve authority,
   current revision and hash, a reason, and stable request identity. It records
   approval without dispatching provider commands.

Routes:
- POST /api/v1/campaign-designs/preview
- POST /api/v1/campaign-designs/approvals

Approval idempotency and correlation values are limited to 128 characters by
the persistence contract.

The approval endpoint is a scoped service API. Odoo's campaign.approved.v1 outbox
consumer is still required to connect the manager's approval event to it. This
change does not claim to deliver that event or to provision telephony resources.

## Required release configuration

CAMPAIGN_DESIGN_ENABLED defaults to false. CAMPAIGN_DESIGN_ENVIRONMENTS defaults
to test,staging. CAMPAIGN_DESIGN_CLIENT_ID defaults to odoo-campaign-design.

After protected review and signed release, configure a service account with only
the necessary campaign scopes, environment, and business-unit claims. Configure
Odoo's CODESTRA_MIDDLEWARE_CAMPAIGN_DESIGN_URL to the exact approved HTTPS preview
route and CODESTRA_MIDDLEWARE_TOKEN_FILE to a private mounted credential reference. Configure
CODESTRA_MIDDLEWARE_CAMPAIGN_TENANTS with reviewed business-unit-to-tenant
bindings; X-Tenant-ID must match the verified token tenant claim. Middleware
binds that tenant to every persisted preview, replay, and approval.
Token acquisition and rotation must use the existing identity service; this
feature never accepts a shared middleware token in place of verified claims.

Schema 0058_campaign_design and the Odoo call_center_campaign 19.0.5.3.3 release
are dependencies. The schema and forward release tuple have a separate PR. An
unmerged branch and an isolated database test are not production release evidence.

## Remaining provisioning and activation work

The root Odoo AUTOMATIC_CAMPAIGN_PROVISIONING.md remains the required full saga:
approval consumer, immutable provisioning run, resource collision checks and
snapshot, signed campaign.provision-disabled adapter command, read-back and
comparison, inactive n8n scope creation, Odoo result delivery, synthetic tests,
and separately authorized activation.

The existing VICIdial adapter entrypoint only reports readiness and has no
campaign.provision-disabled command handler. Its mTLS client has a closed route
allowlist for call/transfer operations. No campaign command can be inferred from
those routes. The N8N repository's production binding policy is also unverified.
These missing contracts and handlers must be implemented and reviewed before a
production provisioning test can execute.

## Test evidence and acceptance

Run the persistent tests with CAMPAIGN_DESIGN_TEST_DATABASE_URL pointing to an
isolated database named campaign_design_test. Each case creates and removes only
its own schema. The dedicated GitHub workflow supplies PostgreSQL so transaction,
concurrency, replay, scope, and retry cases cannot silently skip in that job.

Run the source compatibility check with:
python scripts/verify_campaign_odoo_contract.py --odoo-source /path/to/Odoo
(PYTHONPATH must include this repository.) It executes Odoo's actual source
validation methods against a generated manifest, using a record stub; it is not
an Odoo ORM or deployed end-to-end test.

On the deployment host, python scripts/campaign_production_preflight.py reads
health, required fields, bindings, workflow states, and delivery flags. It never
changes application state. It exits nonzero until the signed release and bounded
canary acceptance are separately proven. Its snapshot is recorded alongside this
document.

Production acceptance must use synthetic records in an isolated TEST campaign,
with dialing/email/SMS disabled. Capture correlated Odoo outbox, Middleware
receipt and run, adapter read-back, inactive n8n workflow identity, and Odoo
result evidence. Retry the same event and verify no duplicate resources, then
exercise an injected retry and a controlled mismatch. Preserve history and
remove only the test resources created by that run. A healthy service or a
preview-only response does not satisfy this acceptance.

Paired Odoo PR: https://github.com/appolon1908-hue/Odoo/pull/95
Schema dependency: https://github.com/appolon1908-hue/Middleware-/pull/222
Source tests and production preflight: ../evidence/campaign-provisioning-20260910.json
