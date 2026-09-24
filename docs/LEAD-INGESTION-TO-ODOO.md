# Form, crawler, and scraper lead ingestion to Odoo

## Objective

All lead-producing systems use the middleware as the only write boundary to Odoo.

```text
website form / crawler result / approved scraper result
                    |
                    v
           edge and private gateway
                    |
                    v
             durable signed inbox
                    |
                    v
       core/lead-intake-normalization
                    |
                    v
 consent + suppression + provenance + dedupe + review policy
                    |
                    v
           transactional outbox
                    |
                    v
            integration/odoo-19
                    |
                    v
       Odoo contact, lead, activity, campaign, result
```

No website, crawler, scraper, n8n workflow, provider service, or browser test writes directly to Odoo.

## Public forms

The reviewed architecture includes form sources for Codestra, Beyvra, Booked4Seasons, Breero, Klyrow, and Telnexa.

A public form submission must include:

- authoritative tenant mapping;
- a stable submission and idempotency ID;
- correlation and causation IDs;
- capture time and source route;
- explicit consent status and channel choices;
- canonical event version `1.0`;
- provenance showing that the person submitted the form;
- normalized contact or company data.

After validation, the middleware creates or updates the Odoo lead in the `new` stage. External contact is allowed only when consent and suppression policy pass.

## Crawler results

Kyqra crawler results enter through the authenticated `POST /api/v1/kyqra/results` route and durable inbox. The route accepts the canonical Codestra event envelope with a batched `payload.results` completion payload. Each result includes the source reference, capture method, job ID, content digest when available, tenant, and provenance. Kyqra pins the shared `kyqra-crawler-v1` contract from `appolon1908-hue/SDK-repository` before delivery.

The middleware may create or update an Odoo record automatically, but the initial stage is:

```text
review_pending
```

The Odoo command must set:

```text
review_required=true
allow_external_contact=false
```

A crawler result cannot trigger SMS, email, dialing, social publication, or automated outreach merely because an Odoo record exists.

## Scraper results

The Codestra Business Scrapper is currently not deployed. Its branch and contract support readiness work only.

When activated through a separate approved change, scraper results follow the same review-pending policy as crawler results and require authoritative provenance. Imports without a valid tenant, source reference, legal-basis classification, or stable idempotency key are rejected or quarantined.

## Deduplication

The normalization service applies identifiers in this order:

1. tenant plus normalized email;
2. tenant plus normalized E.164 phone;
3. tenant plus normalized company domain and company name;
4. tenant plus source system and source record ID.

A duplicate submission reuses the original outcome. It does not create duplicate Odoo leads or repeat external delivery.

Conflicting identifiers are quarantined for review rather than silently merged.

## Odoo command

`contracts/odoo-lead-command.schema.json` extends the canonical command
envelope. Lead-specific fields live under `payload`; the top-level identity,
version, target, requester, correlation, idempotency, and capability fields stay
identical to every other durable command.

The Odoo adapter owns:

- tenant-to-company, sales-team, campaign, and source mapping;
- contact and company resolution;
- lead create/update;
- campaign and source tags;
- activity creation;
- review-stage enforcement;
- provenance note creation;
- result and error writeback;
- idempotency and reconciliation.

## Failure handling

A timeout is an unknown outcome. The adapter first reconciles using command and idempotency IDs. Only a proven non-delivery may be retried.

Retries are bounded. Exhausted work enters the dead-letter and operational-exception flow with an audited replay action.

## Safety controls

Staging must keep these capabilities disabled until the authoritative middleware source maps and enforces them:

```text
FORM_ODOO_DELIVERY_ENABLED=false
CRAWLER_ODOO_DELIVERY_ENABLED=false
SCRAPPER_ODOO_DELIVERY_ENABLED=false
CRAWLER_EXTERNAL_CONTACT_ENABLED=false
SCRAPPER_EXTERNAL_CONTACT_ENABLED=false
```

The application must fail closed when a required control is absent or malformed.

## Activation evidence

Before enabling a source:

- exact reviewed commit and image digest;
- authenticated route and tenant-mapping tests;
- consent and suppression tests;
- schema rejection tests;
- duplicate and collision tests;
- durable inbox and outbox tests;
- Odoo create/update and reconciliation tests;
- crawler/scraper review-pending enforcement;
- dead-letter and replay tests;
- backup/restore and rollback evidence;
- explicit production approval.

## Adapter implementation

The delivery adapter is `app/odoo_transport.py`, registered as the
`odoo-command` outbox destination. It is wired in `workers/run_outbox.py` only
when `ODOO_WRITE` is enabled, so the handler is unreachable while the capability
is closed.

### Outcome discipline

The outbox worker distinguishes three outcomes, and the adapter maps onto them
deliberately:

| Adapter behaviour | Worker action | When |
| --- | --- | --- |
| returns | complete | Odoo answered 200/201, or read-back confirmed the command |
| raises `KnownSafeRetryError` | retry | connection never established, or read-back proved Odoo never recorded the command |
| raises anything else | quarantine for reconciliation | definitive rejection, or an outcome that cannot be confirmed |

A timeout is never a failure. It is an unknown outcome, resolved by reading the
command back from `GET /codestra/middleware/v1/commands/<id>/status` before any
retry is permitted. If reconciliation is itself unreachable, the row stays
quarantined rather than being retried blind.

A 4xx from Odoo is a definitive rejection and is quarantined for an operator
rather than retried, because replaying it cannot change the outcome.

### Configuration

| Variable | Purpose |
| --- | --- |
| `ODOO_WRITE` | Master capability. Off by default; the handler is not registered while off |
| `ODOO_19_BASE_URL` | HTTPS base URL of the Odoo bridge |
| `ODOO_19_HMAC_SECRET` | Default signing secret, minimum 32 bytes |
| `ODOO_19_TENANT_HMAC_SECRETS` | JSON object mapping tenant ID to secret; preferred over the default |
| `ODOO_19_TIMEOUT_SECONDS` | Request timeout, 1-120, default 20 |

Enabling `FORM_ODOO_DELIVERY_ENABLED`, `CRAWLER_ODOO_DELIVERY_ENABLED`, or
`SCRAPPER_ODOO_DELIVERY_ENABLED` without `ODOO_WRITE` is refused at startup, so
a source cannot outrun the capability that carries it.

### Known divergence

`contracts/connector.schema.json` permits only OIDC authentication methods, but
the deployed Odoo bridge authenticates with an HMAC-signed canonical string. The
adapter implements what the bridge actually enforces. Reconciling the connector
registry with that reality is a separate cross-repository decision and has not
been made here.
