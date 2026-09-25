# MCR-B Leads journey readback

The canonical API reads the MCR-C tables through `PostgresCampaignRecyclingStore`.
It creates no second lifecycle, channel-health, suppression, exposure, or policy
store. Existing ingestion and lifecycle transition methods remain the writers.
No provider dispatch, command reservation, execution route, migration, or
production activation is introduced.

## Canonical reads

- `GET /platform/v1/leads/{lead_id}/journey`: registered-caller bearer token with
  `leads.journey.read`; `X-Tenant-ID` must be an explicit verified tenant.
- `GET /platform/v1/leads/{lead_id}/next-action`: requires
  `campaign.engine.read`. Currently returns `503 dependency_unavailable` because
  MCR-C does not provide an authoritative campaign-candidate/address-selection
  reader. It does not substitute an empty catalog, client-supplied candidates,
  or a successful synthetic decision. Completion of next-action evaluation is
  blocked on that dependency; `CampaignRecyclingEngine.evaluate(mode="read")`
  remains the sole decision authority for subsequent integration.

Both require `X-Correlation-ID`, echo it, and use the canonical error envelope.
The handlers authorize before reading. No missing lead defaults to NEW. Reads
are `Cache-Control: no-store`. Tokens are validated by the existing verified
principal, including registered authorized party, issuer/audience and scope.
This change does not provision new Keycloak grants or edge routes.

Journey accepts `limit=1..200` (default 100) and an optional opaque `cursor`.
The cursor contains versioned keyset positions bound to the tenant and lead;
it grants no access and every page reauthorizes the request. Lifecycle pages
use decreasing versions; exposures use descending reservation time with UUID
as a deterministic tie-breaker. Each stream advances independently, using a
lookahead row. A completed stream stays exhausted. The returned arrays are
chronological within each page; subsequent pages contain older history.
Current channel health and additive suppressions accompany every page. These
current-state collections are not independently paginated in this version.

Each page uses a read-only repeatable-read transaction. Pages across requests
are a live view, not a fixed historical snapshot. Refresh to see newer events;
an existing continuation intentionally excludes newly inserted newer events.

## Contract repair

`journey-response.v1.schema.json` references the frozen lifecycle/exposure
schemas and channel/suppression definitions. It documents the persisted
channel-health projection: MCR-C retains evidence hashes, not the complete
original evidence objects promised by the original JourneyResponse. The API
returns those hashes without reconstructing events. Suppression readback is
included explicitly. Every response is JSON-Schema validated before release;
inconsistent stored records produce a safe 503.

The MCR-A design contract remains the frozen authority for semantics and
scopes. Its JourneyResponse now references this durable read projection, with
a journey-specific limit matching MCR-C's existing bound. The runtime marker
records the two read routes separately from the still-disabled execution and
provider effects. Generated platform OpenAPI includes the registered reads,
request parameters, scopes, and response/error schemas.

## Desktop integration boundary

`LeadDetailsModule` accepts an optional `JourneyService`. `createJourneyService`
uses the canonical reads with an explicit tenant and host-supplied authenticated
fetch transport. Credentials are never stored by the client. `LeadJourney`
shows lifecycle/version, channel health, suppressions, history, next-action
reasons, pagination, loading, empty, error, and retry states. Failed next-action
reads do not hide successfully loaded journey data. Requests are cancelled and
late results ignored when the lead or service changes.

The existing desktop supplies synthetic leads and does not have a verified
Middleware Leads bearer/tenant binding. Its default panel therefore reports
that an authenticated connection is required. A live host must supply that
binding and the canonical public lead ID; Odoo integer IDs and synthetic
fixture IDs must never be treated as canonical identities. No browser auth
proxy or production connection is activated by this change.

## Validation

Focused regression command:

```sh
python -m pytest -q tests/test_leads_journey_api.py tests/test_campaign_recycling_engine.py tests/test_campaign_recycling_contracts.py
python scripts/validate_campaign_recycling_contracts.py
python scripts/generate_api_contracts.py --check
npm --prefix agent_desktop test
npm --prefix agent_desktop run build
git diff --check
```

Full-suite and environment-specific results are recorded in the delivery
report. A passing backend subset does not certify frontend or production use.

## Authoritative adapter boundary

`app/core/journey_readback.py` defines `NextActionAuthority.load` and typed
`NextActionInputs`. The source must supply a coherent, complete tenant/lead
snapshot, server-selected addresses and candidates, governed policy, evaluation
time, and safety flags. A paginated journey is never a decision snapshot.
`evaluate_next_action` rejects mismatched identity/channel inputs and delegates
only to `CampaignRecyclingEngine.evaluate(mode="read")`; it has no write API.
The HTTP route uses the explicit unavailable authority until MCR-C supplies a
reviewed implementation and wire-response mapping. This boundary does not
claim that next-action integration is complete or production-ready.
