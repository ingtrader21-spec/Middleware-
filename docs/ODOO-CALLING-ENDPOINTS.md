# Odoo calling endpoints

## Scope and current execution boundary

This change implements the Middleware HTTP admission, status, reconciliation and
same-call hangup endpoints on the existing durable command ledger. It does not
install an Asterisk/VICIdial runtime, create or activate an agent, enroll a browser,
or activate a production call policy. The restricted HMAC-v2 VICIdial adapter is
implemented and bound to the real Temporal worker. Runtime dispatch remains
fail-closed unless the reviewed Server B release, protected calling policy, mTLS
and HMAC material, and disabled-by-default configuration are all installed.

A queued request is not a phone call. Source tests are not evidence of ringing,
SIP registration, two-way audio, hangup, or Odoo lead-history reconciliation.
There is deliberately no invented downstream URL, raw AMI/ARI gateway, arbitrary
dialplan action, or legacy Middleware deployment in this implementation.

## HTTP contract

All paths are mounted in the canonical `app.main.create_app()` application through
its domain router and are included in OpenAPI.

| Method | Path | Required scope |
|---|---|---|
| POST | `/v1/telephony/calls/originate` | `telephony.calls.originate` |
| POST | `/v1/calls/originate` | `telephony.calls.originate` (Middleware compatibility ingress) |
| GET | `/v1/telephony/calls/requests/{operation_id}` | `telephony.calls.read` |
| POST | `/v1/telephony/calls/requests/{operation_id}/reconcile` | `telephony.calls.reconcile` |
| POST | `/v1/telephony/calls/requests/{operation_id}/hangup` | `telephony.calls.hangup` |

The operation ID is a Middleware request UUID, not an Asterisk uniqueid. The
provider's call ID is returned separately only when it exists in authoritative
ledger state. Hangup never accepts a caller-supplied provider call ID.

`/v1/calls/originate` is a Middleware-only compatibility ingress for the reviewed
Odoo event transport. It invokes the same internal-only handler as the canonical
`/v1/telephony/calls/originate` path and is never forwarded to Server B's external
`/v1/calls/originate` endpoint. It accepts only the named `internal_test` alias;
public E.164 destinations remain blocked.

The original short-lived Keycloak bearer must authenticate `azp=odoo-integration`
with the runtime's configured issuer and audience. The existing verifier enforces
signature, issuer, audience and maximum 300-second token lifetime. Calling scopes
and exact `tenant_id`, `sub`, `employee_id`, `campaign_id`, `business_unit` and
`extension` claims are required. Those claims require reviewed issuer-side mapping;
no Keycloak client or grant is created by this PR. An opaque static API key is not
accepted as a substitute. Agent headers or body values cannot override claims.

Mutations require `X-Correlation-ID` and an `Idempotency-Key` equal to the body key.
`X-Tenant-ID`, when supplied, must match the verified claim. Its omission preserves
the existing Odoo client's wire shape; the signed claim remains authoritative.

### Originate

The fields retain the protected Odoo client contract inspected at Odoo commit
`202a80d5a77cd6b0a715bebf7817628d21301359`, file
`custom-addons/codestra_vicidial_crm/models/middleware_client.py`:

- `employee_id`, `campaign`, `business_unit`;
- `destination`, `destination_class`, `destination_country`, `destination_timezone`;
- `caller_id`, `lead_model=crm.lead`, positive integer `lead_id`;
- `recording_requested=false`, `idempotency_key`.

Extra fields and inline credentials are rejected before persistence. External
numbers retain E.164 validation but are not authorized for dispatch by this
internal-only implementation. Internal tests use a named alias such as
`internal:TEST_ECHO` with `destination_class=internal_test`, not an arbitrary SIP
URI, trunk, context, extension string, or customer number. The alias is a contract
identifier; its actual internal route must be independently verified on Server B.

The currently inspected Odoo UI normalizes numbers to E.164 before transport.
Using internal aliases from that UI therefore requires a separately reviewed
internal-test selection and client wiring. Do not put an alias into an ordinary
customer phone field or remove external-number validation globally.

A new persisted request returns HTTP 202 and `dialing=unknown`, with the operation
ID, resource version and status URL. An exact replay returns HTTP 200 and the same
request. A key reused with changed content or correlation returns HTTP 409.
`dialing=attempting` requires an authoritative provider-operation ID and accepted
or readback-pending ledger state. No endpoint represents a queued request as
answered. `blocked` is used only when this API did not dispatch the request or the
canonical cancellation path confirms cancellation before dispatch.

An existing idempotency key is reconciled before evaluating a now-closed start
gate. Otherwise an accepted earlier call could be falsely reported as rejected,
allowing a duplicate. Neither raw provider errors nor credentials are returned.

### Status, reconciliation and hangup

Status verifies the original authenticated command digest and exact actor,
tenant, campaign, business unit and extension. PostgreSQL reads reconstruct this
binding after an API restart. Other actors receive not-found rather than another
agent's operation data.

Reconciliation uses the existing readback-only operation-mutation outbox. It is
not a fresh originate or blind retry. `expected_version` protects new mutations.

Hangup derives the provider call ID and original actor from the persisted
originate operation, refuses an unknown provider ID, and queues an idempotent
same-call command. Its response distinguishes the requested hangup operation from
a confirmed terminal call. Expiry of a start grant does not silently remove the
owner's ability to request termination of that same known call.

## Authorization and durability

No enabled policy is shipped. `CODESTRA_INTERNAL_CALL_POLICY_FILE` must reference
an operator-installed absolute, root-owned regular file, with no group-write or
world permissions (normally 0640 on a read-only mount). The loader rejects final
symlinks and oversized/unreadable policies using the opened inode.

`CallingGrant` in `app/calling_contract.py` is the executable strict schema. It
binds the exact verified principal, internal alias, caller ID, lead ID, source SHA,
authorization reference and a maximum one-hour window. `internal_only=true`,
`external_dialing=false` and `max_calls=1` cannot be widened. Production values,
credentials and an enabled grant do not belong in Git.

Only `telephony-internal.*` is admitted through this scoped API authorization.
The generated global capability registry still declares
`INTERNAL_TELEPHONY_CALLS=false`, and `PRODUCTION_DIALING` and every existing
external-effect flag remain unchanged and disabled. Generic command callers are
not granted the new namespace. Execution is a separate worker/provider boundary.

The existing PostgreSQL `submit_on_connection()` primitive commits the command,
audit record and Temporal outbox together. Transaction-scoped advisory locks
serialize the grant, agent and extension across processes. A single-call grant
cannot be reused with a different UI key. Another active or unknown call prevents
a new reservation; a command that merely finished executing is not sufficient to
prove a call ended. Release of the reservation requires validated terminal call
readback evidence with its digest and matching request/tenant identities.

The explicitly enabled test/development MemoryCommandStore has an equivalent
in-process reservation lock. It is prohibited by this API when the runtime does
not authorize in-memory storage. It is not a production persistence alternative.

## Restricted Server B execution

The Temporal worker owns the only Server B client. Canonical originate and
hangup commands targeting `vicidial-restricted` are sent to the bounded
`/v1/calls/internal/...` routes using HMAC v2 over the exact backend path and
body. The original originate operation ID remains the Server B readback and
hangup identity; an ingress prefix is not added to the signed backend path.

Execution remains disabled unless the operator supplies a private HTTPS/mTLS
origin and protected references in `VICIDIAL_INTERNAL_CALL_BASE_URL`,
`VICIDIAL_INTERNAL_CALL_HMAC_FILE`,
`VICIDIAL_INTERNAL_CALL_SERVICE_IDENTITY`,
`VICIDIAL_INTERNAL_CALL_EXPECTED_HOST`,
`VICIDIAL_INTERNAL_CALL_CA_FILE`,
`VICIDIAL_INTERNAL_CALL_MTLS_CERT_FILE`, and
`VICIDIAL_INTERNAL_CALL_MTLS_KEY_FILE`. No credential value is committed.

The protected `CODESTRA_INTERNAL_CALL_POLICY_FILE` is reloaded immediately
before dispatch and checked against the independently configured running source
SHA. A PostgreSQL attempt claim elects the sole mutation sender. Once claimed,
timeout, disconnect, malformed acknowledgement, or 5xx can only continue by
reading the same Server B operation; none permits another originate.

Only the typed internal-call evidence contract may enter durable command
history. Accepted, ringing, answered, and connected observations remain
nonterminal and require later reconciliation. Completion requires bound terminal
evidence, including the Asterisk identities, end timestamp, duration, and the
internal-only safety assertions. The exact tested downstream implementation is
VICIdial PR #26; its head is an integration dependency, not a protected release.

The owning repositories must separately provide and deploy agent activation,
secure browser credential enrollment, SIP registration, internal destination
routing and the Odoo UI wiring. Then a human browser/headset test must prove the
single correlation chain, two-way audio, hangup and the original lead's history.
Account provisioning or release-image verification alone proves none of those.

## Tests

`tests/test_calling_contract.py` covers validation, exact grants, expiry, release
binding, policy-file permissions, forbidden destinations and disabled defaults.
`tests/test_calling_api.py` exercises the real ASGI router and canonical memory
ledger, including authentication, cross-agent denial, duplicate/concurrent
requests, unknown outcomes, reconciliation, same-call hangup and OpenAPI mounting.
`tests/test_calling_postgres.py` uses a disposable local PostgreSQL database to
exercise atomic command/audit/outbox persistence, concurrent facade instances,
restart readback and rollback on injected outbox failure.

`.github/workflows/odoo-calling-contract.yml` runs these tests against both the
exact PR head and merge result using locked dependencies and the repository's
existing digest-pinned disposable PostgreSQL image. No test contacts a real
telephony service. The one root-owned policy acceptance test is explicitly skipped
when the test process is not root; negative permission tests still run.

Run the pure contract tests with:

```sh
python -m unittest discover -s tests -p 'test_calling_contract.py' -v
```

Run the complete endpoint suite with the repository dependencies installed:

```sh
python -m unittest discover -s tests -p 'test_calling*.py' -v
python scripts/generate_connector_artifacts.py --check
python scripts/validate_integration_fabric.py
```

PostgreSQL tests require `CALLING_TEST_DATABASE_URL` and reject non-local hosts or
a database name other than the disposable `middleware_test_calling`. Missing DB
configuration produces an explicit skip, never a fabricated integration pass.
