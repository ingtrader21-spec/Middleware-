# Automation authorization invariants

The authoritative source is `contracts/automation/operation-policy.v2.json`.
Middleware loads that document fail-closed; the document is not advisory.

## Identity boundary

Keycloak is the token issuer and `middleware-api` is the only accepted audience.
Kong remains the network gateway, but a gateway-added identity header never grants
Middleware authority. Middleware independently validates the bearer token and then
applies the exact client policy.

The automation policy contains ten machine clients. A token may use only scopes
declared for its own `azp`. Unknown, generic, wildcard, duplicated, or implicitly
unioned scopes are denied. A valid scope belonging to a different automation client
is still unauthorized.

## Tenant and actor authority

For automation v2, tenant, actor, workflow family, and workflow version are loaded
from the durable automation job. Caller-supplied tenant or actor values are not
authoritative. They may be accepted only as assertions that must equal server-side
state.

For the legacy n8n v1 compatibility routes, tenant authority remains the verified
token claim. `X-Tenant-ID`, `X-Correlation-ID`, and `Idempotency-Key` must equal the
submitted body; a matching header never overrides the token.

## Workflow and command isolation

A client may claim or operate only its declared workflow families. Command types
are resolved by an exact, non-overlapping prefix registry. The resolved prefix fixes
all three of these values:

- required scope;
- authorized client;
- allowed workflow family.

A messaging token therefore cannot issue a crawler command even when the token is
cryptographically valid. The operations and platform-runtime clients have no
command prefixes and cannot create product effects.

## Nine source invariants

1. generic execute scope is forbidden;
2. generic command scope is forbidden;
3. clients cannot claim another workflow family;
4. caller tenant is not authoritative;
5. caller actor is not authoritative;
6. an active lease is required for steps and commands;
7. provider callbacks are never public-to-n8n;
8. activating a workflow does not enable a capability;
9. live apply remains unauthorized.

The source validator rejects any change to this exact set. Negative authorization
probes run in every source-head and merge-result validation.

## External-effect boundary

Workflow identity and authorization do not enable provider effects. Capabilities
are checked separately and immediately before an effect. `ODOO_WRITE`, SMS, email,
PSTN, live apply, financial effects, and demo-order effects remain disabled unless
a separately reviewed activation contract identifies the exact immutable release.
