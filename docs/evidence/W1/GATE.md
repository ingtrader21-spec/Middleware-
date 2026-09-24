# Gate W1 — Security invariants

- **Status:** READY_FOR_REVIEW
- **Base:** `ac701398caf6ca2bc7880d36a3491053836c9ea3`
- **Deployment changed:** no
- **Live writes changed:** no

## Measured source policy

- automation clients: 10
- automation operations: 13
- command families: 18
- exact source invariants: 9
- generic or wildcard machine scopes allowed: 0
- clients with cross-family claim authority: 0
- operations/platform clients with command prefixes: 0
- negative authorization probes in source validation: 6

## Tests added

- exact client-scope subset enforcement;
- cross-client command-family denial;
- cross-workflow-family claim denial;
- generic, wildcard, and duplicate scope denial;
- issuer and single-audience recheck;
- exact invariant-set drift rejection;
- token-tenant mismatch denial on the legacy compatibility route;
- all three forwarding header/body mismatch cases;
- gateway identity headers cannot replace Middleware bearer-token validation;
- token subject remains the command actor authority;
- status reads remain token-tenant scoped.

## Exit conditions

- [x] Tenant authority is token/job derived, never header derived
- [x] Header/body agreement is covered for all three fields
- [x] Client scopes are exact with no implicit union
- [x] All nine operation-policy invariants are executable
- [x] Independent token validation has a negative route test
- [ ] Exact-head and merge-result checks green
- [ ] Review threads resolved
- [ ] Tag `w1-complete`
