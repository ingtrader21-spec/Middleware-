# Authentication / tenant / security certification review — 2026-09-24

**Verdict: NOT CERTIFIED.** Three reproduced security defects remain. Existing tests passing do not resolve them. No shared runtime source was changed.

Reviewed source SHA: `0606b0db9ff59802f8da3824d209d2effc13f87d`.
Branch: `review/auth-tenant-cert-20260924`.
Scope: authentication, tenant isolation, service identity, authorization, policy/safety, webhook integrity, secrets, provider transport, replay/idempotency and canonical route authority.

## Reproduced findings and exact corrective actions

### AUTH-01 — High: shared bearer bypasses tenant authority on legacy telephony routes

Evidence: `app/core/request_guard.py:188`, `app/api/v1/commands.py:147-179`, and integration mounting in `app/router_registry.py`. The integration profile mounts:

- `GET /api/v1/commands/{command_public_id}`
- `GET /api/v1/telephony/commands/{command_public_id}`
- `POST /api/v1/telephony/commands/{command_public_id}/cancel`

A configured shared Middleware bearer is sufficient. No verified subject, authorized party, tenant grant, or per-operation scope is required by these handlers. The SQL selects only by public ID; cancellation locks that row and commits `CANCELLED` without tenant binding. The forged tenant header is ignored, but there is no token-derived tenant authority to replace it.

Reproduction: `tests/review_auth_tenant_boundaries.py::test_shared_bearer_reaches_unscoped_legacy_command` (three cases) uses the real integration factory and request guard, synthetic shared bearer, and an AsyncMock database returning a foreign resource. Missing bearer is rejected before SQL; shared bearer returns the foreign resource or commits cancellation. The captured SQL has no tenant predicate. This demonstrates application authorization bypass for a bearer holder who knows a resource ID; it does not demonstrate unauthenticated access, a live database exploit, or public edge reachability.

Corrective actions for the owning source lane: remove these routes from the deployed integration profile if obsolete; otherwise require verified original JWT with explicit registered azp, audience, scope and tenant grants. Bind each lookup/update to the authorized tenant in SQL, return non-disclosing 404 for foreign resources, and route mutations through the canonical kernel's authorization, state/version, idempotency and audit controls (or implement equivalent controls for the legacy journal if its data model cannot delegate). Add tenant ownership to the journal/schema if absent. Audit the sibling operation-registration/read/transition routes in this same module; they also rely on the shared guard. Replace the characterization expectations with denial tests after remediation.

### AUTH-02 — High: removed JWKS signing keys remain accepted by machine verifier

Evidence: `app/security.py:59-66` enables `PyJWKClient(cache_keys=True, lifespan=300)`. Pinned PyJWT is 2.13.0 (`requirements-runtime.txt:712`); its installed `jwt/jwks_client.py` implements the per-key cache with `functools.lru_cache` and **no time expiry**. The 300-second lifespan bounds the set cache, not this per-key cache.

Reproduction: `test_machine_verifier_reuses_removed_signing_key` verifies a real RSA-signed token, invalidates the complete JWKS set cache, makes the mocked authoritative JWKS empty, and verifies a fresh token under the removed key. No second JWKS fetch occurs. A holder of a compromised cached private key can mint fresh short-lived tokens; the token's 300-second lifetime does not bound this key-revocation gap. Cache eviction/process replacement may eventually end acceptance, but there is no time bound.

Corrective actions: disable the non-expiring per-key cache, retain bounded JWKS-set caching and timeout, or implement a per-key TTL tied to authority refresh with removal invalidation. Add real-signature tests that expire the set cache, remove a kid, and require rejection; cover same-kid key replacement, unknown kid, JWKS outage and readiness refresh. Define and verify an explicit maximum revocation delay.

### AUTH-03 — High: separate Beyvra email validator accepts tokens without expiry

Evidence: `app/email/security.py:26-43` calls `jwt.decode` without required claims. Signature, issuer, audience, azp/service/environment and scope are checked, but `exp` and `iat` are optional. Tenant values are string-coerced, so JSON null becomes `"None"` and a list becomes its Python string representation. This is a separate runtime (`app/email/runtime.py`, `deploy/beyvra-email/compose.yaml`), not one of the six canonical kernel routes.

Reproduction: `test_email_validator_accepts_no_expiry_and_coerces_tenant` (three cases) verifies genuinely signed RSA JWTs with no exp/iat and accepts string, null and list tenant claims. This does not forge an issuer signature; it demonstrates acceptance of malformed/non-expiring tokens issued by a trusted signer. Malformed tenant coercion alone is not proof of access to an existing tenant.

Corrective actions: require exp/iat/iss/aud/sub/azp/scope and the authoritative tenant claim; validate strict nonempty string subject/tenant (no wildcard or coercion), strict scope/service/environment shape, finite numeric times and the applicable machine-token maximum lifetime. Reuse the canonical identity configuration and verifier where compatible. Convert JWKS/claim failures to generic authentication failures. Add no-expiry, no-iat, long-life, malformed-tenant, wrong-service/azp/audience and cross-tenant read/retry HTTP tests.

## Additional source findings / unverified deployment boundaries

- **Email transport configuration hardening:** `app/email/worker.py:49-63,90-104` takes send/token URLs directly from environment. Unlike `app/klyrow_email_adapter.py`, it does not enforce an HTTPS origin allowlist before sending client credentials or bearer tokens. Its `_secret` merely opens the supplied path. This is an operator/configuration trust risk, not a demonstrated remote attacker-controlled URL. Require approved credential-free HTTPS origins, disabled redirects/proxies unless explicitly authorized, and regular non-symlink permission-checked secret mounts before token acquisition. Test HTTP/unapproved URL rejection before transport. The separate worker only checks `LIVE_EMAIL_DELIVERY` at entry (`app/email/runtime.py`), not the kernel safety gate per delivery; explicitly reconcile that authority before enabling this runtime.
- **Provider mTLS trust boundary:** `app/email/api.py:42` trusts `X-Codestra-Client-Cert-Verified: SUCCESS`. JWT and HMAC remain additional barriers. Prove the listener is private and a trusted proxy strips caller-supplied values and sets this header only after certificate validation, or enforce mTLS directly. No live proxy/network evidence was collected.
- **Email webhook replay/tenant consistency:** the delivery-event duplicate branch (`app/email/api.py:129`) returns success by event ID without comparing the stored payload digest, unlike canonical conflict handling. Compare digest and provider/tenant identity and return 409 on changed-body replay. The postal-native route uses shared token + HMAC and looks up a notification by provider message ID without tenant/provider predicate (`:202`); establish a tenant-bound credential mapping or enforce the single-tenant invariant in persistence and lookup. These are source observations; no database mutation was exercised for them.

## Canonical authority and bypass accounting

Repository evidence confirms `deploy/compose.runtime.yaml:23,168,252` selects the integration entrypoint and port **8095**. `app/application.py` mounts `app/platform/api.py` on all profiles; its six command/operation/describe routes use **/platform/v1** and authenticate in their handlers. Other catalog and product routes also use that prefix; the prefix alone is not a security guarantee.

`generate_route_authority_report.py --check` passes with 320 operations and `DIRECT_EFFECT_BYPASSES=0`. This classifier counts direct external-provider effects, not authorization completeness. It does **not** detect AUTH-01's read/cancel bypass of JWT/tenant/kernel authority. No direct external-provider transport bypass was reproduced on the canonical integration profile.

The report explicitly lists three direct internal-service webphone routes (`/webphone-api/v1/session`, `/renew`, `/revoke`) and five durable-outbox paths pending kernel convergence: `/api/v1/n8n/acknowledgements`, `/v1/observability/incidents`, `/v1/observability/kpis`, `/webhooks/sms/inbound/`, `/webhooks/vicidial/call-result/`. These are alternate paths, not automatically unauthenticated vulnerabilities. The separate email application has its own `/v1/email/*` authority; it is outside this route report. No claim is made that the deployed edge or listening sockets were verified live.

## Controls reviewed and evidence

| Area | Evidence and result |
| --- | --- |
| JWT / service identity / azp / audience | `app/security.py`, `app/control_plane_auth.py`, `app/platform/principal.py`: registered caller selected from unverified azp only for routing, then signature/issuer/audience/azp/scope verified; RS256 only and machine lifetime <=300s. Real-signature negative matrix rejects foreign key, alg=none/HS256, wrong authority, missing scope and expired tokens. AUTH-02 limits certification. |
| Interactive / provisioning authority | `app/core/jwt_auth.py`, `platform_auth.py`, `provisioning_auth.py`: explicit configured authority, scopes and role/tenant checks; platform review independence uses verified sub, not forged headers. Shared bearer rejected on catalog endpoints. The synchronous validator creates a new JWKS client on every validation, so its advertised set cache is not shared across requests; consider reuse with bounded cache/timeout for availability. |
| Tenant isolation | Kernel submit binds subject and authorized tenant; read/timeline/cancel/replay pass selected authorized tenant to storage. Foreign operation reads/cancels are non-disclosing; wildcard grants rejected. Tested in platform API/kernel/security suites. AUTH-01 is an alternate-route gap. Real PostgreSQL tenant cases skipped. |
| Policy / safety | Capability/target bindings, default-disabled effects, tenant/backlog limits, synthetic-only tenant, production TEST_SYN exclusion, tighten-only kills and execution-time safety reevaluation pass existing kernel tests. No live effect enabled. |
| Webhook signatures | `app/security.py` signs method/path/timestamp/event/source/body digest; `app/service.py` checks JWT tenant and all body/header bindings before persistence. Compatibility provider ingress verifies timestamp+body HMAC, bounded JSON and replay digest. Existing fresh-timestamp replay and invalid-signature tests pass. |
| Secrets | `app/secret_reference.py` pins schema, rejects nested forbidden material, traversal/wildcards and cross-environment references. No secret resolution occurs there. Existing reference/file tests pass. Secret mount contents were not read. |
| SMTP / provider boundary | No SMTP client/starttls implementation found in reviewed app/connector-runtime source. Canonical Klyrow adapter uses allowlisted private HTTPS, TLS >=1.2/mTLS, secret mount checks, effect gates and readback of uncertain outcomes. Tests use MockTransport. Actual SMTP/DKIM/provider-side behavior is outside this repository review. Separate email transport caveats above remain. |
| Replay / idempotency | `app/replay.py` uses tenant+event keys, Redis NX lock and ownership-checked release. Durable digest handles conflict after lock release; kernel idempotency binds tenant/caller/payload. Replay requires scope/operator role and safe state; uncertainty triggers reconciliation. Existing tests pass; distributed backend behavior was not exercised live. |

## Validation and limitations

- `security-tests.log`: **363 passed**, 68 warnings.
- `extended-tests.log`: **129 passed, 14 skipped**, 3 warnings. Includes **7 new characterization cases**; their passing result means the defects were reproduced, not remediated.
- Combined: **492 passed, 14 skipped**. The skips require disposable PostgreSQL (`test_tenants_and_campaigns.py`); this lane did not access a live DB or claim SQL/RLS concurrency certification.
- `identity-validator.log`: 18 clients, 32 grants, 8 webhook contracts, 40 event types; all policy checks PASS. Source-state counts still include contract-only/unverified providers.
- `route-validator.log`: committed route report MATCH.
- `diff-check.log`: whitespace validation result.

See `commands.txt` for exact selections. The evidence-local harness clears inherited application/provider environment, uses test settings, disables bytecode/cache writes, and blocks AF_INET/AF_INET6 socket connect/connect_ex before importing application/tests. Provider tests use mocks. It is a Python test safety guard, not an OS sandbox for arbitrary subprocesses. Settings specify `env_file=None`. No live provider calls, deployment, merge, production activation, or secret inspection was performed.

Only this evidence directory and the new `tests/review_auth_tenant_boundaries.py` are committed. The new filename intentionally requires explicit pytest selection. The final delivery reports the pushed commit and remote SHA parity; reviewed source SHA above remains the immutable source baseline.
