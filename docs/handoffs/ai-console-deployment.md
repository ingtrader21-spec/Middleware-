# AI console deployment handoff

Run this only from the local Codex session on web host `49.12.145.107`. Preserve Postly and every existing virtual host. Do not seek administrative SSH to middleware or Qwen.

## Scope

Deploy only `ai.codestra.co` from a signed repository artifact or immutable GHCR digest. Browser traffic must terminate at the existing approved proxy and call only the Middleware browser API:

- `/api/v1/ai/conversations`
- `/api/v1/ai/conversations/{id}/messages`
- `/api/v1/ai/jobs/{id}/stream`
- `/api/v1/ai/jobs/{id}/cancel`

Never proxy or link to Qwen, LiteLLM, Ollama, worker endpoints, private IPs, or `/internal/` paths.

## Deployment procedure

1. Back up and checksum the existing proxy/site configuration.
2. Verify DNS ownership for `ai.codestra.co` and obtain TLS through the existing ACME mechanism without changing other sites.
3. Verify the frontend artifact signature, OIDC identity, transparency log, SBOM, provenance, and VEX.
4. Serve immutable static assets with a restrictive CSP, `frame-ancestors 'none'`, `nosniff`, strict referrer policy, HSTS after TLS validation, and no inline secrets.
5. Use the approved browser session flow. Never store service credentials in JavaScript, browser storage, query strings, or source maps.
6. Proxy only the four allowlisted API/SSE patterns to the approved Middleware public origin. Disable redirects to arbitrary upstreams; bound request and response sizes and timeouts. Disable buffering for SSE only.
7. Preserve Postly and all existing sites byte-for-byte outside the new site block. Validate configuration before reload and roll back automatically on health failure.

## Acceptance

- Authenticated conversation creation and message submission.
- Anonymous, expired-session, cross-tenant, oversized, and disallowed-project requests rejected.
- SSE resumes safely with event IDs and does not leak another tenant's chunks.
- Cancellation is idempotent and visible.
- Keyboard-only navigation, focus order, labels, contrast, reduced motion, responsive layout, and screen-reader announcements pass.
- CSP, CORS, CSRF/session behavior, clickjacking, cache control, XSS encoding, dependency audit, and TLS tests pass.
- Direct Qwen/LiteLLM/Ollama and all `/internal/` requests fail.
- Postly and existing-site regression checks pass.

Return artifact identity, TLS result, route matrix, accessibility/security results, rollback evidence, existing-site checks, and zero external-write counters. Do not include secrets.
