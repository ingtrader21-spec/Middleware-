# Phase 2 Postly authentication certification

- Auth type: organization API key (`Authorization` header).
- Machine-token support: no separate least-privilege service identity in deployed source.
- Secret source: existing Postiz organization API key; no rotation or new broad principal.
- Middleware storage: `/etc/codestra/secrets/middleware-staging/postly/postiz_api_key`.
- Permissions: `0400`, UID/GID `10001:10001`.
- Private route: `10.40.0.1` to `10.40.0.3`, VLAN 4001, MTU 1400.
- TLS identity: `social.codestra.co`, valid through 2026-10-31.
- Valid credential: HTTP 200.
- Invalid credential: HTTP 401.
- Missing credential: HTTP 401.
- Middleware adapter: `AVAILABLE`, configured/enabled/reachable true.
- Account discovery: PASS, zero accounts.
- Production social posts created: zero.
- Odoo writes: zero.

The public API is not source-restricted to the private VLAN; confidentiality relies on
TLS plus the organization credential. This limitation must be addressed before any
production readiness phase.
