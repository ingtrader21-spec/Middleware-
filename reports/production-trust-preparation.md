# Production trust preparation evidence

Status: fail-closed preparation; production activation is not authorized.

- Rollback snapshot: `/var/lib/codestra/backups/full-production-trust-20260810T055013Z`
- Internal network: present, internal-only, `10.254.41.0/28`
- Private aliases: Odoo and n8n resolve only inside the Docker network
- Internal TLS: TLS 1.3, hostname validation passed for both service names
- Odoo route: canonical path prepared; production Odoo addon activation remains
  blocked until exact release authorization
- n8n workflow inventory: one `TEST_SYN_ONLY`; all production candidates remain
  inactive unless explicitly authorized
- Historical outbox: five legacy `event.accepted` rows have no recoverable
  tenant binding and are expired; none were dispatched or replayed
- Production calls made: zero
- Customer data used: no
- Production flags enabled: none

Remaining protected gates are exact-head CI and review after the final commit,
Keycloak service-client administration, separate Release Owner and Security
Owner decisions, and the signed bounded production authorization.
