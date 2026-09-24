# Production change authority

Governance role assignment does not authorize a production change by itself.
A production change requires:

- exact-source Release Owner authorization;
- the separate Security Owner decision;
- independent exact-head source review;
- passed tests and security gates;
- signed immutable artifacts;
- verified backup and rollback readiness;
- ordered production locks;
- an approved change window or documented emergency authority;
- runtime read-back and fail-closed feature-state verification.

The mapped Release Owner may authorize progression into these gates but may not
waive them. Migrations, deployments, integrations, campaigns, calls, WebRTC,
n8n, email, and SMS remain separately gated.
