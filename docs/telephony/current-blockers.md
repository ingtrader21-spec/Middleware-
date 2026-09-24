# Current Production Blockers

The following are evidence-based gates, not implementation preferences:

- A complete per-extension signed inventory has not yet been captured across
  all 23 authoritative collision sources. Candidate 6110 therefore remains
  fail-closed.
- The provisioning-service is explicitly staging-only and uses a local SQLite
  state repository. Its proven saga/adapters must be productionized behind
  PostgreSQL identities before activation.
- Distinct Keycloak production service accounts/scopes are absent.
- Production email/SMS provider credentials, capacity, approved sender and
  approved recipients are absent.
- The requested inactive n8n lifecycle workflows have not been imported.
- Production TURN/WSS/device-binding configuration has not passed browser/SIP
  acceptance.
- Server B SIP/WSS public listeners require an exposure and ACL acceptance
  check.
- No approved private registry was identified for an off-server immutable
  image distribution proof.
- A complete synthetic 6110 activation, SIP registration, VICIdial login,
  suspension and rollback rehearsal has not run.

Production calling, email, SMS and n8n remain disabled. No customer contact was
made.

FULL_EXTENSION_INVENTORY_GATE=BLOCKED
EXTENSION_COLLISION_GATE=BLOCKED
STAGING_ACCEPTANCE_GATE=BLOCKED
SYNTHETIC_ACTIVATION_GATE=BLOCKED
