# Codestra Telephony Platform Inventory

Captured 2026-07-26 in America/Santo_Domingo. This is a read-only baseline.

## Server A

- Identity: `middleware`; public 65.109.65.169; private 10.40.0.1.
- Odoo: 19.0-20260630. The installed `codestra_identity_provisioning`
  module is version 19.0.1.1.2.
- Existing models: all eight mandated `codestra.*` provisioning, identity,
  extension, credential-reference, step and audit models are installed.
- Production projections: 1 extension pool, 1 assignment, 1 identifier
  reservation, 4 identity links, 2 provisioning requests, 4 steps, 4 audits
  and 1 credential reference. They describe the disabled synthetic 6198
  fixture; no 6110 record was found.
- Middleware baseline before this change: commit
  `2a46e24fe29e8a7dde566605aceb1de389dccaef`, clean worktree, 12 migrations.
- Redis: 7.4.5, container-network only; no key matching 6110 was found in the
  available production Redis inventory.
- n8n: production workflows are inactive. Existing workflows do not comprise
  the fifteen lifecycle workflows requested by this mission.
- Keycloak: existing middleware, n8n, desktop, staging provisioning and test
  clients exist. Distinct production identities for allocator, VICIdial,
  PJSIP, webphone, reconciliation, notification and evidence do not.
- Agent Desktop: staging desktop exists. The production-bound WebRTC session
  issuer and device-revocation acceptance are incomplete.
- Email/SMS: interfaces and disabled adapters exist; verified production
  provider identities, capacity and approved destinations do not.
- All broad production mutation, communication, delivery, VICIdial control and
  n8n production flags were false at capture time.

## Server B

- Identity: `static`; public 65.21.67.207; private 10.40.0.2.
- Asterisk: 18.26.4-vici. MariaDB packages: 10.11.15.
- Active channels/calls: zero at capture time.
- PJSIP: no loaded endpoints, AORs, contacts or registrations.
- chan_sip: 14 peers (13 extensions and one carrier trunk); extension peers
  were offline and the carrier trunk was online.
- VICIdial: 44 users, 31 phones, 25 campaigns, 19 user groups, 31 inbound
  groups, zero live agents and zero auto calls.
- 1001 is an active VICIdial user and active SIP phone and remains protected.
- 6101 has historical/configuration references and is permanently excluded.
- 6198 is the prepared inactive synthetic fixture. Its PJSIP configuration is
  intentionally not included, allows only 10.40.0.1, exposes only restricted
  echo `*43`, and denies other routes.
- Private provisioning boundaries listen on 10.40.0.2:8443 and :8444.
  MariaDB and AMI listen on loopback. No database mutation was performed.
- SIP UDP 5060/5061 and WSS 8089 bind publicly and require a separate exposure
  review before production activation.

## Candidate 6110

No loaded PJSIP endpoint, VICIdial user/phone/session, active Asterisk channel,
registration, voicemail, direct dialplan entry, static queue reference, known
VICIdial call-history record, Odoo assignment/request, middleware reservation
or observed Redis lease was found for 6110. This is insufficient to declare
availability until a signed, one-row-per-extension audit is collected from
every authoritative source at reservation time.

SERVER_A_INVENTORY_GATE=PASS
SERVER_B_INVENTORY_GATE=PASS
EXISTING_MODEL_REUSE_GATE=PASS
CURRENT_SAFETY_GATE=PASS
CANDIDATE_6110_CLASSIFICATION=UNKNOWN_REQUIRES_REVIEW
