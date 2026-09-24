# Fixture 6198 V2 blocker remediation

This document does not authorize another call, production ACL changes, event
replay, deployment, or fixture activation.

## Audio

Baresip 1.0's installed `ausine` source accepts only 48 kHz stereo, while the
fixture negotiates G.711 PCMU at 8 kHz mono. The corrected template uses a
generated 1000 Hz, 8 kHz, mono S16LE WAV through the installed `aufile` module,
constrains the account to `PCMU/8000/1`, and consumes receive media with the
ALSA null sink. A privileged operator creates only the protected runtime
directory; the unprivileged test identity generates and reads the mode-`0600`
WAV. It records no received audio.

## Database ACL

The deployed ingress role is discovered at runtime rather than embedded in the
scripts. The lifecycle transaction already has its pre-0014 grants. Migration
0014 created two PostgreSQL-owned tables without granting the ingress role:

- `telephony_call_lifecycle`: requires SELECT, INSERT, UPDATE;
- `telephony_call_lifecycle_event`: requires INSERT and SELECT because the
  deployed ORM emits `INSERT ... RETURNING recorded_at`.

The scripts validate a caller-supplied psql role identifier, reject privileged
roles, and grant only those operations plus schema USAGE. They grant no DELETE,
TRUNCATE, REFERENCES, TRIGGER, CREATE, ownership, membership, or default
privileges. The revoke script removes only the migration-0014 table grants and
retains pre-existing schema USAGE.

After review and merge, a separate mission must apply the production ACL and
replay the three already captured events plus one identical terminal duplicate.
Only successful replay may justify considering authorization for another call.
