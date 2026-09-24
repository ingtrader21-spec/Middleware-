# Encrypted webhook body reconciliation

Every webhook body is encrypted before the database transaction and receives a
credential-free, fsync-backed pending record before the encrypted file is promoted.
Database success clears only the pending record. A semantic conflict removes the
rejected body. An uncertain database or process outcome retains both artifacts until
a later reconciliation query can distinguish an accepted inbox reference from a
rollback or conflicting reference.

Reconciliation runs during Connector Runtime startup, readiness, and subsequent
webhook ingress. A 300-second grace period prevents one replica from deleting a body
while another transaction may still be in flight. Accepted records retain their body;
rolled-back and rejected records are removed; database and filesystem failures remain
journaled for retry. Malformed journal records are counted and fail readiness rather
than triggering unsafe deletion.

The pending record contains no encryption key, webhook secret, token, plaintext body,
or credential. It stores only the file reference, tenant/webhook/event identifiers,
body digest, schema version, and creation time. Files and journal entries remain mode
0600 under a mode-0700 root.
