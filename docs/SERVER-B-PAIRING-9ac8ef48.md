# Server B paired-source regression evidence

Middleware source under test: PR #145, based on `0c56a5ea261d9bca9bef0f565c5b35ddcdc8cd22`
before the fixes recorded by this change.

Selected Server B source: `appolon1908-hue/Vicidialer-Codestra`
`9ac8ef4840f78ba4ad9b816e4e409298505103ce` (PR #29).

The paired test imports the selected Server B implementation directly. It uses
Server B's real FastAPI routes, HMAC v2 authenticator, internal-call policy,
one-call/idempotency enforcement, SQLite call state, and append-only audit.
Only the external Asterisk/AMI effect is replaced with the repository's
synthetic no-effect transport. Credentials, databases, and destinations are
synthetic; the sole destination is `internal:TEST_ECHO`.

The expiry-safe path proves the denial reason for a distinct new originate is
the expired startup authorization (not the consumed quota) before any second
AMI action. The original owner can still read the existing call and submit its
same-call hangup. A synthetic terminal AMI lifecycle event is then persisted by
Server B and consumed through Middleware's actual readback client. The terminal
evidence is identity-bound and complete; the execution store retains one call,
the grant remains consumed, and the AMI action sequence remains exactly one
originate followed by one hangup. Middleware's disposable PostgreSQL regression
separately proves original/hangup convergence after restart without another
mutation or duplicate completion transition.

Commands executed:

```text
PYTHONPATH=<exact-server-b>/vicidial/src pytest -q \
  vicidial/tests/test_internal_calling.py \
  vicidial/tests/test_internal_call_review.py
# 56 passed

CODESTRA_SELECTED_SERVER_B_ROOT=<exact-server-b> \
CODESTRA_SELECTED_SERVER_B_SHA=9ac8ef4840f78ba4ad9b816e4e409298505103ce \
pytest -q tests/pairing/test_selected_server_b.py
# 1 passed
```

The required head and merge-result CI job checks out this exact Server B SHA,
fails if the checkout or SHA verification is absent, and runs the pairing test
with the selected-source variables set. The default local suite may skip this
external-source test; required CI may not.

Server B source publication and independent verification are complete. The
verified runtime source remains `9ac8ef4840f78ba4ad9b816e4e409298505103ce`;
protected builder `def0f1822fe54ab2a0800e8d6e083533df88d064` produced run
`34000565825/1`, artifact `9979357196`, archive SHA-256
`5e3d4083dd94297c1085a28953547d5532e07c9685560184047208ca2cf0a252`.
Durable cryptographic evidence merged in Vicidialer-Codestra at
`0975e8a3b844f81671edadc15d7a743ce58d83c1`, under
`evidence/server-b-verified-source-publication-20260906/`.
These pairing tests execute that exact source through the real Middleware client
and Server B authenticator/routes/state. They do not certify an installed
production pair, live SIP or audible calling. The lock's `protected_release=false`
is retained: publication does not itself authorize runtime activation.

Middleware contains the Temporal worker binding. This is not evidence that a
calling worker is deployed, running, registered, or polling its queue. Runtime
worker verification remains a separate isolated-rehearsal and deployment gate.
