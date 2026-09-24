# Controlled replay v2

This procedure is inert until a later controlled-call mission is independently
authorized.

Keep `SEND_EVENTS=false`. Select only three gateway outbox events whose
LinkedID, UniqueID(s), deterministic IDs, source `6198`, destination `*43`,
context `cs-synth-6198`, producer boot ID, canonical hashes, and bounded UTC
timestamps match the captured call evidence.

Submit the exact captured STARTED, CONNECTED, and ENDED bytes once each, then
submit the byte-identical ENDED event once more. Stop after exactly four HTTP
attempts. Each `Idempotency-Key` equals its event ID; the existing HMAC route,
headers, and `vicidial-server-b` identity remain unchanged.

`TEST_EVIDENCE_ID` belongs only in the operator log and evidence manifest. It
must never appear in the event envelope, payload, headers, or persistence.
Reject incomplete, ambiguous, out-of-window, modified, or unrelated events.
Keep all downstream delivery disabled.
