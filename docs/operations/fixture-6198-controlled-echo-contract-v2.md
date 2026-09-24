# Fixture 6198 controlled echo contract v2

## Status and scope

This runbook prepares a later, separately authorized internal echo test. It
does not itself authorize fixture activation, SIP registration, a call, event
submission, or a production configuration change.

`TEST_EVIDENCE_ID` is an operator/evidence identifier only. It MUST remain in
the external evidence manifest and operator logs. It MUST NOT be inserted into
a lifecycle payload, envelope, HTTP header, database row, or middleware API
request. The deployed Schema V1 envelope remains unchanged.

## Immutable correlation tuple

The later test MUST select records only when all available values agree:

- Asterisk LinkedID;
- Asterisk UniqueID and any channel UniqueIDs;
- the three deterministic lifecycle `event_id` values;
- source extension `6198`;
- destination `*43`;
- dialplan context `cs-synth-6198`;
- an inclusive, tightly bounded call start/end UTC window;
- gateway producer boot ID;
- canonical payload SHA-256 values.

LinkedID is the primary call correlation identity. UniqueID is the fallback and
channel association. Operators must stop if the tuple is incomplete,
ambiguous, or matches an unrelated record.

## Authorized event and call scope

A later mission may authorize exactly one internal call, lasting no more than
30 seconds, and exactly these three captured unique events:

1. `vicidial.call.started`
2. `vicidial.call.connected`
3. `vicidial.call.ended`

It may additionally authorize one replay of the byte-identical ended event.
The `Idempotency-Key` for every lifecycle submission must equal that event's
deterministic `event_id`. No other event, metadata field, call, destination, or
replay is authorized.

## Required safety state

Throughout preparation and any later execution:

- `SEND_EVENTS=false`;
- `ENABLE_EXTERNAL_DELIVERY=false`;
- email, SMS, n8n, WebRTC, VICIdial writes, callbacks, transfers, campaigns,
  and external calling remain disabled;
- the only dialplan route is `6198 -> *43 -> Echo -> Hangup`;
- extension 6110 is untouched;
- no customer route or external trunk is reachable.

The existing ingress remains `/api/v1/events/vicidial` with
`Idempotency-Key`, `X-Signature`, `X-Timestamp`,
`X-Client-Instance-ID`, and `X-Nonce`. The client identity remains
`vicidial-server-b`.

## Later-run stop conditions

Stop before activation or submission if any prerequisite is false, the tuple
matches more than one logical call, the gateway does not retain events while
automatic delivery is disabled, a payload differs from the captured bytes, or
any external side-effect path is enabled.

After the later test, the fixture must be unloaded, registration/call/channel
counts must return to zero, and the authorized audit records must be read back
using the immutable tuple rather than an injected marker.
