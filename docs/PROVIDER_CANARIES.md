# Provider canaries

The staging provider gate consists of exactly four bounded commands:

| Canary | A PASS requires |
|---|---|
| Klyrow email | A Postal API/webhook read-back with provider message ID, delivery event ID, delivered state, recipient fingerprint, and event time. |
| Telnexa SMS | A carrier/Jasmin delivery receipt with provider message ID, receipt ID, delivered state, destination fingerprint, and event time. |
| VICIdial voice | A VICIdial/Asterisk CDR with CDR ID, disposition, positive duration, hangup cause, destination fingerprint, and event time. |
| Social publishing | An external-provider API read-back with post ID, account-reference fingerprint, published state, content fingerprint, and publication time. |

`accepted`, `queued`, `submitted`, a local database state, or an HTTP 2xx from
the write request is never a PASS. Middleware completes a marked canary command
only after `app.provider_canary.validate_provider_canary_evidence` accepts the
channel-specific provider proof. The proof and its canonical SHA-256 digest are
persisted respectively on the command attempt and immutable command audit, then
verified and returned by `GET /v1/operations/{id}`.

## Safety properties

- The configuration must say `enabled: true` and `environment: staging`.
- A non-placeholder approval reference and a separate approved-destination
  reference are required for every channel.
- Destinations and payloads live in untracked payload files. Evidence contains
fingerprints, never email addresses, phone numbers, post content, or tokens.
- Provider event and observation timestamps must fall within the canary run
  window (with five minutes of clock-skew tolerance).
- Each effectful command is submitted exactly once. A timeout or transport
  failure is `INDETERMINATE`; the runner does not retry the write.
- Only read-only operation polling repeats.
- All four canaries must PASS for the run to PASS.

## Configuration

Copy `config/provider-canaries.staging.example.json` outside the repository or
into an ignored secrets directory. Populate its token and four payload files,
replace every approval placeholder, set the deployed HTTPS Middleware origin,
and only then set `enabled` to `true`.

The destination JSON pointers in the example expect these provider command
payload fields:

- email: `/to`
- SMS: `/destination`
- voice: `/destination`
- social: `/account_reference`

The full payload is fingerprinted before the runner adds its reserved `canary`
block. Provider adapters must return those exact destination and payload
fingerprints in their read-back evidence.

## Execution

```bash
python scripts/provider_canaries.py \
  --config /run/secrets/provider-canaries.staging.json \
  --evidence /var/lib/codestra/evidence/provider-canaries/run.json
```

Exit codes are `0` for PASS, `1` for a completed FAIL/INDETERMINATE run, and `2`
when the run is blocked before submission. The console output contains only the
run ID, per-channel outcomes, and evidence path.

## Activation boundary

The repository defaults remain fail-closed: connector manifests are disabled
and the four effect capabilities are false. Do not edit those defaults to make a
canary pass. A deployment must bind reviewed provider adapters, approved staging
credentials and destinations, and a time-bounded capability activation. If any
of those is absent, record BLOCKED/NO_GO; never substitute simulator acceptance
or fabricated evidence.
