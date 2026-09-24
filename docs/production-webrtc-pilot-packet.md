# Production WebRTC pilot packet

Generated: 2026-08-20 (America/Santo_Domingo)

## Decision

`PRODUCTION_PILOT_READY=FAIL`

The technical staging stack is healthy, but no production campaign, human pilot
identity, carrier authorization, caller-ID ownership, destination consent, or
accountable-owner approval is evidenced. PSTN and production dialing remain
disabled. No SIP REGISTER or call was performed.

## Automatically verified evidence

| Gate | Result | Evidence |
|---|---|---|
| Safety state | PASS | `LIVE_PSTN_DIALING=false`; production activation false; zero calls/channels |
| Campaign discovery | BLOCKED | Registry has eight `PROPOSED_DISABLED` candidates; none is approved for a pilot |
| Pilot identity | BLOCKED | Only synthetic `TEST_SYN`/6101 binding is certified; it is not a production identity |
| Endpoint precheck | PASS | 6101 unavailable, zero contacts/channels |
| Carrier/trunk | BLOCKED | No carrier approval reference or approved production registration was found |
| Caller ID | BLOCKED | Requested number has zero Asterisk/VICIdial configuration matches |
| Destination | RECORDED_UNAPPROVED | Controlled destination supplied privately; owner and consent evidence absent |
| Canonical issuer | PASS | `https://auth.codestra.co/realms/codestra` |
| WSS DNS/TLS | PASS | `wss.codestra.agency` resolves to Server B and TLS validates |
| WSS fail-closed | PASS | Unauthenticated upgrade rejected with HTTP 400 |
| SIP.js/browser controls | PASS_STAGING | 39 unit tests and 9 browser tests pass; cleanup, multi-tab, microphone and fail-closed cases covered |
| Running image | PASS | Running immutable digest `sha256:f56fac4943b9928c7ca82cbb19c876fcc8a7c1b1ec65563fa36bc9d767da80eb` |
| Protected source | PASS | merged source `9b817116ae6233af708d201f0233c1f707ee32b7` |
| Production release attestations | BLOCKED | no evidence binding signature, SBOM and provenance to the running desktop digest was found |
| Recording policy | BLOCKED | no approved production pilot recording decision exists |
| Emergency/premium/prohibited policy | BLOCKED | production route is closed, but no approved pilot policy/allowlist exists |
| Capacity | PARTIAL | zero current calls; exact one-attempt/one-call production policy is not deployed |
| Kill switch | PASS_CURRENTLY_ENGAGED | production activation and live PSTN flags are false |

## Candidate campaigns—not approvals

The authoritative registry lists RLP100, TRD200, MOY300, COD400, SCP500,
MBL600, FTP700 and CAL800. All are proposed and disabled. Selecting one is a
business decision and was not inferred.

## HUMAN_APPROVALS_REQUIRED

| FIELD | RESPONSIBLE_ROLE | CURRENT_STATUS | REQUIRED_EVIDENCE | WHERE_TO_RECORD |
|---|---|---|---|---|
| Production campaign/business unit | Business owner | MISSING | Dated selection of one registry campaign and pilot purpose | This packet and JSON `approvals.business_owner` |
| Pilot agent and supervisor | Business owner / supervisor | MISSING | Exact Keycloak subjects, VICIdial users, extensions, tenant/campaign binding, acceptance | `approvals.business_owner` and `approvals.supervisor` |
| Telephony approval | Telephony owner | MISSING | Named approval of trunk, endpoint, route, caller ID and call path | `approvals.telephony_owner` |
| Security approval | Security owner | MISSING | Named approval binding signature, SBOM, provenance and security evidence to running digest | `approvals.security_owner` |
| Compliance approval | Compliance owner | MISSING | Campaign purpose, destination consent, calling hours, recording and prohibited-number policies | `approvals.compliance_owner` |
| Carrier production authorization | Telephony owner / carrier | MISSING | Carrier-issued account/use/country/call-type reference | `carrier.authorization_reference` |
| Caller-ID ownership and use | Business/telephony/compliance owners | MISSING | Provider inventory or invoice plus explicit campaign-use approval | `caller_id` |
| Destination consent | Destination owner / compliance owner | MISSING | Timestamped consent covering this pilot, purpose and single-call scope | `destination.consent` |
| Pilot window | Business, telephony and compliance owners | MISSING | Date, destination-local start/end and timezone | `pilot_window` |
| Calling/recording/prohibited policy | Compliance owner | MISSING | Approved hours, holidays, recording choice, emergency/premium/international rules | `policies` |

## Safe next action

The responsible humans complete the fields above and attach immutable evidence.
Then rerun technical validation. Until every gate passes:

```text
PSTN_DIALING=DISABLED
PRODUCTION_DIALING=DISABLED
CALLS_PLACED=0
SIP_REGISTER_PERFORMED=NO
LIVE_PROVIDER_DISPATCH=false
```
