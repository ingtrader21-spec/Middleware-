# Codex Mission — Middleware Governed PSTN Caller

Date: 2026-09-10

## Server
Execute the caller-side portion on `65.109.65.169` only.
Target VICIdial/Asterisk server: `65.21.67.207` through the existing private/mTLS edge.

## Authority boundary
This document is an execution runbook, not runtime authorization. The canonical Middleware repository currently keeps `runtime_mutation_authority=false`, `live_pstn_dialing=false`, and `PRODUCTION_DIALING=false`. Therefore no real PSTN request may be sent from Middleware until the authoritative repository gates are explicitly updated and approved through protected-branch policy. If those gates remain false, STOP after read-only preflight and report `PSTN_EXECUTION_BLOCKED_BY_REPOSITORY_AUTHORITY`.

## Objective
After repository authority is explicitly granted, submit exactly one authenticated request to the governed VICIdial adapter endpoint `POST /v1/calls/originate` for destination `+18496582053` using only the exact request/authentication contract implemented and tested in this repository at the deployed protected-main SHA.

## Required preconditions
- The Middleware protected-main authority explicitly permits this bounded one-call action.
- The VICIdial adapter on `65.21.67.207` is healthy and running its canonical protected-main release.
- `/ready` on the adapter reports the governed one-call production profile and `production_dialing=true`.
- DIDWW route certification has passed on `65.21.67.207`.
- Durable external-call state shows the authorization has not already been consumed.
- mTLS from `65.109.65.169` to the private edge validates successfully.
- The caller contract below is implemented in source and covered by tests on the exact deployed Middleware SHA.

## Request contract
Do not invent headers, HMAC canonicalization, scopes, nonce semantics, or idempotency behavior from this runbook. Resolve the authoritative implementation and tests first.

Today the existing Middleware `VicidialMTLSClient` transport for `/v1/calls/originate` uses the repository-defined mTLS transport contract and correlation/request headers; the existing HMAC v2 documentation is for internal-call endpoints and MUST NOT be reused for external dialing unless a later protected-main change explicitly implements and tests that external HMAC contract.

If the exact external schema/authentication contract is not present in protected `main`, STOP and implement it in source/tests/docs first, merge it through normal protected-branch policy, deploy that exact SHA, and only then execute. The external request must carry only fields and headers accepted by that exact implementation. Destination remains `+18496582053`, purpose remains a controlled test, and recording must remain disabled.

## Retry policy
Submit once only after all authority and contract gates pass. A transport timeout, 5xx after possible dispatch, `dispatch_unknown`, `submitted_unknown`, or any ambiguous result is a STOP condition. Reconcile adapter durable state and Asterisk events before any further action. Never blindly resend the same or a new operation ID.

## Evidence
Record only non-secret evidence: UTC timestamp, operation/correlation/request identifiers actually defined by the authoritative contract, target host, endpoint, HTTP status, response state, deployed Middleware SHA, adapter release SHA, and reconciliation outcome. Redact authorization material.

## Post-attempt
Confirm with the VICIdial host operator that production dialing is immediately disabled after the attempt and that the adapter returns to its normal fail-closed profile. Middleware repository authority must also be restored to the normal fail-closed state if it was temporarily changed for the bounded call.

## Repository reconciliation
If the live caller contract differs from this repository, fix source/tests/docs first, run CI, and merge through normal protected-branch policy. No live-only Middleware workaround may remain canonical.
