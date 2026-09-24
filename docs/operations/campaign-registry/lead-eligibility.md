# Lead identity and dialing eligibility

Every created/imported lead receives an immutable campaign-scoped ID
immediately. Identity states are ID_ASSIGNED, VALIDATION_PENDING, VALIDATED,
DUPLICATE_REVIEW, REJECTED, and ARCHIVED.

Dialing is separate: NOT_ELIGIBLE, ELIGIBILITY_PENDING, ELIGIBLE, ACTIVE,
PAUSED, DO_NOT_CALL, CONSENT_REVOKED, and CLOSED. An ID never authorizes
dialing.

Eligibility requires an active approved campaign, valid protected phone
record, duplicate and DNC checks, affirmative applicable consent, timezone and
calling-hours approval, approved destination/list/group/scope, and every kill
switch clear. Missing, stale, conflicting, or unknown evidence fails closed.
