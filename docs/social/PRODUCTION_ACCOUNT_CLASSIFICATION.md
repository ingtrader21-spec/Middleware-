# Production account classification

Every Codestra `SocialAccount` must carry exactly one controlled metadata classification: `PRODUCTION_APPROVED_CANARY`, `PRODUCTION_NOT_APPROVED`, `STAGING`, or `UNKNOWN`. Missing values are treated as `UNKNOWN`.

Only `PRODUCTION_APPROVED_CANARY` may pass the production policy, and its Codestra account UUID must also appear in `SOCIAL_PRODUCTION_CANARY_ACCOUNT_IDS`. The account must be connected, assigned to the same provider as the post, and be the only account attached to the initial canary post. Provider IDs and credentials are never canonical or returned as approval evidence.

No approved production inventory was available during this run, so the approved count is zero and live publishing is blocked.
