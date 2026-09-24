# Phase 1 acceptance

Acceptance evidence is provided by `tests/test_social_publishing.py`, the complete repository test suite, Ruff, mypy, Alembic migration validation, secret scan and Docker build. Mandatory cases cover historical provider ownership after a default switch, duplicate-publish prevention, default-off safety, normalized webhook verification, Hootsuite disabled behavior and provider-neutral OpenAPI.

Known limitation: real Postly and Hootsuite credentials were intentionally not used. Phase 2 must perform controlled staging account discovery, draft creation, scheduling and webhook round-trip; Phase 3 implements Hootsuite and migration canary behavior.
