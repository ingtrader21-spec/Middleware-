# Codestra OpenAI provider deployment

This release adds a disabled-by-default provider worker on Server A. It does not
change production routing merely by installing the artifact.

## Required protected inputs

- `/run/secrets/openai/api-key`, owned by the runtime user with mode `0400` or
  `0600`.
- `/run/secrets/openai/safety-salt`, independently random, at least 32 bytes,
  with the same ownership and permissions.
- The existing protected PostgreSQL database URL secret.

Never place either OpenAI secret in environment values, images, logs, evidence,
source control, Server C, or browser JavaScript.

## Controlled activation

1. Preserve the running controller image digest, Qwen worker state, queue depth,
   configuration checksums, and rollback commands.
2. Create an enabled `ai_worker_registrations` record for the exact
   `codestra-openai-01` / `openai-responses-provider` identity with maximum
   concurrency one.
3. Install the attested controller artifact with
   `OPENAI_PROVIDER_ENABLED=false` and validate health.
4. Mount the protected API key and safety salt read-only.
5. Set the explicit chat and coding models and reasoning efforts. Keep the
   project allowlist exactly `codestra-ai-console`.
6. Enable one OpenAI provider worker while the Qwen worker remains available as
   rollback. Do not permit both workers to claim the same profile concurrently.
7. Run authenticated chat, approved coding, streaming, cancellation, timeout,
   tenant denial, project denial, usage-limit, and provider-failure tests.
8. Only after the concurrency-one canary passes, disable new Qwen claims. Do not
   revoke or remove Qwen credentials in this release.

## Rollback

1. Disable the OpenAI provider worker and its worker registration.
2. Confirm it has no active lease; recover an expired lease through the governed
   recovery endpoint when necessary.
3. Re-enable the previously certified Qwen worker registration and routing.
4. Verify chat, coding, cancellation, queue depth zero, and exactly-once result
   delivery.
5. Preserve sanitized failure evidence. Never include prompts, responses, user
   identifiers, API keys, or safety-identifier salts.
