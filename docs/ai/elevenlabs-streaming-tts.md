# Governed ElevenLabs streaming TTS

ElevenLabs TTS is an optional, disabled-by-default provider behind the existing
Server A Keycloak, tenant, project, admission, idempotency, and audit boundary.
Browsers never call ElevenLabs directly. Server C and VICIdial receive no
provider credential. Voice creation, cloning, dubbing, music, sound effects,
Agents, speech-to-speech, STT, telephony activation, and live calls are outside
this release.

## Trust and API contract

Authenticated `codestra_ai_user` principals may call
`POST /api/v1/ai/tts/stream` only for project `codestra-ai-console`. Requests
carry an idempotency key and correlation ID, text of at most 1,000 characters,
and the public profile name `canary`. Server A resolves that profile to the
protected `ELEVENLABS_CANARY_VOICE_ID`; clients cannot submit a provider voice
ID. Only `mp3_44100_128` is public. `ulaw_8000` is validated configuration for a
future separately authorized telephony phase and is not accepted by this API.

The adapter calls only
`https://api.elevenlabs.io/v1/text-to-speech/{voice_id}/stream`, sends the API
key in the server-side `xi-api-key` header, prefetches one non-empty audio chunk
before returning HTTP 200, and then relays bounded chunks with backpressure.
Disconnecting closes the upstream stream. Retries are limited to two and occur
only for connection, 429, or 5xx failures before audio is emitted.

## Configuration and retention

Conservative defaults are 10 seconds to connect, 60 seconds to read, 90 seconds
total, two retries, one concurrent stream, and standard provider logging.
`ELEVENLABS_REQUEST_LOGGING_MODE=zero_retention` adds `enable_logging=false`,
but that mode requires an eligible ElevenLabs plan. Operators must not claim
zero retention until the provider account entitlement and a canary prove it.

Startup readiness fails when an enabled provider lacks the exact approved host,
model, formats, concurrency, timeout policy, configured voice, or safe readable
secret. Keep `ELEVENLABS_PROVIDER_ENABLED=false` during artifact installation.

## Secret lifecycle

The source key remains `/etc/codestra/secrets/elevenlabs/api-key`, owned by root
with mode `0600`. During an attested deployment, an operator creates an
ephemeral runtime copy at `/run/secrets/elevenlabs-api-key`, owned by
`10001:10001`, mode `0400`, and mounts it read-only. The value must never enter
environment variables, images, Git, CI, Server C, n8n, VICIdial, logs, metrics,
or evidence. Rotation installs a new source key through the protected input
flow, creates a new runtime copy, restarts only Server A middleware, validates a
synthetic canary, then revokes the old provider key. Suspected exposure requires
immediate provider disablement, provider-key revocation, evidence preservation,
and incident escalation.

## Errors, metrics, and cost controls

Provider 400/422, 401, 403, and 404 responses are terminal and sanitized. A 429
or 5xx response is retryable only before the first byte. DNS/TLS failures and
timeouts map to provider-unavailable errors. Empty streams fail before HTTP 200;
partial streams are marked incomplete and never retried.

Metrics contain counts, stable error classes, character counts, audio bytes,
time to first audio, duration, active streams, and cancellations. They never
contain text, audio, keys, raw identities, voice IDs, or provider bodies. Local
limits are ten requests per user per minute, twenty per tenant per minute, and
one globally active stream. Provider-side key credit quotas remain a required
secondary cost guardrail.

## Canary, rollback, and future work

After exact-head review, protected CI, merge, new artifact evidence, and
artifact-bound approval, deploy on Server A with the provider disabled. Confirm
OpenAI acceptance independently, configure one approved canary voice, inject
the runtime secret, then synthesize only: “Hello. This is the Codestra
ElevenLabs text to speech canary.” Do not persist the audio.

On failure, disable ElevenLabs admission, remove the runtime copy, restore the
previous controller artifact, and confirm non-AI health. There is no Qwen or
Server B rollback. Server C audio playback and VICIdial/STT integration require
separate governed releases and are explicitly not activated here.
