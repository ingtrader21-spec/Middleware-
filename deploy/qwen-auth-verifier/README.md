# Qwen read-only authentication verifier candidate

This package prepares one private, read-only authentication probe. It is not a deployment authorization.

The route accepts only `POST /internal/api/v1/ai/auth/verify`. Caddy requires the approved client CA, source `10.40.0.4`, and overwrites the internal client-certificate header. The dedicated ASGI process exposes no command, callback, workflow, database, or downstream route. Durable replay markers are the verifier's only writable state.

The HMAC secret is mounted from the middleware-controlled file specified by `secret-mount-manifest-v1.json`; its value must never be copied into Compose environment, an image layer, source, logs, or evidence.
