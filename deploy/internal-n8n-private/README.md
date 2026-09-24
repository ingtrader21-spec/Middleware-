# Private n8n TLS proxy

This dedicated Caddy service replaces only the retired proxy's private n8n
hostname. It publishes no host ports, accepts callers from the internal
integration network, and exposes only attestation, health/readiness, and the
governed event webhook. Production workflows and external delivery remain
disabled independently of this transport.
