# Hootsuite

The Phase 1 adapter implements the provider contract and accurate health/capability reporting but has no outbound implementation. Without credentials it reports `NOT_CONFIGURED`; with configuration but before implementation/activation it reports `DISABLED`. It never claims success.

Phase 3 should add OAuth token lifecycle, account discovery, request mappings, native webhook verification and the same normalized contract without changing Social API clients.
