# Redis key model

Redis leases, replay guards, and rate limits will use `codestra:middleware:v1:` namespaced keys with hashed subjects and explicit TTLs. Redis is not required for ingestion acceptance in this Phase 1 implementation; future rate limiting and replay protection must fail closed when Redis is unavailable.
