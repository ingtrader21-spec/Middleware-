# Redis runtime design

Redis is an availability optimization, never the system of record. Namespaces
are `codestra:<environment>:<owner>:<type>:...`; environment is limited to
test, staging, or production and key components reject delimiter injection.

| Key type | TTL | Purpose | Owner |
|---|---:|---|---|
| lock | 60s | distributed lease acceleration | middleware |
| replay | 600s | replay cache over durable nonce record | middleware |
| rate | 60s | rate window | middleware |
| token | 300s | service-token cache | middleware |
| dedupe | 3600s | duplicate acceleration | middleware |
| execution | 900s | temporary n8n execution hint | n8n |
| circuit | 300s | transient breaker state | middleware |

Every write uses `SET NX EX`. Redis errors degrade to PostgreSQL-backed
processing. Durable results, audit, call history, business records, financial
records, dead letters, and permanent workflow state never live exclusively in
Redis.

Staging Redis 7.4.5 is queue-private, has no published port, requires the
`n8n-service` ACL identity, denies administrative CONFIG/ACL commands to that
identity, uses AOF plus snapshots, and is isolated from production namespaces.
