# WebRTC rollback package

The active deployment is not changed by candidate preparation. The rollback target is the last approved immutable digest recorded in deployment inventory. Restore its matching configuration and policy backup, leave the production gate false, then validate health, canonical issuer, WSS fail-closed behavior, policy availability, and running digest. If any validation fails, keep the gate false and isolate the candidate.

Rollback command template: `deploy-approved-digest --slot current --digest "$CURRENT_APPROVED_DIGEST" --config "$ROLLBACK_CONFIG" --production-gate=false`. Values must come from signed deployment inventory, never from chat or an untrusted environment.
