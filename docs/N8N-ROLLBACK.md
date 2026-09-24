# n8n runtime rollback

Disable `N8N_RUNTIME_ENABLED` and `REDIS_RUNTIME_ENABLED` first. Stop the new
dispatcher while leaving PostgreSQL and existing n8n queue services intact.
Revert the staging middleware image to its recorded digest. Do not delete
execution/result rows; they are audit and recovery evidence.

If schema rollback is authorized and no runtime records must be retained,
downgrade from `0034_n8n_redis_runtime` to `0033_tts_job_runtime`. Otherwise
leave the additive tables in place while the feature stays disabled. Redis
keys expire automatically and are not required for recovery. Never roll back by
flushing shared Redis or deleting n8n/PostgreSQL volumes.
