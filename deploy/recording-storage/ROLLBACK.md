# Rollback

Stop application traffic, preserve the locked versioned bucket, revoke scoped
application credentials, and restore the previous pinned source revision.
Rollback must never delete buckets, versions, retention records, or legal holds.
Keep `RETENTION_DELETE_ENABLED=false`; database schema downgrade requires a
separate approved preservation/export plan.
