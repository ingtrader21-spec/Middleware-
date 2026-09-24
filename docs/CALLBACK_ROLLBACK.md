# Callback Rollback

Disable callback API routing and scheduler workers first. Preserve callback and event tables. Roll back application images to the recorded digest. Do not downgrade the database while callback data exists; the Alembic downgrade is destructive and is reserved for an unused isolated clone. Re-enable only after schema/application compatibility and TEST_SYN reconciliation pass.
