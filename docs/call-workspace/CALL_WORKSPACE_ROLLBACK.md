# Call Workspace Rollback

Rollback is release-based and preserves evidence.

1. Disable TEST_SYN event delivery and screen-pop flags. Keep all live communication flags false.
2. Stop the candidate Agent Desktop, gateway and middleware workloads; redeploy the previously signed immutable digests.
3. If the Odoo upgrade caused a defect, stop Odoo workers, restore the validated pre-upgrade database and matching filestore together, then deploy the previous authoritative addon SHA. Do not manually drop new columns or audit tables.
4. Revoke candidate realtime sessions and confirm active sockets, calls and Asterisk channels are zero.
5. Validate internal TLS, previous health checks and zero customer impact.
6. Preserve failed candidate logs, correlation IDs, database backup checksums, SBOM/provenance and rollback timestamps. Do not preserve secrets in incident artifacts.

Forward-fix is preferred for isolated non-destructive UI defects. Database rollback is required when schema/data integrity or tenant isolation cannot be proven.
