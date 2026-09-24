# Emergency rollback authority

The mapped Rollback Approver may authorize immediate restoration of the last
verified fail-closed application and database state when a mandatory release
gate or runtime invariant fails.

Emergency rollback authority includes stopping delivery, restoring the prior
exact image and configuration, restoring a verified backup when required, and
maintaining production locks through verification.

It does not authorize destructive improvised SQL, deletion of evidence,
activation of another capability, or expansion of production scope. The
decision must identify the incident, exact affected release, rollback target,
timestamp, verification evidence, and final feature-gate state.
