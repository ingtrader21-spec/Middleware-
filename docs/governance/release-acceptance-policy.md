# Release acceptance policy

Only a mapped Release Owner may authorize an exact source for release. Release
authorization must bind the repository, exact source commit, applicable PR and
merge commit, exact CI runs, immutable image digest, security evidence
checksums, and decision timestamp.

Only a mapped Security Owner may issue the corresponding security decision.
When the same account holds both roles, two clearly separated authenticated
decisions are required.

Source changes require independent exact-head review by an approved reviewer,
including `kazan555` where repository policy names that reviewer. A stale
review, review request, comment, repository-admin status, or approval against a
different commit is insufficient.

Unknown identities, incomplete bindings, stale evidence, unresolved blocking
threads, failed checks, and feature-state drift fail closed.
