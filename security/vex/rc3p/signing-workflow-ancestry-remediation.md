# RC3P Signing Workflow Ancestry Remediation

## Failed run

- Failed workflow run: `30228382916`
- Failure phase: approved source ancestry verification, before signing
- Approved source commit: `419650868659efa3589dcda29c1615c27b71f493`
- Prior main commit: `fca346caa0092d92406b89736cf2cbfacbf90824`

The failed run did not create a VEX signature or release tag and did not perform
deployment.

## Workflow integrity

- Old workflow SHA-256:
  `055b5ac14017dba6d0dbf6849c293fb6c7653ab49809ee3610dbec0c93313a50`
- Repaired workflow SHA-256:
  `c8c36ce2b012c43ebe54ad943b4a096ad980937756177533ac69df626f97fcdc`

The ancestry gate requires `fetch-depth: 0` because the default shallow
checkout did not contain the approved source commit object. Without the object,
Git could not prove that the approved source commit is an ancestor of the
workflow revision. The repaired checkout retrieves full history and the gate
now explicitly verifies that the repository is not shallow, that the approved
commit object exists, and that it is an ancestor of `GITHUB_SHA`.

## Review gate

Signing, release tagging, migration, and production deployment remain blocked
until this workflow repair and its updated integrity record receive independent
review and are merged into `main`.
