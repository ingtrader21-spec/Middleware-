# Portfolio-wide production branch ruleset

This package applies one repository ruleset to every active repository owned by
`appolon1908-hue`.

## Exact policy

The ruleset is named `AI automated production branch gates` and targets only
`refs/heads/production`.

It enforces:

- pull-request changes;
- squash-only merges;
- zero mandatory approving reviews;
- no code-owner or last-push approval requirement;
- resolved review conversations;
- linear history;
- blocked force pushes;
- blocked branch deletion;
- no bypass actors.

It does not create `production`, move any branch, change default-branch rules,
change status checks, edit environments or secrets, deploy software, or activate
runtime effects.

## Authority and token

The owner-only workflow uses the existing secret name:

`CODESTRA_REPOSITORY_ADMIN_TOKEN`

The secret must be a short-lived fine-grained personal access token owned by
`appolon1908-hue`, granted access to every repository in scope, with repository
**Administration: Read and write**. Metadata read access is implicit.

Never place the token in a commit, issue, pull request, workflow input, log, or
chat. Rotate or remove it after the verified rollout.

## Fail-closed behavior

Before the first mutation, the applier:

1. enumerates all repositories visible to the authenticated owner token;
2. filters only active repositories owned by `appolon1908-hue`;
3. proves every repository in the committed 56-repository minimum inventory is
   visible;
4. proves ruleset administration can be read for every selected repository.

If any known repository is absent or any preflight request fails, no repository
is mutated. New repositories discovered beyond the committed minimum are also
included automatically.

The apply is idempotent. It creates the named ruleset when absent and updates it
when present. Existing differently named rulesets are left untouched.

## Execution

The first rollout runs automatically after the protected squash merge of the
portfolio-governance PR into `main`. The push trigger is path-scoped and also
requires the merge commit message to identify this exact portfolio ruleset
change.

A fail-closed retry remains available. The workflow is locked to repository
owner ID `275410064`, issue `#116`, and this exact owner comment:

```text
/apply-portfolio-production-ruleset v1
```

After applying, the workflow verifies the live ruleset on every repository and
posts a non-secret Markdown summary to issue #116. JSON and Markdown evidence
are also retained as a workflow artifact.
