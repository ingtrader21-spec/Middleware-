# RC3P Keyless Signer Administrator Setup

The workflow is configuration-only until a repository administrator completes
this checklist and a real security owner approves the RC3P decision.

## GitHub administrator steps

1. Open `Codestra-SRL/codestra-middleware` → **Settings** → **Environments**.
2. Create the environment `security-release`.
3. Add the named human security owner as a required reviewer. Do not use a
   placeholder, bot, or workflow author.
4. Enable **Prevent self-review** when supported by the GitHub plan.
5. Limit environment deployment branches to `main` only. Do not permit all
   branches or tags.
6. Under **Branches**, protect `main`; require pull-request review and passing
   status checks, and prohibit force pushes and deletion.
7. Add CODEOWNERS protection for
   `.github/workflows/sign-rc3p-openvex.yml`,
   `docs/security/organizational-signing-policy.md`, and
   `security/vex/rc3p/`.
8. Require reviewed pull requests for workflow changes and prevent direct
   workflow modification without security review.
9. Confirm organization audit-log retention and export meet the seven-year
   evidence requirement.
10. Confirm GitHub Actions is enabled and OIDC token issuance is permitted for
    this repository. Do not create a signing secret or upload a private key.
11. Confirm the workflow retains only:
    - `contents: read`
    - `id-token: write`
12. Record the expected certificate identity exactly:

    ```text
    https://github.com/Codestra-SRL/codestra-middleware/.github/workflows/sign-rc3p-openvex.yml@refs/heads/main
    ```

13. Record the expected certificate issuer exactly:

    ```text
    https://token.actions.githubusercontent.com
    ```

14. Review and complete the human security-owner decision outside automation.
15. Dispatch the workflow only after environment protection and approval are
    independently verified.

Referencing `security-release` in workflow YAML does not prove that the
environment exists or has required reviewers.
