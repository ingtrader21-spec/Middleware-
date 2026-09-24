# Codestra SRL Organizational Signing Policy

Status: Draft awaiting repository-environment configuration and human approval.

## Scope and purpose

- Organization: Codestra SRL
- Purpose: software supply-chain signatures and VEX attestations.
- Mechanism: Sigstore keyless signing through GitHub Actions OIDC.
- Approved repository: `Codestra-SRL/codestra-middleware`.
- Approved workflow:
  `.github/workflows/sign-rc3p-openvex.yml`.
- Approved ref: `refs/heads/main`.
- Protected GitHub environment: `security-release`.
- Required human approvers: at least one named security owner who is not the
  workflow initiator, where GitHub plan capabilities support preventing
  self-review.

The required signer certificate identity is:

```text
https://github.com/Codestra-SRL/codestra-middleware/.github/workflows/sign-rc3p-openvex.yml@refs/heads/main
```

The required certificate issuer is:

```text
https://token.actions.githubusercontent.com
```

## Permitted and prohibited artifacts

Permitted artifacts are reviewed VEX documents, SBOM attestations, provenance
attestations, and release checksums bound to immutable artifact or OCI digests.

Prohibited artifacts include mutable image tags without digest binding,
customer data, credentials, private keys, database exports, raw recordings,
unreviewed binaries, and any assertion that is not supported by retained
evidence.

## Identity, transparency, and verification

Signing must use GitHub Actions OIDC through the exact repository, workflow,
and ref above. No persistent signing key or repository signing secret is
allowed. Every signature must produce a Sigstore bundle containing certificate
and Rekor transparency evidence. Verification must check:

1. The signed payload checksum.
2. The exact certificate identity.
3. The exact OIDC issuer.
4. Transparency-log inclusion.
5. The immutable product digest referenced by the VEX.
6. The approved security-owner decision and its expiration.

Raw unsigned material must be retained alongside the signature bundle.

## Audit and retention

GitHub workflow logs, environment approvals, unsigned payloads, Sigstore
bundles, verification output, and associated evidence checksums must be
retained for at least seven years or longer when required by Codestra SRL
policy. GitHub organization audit logs must be retained according to the
organization's approved audit-retention configuration.

## Separation of duties

- Build maintainers create candidate images and evidence.
- Security reviewers approve or reject the VEX decision.
- The protected environment authorizes the signing job.
- An independent reviewer verifies the resulting bundle.
- The workflow does not create release tags or deploy production.

The named security owner and remediation owner remain human-controlled fields
and are not assigned by this policy draft.

## Incident response and revocation

Revoke or suspend signer trust when repository ownership, workflow path,
approved ref, OIDC issuer, environment rules, or organization control changes;
when an action pin or cosign checksum is compromised; when evidence checksums
fail; or when unauthorized workflow execution is detected.

On workflow compromise:

1. Disable the `security-release` environment.
2. Remove affected artifacts from release eligibility.
3. Preserve GitHub and Rekor audit evidence.
4. Rotate or revoke affected repository credentials even though signing is
   keyless.
5. Review all signatures issued from the affected workflow identity.
6. Restore only after independent security review.

Identity revocation is performed by disabling the workflow/environment,
changing the approved identity policy, and recording revoked bundle identities
in the release-verification policy.

## Review

This policy requires annual review and immediate review after repository
transfer, workflow change, signer-policy change, OIDC/Sigstore incident, or
security-owner change. Remediation ownership is awaiting assignment by Codestra
SRL. Draft approval does not imply that the GitHub environment currently
exists or is correctly protected.
