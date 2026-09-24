# RC3P OpenVEX Signing Input

This directory contains only the reviewed, unsigned OpenVEX input and its
checksum. It contains no signing credentials or mutable scanner output.

The document is bound to:

```text
codestra/middleware@sha256:d48b4f2a6d1804b0fce14fdeaccfcdb976171c32c0c5704efadb8a6651c62ebe
```

The expected document SHA-256 is:

```text
eed2f59523e87385abe2743c438ddb45d00c37bf7926923791ba8da245ae5a2e
```

Verify locally:

```bash
cd security/vex/rc3p
sha256sum -c openvex.json.sha256
```

The GitHub workflow independently repeats this check before requesting an OIDC
identity. A valid signature must match the exact workflow identity and GitHub
OIDC issuer documented in the organizational signing policy.
