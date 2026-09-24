# Bounded Canary Gateway RC1 Security Binding

This directory binds the reviewed bounded-canary gateway source, immutable
Docker Hub digest, SBOMs, scanner evidence, fixed-backport decision, and
OpenVEX statements.

The signing workflow runs only from `main`, generates and signs the canonical
Cosign image-identity payload, signs the exact OpenVEX document, and
independently verifies both Sigstore bundles. The image payload is checked for
the exact repository and manifest digest before and after verification. The
workflow does not deploy the image or mutate production.
