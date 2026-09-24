# Gateway schema-1 correlation safety RC1

This package binds source, image, SBOM, scan reconciliation, security decision,
and OpenVEX to:

`docker.io/codestra1980/telephony-event-gateway@sha256:dc91007162f64410eb97b163502bad013a2adb670a28d0655572326da18f42fb`

Signing is permitted only after this exact PR head is independently approved
and merged to `main`. The workflow signs an image identity payload and the
exact OpenVEX document using GitHub OIDC, then independently verifies both
bundles against the workflow identity and issuer.
