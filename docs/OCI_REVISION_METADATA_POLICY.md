# OCI revision metadata policy

Production Middleware images must encode distinct source identities:

- `org.opencontainers.image.revision`: exact 40-character protected Git commit
- `org.opencontainers.image.source`: protected repository URL
- `org.opencontainers.image.version`: immutable release identifier
- `codestra.source_tree.sha256`: optional 64-character source-tree checksum

A source-tree SHA-256 must never be stored in the OCI revision field or treated
as a Git commit.

The historical webhook image used source-tree digest
`4a3ac0b57d37325f27e786a2bdff94f73dc6b60d025521571899bf94c7934edb`
as its revision. Its documented historical base was
`51416422eaaa959c8c7223ad1434287597eb8007`, but exact reproducibility from that
commit plus documented generated files was not proven. This policy therefore
does not relabel the historical artifact or fabricate an exact Git SHA.

Protected `main` is the clean successor implementation for future event-gateway
and external-webhook-worker builds. Any such build must pass normal protected
CI and produce its own exact commit, digest, SBOM, provenance, and vulnerability
evidence. This source-governance change does not authorize a production build or
deployment.
