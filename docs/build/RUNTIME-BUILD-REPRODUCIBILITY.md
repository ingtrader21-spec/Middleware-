# Runtime build reproducibility evidence

This evidence records the local clean-checkout-equivalent build exercise for
the build-system change. Image IDs are local BuildKit results, not published
release digests and not a claim of byte-for-byte deterministic construction.
CI rebuilds the final PR SHA and publishes SBOM artifacts.

The production runtime is rebuilt from the immutable Python slim Bookworm base with
exactly `libpcre2-8-0=10.42-1+deb12u1` installed from Debian security repositories.
This replaces the vulnerable distroless runtime and fixes CVE-2026-86145 and
CVE-2026-89161 without an uncontrolled distribution upgrade. The supply-chain
validator rejects removal or loosening of this exact package pin.

```text
SOURCE_SHA=844d13c7ba808653a7d982c63353bc67cdc9adef (frozen main used for local candidate labels)
BASE_IMAGE_DIGESTS=python builder sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1; test sha256:62eafe52c91cad83c2c74e630bfde917da8c253673e695665d454def84fc9a13; final sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1
OPENSSL_VERSION=3.0.20 (test image only)
PYTHON_VERSION=3.13.15 builder/test; 3.13.15 slim Bookworm final
LOCKFILE_HASH=runtime 114b8f10bb38ea322e9989db460d3c4f7539ab89d9d0656e4f7efc4572eb4447; test 81ada0e0c804a7cb2e32772088292b563fa5b51c9371f7c7cc0132ef25a006c8; connector db28131adce3fb29e0b3ffb77ee427160dd9973f5d3320288d8b354971f01595
DOCKERFILE_HASH=7b31bc40fb99a8314c44d2e24589fe8958ce07e62a3148e0db4720fd8eb38b6a

API_IMAGE_DIGEST=sha256:7812b5407093e2ad1d97f550dbe2b48d76294b7b3fe5bc2119e7ce3d999ac475 (local image ID)
WORKER_IMAGE_DIGEST=sha256:9dafeb34208f0f3da4264625dc19c8ec19bd9ae6db8bcc47ec7dd361f4d1c88c (local image ID)
CONNECTOR_IMAGE_DIGEST=sha256:298502b187fa889495c76a345587e41c110b960dd9a31a298689af2523fb2df9 (local image ID)

TEST_TARGET=Dockerfile.runtime:test
TEST_RESULT=111 passed, 23 skipped, 11 subtests passed

SCANNER_RESULT=Trivy: API and connector each CRITICAL=0 HIGH=17 MEDIUM=62 LOW=51 UNKNOWN=9; fixable CRITICAL/HIGH=0; repository policy PASS
SBOM_RESULT=SPDX JSON generated
```

SBOM checksums:

- Middleware runtime: `sha256:ab9c8f31f90ae90edac7aa7ddf0e9df4d7654a971584019a340e3a86abfcbbf0`
- Connector runtime: `sha256:3b00bbb8af39501a759be5697220390523d23338ac29a231f9876147f767a8f0`

The 23 skipped tests are explicit infrastructure gates: 2 NATS JetStream, 19
PostgreSQL/Redis (including lease and synthetic acceptance coverage), 1 combined
synthetic acceptance, and 1 Temporal test-server case. They are `SKIPPED`, not
PASS; the existing dedicated CI jobs execute those suites with disposable
dependencies.

## OpenSSL failure evidence

`docker build --target test` against the frozen capture failed in
`RUN apk add --no-cache openssl=3.5.7-r0`: the repository selected
`openssl-3.5.8-r0`, whose required `libcrypto3` and `libssl3` versions conflict
with 3.5.7-r0. The canonical test target now consumes the test base's immutable
OpenSSL 3.0.20 package set and asserts that version during every CI build.

## Runtime acceptance

The API started on `--network none` with synthetic test configuration,
`--read-only`, a bounded `/tmp` tmpfs, all capabilities dropped, and
`no-new-privileges`. `/health` returned 200. `/ready` returned the expected 503
because JWKS was unavailable on the isolated network. `/version` returned the
source SHA, release version, and build time. The process ran as UID/GID 65532.

The connector image independently imported both installed distributions without
`PYTHONPATH` pointing at the monorepo root. It intentionally fails closed without
its database, identity, cursor-HMAC, encryption-key, and writable encrypted-body
volume configuration.

## Build context and secrets

`.dockerignore` excludes Git data, environment files, secrets, private-key and
certificate material, caches, virtual environments, logs, dumps, runtime
evidence, and `server-baseline`. `scripts/verify_container_image.sh` verifies
numeric non-root execution, all four OCI labels, and absence of a synthetic
secret marker from image history, configuration, and serialized layers.

## Compose

Canonical `main` contains no Compose file, so `docker compose config` is
`NOT_APPLICABLE`, not PASS. The future consolidation PR must consume these named
targets and apply the documented read-only/capability constraints.
