# ADR: Runtime OS package pinning

Status: accepted for `fix/runtime-docker-reproducibility`.

## Context

The frozen server capture at `85b7898456abd4bdd0928b80ea925cafd8ad0f4c`
contains an Alpine test stage with `apk add --no-cache openssl=3.5.7-r0`.
The mTLS tests invoke the OpenSSL CLI to create and verify synthetic
certificates. OpenSSL is not an application runtime dependency. The associated
security note says that test tooling and the OpenSSL CLI were intentionally
excluded from the production image, and that the production base was selected
to remediate inherited OS findings.

WHY_THE_PIN_EXISTED=The exact APK revision attempted to make the synthetic mTLS test tool and its security state repeatable. It was test-only and was introduced with the captured evidence history; no earlier explanatory commit exists in the sanitized branch.

WHY_IT_BROKE=Alpine's repository and the pinned base moved as a set to OpenSSL 3.5.8-r0 while the Dockerfile demanded only the 3.5.7-r0 package. APK correctly rejected the mixed libcrypto/libssl package set.

## Decision

NEW_POLICY=Pin immutable builder, test, and final base-image digests. Do not upgrade OS packages during the build. Production final images use the pinned distroless base and install no OS packages. The test target uses a pinned Debian base whose immutable filesystem already supplies OpenSSL 3.0.20; it does not install or independently pin an OpenSSL package revision.

Python dependencies remain exact and hash-locked. A change to any base digest,
lock file, Python version, or expected test OpenSSL version is a reviewed build
policy change. CI builds the real `test` target without cache and asserts the
OpenSSL version, so the captured regression cannot silently return.

ROLLBACK_POLICY=Revert the complete base-digest and policy change together. Never restore a package-only OpenSSL pin against a mutable repository. If the selected base fails policy, select and scan another immutable base digest, regenerate SBOM evidence, and rerun every supported target.

## Security consequences

The API, worker, and connector final stages contain no shell or package manager,
run as numeric UID/GID 65532, and carry only their hash-locked Python packages
and required source/configuration. The test image is not publishable as a
production runtime.
