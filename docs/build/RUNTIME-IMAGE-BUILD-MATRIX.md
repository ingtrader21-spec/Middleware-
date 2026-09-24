# Runtime image build matrix

The repository has one supported build definition, `Dockerfile.runtime`. CI
selects explicit named targets. There is no separate migration or specialized
adapter Dockerfile: the migration runner is packaged in the API/worker runtime,
and no specialized adapter image is canonical yet.

## Immutable bases

| Purpose | Human-readable tag | Immutable digest | Package policy |
|---|---|---|---|
| Python dependency builder | `python:3.14.7-slim-bookworm` | `sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56` | No OS package installation or upgrade |
| Test | `python:3.14.7-bookworm` | `sha256:4121f1893084fd19c71df52b7a48565d47f5bf36173d2c2ce8bca626512ef3db` | Uses base-provided OpenSSL 3.0.20; no OS package installation or upgrade |
| Production final | `python:3.14.7-slim-bookworm` | `sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56` | Rebuilt intermediate installs only `libpcre2-8-0=10.42-1+deb12u1`; runtime stages inherit that fixed package set |

## Supported targets

| IMAGE_ROLE | DOCKERFILE | TARGET | BASE_IMAGE | BASE_DIGEST | PACKAGE_MANAGER | OS_PACKAGES | PYTHON_DEPENDENCIES | RUN_USER | ENTRYPOINT/CMD | HEALTHCHECK | OCI_SOURCE_LABEL | OCI_REVISION_LABEL | OCI_VERSION_LABEL | BUILD_STATUS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Middleware API | `Dockerfile.runtime` | `runtime` | official Python 3.14.7 slim Bookworm | `sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56` | APT only in patched base | `libpcre2-8-0=10.42-1+deb12u1` | `requirements-runtime.txt`, exact hashes | `65532:65532` | explicit `/usr/local/bin/python3.14` entrypoint; `-m uvicorn app.main:create_app --factory` | `/health` liveness; `/ready` is separate readiness | build arg | build arg | build arg | PASS locally |
| Outbox/Temporal worker family (also `scheduler`, `reconciler` stages: same image, different command) | `Dockerfile.runtime` | `worker` | official Python 3.14.7 slim Bookworm | same final digest | APT only in patched base | `libpcre2-8-0=10.42-1+deb12u1` | `requirements-runtime.txt`, exact hashes | `65532:65532` | explicit `/usr/local/bin/python3.14` entrypoint; default `-m workers.run_outbox`; deployments may select the packaged Temporal module | Process liveness; readiness is worker/dependency telemetry, not an HTTP liveness probe | build arg | build arg | build arg | PASS locally |
| Connector Runtime | `Dockerfile.runtime` | `connector-runtime` | official Python 3.14.7 slim Bookworm | same final digest | APT only in patched base | `libpcre2-8-0=10.42-1+deb12u1` | `requirements-connector-runtime.txt`, exact hashes; installed connector SDK and service wheels | `65532:65532` | explicit `/usr/local/bin/python3.14` entrypoint; `-m uvicorn codestra_connector_runtime.main:app` | `/healthz` liveness; `/readyz` readiness | build arg | build arg | build arg | PASS independently |
| Test image | `Dockerfile.runtime` | `test` | Python 3.14.7 Bookworm | `sha256:4121f1893084fd19c71df52b7a48565d47f5bf36173d2c2ce8bca626512ef3db` | None invoked | Base-provided OpenSSL 3.0.20 | `requirements-test.txt`, exact hashes | `10001:10001` | `pytest -q` | Not long-running | build arg | build arg | build arg | PASS; 111 passed, 23 skipped |
| Migration invocation | `Dockerfile.runtime` | `runtime` | same as API | same final digest | APT only in patched base | `libpcre2-8-0=10.42-1+deb12u1` | runtime lock | `65532:65532` | override inherited entrypoint arguments to run `/app/scripts/migrate_runtime.py` | Job exit status | build arg | build arg | build arg | Packaged; no separate image |

All Codestra-built targets accept `SOURCE_REPOSITORY`, `SOURCE_REVISION`,
`SOURCE_VERSION`, and `BUILD_DATE`. API and worker expose immutable metadata as
`APP_SOURCE_SHA`, `APP_VERSION`, and `BUILD_TIME`; the connector exposes
`CONNECTOR_RUNTIME_RELEASE_SHA`.

## Deployment security contract

Production composition must set `read_only: true`, `cap_drop: [ALL]`, and
`security_opt: [no-new-privileges:true]`. `/tmp` is an explicit bounded tmpfs.
The connector's encrypted webhook body directory must be an explicitly owned
ephemeral or dedicated volume; application source remains read-only. No
canonical target requires a Linux capability.
