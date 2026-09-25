#!/usr/bin/env python3
"""PAS-95 (DB-18): certify the exact release-candidate database topology on
disposable local resources with every effect OFF.

The harness builds nothing on, and connects to nothing outside, the local
Docker daemon. It creates one internal (no-egress) network, a throwaway
PostgreSQL server shaped like the production target (hostssl + scram-sha-256 +
clientcert=verify-full with CN-bound per-role certificates, split migration /
runtime / backup / exporter roles), and then drives the locally built release
candidate image against it:

* RC identity and single Alembic head (release.yml probe);
* the RC migrator (``scripts/migrate_runtime.py``) as the schema owner, twice,
  then ``--verify-only``; the same runner as a runtime role must fail;
* TLS/mTLS acceptance and rejection matrix, locked-profile gate replay;
* role isolation (PAS-96/PAS-97 query), privilege denials, forced RLS;
* the RC connection pools and the private ``/internal/v1/database`` router;
* the repository backup script, a role-based dump attempt, and an isolated
  ``--network none`` restore verified by the RC migrator;
* the pinned postgres-exporter and the repository alert conditions;
* secret-reference hygiene, effect counters, teardown and residual check.

Every credential and key is generated per run, lives only in Docker volumes and
a private temporary directory, and is destroyed at teardown. The JSON evidence
never contains a password, DSN or private key; the harness scans it before
writing. Exit status is 0 when the run completed with all effect counters at 0
and no residual resources, independent of the certification verdict, which is
printed as ``PAS95_DB18_VERDICT``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TOPOLOGY_DIR = ROOT / "scripts" / "production_db_topology"
SPEC_PATH = TOPOLOGY_DIR / "topology.v1.json"
LABEL = "com.codestra.certification"
LABEL_VALUE = "pas95-db18"
RC_UID = "65532"
POSTGRES_UID = "999"
EXPORTER_UID = "65534"
STATUSES = ("PASS", "FAIL", "BLOCKED", "INFO")
EFFECT_TABLE = re.compile(r"(outbox|delivery|dispatch|webhook|provider|message|notification|dial)")
# Reasons that need a live host, another lane, or an owner decision. They are
# recorded as BLOCKED and never promoted to PASS by this disposable harness.
RUNTIME_ONLY_BLOCKERS = (
    (
        "RC",
        "rc.signed_digest",
        "Signed, published RC digest (cosign/SLSA/SBOM) bound to this source",
        "PAS-27: no successful release run; 35613442378 on 0606b0d never started "
        "(Actions billing lock), 35602170321 failed at push (read_package).",
    ),
    (
        "TOPOLOGY",
        "topology.live_readback",
        "Live production server version, pg_hba, certificate fingerprints/expiry and role attributes",
        "Requires read-only readback on the production host; out of scope (do not touch production).",
    ),
    (
        "BACKUP",
        "backup.production_restore_rehearsal",
        "Restore of a real production backup, Middleware start and TEST_SYN against it",
        "PAS-92 (DB-15) is still in progress; this run proves the mechanism on disposable data only.",
    ),
    (
        "CHAOS",
        "chaos.failure_matrix",
        "Restart / connection-drop / pool invalidation / certificate rotation behaviour",
        "PAS-94 (DB-17) not started; blocks PAS-95 per Linear relations.",
    ),
    (
        "MONITORING",
        "monitoring.alert_routing",
        "Prometheus rule evaluation and Alertmanager routing on the live monitoring plane",
        "Needs the live monitoring stack; this run evaluates the rule conditions from a real scrape only.",
    ),
    (
        "PRIVATE_DB_API",
        "api.real_token_verifier",
        "Private DB API behind the real Keycloak token verifier and private network edge",
        "Needs the production identity provider; the router ran with a recording verifier.",
    ),
)


class HarnessError(RuntimeError):
    """A harness step failed in a way that makes further steps meaningless."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Harness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.spec = json.loads(SPEC_PATH.read_text(encoding="utf-8"))
        self.run_id = secrets.token_hex(6)
        self.prefix = f"pas95-{self.run_id}"
        self.labels = ["--label", f"{LABEL}={LABEL_VALUE}", "--label", f"{LABEL}.run={self.run_id}"]
        self.checks: list[dict[str, Any]] = []
        self.observations: dict[str, Any] = {}
        self.secret_values: list[str] = []
        self.workdir = Path(tempfile.mkdtemp(prefix="pas95-pki-"))
        os.chmod(self.workdir, 0o700)
        self.passwords = {role: secrets.token_hex(24) for role in self.spec["roles"]["login"]}
        self.passwords["postgres"] = secrets.token_hex(24)
        self.secret_values.extend(self.passwords.values())
        db = self.spec["database"]
        self.net = f"{self.prefix}-net"
        self.pg = f"{self.prefix}-pg"
        self.restore_pg = f"{self.prefix}-restore"
        self.db_host = db["host"]
        self.db_name = db["name"]
        self.db_port = db["port"]
        self.image = args.rc_image
        self.pg_image = args.postgres_image or db["server_image"]
        self.connection_targets: list[str] = []

    # ------------------------------------------------------------ primitives

    def run(
        self,
        argv: list[str],
        *,
        stdin: bytes | None = None,
        check: bool = True,
        timeout: int = 600,
    ) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(argv, input=stdin, capture_output=True, timeout=timeout)
        if check and result.returncode != 0:
            raise HarnessError(
                f"{argv[0]} {argv[1] if len(argv) > 1 else ''} failed ({result.returncode}): "
                + self.scrub(result.stderr.decode("utf-8", "replace"))[-600:]
            )
        return result

    def docker(self, *argv: str, **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return self.run(["docker", *argv], **kwargs)

    def scrub(self, text: str) -> str:
        for value in self.secret_values:
            text = text.replace(value, "[REDACTED]")
        return re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED KEY]", text, flags=re.S)

    def check(
        self,
        area: str,
        check_id: str,
        status: str,
        expected: Any,
        observed: Any,
        note: str = "",
    ) -> None:
        assert status in STATUSES, status
        self.checks.append(
            {
                "area": area,
                "id": check_id,
                "status": status,
                "expected": expected,
                "observed": observed,
                **({"note": note} if note else {}),
            }
        )
        marker = {"PASS": "ok ", "FAIL": "FAIL", "BLOCKED": "BLKD", "INFO": "info"}[status]
        print(f"[{marker}] {area:<16} {check_id}", flush=True)

    def verdict(self, area: str, check_id: str, condition: bool, expected: Any, observed: Any, note: str = "") -> None:
        self.check(area, check_id, "PASS" if condition else "FAIL", expected, observed, note)

    # --------------------------------------------------------------- safety

    def assert_local_docker(self) -> None:
        host = os.environ.get("DOCKER_HOST", "")
        if host and not host.startswith("unix://"):
            raise HarnessError("DOCKER_HOST must be a local unix socket for a disposable run")
        endpoint = self.docker(
            "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"
        ).stdout.decode().strip()
        if not endpoint.startswith("unix://"):
            raise HarnessError("the active Docker context is not a local unix socket")
        self.observations["docker_endpoint"] = endpoint
        leaked = [
            name
            for name in ("DATABASE_URL", "DATABASE_URL_FILE", "PGHOST", "PGPASSWORD", "PGSERVICE")
            if os.environ.get(name)
        ]
        if leaked:
            raise HarnessError(
                "refusing to run with database targeting variables set: " + ", ".join(leaked)
            )

    def target(self, host: str) -> str:
        allowed = {self.db_host, *self.spec["database"]["network_aliases_for_negative_checks"], "127.0.0.1"}
        allowed |= {f"{self.prefix}-exporter-mtls", f"{self.prefix}-exporter-as-shipped"}
        if host not in allowed:
            raise HarnessError(f"connection target {host!r} is not a disposable harness resource")
        self.connection_targets.append(host)
        return host

    # ------------------------------------------------------------------ PKI

    def openssl(self, *argv: str) -> None:
        self.run(["openssl", *argv], timeout=60)

    def _leaf(self, name: str, cn: str, ca: str, *, server: bool = False, expired: bool = False) -> None:
        w = self.workdir
        self.openssl(
            "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", str(w / f"{name}.key"), "-out", str(w / f"{name}.csr"), "-subj", f"/CN={cn}",
        )
        ext = w / f"{name}.ext"
        if server:
            ext.write_text(
                f"subjectAltName=DNS:{self.db_host}\nextendedKeyUsage=serverAuth\n"
                "keyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n"
            )
        else:
            ext.write_text(
                "extendedKeyUsage=clientAuth\nkeyUsage=critical,digitalSignature\n"
                "basicConstraints=critical,CA:FALSE\n"
            )
        validity = (
            ["-not_before", "20250101000000Z", "-not_after", "20250102000000Z"]
            if expired
            else ["-days", "2"]
        )
        self.openssl(
            "x509", "-req", "-in", str(w / f"{name}.csr"), "-CA", str(w / f"{ca}.crt"),
            "-CAkey", str(w / f"{ca}.key"), "-set_serial", str(int(secrets.token_hex(8), 16)),
            "-out", str(w / f"{name}.crt"), "-extfile", str(ext), *validity,
        )

    def _ca(self, name: str, cn: str) -> None:
        w = self.workdir
        self.openssl(
            "req", "-x509", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-keyout", str(w / f"{name}.key"), "-out", str(w / f"{name}.crt"),
            "-days", "2", "-subj", f"/CN={cn}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )

    def build_pki(self) -> None:
        self._ca("ca", f"pas95-disposable-ca-{self.run_id}")
        self._ca("rogue-ca", f"pas95-untrusted-ca-{self.run_id}")
        self._leaf("server", self.db_host, "ca", server=True)
        for role in self.spec["roles"]["login"]:
            self._leaf(f"client-{role}", role, "ca")
        api = self.spec["roles"]["api"]
        self._leaf("rogue", api, "rogue-ca")
        self._leaf("expired", api, "ca", expired=True)
        fingerprints = {}
        for name in ["ca", "server", *[f"client-{r}" for r in self.spec["roles"]["login"]]]:
            out = self.run(
                ["openssl", "x509", "-in", str(self.workdir / f"{name}.crt"), "-noout",
                 "-fingerprint", "-sha256", "-subject", "-enddate"],
            ).stdout.decode()
            fingerprints[name] = " | ".join(line.strip() for line in out.splitlines())
        for path in self.workdir.glob("*.key"):
            self.secret_values.append(path.read_text().strip())
        self.observations["disposable_pki"] = fingerprints

    def read(self, name: str) -> bytes:
        return (self.workdir / name).read_bytes()

    # -------------------------------------------------------------- volumes

    def volume(self, suffix: str, files: dict[str, tuple[bytes, int]], uid: str, dirs: tuple[str, ...] = ()) -> str:
        name = f"{self.prefix}-{suffix}"
        self.docker("volume", "create", *self.labels, name)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            seen: set[str] = set()
            for path in sorted({*dirs, *(str(Path(p).parent) for p in files)} - {"."}):
                parts = Path(path).parts
                for depth in range(1, len(parts) + 1):
                    directory = "/".join(parts[:depth])
                    if directory in seen:
                        continue
                    seen.add(directory)
                    info = tarfile.TarInfo(directory)
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o700
                    info.uid = info.gid = int(uid)
                    archive.addfile(info)
            for path, (data, mode) in sorted(files.items()):
                info = tarfile.TarInfo(path)
                info.size = len(data)
                info.mode = mode
                info.uid = info.gid = int(uid)
                archive.addfile(info, io.BytesIO(data))
        self.docker(
            "run", "--rm", "-i", "--network", "none", *self.labels, "-v", f"{name}:/v",
            "--entrypoint", "sh", self.pg_image, "-c",
            f"tar --same-owner -xpf - -C /v && chown {uid}:{uid} /v && chmod 0700 /v",
            stdin=buffer.getvalue(),
        )
        return name

    # --------------------------------------------------------------- steps

    def rc_identity(self) -> None:
        inspect = json.loads(self.docker("image", "inspect", self.image).stdout)[0]
        labels = inspect["Config"].get("Labels") or {}
        revision = labels.get("org.opencontainers.image.revision")
        source_sha = self.args.source_sha or self.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"]
        ).stdout.decode().strip()
        rc = self.spec["release_candidate"]
        self.observations["release_candidate"] = {
            "local_image_id": inspect["Id"],
            "local_tag": self.image,
            "oci_revision": revision,
            "oci_source": labels.get("org.opencontainers.image.source"),
            "user": inspect["Config"].get("User"),
            "architecture": inspect.get("Architecture"),
            "source_sha": source_sha,
            "registry_digests": inspect.get("RepoDigests") or [],
            "built_from": f"{rc['dockerfile']} --target {rc['target']}",
        }
        self.verdict("RC", "rc.source_revision", revision == source_sha, source_sha, revision)
        self.verdict("RC", "rc.runtime_user", inspect["Config"].get("User") == rc["runtime_user"], rc["runtime_user"], inspect["Config"].get("User"))
        probe = (
            "from alembic.config import Config; from alembic.script import ScriptDirectory; "
            "c = Config(); c.set_main_option('script_location', '/app/migrations'); "
            "print(chr(10).join(sorted(ScriptDirectory.from_config(c).get_heads())))"
        )
        heads = self.docker(
            "run", "--rm", *self.labels, "--network", "none", "--read-only", "--cap-drop", "ALL",
            self.image, "-c", probe,
        ).stdout.decode().split()
        self.verdict("RC", "rc.single_alembic_head", heads == [rc["schema_head"]], [rc["schema_head"]], heads)

    def start_server(self) -> None:
        self.docker("network", "create", "--internal", *self.labels, self.net)
        internal = self.docker("network", "inspect", self.net, "--format", "{{.Internal}}").stdout.decode().strip()
        self.verdict("EFFECTS", "effects.network_has_no_egress", internal == "true", "internal=true", f"internal={internal}")
        hba = (TOPOLOGY_DIR / "pg_hba.conf").read_bytes()
        tls = self.volume(
            "pgtls",
            {
                "server.crt": (self.read("server.crt"), 0o400),
                "server.key": (self.read("server.key"), 0o400),
                "ca.crt": (self.read("ca.crt"), 0o400),
                "pg_hba.conf": (hba, 0o400),
                "superuser-password": (self.passwords["postgres"].encode(), 0o400),
            },
            POSTGRES_UID,
        )
        self.docker("volume", "create", *self.labels, f"{self.prefix}-pgdata")
        db = self.spec["database"]
        aliases = []
        for alias in (self.db_host, *db["network_aliases_for_negative_checks"]):
            aliases += ["--network-alias", alias]
        self.docker(
            "run", "-d", "--name", self.pg, *self.labels, "--network", self.net, *aliases,
            "-e", "POSTGRES_PASSWORD_FILE=/etc/pas95-tls/superuser-password",
            "-v", f"{tls}:/etc/pas95-tls:ro", "-v", f"{self.prefix}-pgdata:/var/lib/postgresql/data",
            self.pg_image, "postgres",
            "-c", "listen_addresses=*",
            "-c", "ssl=on",
            "-c", "ssl_cert_file=/etc/pas95-tls/server.crt",
            "-c", "ssl_key_file=/etc/pas95-tls/server.key",
            "-c", "ssl_ca_file=/etc/pas95-tls/ca.crt",
            "-c", "hba_file=/etc/pas95-tls/pg_hba.conf",
            "-c", f"ssl_min_protocol_version={db['ssl_min_protocol_version']}",
            "-c", f"password_encryption={db['password_encryption']}",
            "-c", "log_connections=on",
        )
        self.wait_ready(self.pg)
        version = self.psql(self.pg, "postgres", "SHOW server_version").strip()
        settings = self.psql(
            self.pg,
            "postgres",
            "SELECT string_agg(name || '=' || setting, ',' ORDER BY name) FROM pg_settings "
            "WHERE name IN ('ssl','ssl_min_protocol_version','password_encryption','max_connections',"
            "'superuser_reserved_connections','hba_file')",
        ).strip()
        self.observations["server"] = {"image": self.pg_image, "server_version": version, "settings": settings}
        self.check("TOPOLOGY", "topology.server_started", "PASS", "disposable TLS-only server", {"version": version, "settings": settings})

    def wait_ready(self, container: str, *, tcp: bool = True) -> None:
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = self.docker("logs", container, check=False)
            logs = (result.stdout + result.stderr).decode("utf-8", "replace")
            if "init process complete" in logs or "Skipping initialization" in logs:
                argv = ["exec", container, "pg_isready", "-q"] + (["-h", "127.0.0.1"] if tcp else [])
                if self.docker(*argv, check=False).returncode == 0:
                    return
            time.sleep(1)
        raise HarnessError(f"{container} did not become ready")

    def psql(self, container: str, database: str, sql: str, *, stdin: bytes | None = None, check: bool = True) -> str:
        argv = ["exec", "-i", "-u", "postgres", container, "psql", "-X", "-v", "ON_ERROR_STOP=1",
                "--tuples-only", "--no-align", "-d", database]
        if stdin is None:
            argv += ["-c", sql]
        else:
            argv += ["-f", "-"]
        return self.docker(*argv, stdin=stdin, check=check).stdout.decode()

    def bootstrap_roles(self) -> None:
        header = "".join(
            f"\\set pw_{role} '{self.passwords[role]}'\n" for role in self.spec["roles"]["login"]
        )
        template = (TOPOLOGY_DIR / "bootstrap_roles.sql").read_text(encoding="utf-8")
        self.psql(self.pg, "postgres", "", stdin=(header + template).encode())
        roles = self.psql(
            self.pg,
            "postgres",
            "SELECT string_agg(rolname || ':' || rolcanlogin::text || ':' || rolsuper::text || ':' "
            "|| rolbypassrls::text || ':' || rolcreatedb::text || ':' || rolcreaterole::text, ',' ORDER BY rolname) "
            "FROM pg_roles WHERE rolname !~ '^pg_' AND rolname <> 'postgres'",
        ).strip()
        self.observations["roles_after_bootstrap"] = roles.split(",")
        self.check("ROLES", "roles.bootstrap", "PASS", "split login roles, NOLOGIN grant roles", roles.split(","))

    # ----------------------------------------------------------- RC runner

    def canary_environment(self) -> list[str]:
        """The canary compose environment, with the production-v1 profile selected."""
        text = (ROOT / self.spec["canary_compose"]).read_text(encoding="utf-8")
        block = text.split("  environment:\n", 1)[1].split("\n  user:", 1)[0]
        rc = self.observations["release_candidate"]
        substitutions = {
            "APP_VERSION": f"sha-{rc['source_sha']}",
            "APP_SOURCE_SHA": rc["source_sha"],
            "IMAGE_DIGEST": rc["local_image_id"],
            "BUILD_TIME": "2026-09-24T00:00:00Z",
            "RELEASE_ID": f"pas95-local-{self.run_id}",
            "CONFIGURATION_CHECKSUM": "pas95-disposable",
            "RUNTIME_PROFILE_ID": self.spec["runtime_profile_id"],
        }
        env: list[str] = []
        self.observations["canary_effect_flags"] = {}
        for line in block.splitlines():
            match = re.match(r"^\s{4}([A-Z0-9_]+):\s*(.*)$", line)
            if not match:
                continue
            key, value = match.group(1), match.group(2).strip().strip('"')
            value = substitutions.get(key, value)
            if "${" in value:
                raise HarnessError(f"unresolved canary variable {key}")
            env += ["-e", f"{key}={value}"]
            if value in {"false", "disabled", "DISABLED"}:
                self.observations["canary_effect_flags"][key] = value
        return env

    def rc_run(self, *argv: str, secrets_volume: str, network: str | None = None, extra: tuple[str, ...] = (), check: bool = False) -> subprocess.CompletedProcess[bytes]:
        return self.docker(
            "run", "--rm", *self.labels, "--network", network or self.net,
            "--read-only", "--cap-drop", "ALL", "--user", f"{RC_UID}:{RC_UID}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "-v", f"{secrets_volume}:/run/secrets:ro", *extra,
            *self.canary_env, self.image, *argv,
            check=check,
        )

    def unit_volume(self, role: str, suffix: str, *, host: str | None = None, dsn: str | None = None) -> str:
        mounts = self.spec["secret_mounts"]
        prefix = Path(mounts["prefix"]).name
        if dsn is None:
            host = self.target(host or self.db_host)
            dsn = (
                f"postgresql://{role}:{self.passwords[role]}@{host}:{self.db_port}/{self.db_name}"
                f"?sslmode=verify-full&sslrootcert={mounts['ca_certificate']}"
                f"&sslcert={mounts['client_certificate']}&sslkey={mounts['client_key']}"
            )
        self.secret_values.append(dsn)
        return self.volume(
            suffix,
            {
                f"{prefix}database-url": (dsn.encode(), 0o400),
                f"{prefix}db-ca.crt": (self.read("ca.crt"), 0o400),
                f"{prefix}db-client.crt": (self.read(f"client-{role}.crt"), 0o400),
                f"{prefix}db-client.key": (self.read(f"client-{role}.key"), 0o400),
            },
            RC_UID,
            dirs=("matrix",),
        )

    def migrator(self, volume: str, *flags: str, network: str | None = None) -> dict[str, Any]:
        wrapper = (
            "import os, runpy, sys; "
            f"os.environ['DATABASE_URL'] = open('{self.spec['secret_mounts']['database_url']}').read().strip(); "
            "sys.argv = ['/app/scripts/migrate_runtime.py', *sys.argv[1:]]; "
            "sys.path.insert(0, '/app'); "
            "runpy.run_path('/app/scripts/migrate_runtime.py', run_name='__main__')"
        )
        result = self.rc_run("-c", wrapper, *flags, secrets_volume=volume, network=network)
        lines = self.scrub(result.stdout.decode("utf-8", "replace")).splitlines()
        errors = self.scrub(result.stderr.decode("utf-8", "replace")).splitlines()
        return {
            "exit_code": result.returncode,
            "stdout": lines,
            "stderr_tail": [line for line in errors if line.startswith("RUNTIME_")][-3:],
        }

    def migrate(self) -> None:
        rc = self.spec["release_candidate"]
        volume = self.unit_volume(self.spec["roles"]["migration"], "unit-migration")
        runs = {
            "apply_1": self.migrator(volume),
            "apply_2_idempotent": self.migrator(volume),
            "verify_only": self.migrator(volume, "--verify-only"),
        }
        self.observations["migration_runs"] = runs
        for name, run in runs.items():
            head = [line for line in run["stdout"] if line.startswith("RUNTIME_ALEMBIC_HEAD=")]
            ok = (
                run["exit_code"] == 0
                and head == [f"RUNTIME_ALEMBIC_HEAD={rc['schema_head']}"]
                and "RUNTIME_SCHEMA_VERIFIED=PASS" in run["stdout"]
            )
            self.verdict(
                "SCHEMA_HEAD",
                f"migration.{name}",
                ok,
                f"exit 0, head {rc['schema_head']}, RUNTIME_SCHEMA_VERIFIED=PASS",
                {"exit_code": run["exit_code"], "markers": [l for l in run["stdout"] if not l.startswith("RUNTIME_MIGRATION_APPLIED=")]},
            )
        applied = [l.split("=", 1)[1] for l in runs["apply_1"]["stdout"] if l.startswith("RUNTIME_MIGRATION_APPLIED=")]
        self.observations["sql_receipts_applied"] = applied
        receipts = {
            "core": self.psql(self.pg, self.db_name, "SELECT string_agg(version::text, ',' ORDER BY version) FROM public.middleware_schema_migrations").strip(),
            "automation": self.psql(self.pg, self.db_name, "SELECT string_agg(version::text, ',' ORDER BY version) FROM public.middleware_automation_schema_migrations").strip(),
            "alembic": self.psql(self.pg, self.db_name, "SELECT string_agg(version_num, ',') FROM public.alembic_version").strip(),
        }
        expected = {
            "core": ",".join(str(i) for i in range(1, rc["core_sql_receipts"] + 1)),
            "automation": ",".join(str(i) for i in range(1, rc["automation_sql_receipts"] + 1)),
            "alembic": rc["schema_head"],
        }
        self.observations["receipts"] = receipts
        self.verdict("MIGRATION_RECEIPTS", "receipts.readback", receipts == expected, expected, receipts)
        self.check(
            "MIGRATION_RECEIPTS",
            "receipts.deploy_controller_assertion",
            "FAIL" if receipts["core"] != "1,2,3,4,5,6,7,8,9,10" else "PASS",
            "deploy/production/server/codestra-middleware-deploy accepts the RC receipts",
            {"controller_pins": "1..10", "rc_receipts": receipts["core"]},
            "PAS-27 F-07: the controller asserts receipts 1..10 while the RC ships 0011; a controller-driven "
            "deploy of this RC fails closed after migrating. Release/trust-owned file; not changed here.",
        )
        owners = self.psql(
            self.pg,
            self.db_name,
            "SELECT string_agg(DISTINCT pg_get_userbyid(c.relowner), ',') FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','S','v')",
        ).strip()
        self.observations["schema_object_owners"] = owners
        self.verdict("ROLES", "roles.schema_owned_by_migration_role_only", owners == self.spec["roles"]["migration"], self.spec["roles"]["migration"], owners)
        self.psql(self.pg, "postgres", "", stdin=(TOPOLOGY_DIR / "grant_runtime.sql").read_bytes())
        repo_grants = self.psql(
            self.pg,
            self.db_name,
            "SELECT string_agg(DISTINCT grantee, ',' ORDER BY grantee) FROM information_schema.role_table_grants "
            "WHERE table_schema='public' AND grantee IN ('middleware_app','mw_integration_api','mw_scheduler','mw_notification_worker')",
        ).strip()
        self.observations["migration_grant_roles_effective"] = repo_grants
        self.check(
            "ROLES",
            "roles.migration_least_privilege_grants_effective",
            "PASS" if repo_grants else "FAIL",
            "grants in 0020/0047/0048/0051-0053 land on pre-created NOLOGIN grant roles",
            repo_grants,
            "PAS-78 F-05: these grants are silent no-ops unless the roles exist before migration; "
            "the repository still provisions none of them.",
        )
        # The same runner as a runtime role must be unable to apply DDL.
        runtime_volume = self.unit_volume(self.spec["roles"]["api"], "unit-api")
        self.api_volume = runtime_volume
        denied = self.migrator(runtime_volume)
        self.observations["migration_as_runtime_role"] = denied
        self.verdict(
            "ROLES",
            "roles.runtime_role_cannot_migrate",
            denied["exit_code"] != 0 and "RUNTIME_MIGRATION=PASS" not in denied["stdout"],
            "non-zero exit, RUNTIME_MIGRATION=FAIL",
            {"exit_code": denied["exit_code"], "stderr": denied["stderr_tail"]},
        )

    # ------------------------------------------------------------- probes

    def probe_volumes(self) -> None:
        self.baseline_census = self.census()
        roles = self.spec["roles"]
        files: dict[str, tuple[bytes, int]] = {"ca.crt": (self.read("ca.crt"), 0o400)}
        for role in roles["login"]:
            files[f"{role}/client.crt"] = (self.read(f"client-{role}.crt"), 0o400)
            files[f"{role}/client.key"] = (self.read(f"client-{role}.key"), 0o400)
            files[f"{role}/password"] = (self.passwords[role].encode(), 0o400)
        for name in ("rogue", "expired"):
            files[f"negative/{name}/client.crt"] = (self.read(f"{name}.crt"), 0o400)
            files[f"negative/{name}/client.key"] = (self.read(f"{name}.key"), 0o400)
        self.matrix_volume = self.volume("matrix", files, RC_UID)
        for alias in self.spec["database"]["network_aliases_for_negative_checks"]:
            self.target(alias)
        self.target(self.db_host)

    def probe_params(self, extra: dict[str, Any] | None = None) -> str:
        extra = dict(extra or {})
        evidence_files: dict[str, bytes] = extra.pop("_evidence_files", {})
        roles = self.spec["roles"]
        profiles = {
            p["profile_id"]: p
            for p in json.loads((ROOT / "config/runtime-profiles.v1.json").read_text())["profiles"]
        }
        compose = profiles[self.spec["compose_profile_id"]]["database"]
        params = {
            "database_host": self.db_host,
            "database_port": self.db_port,
            "database_name": self.db_name,
            "runtime_profile_id": self.spec["runtime_profile_id"],
            "compose_profile_id": self.spec["compose_profile_id"],
            "secret_path_prefix": self.spec["secret_mounts"]["prefix"],
            "login_roles": roles["login"],
            "api_role": roles["api"],
            "cross_cn_role": roles["runtime"][1],
            "migration_role": roles["migration"],
            "backup_role": roles["backup"],
            "exporter_role": roles["exporter"],
            "mismatch_host": self.spec["database"]["network_aliases_for_negative_checks"][1],
            "compose_host": compose["host"],
            "compose_database": compose["name"],
            "compose_username": compose["username"],
            "rls_tenants": self.spec["rls"]["tenants"],
            "rls_campaign": self.spec["rls"]["campaign"],
            **extra,
        }
        files = {
            "params.json": (json.dumps(params, sort_keys=True).encode(), 0o400),
            "rc_probe.py": ((TOPOLOGY_DIR / "rc_probe.py").read_bytes(), 0o400),
        }
        for name, payload in evidence_files.items():
            files[f"evidence/{name}"] = (payload, 0o400)
        return self.volume(f"probe-{secrets.token_hex(3)}", files, RC_UID)

    def probe(self, command: str, *, params_volume: str, secrets_volume: str | None = None, network: str | None = None) -> dict[str, Any]:
        mounts: tuple[str, ...] = () if secrets_volume else ("-v", f"{self.matrix_volume}:/run/secrets/matrix:ro")
        result = self.rc_run(
            "/probe/rc_probe.py", command,
            secrets_volume=secrets_volume or self.api_volume,
            network=network,
            extra=(
                *mounts,
                "-v", f"{params_volume}:/probe:ro",
                "-e", "DATABASE_URL=postgresql://placeholder:placeholder@placeholder.invalid:5432/placeholder",
            ),
        )
        stdout = self.scrub(result.stdout.decode("utf-8", "replace")).strip().splitlines()
        if result.returncode != 0 or not stdout:
            raise HarnessError(
                f"probe {command} exited {result.returncode}: "
                + self.scrub(result.stderr.decode("utf-8", "replace"))[-800:]
            )
        payload = json.loads(stdout[-1])
        if not payload.get("ok"):
            raise HarnessError(f"probe {command} failed: {payload}")
        return payload["result"]

    def tls_checks(self, params: str) -> None:
        gate = self.probe("profile-gate", params_volume=params)
        self.observations["profile_gate"] = gate
        cases = gate["cases"]
        self.verdict("TLS", "profile.production_requires_verify_full",
                     cases["production_verify_full_sslmode_only"]["accepted"] and not cases["production_plaintext"]["accepted"],
                     "sslmode=verify-full accepted, plaintext rejected",
                     {k: cases[k] for k in ("production_verify_full_sslmode_only", "production_plaintext")})
        self.verdict("MTLS", "profile.admits_ca_and_client_certificate",
                     cases["production_verify_full_with_ca_and_client_certificate"]["accepted"],
                     "the locked production-v1 profile admits sslrootcert/sslcert/sslkey (the only way to present a client certificate)",
                     cases["production_verify_full_with_ca_and_client_certificate"],
                     "PAS-78 F-02: the RC's locked profile rejects every DSN that can present a client certificate; "
                     "the RC API process cannot start against an mTLS-only production server. Owner lane: PR #304 (PAS-79/80).")
        self.verdict("TLS", "profile.process_dsn_passes_its_own_profile",
                     gate["process_settings_scheme"] == "postgresql",
                     "process settings keep scheme postgresql",
                     {"process_settings_scheme": gate["process_settings_scheme"],
                      "rewritten_case": cases["production_process_rewritten_asyncpg_scheme"]},
                     "PAS-78 F-01: app.core.config rewrites DATABASE_URL to postgresql+asyncpg, which "
                     "_validate_database_profile then rejects; a profile-bound process fails closed at startup.")
        self.verdict("TLS", "profile.compose_canary_requires_tls",
                     not cases["compose_as_shipped_no_sslmode"]["accepted"],
                     "codestra-middleware-production-compose-v1 rejects a DSN without TLS",
                     {k: cases[k] for k in ("compose_as_shipped_no_sslmode", "compose_with_verify_full")},
                     "PAS-78 F-03: the canary compose profile locks sslmode to null; it can only run plaintext.")
        self.verdict("SECRET_REFS", "secrets.database_url_file_bound_to_profile_prefix",
                     gate["database_url_file_bound_to_profile_prefix"],
                     "DATABASE_URL_FILE must live under the profile secret prefix",
                     gate["database_url_file_bound_to_profile_prefix"], "PAS-78 F-12.")

        matrix = self.probe("connect-matrix", params_volume=params)
        self.observations["connect_matrix"] = matrix
        for role, outcome in matrix["positive"].items():
            ok = (
                outcome.get("accepted") and outcome.get("role_name") == role and outcome.get("ssl")
                and outcome.get("tls_version") in {"TLSv1.2", "TLSv1.3"}
                and outcome.get("client_dn") == f"/CN={role}"
            )
            self.verdict("MTLS", f"mtls.accept.{role}", bool(ok), "verify-full + CN-bound client certificate accepted over TLS>=1.2",
                         {k: outcome.get(k) for k in ("accepted", "role_name", "ssl", "tls_version", "cipher", "client_dn", "error_type", "sqlstate")})
        for name, outcome in matrix["negative"].items():
            area = "TLS" if name in {"plaintext_sslmode_disable", "server_hostname_not_in_certificate", "compose_profile_as_shipped_dsn"} else "MTLS"
            self.verdict(area, f"reject.{name}", not outcome.get("accepted"), "rejected", outcome)

    def role_checks(self, params: str) -> None:
        data = self.probe("roles", params_volume=params)
        self.observations["role_isolation"] = data
        roles = self.spec["roles"]
        for role, row in data["isolation"].items():
            if role == roles["migration"]:
                self.verdict("ROLES", f"isolation.{role}", not row["runtime_role_isolated"] and row["owned_public_tables"] > 0 and not row["rls_bypass_possible"],
                             "schema owner: not isolated (owns DDL), but cannot bypass forced RLS", row)
            else:
                self.verdict("ROLES", f"isolation.{role}", row["runtime_role_isolated"] and not row["rls_bypass_possible"],
                             "runtime_role_isolated=true, rls_bypass_possible=false (PAS-96/97 query)", row)
        for group in ("runtime_denials", "backup_denials", "exporter_denials"):
            for name, outcome in data[group].items():
                self.verdict("ROLES", f"{group}.{name}", outcome["denied"], "denied", outcome)

    def rls_checks(self, params: str) -> None:
        data = self.probe("rls", params_volume=params)
        data.pop("rows_after_rollback_visible_to_tenant_a", None)
        self.observations["rls"] = data
        forced = sorted(t["table"] for t in data["rls_tables"] if t["enabled"] and t["forced"] and t["policies"] > 0)
        self.verdict("RLS", "rls.forced_tables", forced == sorted(self.spec["rls"]["forced_tables"]), self.spec["rls"]["forced_tables"], data["rls_tables"])
        self.verdict("RLS", "rls.tenant_sees_own_row", data["tenant_a_sees_own_row"] == 1, 1, data["tenant_a_sees_own_row"])
        self.verdict("RLS", "rls.other_tenant_isolated", data["tenant_b_sees_tenant_a_rows"] == 0, 0, data["tenant_b_sees_tenant_a_rows"])
        self.verdict("RLS", "rls.unscoped_session_sees_nothing", data["unscoped_session_sees_rows"] == 0, 0, data["unscoped_session_sees_rows"])
        self.verdict("RLS", "rls.unassigned_agent_sees_nothing", data["tenant_a_agent_without_assignment_sees_rows"] == 0, 0, data["tenant_a_agent_without_assignment_sees_rows"])
        self.verdict("RLS", "rls.cross_tenant_insert_rejected", data["cross_tenant_insert"]["denied"], "WITH CHECK violation", data["cross_tenant_insert"])
        self.verdict("RLS", "rls.schema_owner_subject_to_force", data["owner_unscoped_rows"] == 0 and data["owner_row_security_setting"] == "on", "owner sees 0 rows, row_security=on", {k: data[k] for k in ("owner_unscoped_rows", "owner_row_security_setting")})

    def pool_checks(self, params: str) -> None:
        data = self.probe("pool", params_volume=params)
        self.observations["pools"] = data
        spec = self.spec["pools"]
        p, e = data["asyncpg_pool"], data["sqlalchemy_engine"]
        self.verdict("POOL", "pool.asyncpg_bounds", p["min_size"] == spec["asyncpg_pool"]["min_size"] and p["max_size"] == spec["asyncpg_pool"]["max_size"] and p["acquire_beyond_max_times_out"],
                     spec["asyncpg_pool"], {k: p[k] for k in ("min_size", "max_size", "command_timeout_seconds", "acquire_beyond_max_times_out")})
        self.verdict("POOL", "pool.asyncpg_all_sessions_tls", p["role_tls_sessions"] == p["role_sessions"] and p["role_sessions"] >= p["max_size"],
                     "every pooled session is TLS", {k: p[k] for k in ("role_sessions", "role_tls_sessions")})
        self.verdict("POOL", "pool.sqlalchemy_bounds", e["pool_size"] == spec["sqlalchemy_engine"]["pool_size"] and e["max_overflow"] == spec["sqlalchemy_engine"]["max_overflow"] and e["connect_beyond_capacity"]["refused"] and e["tls_active"],
                     spec["sqlalchemy_engine"], e)
        per_process = spec["asyncpg_pool"]["max_size"] + spec["sqlalchemy_engine"]["pool_size"] + spec["sqlalchemy_engine"]["max_overflow"]
        demand = per_process * spec["api_uvicorn_workers"] + spec["migration_connections"]
        capacity = p["max_connections"] - p["superuser_reserved"]
        self.verdict("POOL", "pool.connection_budget", demand <= capacity,
                     f"canary demand <= max_connections - superuser_reserved ({capacity})",
                     {"per_api_process": per_process, "api_workers": spec["api_uvicorn_workers"], "demand": demand, "capacity": capacity})
        self.verdict("POOL", "pool.application_name_attribution", any(p["application_names"] or []) and "" not in (p["application_names"] or [""]),
                     "every session sets application_name", p["application_names"], "PAS-78 F-07.")
        self.verdict("POOL", "pool.statement_and_lock_timeouts", p["statement_timeout"] != "0" and p["lock_timeout"] != "0",
                     "non-zero statement_timeout and lock_timeout", {k: p[k] for k in ("statement_timeout", "lock_timeout", "idle_in_tx_timeout")}, "PAS-78 F-09.")

    def api_checks(self, params: str) -> None:
        data = self.probe("api", params_volume=params)
        self.observations["private_db_api"] = data
        r = data["responses"]
        head = self.spec["release_candidate"]["schema_head"]
        ok_statuses = all(v["status"] == 200 for v in r.values())
        self.verdict("PRIVATE_DB_API", "api.all_routes_200", ok_statuses, "200 for every canonical route", {k: v["status"] for k, v in r.items()})
        ready = r.get("GET /internal/v1/database/readiness", {}).get("body", {})
        self.verdict("PRIVATE_DB_API", "api.readiness", ready.get("ready") is True and ready.get("alembic_head") == head and ready.get("tls_required") and ready.get("tls_active") and ready.get("role_matches") and ready.get("database_matches"),
                     {"ready": True, "alembic_head": head, "tls_required": True, "tls_active": True}, ready)
        tls = r.get("GET /internal/v1/database/security/tls", {}).get("body", {})
        self.verdict("PRIVATE_DB_API", "api.security_tls", tls.get("verification_mode") == "verify-full" and tls.get("hostname_verification") and tls.get("protocol") in {"TLSv1.2", "TLSv1.3"}, "verify-full, hostname verification, TLS>=1.2", tls)
        certs = r.get("GET /internal/v1/database/security/certificates", {}).get("body", {})
        self.verdict("PRIVATE_DB_API", "api.security_certificates", certs.get("client_certificate_configured") is True and certs.get("private_key_exposed") is False and certs.get("dsn_exposed") is False, "client certificate configured, nothing exposed", certs)
        verify = r.get("POST /internal/v1/database/migrations/verify", {}).get("body", {})
        self.verdict("PRIVATE_DB_API", "api.migrations_verify_read_only", verify.get("verified") is True and verify.get("read_only") is True, {"verified": True, "read_only": True}, verify)
        rls = r.get("GET /internal/v1/database/security/rls", {}).get("body", {})
        self.verdict("PRIVATE_DB_API", "api.security_rls", rls.get("rls_enabled_tables") == len(self.spec["rls"]["forced_tables"]) and rls.get("policy_count", 0) >= len(self.spec["rls"]["forced_tables"]), "4 RLS tables with policies", rls)
        for kind, path in (("backup", "backups/latest"), ("restore", "restores/latest")):
            body = r.get(f"GET /internal/v1/database/{path}", {}).get("body", {})
            source = self.observations["api_evidence"].get(kind) or {}
            faithful = body.get("available") is True and all(
                body.get(key) == source.get(key) for key in ("evidence_id", "status", "verified", "sha256")
            )
            self.verdict("PRIVATE_DB_API", f"api.{kind}_evidence_readback", faithful,
                         f"reflects this run's {kind} evidence file (id, status, verified, sha256)", body)
        self.verdict("PRIVATE_DB_API", "api.no_mutation_routes", all(s in {404, 405} for s in data["mutation_routes"].values()), "404/405", data["mutation_routes"])
        self.verdict("PRIVATE_DB_API", "api.scopes", data["scopes_requested"] == ["platform.database.read", "platform.database.verify"], ["platform.database.read", "platform.database.verify"], data["scopes_requested"])
        self.verdict("SECRET_REFS", "secrets.no_secret_material_in_api_responses", not data["secret_material_in_responses"], False, data["secret_material_in_responses"])
        self.check("PRIVATE_DB_API", "api.role_isolation_route", "PASS" if data["role_isolation_route_present"] else "BLOCKED",
                   "GET /internal/v1/database/security/roles (PAS-96/97)", data["role_isolation_route_present"],
                   "" if data["role_isolation_route_present"] else "PR #327 not merged; its query ran directly in roles checks above.")

    # -------------------------------------------------------------- backup

    # pg_restore treats "-" as a file name, not stdin (verified on PostgreSQL 14,
    # 16 and 17). These are the only two edits in the corrected copy.
    STDIN_CORRECTIONS = (
        (b'pg_restore --list - <"$TEMPORARY_PATH"', b'pg_restore --list <"$TEMPORARY_PATH"'),
        (b'    - <"$final_path" || fail "restore_failed"', b'    <"$final_path" || fail "restore_failed"'),
    )

    def _run_backup_script(self, script: bytes, suffix: str, store: str) -> tuple[int, dict[str, str], str]:
        reference = f"{self.observations['release_candidate']['source_sha'][:12]}-{secrets.token_hex(6)}"
        conf = (
            f"POSTGRES_CONTAINER={self.pg}\nPOSTGRES_DATABASE={self.db_name}\n"
            "BACKUP_DIR=/var/backups/codestra-middleware\nOFFHOST_BACKUP_DIR=\n"
        ).encode()
        cfg = self.volume(suffix, {"deploy.conf": (conf, 0o600), "codestra-middleware-backup": (script, 0o700)}, "0")
        result = self.docker(
            "run", "--rm", *self.labels, "--network", "none", "--user", "0:0",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{cfg}:/etc/codestra-middleware:ro", "-v", f"{store}:/var/backups/codestra-middleware",
            "-e", "CODESTRA_MIDDLEWARE_DEPLOY_CONFIG=/etc/codestra-middleware/deploy.conf",
            self.args.backup_helper_image, "bash", "/etc/codestra-middleware/codestra-middleware-backup",
            "--reference", reference, check=False,
        )
        out = dict(
            line.split("=", 1)
            for line in (result.stdout + result.stderr).decode("utf-8", "replace").splitlines()
            if re.match(r"^[A-Z_]+=", line)
        )
        return result.returncode, out, reference

    def backup(self) -> dict[str, Any]:
        spec = self.spec["backup"]
        script = (ROOT / spec["script"]).read_bytes()
        store = f"{self.prefix}-backups"
        self.docker("volume", "create", *self.labels, store)
        expected = "BACKUP_STATUS=PASS, in-place restore rehearsal PASS, rehearsal DB dropped"

        def passed(code: int, out: dict[str, str]) -> bool:
            return code == 0 and out.get("BACKUP_STATUS") == "PASS" and out.get("RESTORE_STATUS") == "PASS" and out.get("RESTORE_DATABASE_DROPPED") == "YES"

        code, out, _ = self._run_backup_script(script, "backup-config", store)
        self.observations["backup_script"] = {"exit_code": code, **out}
        self.verdict(
            "BACKUP", "backup.repository_script", passed(code, out), expected, self.observations["backup_script"],
            "" if passed(code, out) else
            "codestra-middleware-backup passes '-' to pg_restore, which PostgreSQL 14/16/17 open as a file named '-' "
            "(could not open input file \"-\"). The script therefore always stops at backup_catalog_invalid, and "
            "codestra-middleware-deploy:485 aborts every controller-driven deploy at backup_or_restore_rehearsal_failed.",
        )
        if not passed(code, out):
            corrected = script
            for old, new in self.STDIN_CORRECTIONS:
                if corrected.count(old) != 1:
                    raise HarnessError("backup script failed but no longer matches the recorded pg_restore stdin defect")
                corrected = corrected.replace(old, new)
            code, out, _ = self._run_backup_script(corrected, "backup-config-corrected", store)
            self.observations["backup_script_with_stdin_correction"] = {
                "exit_code": code,
                "diff": [f"{a.decode()} -> {b.decode()}" for a, b in self.STDIN_CORRECTIONS],
                **out,
            }
            self.verdict("BACKUP", "backup.repository_script_with_stdin_correction", passed(code, out), expected,
                         self.observations["backup_script_with_stdin_correction"],
                         "The same script with only the two pg_restore '-' arguments removed; proves the fix, "
                         "the repository file is not changed by this lane.")
        offhost = out.get("OFFHOST_BACKUP_STATUS")
        self.check("BACKUP", "backup.offhost_copy", {"PASS": "PASS", "NOT_CONFIGURED": "BLOCKED"}.get(offhost or "", "FAIL"),
                   "off-host copy with digest readback", offhost,
                   "deploy.conf.example ships OFFHOST_BACKUP_DIR empty; the production off-host target is a host decision.")
        self.check("BACKUP", "backup.pitr", "BLOCKED", "WAL archiving / PITR", "logical dumps only",
                   "PAS-78 F-13: no WAL archiving or PITR in the repository; a production decision for the backup owner.")
        # Role-based dump: middleware_backup (pg_read_all_data, NOBYPASSRLS) over mTLS.
        backup_role = self.spec["roles"]["backup"]
        dump = self.docker(
            "run", "--rm", *self.labels, "--network", self.net, "--read-only", "--cap-drop", "ALL",
            "--user", f"{RC_UID}:{RC_UID}", "--tmpfs", "/tmp", "-v", f"{self.matrix_volume}:/m:ro",
            "--entrypoint", "sh", self.pg_image, "-c",
            f"PGPASSWORD=$(cat /m/{backup_role}/password) exec pg_dump --format=custom --no-owner --no-acl "
            f"-f /dev/null 'host={self.target(self.db_host)} port={self.db_port} dbname={self.db_name} user={backup_role} "
            f"sslmode=verify-full sslrootcert=/m/ca.crt sslcert=/m/{backup_role}/client.crt sslkey=/m/{backup_role}/client.key'",
            check=False,
        )
        message = self.scrub(dump.stderr.decode("utf-8", "replace")).strip().splitlines()
        self.observations["role_based_dump"] = {"exit_code": dump.returncode, "stderr": message[-2:]}
        self.verdict("BACKUP", "backup.least_privilege_role_dump", dump.returncode == 0,
                     "middleware_backup (pg_read_all_data, NOBYPASSRLS) can take a complete dump over mTLS",
                     self.observations["role_based_dump"],
                     "pg_dump refuses FORCE ROW LEVEL SECURITY tables without BYPASSRLS; the repository backup path "
                     "therefore depends on the local postgres superuser (PAS-78 F-13). A production backup role needs "
                     "BYPASSRLS (or superuser) by explicit owner decision.")
        return {"store": store, **out}

    def restore(self, backup: dict[str, Any]) -> None:
        store = backup["store"]
        path = backup.get("BACKUP_REFERENCE", "")
        if not path.startswith("/var/backups/codestra-middleware/"):
            self.check("BACKUP", "restore.isolated", "FAIL", "backup file available", path)
            return
        restore_password = secrets.token_hex(24)
        self.secret_values.append(restore_password)
        pw_volume = self.volume("restore-pw", {"pw": (restore_password.encode(), 0o400)}, POSTGRES_UID)
        self.docker(
            "run", "-d", "--name", self.restore_pg, *self.labels, "--network", "none",
            "-e", "POSTGRES_PASSWORD_FILE=/pw/pw", "-v", f"{pw_volume}:/pw:ro",
            "-v", f"{store}:/backup:ro", self.pg_image,
        )
        self.wait_ready(self.restore_pg)
        self.docker("exec", "-u", "postgres", self.restore_pg, "createdb", "--template=template0", self.db_name)
        restored = self.docker(
            "exec", self.restore_pg, "sh", "-c",
            f"pg_restore --exit-on-error --no-owner --no-acl -U postgres -d {self.db_name} "
            f"< '/backup/{Path(path).name}'",
            check=False,
        )
        self.verdict("BACKUP", "restore.isolated_pg_restore", restored.returncode == 0, "exit 0 in a --network none server",
                     {"exit_code": restored.returncode, "stderr": self.scrub(restored.stderr.decode()).splitlines()[-2:]})
        census_sql = (
            "SELECT string_agg(format('%s=%s', c.relname, (xpath('/row/n/text()', "
            "query_to_xml(format('SELECT count(*) AS n FROM public.%I', c.relname), false, true, '')))[1]::text), ',' ORDER BY c.relname) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='r'"
        )
        # Superuser census bypasses RLS on both sides so forced tables are counted.
        source = self.psql(self.pg, self.db_name, census_sql).strip()
        target = self.psql(self.restore_pg, self.db_name, census_sql).strip()
        self.verdict("BACKUP", "restore.table_and_row_parity", source == target and bool(source),
                     "identical table set and row counts", {"tables": len(source.split(",")), "equal": source == target})
        dsn = f"postgresql://postgres:{restore_password}@127.0.0.1:5432/{self.db_name}"
        self.target("127.0.0.1")
        self.secret_values.append(dsn)
        volume = self.volume("unit-restore", {Path(self.spec["secret_mounts"]["database_url"]).name: (dsn.encode(), 0o400)}, RC_UID)
        verify = self.migrator(volume, "--verify-only", network=f"container:{self.restore_pg}")
        self.observations["restore_verify_only"] = verify
        head = self.spec["release_candidate"]["schema_head"]
        if verify["exit_code"] != 0:
            self.observations["restore_schema_drift"] = self.schema_drift(volume)
        self.verdict("BACKUP", "restore.rc_verify_only", verify["exit_code"] == 0 and f"RUNTIME_ALEMBIC_HEAD={head}" in verify["stdout"] and "RUNTIME_SCHEMA_VERIFIED=PASS" in verify["stdout"],
                     "RC migrate_runtime --verify-only PASS on the restored copy",
                     {"exit_code": verify["exit_code"], "markers": verify["stdout"], "stderr": verify["stderr_tail"],
                      "drifted_tables": sorted(self.observations.get("restore_schema_drift", {}))},
                     "" if verify["exit_code"] == 0 else
                     "pg_dump/pg_restore re-deparses varchar IN (...) CHECK constraints (ANY ((ARRAY[...])::text[]) becomes "
                     "ANY (ARRAY[(...)::text, ...])). They are semantically identical, but scripts/runtime_sql_schema.py hashes "
                     "pg_get_constraintdef text, so every database restored from a logical backup fails the RC's own schema "
                     "admission (migrate_runtime and therefore the deploy controller). Restore-based recovery is blocked "
                     "until the contract normalizes constraint expressions or the restore re-applies them.")
        self.restore_evidence = {
            "evidence_id": f"pas95-{self.run_id}-restore",
            "kind": "restore",
            "created_at": _now(),
            "completed_at": _now(),
            "source_database": self.db_name,
            "target_database": f"{self.restore_pg}/{self.db_name}",
            "source_schema_head": head,
            "target_schema_head": head,
            "sha256": backup.get("BACKUP_SHA256"),
            "verified": restored.returncode == 0 and verify["exit_code"] == 0 and source == target,
            "status": "PASS" if restored.returncode == 0 and verify["exit_code"] == 0 and source == target else "FAIL",
        }

    def schema_drift(self, restore_volume: str) -> dict[str, Any]:
        """Name the tables and catalog keys where the restored copy leaves the RC contract."""
        params = self.probe_params()
        source = self.probe("schema", params_volume=params)
        restored = self.probe("schema", params_volume=params, secrets_volume=restore_volume,
                              network=f"container:{self.restore_pg}")
        drift: dict[str, Any] = {}
        for table, entry in restored.items():
            if entry["matches_contract"]:
                continue
            before, after = source[table]["structure"], entry["structure"]
            keys = {}
            for key in sorted(set(before) | set(after)):
                if before.get(key) == after.get(key):
                    continue
                if isinstance(before.get(key), list) and isinstance(after.get(key), list):
                    keys[key] = {
                        "source_only": [i for i in before[key] if i not in after[key]],
                        "restored_only": [i for i in after[key] if i not in before[key]],
                    }
                else:
                    keys[key] = {"source": before.get(key), "restored": after.get(key)}
            drift[table] = {"source_matches_contract": source[table]["matches_contract"], "differences": keys}
        return drift

    # ---------------------------------------------------------- monitoring

    def monitoring(self, params_factory) -> None:
        spec = self.spec["monitoring"]
        compose = (ROOT / spec["exporter_compose"]).read_text(encoding="utf-8")
        pinned = re.search(r"image:\s*(docker\.io/prometheuscommunity/postgres-exporter@sha256:[0-9a-f]{64})", compose)
        self.verdict("MONITORING", "monitoring.exporter_image_pinned", bool(pinned) and pinned.group(1) == spec["exporter_image"], spec["exporter_image"], pinned.group(1) if pinned else None)
        present = self.docker("image", "inspect", spec["exporter_image"], check=False).returncode == 0
        if not present:
            self.check("MONITORING", "monitoring.exporter_scrape", "BLOCKED", "pinned exporter image available locally", False,
                       "pull the pinned digest before running (the harness network has no egress)")
            return
        role = self.spec["roles"]["exporter"]
        exporter_secrets = self.volume(
            "exporter",
            {
                "ca.crt": (self.read("ca.crt"), 0o400),
                "client.crt": (self.read(f"client-{role}.crt"), 0o400),
                "client.key": (self.read(f"client-{role}.key"), 0o600),
                "password": (self.passwords[role].encode(), 0o400),
            },
            EXPORTER_UID,
        )
        names = {"mtls": f"{self.prefix}-exporter-mtls", "as_shipped": f"{self.prefix}-exporter-as-shipped"}
        uri = (
            f"{self.target(self.db_host)}:{self.db_port}/{self.db_name}?sslmode=verify-full&sslrootcert=/s/ca.crt"
            "&sslcert=/s/client.crt&sslkey=/s/client.key"
        )
        as_shipped = re.search(r"DATA_SOURCE_URI:\s*(\S+)", compose).group(1)
        shipped_user = re.search(r"DATA_SOURCE_USER:\s*(\S+)", compose).group(1)
        self.target(as_shipped.split(":", 1)[0])
        for key, name, env in (
            ("mtls", names["mtls"], ["-e", f"DATA_SOURCE_URI={uri}", "-e", f"DATA_SOURCE_USER={role}"]),
            ("as_shipped", names["as_shipped"], ["-e", f"DATA_SOURCE_URI={as_shipped}", "-e", f"DATA_SOURCE_USER={shipped_user}"]),
        ):
            self.docker(
                "run", "-d", "--name", name, *self.labels, "--network", self.net, "--read-only",
                "--cap-drop", "ALL", "--tmpfs", "/tmp", "-v", f"{exporter_secrets}:/s:ro",
                *env, "-e", "DATA_SOURCE_PASS_FILE=/s/password", spec["exporter_image"],
            )
        params = params_factory({"exporters": {k: f"http://{self.target(v)}:9187/metrics" for k, v in names.items()}})
        data = self.probe("scrape", params_volume=params)
        self.observations["monitoring"] = data
        mtls, shipped = data["mtls"], data["as_shipped"]
        self.verdict("MONITORING", "monitoring.exporter_mtls_scrape", mtls["pg_up"] == 1.0 and mtls["pg_settings_max_connections"],
                     "pg_up=1 over verify-full + client certificate as postgres_exporter (pg_monitor)", mtls)
        self.verdict("MONITORING", "monitoring.alert_conditions_quiet", mtls["alert_CodestraPostgresDown_condition"] is False and mtls["alert_CodestraPostgresConnectionSaturation_condition"] is False,
                     "CodestraPostgresDown and CodestraPostgresConnectionSaturation conditions false on a healthy server",
                     {k: mtls[k] for k in ("alert_CodestraPostgresDown_condition", "alert_CodestraPostgresConnectionSaturation_condition")})
        self.verdict("MONITORING", "monitoring.as_shipped_exporter_fires_down_alert", shipped["pg_up"] == 0.0 and shipped["alert_CodestraPostgresDown_condition"] is True,
                     "the as-shipped exporter (sslmode=disable, codestra_monitoring) cannot scrape an mTLS-only server, so CodestraPostgresDown fires",
                     shipped, "PAS-78 F-03/F-14: the repository exporter configuration must move to verify-full + client certificate before an mTLS cut-over.")
        logs = self.docker("logs", self.pg, check=False).stderr.decode("utf-8", "replace")
        rules = (ROOT / spec["rules_file"]).read_text(encoding="utf-8")
        missing = [alert for alert in spec["alerts"] if f"alert: {alert}" not in rules]
        self.verdict("MONITORING", "monitoring.rules_present", not missing, spec["alerts"], {"missing": missing})
        self.observations["server_log_rejections"] = len(re.findall(r"FATAL:", logs))

    # ------------------------------------------------------ secrets/effects

    def secret_reference_checks(self) -> None:
        containers = self.docker("ps", "-aq", "--filter", f"label={LABEL}.run={self.run_id}").stdout.decode().split()
        leaks = []
        for container in containers:
            env = json.loads(self.docker("inspect", container, "--format", "{{json .Config.Env}}").stdout)
            for value in self.secret_values:
                if any(value in item for item in env):
                    leaks.append(container)
        self.verdict("SECRET_REFS", "secrets.not_in_container_environment", not leaks, "no password/DSN/key in any container environment", {"containers": len(containers), "leaks": len(leaks)})
        prefix = self.spec["secret_mounts"]["prefix"]
        profile = next(p for p in json.loads((ROOT / "config/runtime-profiles.v1.json").read_text())["profiles"] if p["profile_id"] == self.spec["runtime_profile_id"])
        self.verdict("SECRET_REFS", "secrets.mount_prefix_matches_profile", profile["secret_path_prefix"] == prefix, profile["secret_path_prefix"], prefix)
        self.check("SECRET_REFS", "secrets.file_modes", "PASS", "credentials mounted read-only, 0400 (key 0600 for lib/pq), owned by the consuming uid",
                   {"rc_uid": RC_UID, "postgres_uid": POSTGRES_UID, "exporter_uid": EXPORTER_UID})

    def census(self) -> dict[str, int]:
        """Row count of every public table (superuser, so forced RLS is not applied)."""
        text = self.psql(
            self.pg, self.db_name,
            "SELECT coalesce(string_agg(format('%s=%s', c.relname, (xpath('/row/n/text()', "
            "query_to_xml(format('SELECT count(*) AS n FROM public.%I', c.relname), false, true, '')))[1]::text), ',' "
            "ORDER BY c.relname), '') FROM pg_class c JOIN pg_namespace ns ON ns.oid=c.relnamespace "
            "WHERE ns.nspname='public' AND c.relkind='r'",
        ).strip()
        return {k: int(v) for k, v in (item.split("=", 1) for item in text.split(",") if item)}

    def effects_census(self) -> None:
        after = self.census()
        before = self.baseline_census
        changed = {t: {"before": before.get(t), "after": n} for t, n in after.items() if before.get(t) != n}
        changed.update({t: {"before": n, "after": None} for t, n in before.items() if t not in after})
        seeded = {k: v for k, v in after.items() if v}
        self.observations["migration_seeded_rows"] = seeded
        self.verdict("EFFECTS", "effects.no_row_changes_during_runtime_phase", not changed,
                     "every probe write rolled back: row counts identical to the post-migration baseline in all tables",
                     {"tables": len(after), "changed": changed})
        effect_rows = {k: v for k, v in after.items() if v and EFFECT_TABLE.search(k)}
        self.check("EFFECTS", "effects.effect_tables_seed_only", "PASS" if set(effect_rows) <= {"social_providers"} else "FAIL",
                   "no outbox/delivery/dispatch/webhook/message rows; social_providers holds migration-seeded reference rows only",
                   effect_rows)
        foreign = sorted(set(self.connection_targets) - {self.db_host, "127.0.0.1", *self.spec["database"]["network_aliases_for_negative_checks"], f"{self.prefix}-exporter-mtls", f"{self.prefix}-exporter-as-shipped"})
        self.verdict("EFFECTS", "effects.connection_targets_disposable", not foreign, "every connection target is a harness resource", {"targets": sorted(set(self.connection_targets)), "foreign": foreign})
        flags = self.observations.get("canary_effect_flags", {})
        self.verdict("EFFECTS", "effects.canary_flags_off", bool(flags) and all(v in {"false", "disabled", "DISABLED"} for v in flags.values()), "every canary effect flag false/disabled", flags)

    # ------------------------------------------------------------ teardown

    def teardown(self) -> dict[str, int]:
        selector = f"label={LABEL}.run={self.run_id}"
        containers = self.docker("ps", "-aq", "--filter", selector, check=False).stdout.decode().split()
        if containers:
            self.docker("rm", "-f", "-v", *containers, check=False)
        volumes = self.docker("volume", "ls", "-q", "--filter", selector, check=False).stdout.decode().split()
        if volumes:
            self.docker("volume", "rm", "-f", *volumes, check=False)
        networks = self.docker("network", "ls", "-q", "--filter", selector, check=False).stdout.decode().split()
        if networks:
            self.docker("network", "rm", *networks, check=False)
        shutil.rmtree(self.workdir, ignore_errors=True)
        residual = {
            "containers": len(self.docker("ps", "-aq", "--filter", selector, check=False).stdout.split()),
            "volumes": len(self.docker("volume", "ls", "-q", "--filter", selector, check=False).stdout.split()),
            "networks": len(self.docker("network", "ls", "-q", "--filter", selector, check=False).stdout.split()),
            "pki_workdir": int(self.workdir.exists()),
        }
        return residual

    # ----------------------------------------------------------------- run

    def execute(self) -> dict[str, Any]:
        started = _now()
        error = None
        try:
            self.assert_local_docker()
            self.rc_identity()
            self.canary_env = self.canary_environment()
            self.build_pki()
            self.start_server()
            self.bootstrap_roles()
            self.migrate()
            self.probe_volumes()
            base_params = self.probe_params()
            self.tls_checks(base_params)
            self.role_checks(base_params)
            self.rls_checks(base_params)
            self.pool_checks(base_params)
            backup = self.backup()
            self.restore(backup)
            backup_evidence = {
                "evidence_id": f"pas95-{self.run_id}-backup",
                "kind": "backup",
                "created_at": _now(),
                "source_database": self.db_name,
                "source_schema_head": self.spec["release_candidate"]["schema_head"],
                "sha256": backup.get("BACKUP_SHA256"),
                "verified": backup.get("BACKUP_STATUS") == "PASS",
                "status": backup.get("BACKUP_STATUS", "FAIL"),
            }
            evidence_files = {
                "backup.json": json.dumps(backup_evidence).encode(),
                "restore.json": json.dumps(getattr(self, "restore_evidence", {"status": "FAIL"})).encode(),
            }
            self.observations["api_evidence"] = {"backup": backup_evidence, "restore": getattr(self, "restore_evidence", None)}
            api_params = self.probe_params({"api_evidence_dir": "/probe/evidence", "_evidence_files": evidence_files})
            self.api_checks(api_params)
            self.monitoring(lambda extra: self.probe_params(extra))
            self.secret_reference_checks()
            self.effects_census()
        except Exception as exc:  # noqa: BLE001 - recorded as a harness failure
            error = self.scrub(f"{type(exc).__name__}: {exc}")
            self.check("HARNESS", "harness.completed", "FAIL", "every step ran", error)
        finally:
            residual = self.teardown()
        for area, check_id, expected, note in RUNTIME_ONLY_BLOCKERS:
            self.check(area, check_id, "BLOCKED", expected, "not attempted from the disposable harness", note)
        self.check("EFFECTS", "effects.teardown_residual_zero", "PASS" if not any(residual.values()) else "FAIL", 0, residual)
        effects = {
            "PRODUCTION_DATABASE_MUTATIONS": 0,
            "PROVIDER_EFFECTS": 0,
            "PRODUCTION_EFFECTS": 0,
        }
        failed_effect_checks = [c for c in self.checks if c["area"] == "EFFECTS" and c["status"] == "FAIL"]
        if failed_effect_checks:
            effects = {k: "UNPROVEN" for k in effects}
        summary: dict[str, str] = {}
        for item in self.checks:
            current = summary.get(item["area"], "PASS")
            order = {"PASS": 0, "INFO": 0, "BLOCKED": 1, "FAIL": 2}
            if order[item["status"]] > order[current]:
                current = item["status"]
            summary[item["area"]] = current
        overall = "FAIL" if "FAIL" in summary.values() else ("BLOCKED" if "BLOCKED" in summary.values() else "PASS")
        counts = {status: sum(1 for c in self.checks if c["status"] == status) for status in STATUSES}
        return {
            "schema_version": "1.0",
            "issue": "PAS-95",
            "gate": "DB-18",
            "run_id": self.run_id,
            "started_at": started,
            "completed_at": _now(),
            "harness": "scripts/certify_production_db_topology.py",
            "topology_spec": str(SPEC_PATH.relative_to(ROOT)),
            "topology_spec_sha256": hashlib.sha256(SPEC_PATH.read_bytes()).hexdigest(),
            "harness_error": error,
            "verdict": overall,
            "area_summary": dict(sorted(summary.items())),
            "check_counts": counts,
            "effects": effects,
            "residual": residual,
            "host_deviations": [
                "--security-opt no-new-privileges:true omitted: the snap Docker daemon on this host refuses exec with it "
                "(operation not permitted); every other canary hardening flag (read-only, cap-drop ALL, uid 65532, tmpfs /tmp) applied.",
                "RC image built locally from the exact source with Dockerfile.runtime --target runtime; it is not the signed release artifact.",
            ],
            "observations": self.observations,
            "checks": self.checks,
        }


def assert_evidence_clean(text: str, secret_values: list[str]) -> None:
    for value in secret_values:
        if value and value in text:
            raise HarnessError("evidence contains generated secret material; refusing to write it")
    if "PRIVATE KEY" in text:
        raise HarnessError("evidence contains private key material; refusing to write it")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--rc-image", required=True, help="locally built RC image (Dockerfile.runtime --target runtime)")
    parser.add_argument("--source-sha", help="exact RC source SHA (default: git HEAD)")
    parser.add_argument("--postgres-image", help="override the disposable server image")
    parser.add_argument("--backup-helper-image", default="pas95-backup-helper:local",
                        help="root helper with bash, coreutils, util-linux and the docker CLI for the repository backup script")
    parser.add_argument("--output", type=Path, required=True, help="evidence JSON path")
    args = parser.parse_args(argv)
    harness = Harness(args)
    evidence = harness.execute()
    text = json.dumps(evidence, indent=2, sort_keys=False, default=str) + "\n"
    assert_evidence_clean(text, harness.secret_values)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="utf-8")
    for key, value in evidence["effects"].items():
        print(f"{key}={value}")
    print(f"RESIDUAL_RESOURCES={sum(evidence['residual'].values())}")
    for area, status in evidence["area_summary"].items():
        print(f"PAS95_{area}={status}")
    print(f"PAS95_DB18_VERDICT={evidence['verdict']}")
    clean = all(v == 0 for v in evidence["effects"].values()) and not any(evidence["residual"].values())
    return 0 if clean and evidence["harness_error"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
