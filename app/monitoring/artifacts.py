"""Read bounded release artifacts through a directory descriptor."""

from contextlib import ExitStack
import hashlib
import os
from pathlib import PurePosixPath
import stat

from fastapi import HTTPException

from .backends import MAX_RESPONSE_BYTES, load_config, service_for


_DIR_FD_SUPPORTED = os.open in os.supports_dir_fd and os.open in os.supports_fd


def _read_via_dir_fd(root: str, path: PurePosixPath) -> bytes:
    """Descriptor-relative open path used on platforms that support dir_fd.

    Both paths come from release configuration, never directly from the request.
    Descriptor-relative opens keep containment valid while directories change,
    and reject symlinks at every path component.
    """
    with ExitStack() as stack:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory = os.open(root, flags)
        stack.callback(os.close, directory)
        for part in path.parts[:-1]:
            directory = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
            stack.callback(os.close, directory)
        descriptor = os.open(
            path.parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory,
        )
        with os.fdopen(descriptor, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("artifact must be a regular file")
            return stream.read(MAX_RESPONSE_BYTES + 1)


def _read_via_resolved_path(root: str, path: PurePosixPath) -> bytes:
    """Fallback for platforms without dir_fd support (e.g. Windows).

    Containment and symlink-rejection are enforced by resolving the real path
    of every intermediate component and comparing it against the real root,
    instead of relying on descriptor-relative opens.
    """
    real_root = os.path.realpath(root)
    current = real_root
    for part in path.parts:
        candidate = os.path.join(current, part)
        if os.path.islink(candidate):
            raise ValueError("artifact path must not contain symbolic links")
        current = candidate
    real_target = os.path.realpath(current)
    if os.path.commonpath([real_root, real_target]) != real_root:
        raise ValueError("artifact must have a relative path inside its root")
    if not os.path.isfile(real_target):
        raise ValueError("artifact must be a regular file")
    with open(real_target, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("artifact must be a regular file")
        return stream.read(MAX_RESPONSE_BYTES + 1)


def read_artifact(root: str, relative_path: str, expected_digest: str) -> bytes:
    """Open only regular files below the mounted root, without following links.

    Uses descriptor-relative opens where the platform supports dir_fd, and a
    resolved-path containment check on platforms (e.g. Windows) that do not.
    """
    path = PurePosixPath(relative_path)
    if path.is_absolute() or not path.parts or any(p == ".." for p in path.parts):
        raise ValueError("artifact must have a relative path inside its root")
    if _DIR_FD_SUPPORTED:
        raw = _read_via_dir_fd(root, path)
    else:
        raw = _read_via_resolved_path(root, path)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("artifact exceeds size limit")
    if "sha256:" + hashlib.sha256(raw).hexdigest() != expected_digest:
        raise ValueError("artifact digest mismatch")
    return raw


def read_approved_artifact(principal, service_id, environment, artifact_id, digest):
    """Resolve an approved identifier using one mounted configuration snapshot."""
    config = load_config()
    service = service_for(config, principal, service_id, environment)
    binding = config.get("artifacts", {}).get(artifact_id, {})
    if (
        binding.get("service_id") != service_id
        or binding.get("environment") != environment
        or binding.get("sha256") != digest
    ):
        raise HTTPException(
            403, "artifact is not approved for this service and environment"
        )
    return service, read_artifact(config["artifact_root"], binding["path"], digest)
