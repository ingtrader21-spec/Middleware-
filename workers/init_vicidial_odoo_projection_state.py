from __future__ import annotations

import os
import stat
from pathlib import Path

_WORKER_UID = 65532
_WORKER_GID = 65532
_DEFAULT_STATE_DIRECTORY = Path("/state")


class StateDirectoryInitializationError(RuntimeError):
    """Raised when the projection state volume cannot be prepared safely."""


def prepare_state_directory(
    path: Path,
    *,
    uid: int = _WORKER_UID,
    gid: int = _WORKER_GID,
) -> None:
    """Atomically prepare one existing, non-symlink state directory.

    The initializer intentionally uses only Python and file-descriptor operations
    available in the released distroless runtime image. It neither creates a
    path outside the mounted volume nor invokes a shell or external utility.
    """

    if not path.is_absolute():
        raise StateDirectoryInitializationError(
            "state directory must be an absolute path"
        )
    if uid < 0 or gid < 0:
        raise StateDirectoryInitializationError(
            "state directory uid and gid must be non-negative"
        )

    if os.name == "nt":
        if not path.is_dir() or path.is_symlink():
            raise StateDirectoryInitializationError(
                "state directory cannot be opened safely"
            )
        os.chmod(path, 0o700)
        return

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StateDirectoryInitializationError(
            f"state directory cannot be opened safely: {path}"
        ) from exc

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            raise StateDirectoryInitializationError(
                "state path is not a directory"
            )

        os.fchmod(descriptor, 0o700)
        os.fchown(descriptor, uid, gid)

        after = os.fstat(descriptor)
        if (
            after.st_uid != uid
            or after.st_gid != gid
            or stat.S_IMODE(after.st_mode) != 0o700
        ):
            raise StateDirectoryInitializationError(
                "state directory ownership or mode verification failed"
            )
    except OSError as exc:
        raise StateDirectoryInitializationError(
            "state directory ownership preparation failed"
        ) from exc
    finally:
        os.close(descriptor)


def main() -> int:
    raw_path = os.getenv(
        "VICIDIAL_ODOO_STATE_DIRECTORY",
        str(_DEFAULT_STATE_DIRECTORY),
    ).strip()
    if not raw_path:
        raise StateDirectoryInitializationError(
            "VICIDIAL_ODOO_STATE_DIRECTORY must not be empty"
        )

    path = Path(raw_path)
    prepare_state_directory(path)
    print(
        "VICIDIAL_ODOO_STATE_DIRECTORY_READY="
        f"{path}:uid={_WORKER_UID}:gid={_WORKER_GID}:mode=0700"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
