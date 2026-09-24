"""Deprecated compatibility shim. Import ``app.core.runtime`` instead.

The runtime container, its readiness report and its builder are defined once
in :mod:`app.core.runtime`. This module keeps the former names importable
for one release and defines nothing of its own.
"""

from __future__ import annotations

import warnings

from app.core.runtime import (
    ReadinessReport,
    RuntimeContainer,
    RuntimeStartupError,
    _asyncpg_dsn,
    build_runtime_container,
)

Runtime = RuntimeContainer
build_runtime = build_runtime_container

__all__ = [
    "ReadinessReport",
    "Runtime",
    "RuntimeContainer",
    "RuntimeStartupError",
    "_asyncpg_dsn",
    "build_runtime",
    "build_runtime_container",
]

warnings.warn(
    "app.runtime is a deprecated shim; import app.core.runtime instead",
    DeprecationWarning,
    stacklevel=2,
)
