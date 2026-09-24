"""Deprecated compatibility shim. Import ``app.core.config`` instead.

Every field, environment name, default, validator and security rule that used
to live here is now defined once in :mod:`app.core.config`. This module keeps
the old import path working for one release while consumers are migrated; it
defines nothing of its own and is removed by the architecture governance
tests if it ever grows back.
"""

from __future__ import annotations

import warnings

from app.core.config import (
    EXTERNAL_DELIVERY_EFFECTS,
    RUNTIME_PROFILES_PATH,
    SUPPORTED_EXTERNAL_EFFECTS,
    UMBRELLA_CONTROL_NAMES,
    WEBHOOK_PRODUCERS,
    ConfigurationError,
    Settings,
)

__all__ = [
    "ConfigurationError",
    "EXTERNAL_DELIVERY_EFFECTS",
    "RUNTIME_PROFILES_PATH",
    "SUPPORTED_EXTERNAL_EFFECTS",
    "Settings",
    "UMBRELLA_CONTROL_NAMES",
    "WEBHOOK_PRODUCERS",
]

warnings.warn(
    "app.config is a deprecated shim; import app.core.config instead",
    DeprecationWarning,
    stacklevel=2,
)
