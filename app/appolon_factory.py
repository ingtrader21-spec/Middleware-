"""Deprecated compatibility shim. Import ``app.application`` instead.

The Appolon application factory is now the single application factory in
:mod:`app.application`; its inline routes live in :mod:`app.appolon_routes`.
This module keeps the former import path working for one release and
defines nothing of its own.
"""

from __future__ import annotations

import warnings

from app.application import create_app

__all__ = ["create_app"]

warnings.warn(
    "app.appolon_factory is a deprecated shim; import app.application instead",
    DeprecationWarning,
    stacklevel=2,
)
