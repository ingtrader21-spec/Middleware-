#!/usr/bin/env python3
"""Compatibility entry point for the current integration release authority.

The reviewed ruleset engine is preserved in the base module. This public path
now delegates to the seven-repository v2 authority so existing manual and
automated callers cannot silently validate the obsolete four-repository set.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
V2_SCRIPT = (
    ROOT
    / "scripts"
    / "apply_integration_main_release_authorities_v2.py"
)

spec = importlib.util.spec_from_file_location(
    "integration_main_release_authorities_v2",
    V2_SCRIPT,
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load current integration authority")
V2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V2)
V2.configure_base()
BASE = V2.BASE


def main(argv: list[str] | None = None) -> int:
    return V2.main(list(sys.argv[1:] if argv is None else argv))


def __getattr__(name: str) -> Any:
    return getattr(BASE, name)


if __name__ == "__main__":
    raise SystemExit(main())
