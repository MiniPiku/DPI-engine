"""Console output helpers (Windows-safe UTF-8)."""

from __future__ import annotations

import sys


def configure_stdout() -> None:
    """Use UTF-8 on stdout when supported (e.g. Windows Terminal)."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass
