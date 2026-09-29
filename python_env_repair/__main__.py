"""Module entry point: ``python -B -m python_env_repair``."""

from __future__ import annotations

import sys

from python_env_repair.cli import main

if __name__ == "__main__":
    sys.exit(main())
