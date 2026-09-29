"""Detect and repair ``console_scripts`` launchers of the running Python environment.

Importing this package has no side effects beyond registering a ``NullHandler`` on the
package logger. Use :func:`run` for programmatic access; it does not configure logging.
"""

from __future__ import annotations

import logging

from python_env_repair.version import VERSION

__version__ = VERSION

logging.getLogger(__name__).addHandler(logging.NullHandler())

from python_env_repair.environment import EnvironmentDetectionError, current_environment  # noqa: E402
from python_env_repair.models import (  # noqa: E402
    EnvironmentInfo,
    Operation,
    OverallStatus,
    RelocationContext,
    RelocationSource,
    RepairReport,
    RepairResult,
    VerificationCommand,
    VerificationMode,
    VerificationPolicy,
)
from python_env_repair.workflow import RunOptions, run  # noqa: E402

__all__ = [
    "EnvironmentDetectionError",
    "EnvironmentInfo",
    "Operation",
    "OverallStatus",
    "RelocationContext",
    "RelocationSource",
    "RepairReport",
    "RepairResult",
    "RunOptions",
    "VerificationCommand",
    "VerificationMode",
    "VerificationPolicy",
    "__version__",
    "current_environment",
    "run",
]
