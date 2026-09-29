"""Identify the target environment from the running interpreter."""

from __future__ import annotations

import os
import platform as _platform
import sys
import sysconfig
from pathlib import Path

from python_env_repair.models import EnvironmentInfo
from python_env_repair.platform import detect_platform


class EnvironmentDetectionError(RuntimeError):
    """Raised when the target environment cannot be identified safely."""


def _absolute(path: str) -> Path:
    # abspath normalizes the path lexically without resolving symlinks, so a venv's
    # bin/python symlink is kept instead of being replaced by the base interpreter.
    return Path(os.path.abspath(path))


def _dedupe_roots(paths: list[str]) -> tuple[Path, ...]:
    seen: set[str] = set()
    roots: list[Path] = []
    for raw in paths:
        if not raw:
            continue
        path = _absolute(raw)
        key = os.path.normcase(os.path.realpath(path))
        if key in seen:
            continue
        seen.add(key)
        roots.append(path)
    return tuple(roots)


def current_environment() -> EnvironmentInfo:
    """Describe the environment of the interpreter running this utility.

    Only the installation scheme's ``purelib`` and ``platlib`` directories are used as
    metadata roots. User site-packages, base-interpreter site-packages visible through
    ``--system-site-packages``, and ``PYTHONPATH`` entries are outside the repair scope.

    Returns:
        The environment description.

    Raises:
        EnvironmentDetectionError: If the interpreter path or scripts directory is unknown.
        UnsupportedPlatformError: If the operating system is not supported.
    """
    platform = detect_platform()
    if not sys.executable:
        raise EnvironmentDetectionError("sys.executable is empty; the target interpreter path is unknown")
    scripts = sysconfig.get_path("scripts")
    if not scripts:
        raise EnvironmentDetectionError("sysconfig did not report a scripts directory")
    roots = _dedupe_roots([sysconfig.get_path("purelib"), sysconfig.get_path("platlib")])
    if not roots:
        raise EnvironmentDetectionError("sysconfig did not report any site-packages directory")
    return EnvironmentInfo(
        python=_absolute(sys.executable),
        prefix=_absolute(sys.prefix),
        base_prefix=_absolute(getattr(sys, "base_prefix", sys.prefix)),
        scripts_dir=_absolute(scripts),
        metadata_roots=roots,
        platform=platform,
        python_version=_platform.python_version(),
        implementation=sys.implementation.name,
    )
