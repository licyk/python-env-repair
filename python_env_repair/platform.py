"""Supported platform selection and filename policy."""

from __future__ import annotations

import os
import re
import sys
from typing import Optional

from python_env_repair.models import Platform


class UnsupportedPlatformError(RuntimeError):
    """Raised when the running operating system is not one of the supported platforms."""


_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(10)} | {f"LPT{i}" for i in range(10)}
_WINDOWS_FORBIDDEN_CHARS = set('<>:"|?*')
_INTERPRETER_NAME = re.compile(r"^pythonw?(\d+(\.\d+)?)?t?(\.exe)?$", re.IGNORECASE)
_MAX_NAME_LENGTH = 200


def detect_platform(sys_platform: Optional[str] = None) -> Platform:
    """Map ``sys.platform`` to a supported platform.

    Args:
        sys_platform: Value to classify; defaults to the running interpreter's ``sys.platform``.

    Returns:
        The supported platform.

    Raises:
        UnsupportedPlatformError: If the platform is not Windows, Linux, or macOS.
    """
    value = sys.platform if sys_platform is None else sys_platform
    if value == "win32":
        return Platform.WINDOWS
    if value == "darwin":
        return Platform.MACOS
    if value.startswith("linux"):
        return Platform.LINUX
    raise UnsupportedPlatformError(f"Unsupported platform: {value}")


def launcher_filename(name: str, platform: Platform) -> str:
    """Return the launcher filename the generator produces for an entry point name."""
    if platform is Platform.WINDOWS:
        # distlib drops a ".py*" suffix before appending ".exe".
        stem, ext = os.path.splitext(name)
        return f"{stem if ext.startswith('.py') else name}.exe"
    return name


def legacy_sidecar_filename(name: str, platform: Platform) -> Optional[str]:
    """Return the legacy Windows ``-script.py`` sidecar name, which is observed but never written."""
    if platform is Platform.WINDOWS:
        return f"{name}-script.py"
    return None


def collision_key(filename: str, platform: Platform) -> str:
    """Key under which two filenames refer to the same file on the platform.

    Windows and default macOS filesystems are case-insensitive, so names are case-folded there.
    """
    if platform in (Platform.WINDOWS, Platform.MACOS):
        return filename.casefold()
    return filename


def is_protected_interpreter_name(filename: str) -> bool:
    """Whether a filename looks like a Python interpreter that must never be replaced."""
    return bool(_INTERPRETER_NAME.match(filename))


def validate_entry_name(name: str, platform: Platform) -> Optional[str]:
    """Check that an entry point name maps to a safe filename inside the scripts directory.

    Args:
        name: Entry point name from metadata.
        platform: Target platform.

    Returns:
        ``None`` if the name is acceptable, otherwise a short explanation.
    """
    if not name:
        return "empty name"
    if len(name) > _MAX_NAME_LENGTH:
        return "name is too long"
    if name in (".", ".."):
        return "name refers to a directory"
    if "/" in name or "\\" in name:
        return "name contains a path separator"
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        return "name contains control characters"
    if any(char.isspace() for char in name):
        return "name contains whitespace"
    if name.startswith("-"):
        return "name starts with '-'"
    if name.startswith("["):
        return "name starts with '['"
    if platform is Platform.WINDOWS:
        if any(char in _WINDOWS_FORBIDDEN_CHARS for char in name):
            return "name contains a character that is invalid on Windows"
        if name.endswith((".", " ")):
            return "name ends with a dot or space"
        if name.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            return "name is a reserved Windows device name"
    return None
