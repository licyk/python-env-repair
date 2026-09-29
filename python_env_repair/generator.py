"""Console-script generator: Unix scripts and Windows launchers without a runtime dependency.

The output follows pip 26.2.1, which uses distlib's ``ScriptMaker`` with its own template:

* Unix: ``#!<python>`` when the path has no spaces and fits the kernel limit, otherwise
  distlib's ``/bin/sh`` wrapper, followed by the script text.
* Windows: a vendored distlib console launcher stub, then ``#!<python>``, then a ZIP
  archive holding ``__main__.py`` with the script text.

Differences from distlib are deliberate. The interpreter path is always quoted when it
contains spaces (distlib leaves an explicit executable unquoted). Paths that cannot be
quoted safely for ``/bin/sh`` are rejected. Without ``SOURCE_DATE_EPOCH`` the ZIP
timestamp is fixed, so the same inputs always produce the same bytes. With
``SOURCE_DATE_EPOCH`` set, output is byte-identical to distlib 0.4.3 configured with the
same template and executable.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import struct
import sysconfig
import time
import zipfile
from importlib import resources
from pathlib import Path
from typing import Optional

from python_env_repair.models import JsonDict, Platform, ReasonCode
from python_env_repair.platform import launcher_filename

TEMPLATE_ORIGIN = "pip 26.2.1"
STUB_ORIGIN = "distlib 0.4.3"

# pip 26.2.1 PipScriptMaker.script_template (pip/_internal/operations/install/wheel.py).
SCRIPT_TEMPLATE = """\
import sys
from %(module)s import %(import_name)s
if __name__ == '__main__':
    sys.argv[0] = sys.argv[0].removesuffix('.exe')
    sys.exit(%(func)s())
"""

LAUNCHER_STUBS = {
    "t32.exe": "6b4195e640a85ac32eb6f9628822a622057df1e459df7c17a12f97aeabc9415b",
    "t64.exe": "81a618f21cb87db9076134e70388b6e9cb7c2106739011b6a51772d22cae06b7",
    "t64-arm.exe": "ebc4c06b7d95e74e315419ee7e88e1d0f71e9e9477538c00a93a9ff8c66a6cfc",
}

_IDENTIFIER = r"(?!\d)\w+"
_MODULE = re.compile(rf"{_IDENTIFIER}(\.{_IDENTIFIER})*")
_ATTRIBUTE = _MODULE
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_MAX_SHEBANG = {Platform.LINUX: 127, Platform.MACOS: 512}
_UNSAFE_IN_SH_QUOTES = set('"$`\\')


class GenerationError(Exception):
    """Generation is impossible or unsafe for the given inputs."""

    def __init__(self, reason: ReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


def enquote_executable(executable: str) -> str:
    """Quote an interpreter path containing spaces, as distlib's ``enquote_executable`` does."""
    if " " not in executable or executable.startswith('"'):
        return executable
    if executable.startswith("/usr/bin/env "):
        env, rest = executable.split(" ", 1)
        return f'{env} "{rest}"' if " " in rest and not rest.startswith('"') else executable
    return f'"{executable}"'


def build_shebang(executable: str, platform: Platform, *, cross_compiling: bool = False) -> bytes:
    """Build the first line(s) that bind a script to ``executable``.

    Args:
        executable: Absolute interpreter path, unquoted.
        platform: Target platform.
        cross_compiling: Force the ``/bin/sh`` wrapper (distlib does this for cross builds).

    Returns:
        The shebang bytes, ending in a newline.

    Raises:
        GenerationError: If the path is not valid UTF-8 or cannot be quoted safely.
    """
    if any(char in executable for char in "\r\n\0"):
        raise GenerationError(ReasonCode.GENERATION_FAILED, "interpreter path contains a line break or NUL")
    try:
        quoted = enquote_executable(executable).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise GenerationError(ReasonCode.GENERATION_FAILED, f"interpreter path is not valid UTF-8: {exc}") from exc
    if platform is Platform.WINDOWS:
        return b"#!" + quoted + b"\n"
    simple = not cross_compiling and b" " not in quoted and len(quoted) + 3 <= _MAX_SHEBANG[platform]
    if simple:
        return b"#!" + quoted + b"\n"
    if any(char in _UNSAFE_IN_SH_QUOTES for char in executable):
        raise GenerationError(ReasonCode.GENERATION_FAILED, "interpreter path needs the /bin/sh wrapper but contains characters that cannot be quoted safely")
    if not quoted.startswith(b'"'):
        quoted = b'"' + quoted + b'"'
    return b"#!/bin/sh\n'''exec' " + quoted + b' "$0" "$@"\n' + b"' '''\n"


def script_text(module: str, attribute: str) -> bytes:
    """Render the script body for ``module:attribute``.

    Raises:
        GenerationError: If either part is not a dotted identifier.
    """
    if not _MODULE.fullmatch(module) or not _ATTRIBUTE.fullmatch(attribute):
        raise GenerationError(ReasonCode.GENERATION_FAILED, f"entry point {module}:{attribute} is not a dotted identifier reference")
    return (SCRIPT_TEMPLATE % {"module": module, "import_name": attribute.split(".", 1)[0], "func": attribute}).encode("utf-8")


def select_stub(platform_tag: Optional[str] = None, pointer_bits: Optional[int] = None) -> str:
    """Choose the console launcher stub for the interpreter's architecture (distlib's rule)."""
    tag = sysconfig.get_platform() if platform_tag is None else platform_tag
    bits = struct.calcsize("P") * 8 if pointer_bits is None else pointer_bits
    if tag == "win-arm64":
        return "t64-arm.exe"
    return "t64.exe" if bits == 64 else "t32.exe"


def load_stub(name: str) -> bytes:
    """Read a vendored launcher stub and check it against the pinned SHA-256.

    Raises:
        GenerationError: If the stub is unknown, missing, or modified.
    """
    expected = LAUNCHER_STUBS.get(name)
    if expected is None:
        raise GenerationError(ReasonCode.GENERATOR_UNAVAILABLE, f"no launcher stub named {name}")
    try:
        data = resources.files("python_env_repair").joinpath("_launchers").joinpath(name).read_bytes()
    except (OSError, FileNotFoundError) as exc:
        raise GenerationError(ReasonCode.GENERATOR_UNAVAILABLE, f"launcher stub {name} is missing: {exc}") from exc
    if hashlib.sha256(data).hexdigest() != expected:
        raise GenerationError(ReasonCode.GENERATOR_UNAVAILABLE, f"launcher stub {name} failed its integrity check")
    return data


def _zip_date_time() -> tuple[int, int, int, int, int, int]:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            moment = time.gmtime(int(epoch))[:6]
        except (ValueError, OverflowError, OSError):
            return _FIXED_ZIP_TIME
        return max(moment, _FIXED_ZIP_TIME)
    return _FIXED_ZIP_TIME


def build_windows_launcher(stub: bytes, shebang: bytes, script: bytes) -> bytes:
    """Concatenate a launcher stub, the shebang, and a ZIP archive holding ``__main__.py``."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(zipfile.ZipInfo(filename="__main__.py", date_time=_zip_date_time()), script)
    return stub + shebang + stream.getvalue()


def build_artifact(module: str, attribute: str, executable: str, platform: Platform, *, stub_name: Optional[str] = None) -> bytes:
    """Build the complete bytes of one console-script artifact."""
    shebang = build_shebang(executable, platform)
    script = script_text(module, attribute)
    if platform is Platform.WINDOWS:
        return build_windows_launcher(load_stub(stub_name or select_stub()), shebang, script)
    return shebang + script


def write_artifact(name: str, data: bytes, platform: Platform, directory: Path) -> Path:
    """Write an artifact into an empty staging directory (never over an existing file).

    On POSIX the mode becomes ``(mode | 0o555) & 0o7777`` after the umask, like distlib.
    """
    path = directory / launcher_filename(name, platform)
    with open(path, "xb") as handle:
        handle.write(data)
    if platform is not Platform.WINDOWS and os.name == "posix":
        os.chmod(path, (os.stat(path).st_mode | 0o555) & 0o7777)
    return path


def generator_info() -> JsonDict:
    """Describe the generator for reports."""
    return {"name": "python_env_repair.generator", "template": TEMPLATE_ORIGIN, "windows_stubs": STUB_ORIGIN, "available": True}
