"""Test helpers: disposable fake environments built from metadata files only."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pytest

from python_env_repair.models import EnvironmentInfo, Platform

PIP_BODY = """# -*- coding: utf-8 -*-
import re
import sys
from {module} import {attr}
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])
    sys.exit({call}())
"""


def pip_script(interpreter: str, value: str) -> bytes:
    """A console script in the form pip writes."""
    module, attr = value.split(":")
    return f"#!{interpreter}\n".encode() + PIP_BODY.format(module=module, attr=attr.split(".")[0], call=attr).encode()


def windows_launcher(value: str, stub: bytes = b"MZ" + b"\0" * 64) -> bytes:
    """Bytes shaped like a distlib Windows launcher: PE stub, shebang, ZIP with __main__.py."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        module, attr = value.split(":")
        archive.writestr("__main__.py", PIP_BODY.format(module=module, attr=attr.split(".")[0], call=attr))
    return stub + b'#!"C:\\old\\venv\\Scripts\\python.exe"\n' + stream.getvalue()


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


@dataclass
class FakeEnv:
    """A fake environment: a scripts directory and a site-packages directory."""

    root: Path
    platform: Platform = Platform.LINUX
    python: Path = field(default_factory=lambda: Path(os.path.abspath(sys.executable)))

    def __post_init__(self) -> None:
        self.prefix = self.root / "venv"
        self.scripts = self.prefix / ("Scripts" if self.platform is Platform.WINDOWS else "bin")
        self.site = self.prefix / "lib" / "site-packages"
        self.scripts.mkdir(parents=True, exist_ok=True)
        self.site.mkdir(parents=True, exist_ok=True)

    def info(self, **overrides: object) -> EnvironmentInfo:
        values: dict[str, object] = {
            "python": self.python,
            "prefix": self.prefix,
            "base_prefix": self.root / "base",
            "scripts_dir": self.scripts,
            "metadata_roots": (self.site,),
            "platform": self.platform,
            "python_version": "3.11.12",
            "implementation": "cpython",
        }
        values.update(overrides)
        return EnvironmentInfo(**values)  # type: ignore[arg-type]

    def add_dist(self, name: str, version: str, console: dict[str, str], *, record_scripts: tuple[str, ...] = (), root: Optional[Path] = None, suffix: str = ".dist-info") -> Path:
        base = root or self.site
        meta = base / f"{name.replace('-', '_')}-{version}{suffix}"
        meta.mkdir(parents=True)
        (meta / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8")
        lines = ["[console_scripts]"] + [f"{key} = {value}" for key, value in console.items()]
        (meta / "entry_points.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
        record = []
        rel_scripts = os.path.relpath(self.scripts, base)
        for script in record_scripts:
            record.append(f"{rel_scripts}/{script},,")
        record.append(f"{meta.name}/METADATA,{_record_hash((meta / 'METADATA').read_bytes())},")
        record.append(f"{meta.name}/RECORD,,")
        (meta / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")
        return meta

    def write(self, name: str, data: bytes, mode: int = 0o755) -> Path:
        path = self.scripts / name
        path.write_bytes(data)
        if self.platform is not Platform.WINDOWS:
            os.chmod(path, mode)
        return path


def snapshot(root: Path) -> dict[str, tuple[str, int, int]]:
    """Content hash, mode, and mtime of every file under ``root``."""
    result: dict[str, tuple[str, int, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for filename in filenames:
            path = Path(dirpath) / filename
            st = os.lstat(path)
            digest = hashlib.sha256(path.read_bytes()).hexdigest() if not os.path.islink(path) else "link:" + os.readlink(path)
            result[str(path.relative_to(root))] = (digest, st.st_mode, st.st_mtime_ns)
        for dirname in dirnames:
            path = Path(dirpath) / dirname
            result[str(path.relative_to(root)) + "/"] = ("dir", os.lstat(path).st_mode, 0)
    return result


posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX behavior")
