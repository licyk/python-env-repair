"""Native acceptance on POSIX: a real venv, a pip-installed local wheel, a moved environment.

Fixture preparation (venv creation and an offline ``pip install --no-index``) is a separate
phase; snapshots are taken after it. The repair utility is then invoked as
``<moved-venv>/bin/python -B -m python_env_repair`` with sockets and subprocess creation
disabled, so any network access or installer invocation would fail the run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.helpers import snapshot

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX native acceptance")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GUARD = """
import runpy, socket, subprocess, sys
class _BlockedSocket(socket.socket):
    def __init__(self, *args, **kwargs):
        raise RuntimeError("network access blocked during repair")
class _BlockedPopen(subprocess.Popen):
    def __init__(self, *args, **kwargs):
        raise RuntimeError("subprocess blocked during repair: " + repr(args[:1]))
socket.socket = _BlockedSocket
subprocess.Popen = _BlockedPopen
sys.argv = ["python_env_repair"] + sys.argv[1:]
runpy.run_module("python_env_repair", run_name="__main__", alter_sys=True)
"""


def _hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def build_wheel(directory: Path) -> Path:
    files = {
        "demo_pkg/__init__.py": b"def main():\n    print('demo ok')\n    return 0\n\ndef other():\n    return 0\n",
        "demo_pkg-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: demo-pkg\nVersion: 1.0\n",
        "demo_pkg-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "demo_pkg-1.0.dist-info/entry_points.txt": b"[console_scripts]\ndemo-tool = demo_pkg:main\ndemo-other = demo_pkg:other\ncollide = demo_pkg:other\n",
    }
    record = [f"{name},{_hash(data)},{len(data)}" for name, data in files.items()] + ["demo_pkg-1.0.dist-info/RECORD,,"]
    wheel = directory / "demo_pkg-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("demo_pkg-1.0.dist-info/RECORD", "\n".join(record) + "\n")
    return wheel


@pytest.fixture(scope="module")
def installed_venv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("native")
    venv = base / "prepared" / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=120)
    wheel = build_wheel(base)
    subprocess.run(
        [sys.executable, "-m", "pip", "--python", str(venv / "bin" / "python"), "install", "--no-index", "--no-deps", "--no-compile", "--disable-pip-version-check", "-q", str(wheel)],
        check=True,
        timeout=300,
    )
    assert (venv / "bin" / "demo-tool").exists()
    # An unrelated native binary occupying a metadata-declared name, and a standalone binary.
    (venv / "bin" / "collide").write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 64)
    (venv / "bin" / "uv").write_bytes(b"\x7fELF\x02\x01\x01" + b"\1" * 64)
    os.chmod(venv / "bin" / "uv", 0o755)
    return venv


@pytest.fixture
def moved_venv(installed_venv: Path, tmp_path: Path) -> Path:
    staged = tmp_path / "old-location" / "venv"
    shutil.copytree(installed_venv, staged, symlinks=True)
    # Make the pip-generated scripts point at the pre-move location, then move the tree.
    for name in ("demo-tool", "demo-other"):
        path = staged / "bin" / name
        path.write_bytes(path.read_bytes().replace(str(installed_venv).encode(), str(staged).encode()))
    # The new location contains a space, so regenerated scripts need the quoted /bin/sh wrapper.
    target = tmp_path / "new location" / "venv"
    target.parent.mkdir()
    os.rename(staged, target)
    return target


@pytest.fixture
def tool_path(tmp_path: Path) -> str:
    """PYTHONPATH exposing only this package (no third-party dependency) to the target interpreter."""
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "python_env_repair").symlink_to(PROJECT_ROOT / "python_env_repair")
    return str(tools)


def run_tool(venv: Path, tool_path: str, *args: str) -> tuple[int, dict]:
    env = dict(os.environ, PYTHONPATH=tool_path)
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    completed = subprocess.run([str(venv / "bin" / "python"), "-B", "-c", GUARD, *args, "--json"], capture_output=True, text=True, env=env, timeout=120, cwd=venv.parent)
    assert completed.stdout, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def statuses(report: dict) -> dict[str, str]:
    return {entry["name"]: entry["overall_status"] for entry in report["entries"]}


def test_moved_environment_is_repaired(moved_venv: Path, tool_path: str) -> None:
    python = moved_venv / "bin" / "python"
    interpreter = subprocess.run([str(python), "-c", "import sys; print(sys.prefix)"], capture_output=True, text=True, timeout=60)
    assert interpreter.returncode == 0, "interpreter relocation failure (not a console-script failure)"
    with pytest.raises(FileNotFoundError):  # the shebang interpreter no longer exists
        subprocess.run([str(moved_venv / "bin" / "demo-tool")], capture_output=True, timeout=60)

    site = snapshot(moved_venv / "lib")
    binaries = {name: (moved_venv / "bin" / name).read_bytes() for name in ("collide", "uv", "python")}
    code, report = run_tool(moved_venv, tool_path, "repair")
    assert code == 0, report
    assert statuses(report) == {"collide": "skipped", "demo-other": "repaired", "demo-tool": "repaired"}
    assert report["environment"]["python"] == str(python)
    assert report["diagnostics"]["file_logging"] is False

    # Compare before running any entry point: running one may legitimately write bytecode.
    assert snapshot(moved_venv / "lib") == site
    assert {name: (moved_venv / "bin" / name).read_bytes() for name in binaries} == binaries
    head = (moved_venv / "bin" / "demo-tool").read_bytes().split(b"\n", 2)
    assert head[0] == b"#!/bin/sh" and head[1].startswith(b"'" * 3 + b"exec' " + f'"{python}"'.encode())
    fixed = subprocess.run([str(moved_venv / "bin" / "demo-tool")], capture_output=True, text=True, timeout=60)
    assert fixed.returncode == 0 and fixed.stdout.strip() == "demo ok"
    assert sorted(path.name for path in (moved_venv / "bin").iterdir() if path.name.startswith("demo")) == ["demo-other", "demo-tool"]


def test_detect_and_dry_run_write_nothing(moved_venv: Path, tool_path: str) -> None:
    before = snapshot(moved_venv.parent)
    code, report = run_tool(moved_venv, tool_path, "detect")
    assert code == 0 and statuses(report)["demo-tool"] == "planned"
    code, report = run_tool(moved_venv, tool_path, "repair", "--dry-run")
    assert code == 0 and statuses(report)["demo-tool"] == "planned"
    assert snapshot(moved_venv.parent) == before


def test_second_repair_and_verification(moved_venv: Path, tool_path: str) -> None:
    run_tool(moved_venv, tool_path, "repair")
    before = snapshot(moved_venv.parent)
    code, report = run_tool(moved_venv, tool_path, "repair")
    assert code == 0 and report["summary"]["artifacts"]["modified"] == 0
    assert snapshot(moved_venv.parent) == before
    code, report = run_tool(moved_venv, tool_path, "verify")
    assert code == 0 and statuses(report) == {"collide": "skipped", "demo-other": "valid", "demo-tool": "valid"}


def test_explicit_startup_verification(moved_venv: Path, tool_path: str) -> None:
    run_tool(moved_venv, tool_path, "repair")
    env = dict(os.environ, PYTHONPATH=tool_path)
    completed = subprocess.run(
        [str(moved_venv / "bin" / "python"), "-B", "-m", "python_env_repair", "verify", "--json", "--verification", "execute", "--verify-command", "demo-tool=", "--verify-command", "demo-other="],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    report = json.loads(completed.stdout)
    assert completed.returncode == 0, report
    tool = next(entry for entry in report["entries"] if entry["name"] == "demo-tool")
    invocation = tool["verification"][1]
    assert invocation["status"] == "passed" and invocation["details"]["stdout"]["text"].strip() == "demo ok"
    assert "demo ok" not in completed.stdout.split("{", 1)[0]
