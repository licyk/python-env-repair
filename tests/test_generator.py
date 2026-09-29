"""Built-in generator: byte equivalence with distlib, stubs, and safety checks."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from python_env_repair import generator
from python_env_repair.detector import ConsoleScript, is_generated_wrapper, parse_unix_launcher, windows_launcher_matches
from python_env_repair.generator import GenerationError, build_artifact, build_shebang, load_stub, script_text, select_stub
from python_env_repair.models import ArtifactKind, Platform, ReasonCode

distlib_scripts = pytest.importorskip("distlib.scripts", reason="distlib is a test-only dependency")

MODULE, ATTRIBUTE = "pkg.cli", "app.main"


def script(name: str = "tool") -> ConsoleScript:
    return ConsoleScript(script_id="script-0001", name=name, value=f"{MODULE}:{ATTRIBUTE}", package="pkg", version="1.0", metadata_path=Path("pkg-1.0.dist-info"))


def distlib_output(tmp_path: Path, executable: str, *, windows_stub: bytes | None = None) -> bytes:
    maker = distlib_scripts.ScriptMaker(None, str(tmp_path), add_launchers=windows_stub is not None)
    maker.script_template = generator.SCRIPT_TEMPLATE
    maker.executable = distlib_scripts.enquote_executable(executable)
    maker.variants = {""}
    if windows_stub is not None:
        # Exercise distlib's Windows launcher assembly on any OS with the same stub bytes.
        maker._is_nt = True
        maker._get_launcher = lambda kind: windows_stub  # type: ignore[attr-defined]
    written = maker.make(f"tool = {MODULE}:{ATTRIBUTE}")
    assert len(written) == 1
    return Path(written[0]).read_bytes()


@pytest.mark.parametrize("executable", ["/opt/venv/bin/python", "/opt/vénv/bin/python3.11", "/opt/my venv/bin/python"])
def test_unix_output_matches_distlib(tmp_path: Path, executable: str) -> None:
    assert build_artifact(MODULE, ATTRIBUTE, executable, Platform.LINUX) == distlib_output(tmp_path, executable)


def test_windows_launcher_matches_distlib(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    stub = load_stub("t64.exe")
    executable = "C:\\venv\\Scripts\\python.exe"
    assert build_artifact(MODULE, ATTRIBUTE, executable, Platform.WINDOWS, stub_name="t64.exe") == distlib_output(tmp_path, executable, windows_stub=stub)


def test_long_path_uses_quoted_shell_wrapper() -> None:
    executable = "/opt/" + "x" * 140 + "/bin/python"
    shebang = build_shebang(executable, Platform.LINUX)
    assert shebang == b"#!/bin/sh\n'''exec' \"" + executable.encode() + b'" "$0" "$@"\n' + b"' '''\n"
    assert build_shebang(executable, Platform.MACOS) == b"#!" + executable.encode() + b"\n"
    launcher = parse_unix_launcher(shebang + script_text(MODULE, ATTRIBUTE))
    assert launcher is not None and launcher.kind is ArtifactKind.SHELL_WRAPPER and launcher.interpreter == executable


def test_windows_shebang_quotes_spaces() -> None:
    assert build_shebang("C:\\Program Files\\venv\\python.exe", Platform.WINDOWS) == b'#!"C:\\Program Files\\venv\\python.exe"\n'


@pytest.mark.parametrize("executable", ["/opt/my $HOME/python", '/opt/my "q"/python', "/opt/my `x`/python", "/opt/a\\ b/python", "/opt/venv/bin/python\n"])
def test_unsafe_interpreter_paths_are_rejected(executable: str) -> None:
    with pytest.raises(GenerationError) as info:
        build_shebang(executable, Platform.LINUX)
    assert info.value.reason is ReasonCode.GENERATION_FAILED


@pytest.mark.parametrize("module, attribute", [("pkg;import os", "main"), ("pkg", "main()"), ("1pkg", "main"), ("pkg", "")])
def test_script_text_rejects_non_identifiers(module: str, attribute: str) -> None:
    with pytest.raises(GenerationError):
        script_text(module, attribute)


def test_generated_output_is_recognized_by_detector(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    unix = build_artifact(MODULE, ATTRIBUTE, "/opt/venv/bin/python", Platform.LINUX)
    launcher = parse_unix_launcher(unix)
    assert launcher is not None and is_generated_wrapper(launcher.body, script())
    windows = build_artifact(MODULE, ATTRIBUTE, "C:\\venv\\Scripts\\python.exe", Platform.WINDOWS, stub_name="t64.exe")
    assert windows_launcher_matches(windows, script())
    assert windows == build_artifact(MODULE, ATTRIBUTE, "C:\\venv\\Scripts\\python.exe", Platform.WINDOWS, stub_name="t64.exe")


def test_stub_selection() -> None:
    assert select_stub("win-amd64", 64) == "t64.exe"
    assert select_stub("win32", 32) == "t32.exe"
    assert select_stub("win-arm64", 64) == "t64-arm.exe"


def test_stubs_are_intact_and_pinned() -> None:
    for name, digest in generator.LAUNCHER_STUBS.items():
        data = load_stub(name)
        assert data.startswith(b"MZ") and hashlib.sha256(data).hexdigest() == digest


def test_modified_stub_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(generator.LAUNCHER_STUBS, "t64.exe", "0" * 64)
    with pytest.raises(GenerationError) as info:
        load_stub("t64.exe")
    assert info.value.reason is ReasonCode.GENERATOR_UNAVAILABLE
    with pytest.raises(GenerationError):
        load_stub("w64.exe")


def test_vendored_stubs_match_distlib_release() -> None:
    import distlib

    source = Path(distlib.__file__).parent
    if getattr(distlib, "__version__", None) != "0.4.3":
        pytest.skip("comparison is pinned to distlib 0.4.3")
    for name in generator.LAUNCHER_STUBS:
        assert load_stub(name) == (source / name).read_bytes()
