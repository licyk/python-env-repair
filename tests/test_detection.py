"""Read-only discovery and detection behavior."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from python_env_repair.detector import detect, parse_unix_launcher
from python_env_repair.discovery import discover_console_scripts, installer_names
from python_env_repair.models import (
    ArtifactKind,
    DetectionStatus,
    Platform,
    PreviousArtifact,
    ReasonCode,
    RelocationContext,
    RelocationSource,
    RepairResult,
)
from python_env_repair.platform import validate_entry_name
from tests.helpers import FakeEnv, pip_script, posix_only, snapshot, windows_launcher


def run_detect(env: FakeEnv, relocation: RelocationContext | None = None) -> dict[str, RepairResult]:
    info = env.info()
    results = detect(info, discover_console_scripts(info), relocation or RelocationContext())
    return {f"{result.script.package}:{result.script.name}": result for result in results}


def by_name(results: dict[str, RepairResult], name: str) -> RepairResult:
    matches = [result for key, result in results.items() if key.endswith(":" + name)]
    assert len(matches) == 1, results.keys()
    return matches[0]


def test_valid_script_is_valid_and_untouched(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"}, record_scripts=("demo",))
    fake_env.write("demo", pip_script(str(fake_env.python), "demo.cli:main"))
    before = snapshot(fake_env.root)
    result = by_name(run_detect(fake_env), "demo")
    assert result.detection_status is DetectionStatus.VALID
    assert result.reason_code is ReasonCode.CURRENT_INTERPRETER
    assert result.script.launcher is not None and result.script.launcher.listed_in_record
    assert snapshot(fake_env.root) == before


def test_stale_shebang_is_candidate_with_evidence(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    fake_env.write("demo", pip_script("/old/venv/bin/python", "demo.cli:main"))
    result = by_name(run_detect(fake_env), "demo")
    assert result.candidate and result.reason_code is ReasonCode.STALE_SHEBANG
    assert result.evidence["observed_interpreter"] == "/old/venv/bin/python"
    assert result.evidence["expected_python"] == str(fake_env.python)
    assert result.evidence["interpreter_exists"] is False


def test_base_interpreter_behind_venv_symlink_is_stale(fake_env: FakeEnv) -> None:
    link = fake_env.scripts / "python"
    link.symlink_to(fake_env.python)
    env = fake_env
    env.python = link
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    # Shebang names the resolved base interpreter: same binary, but outside the environment.
    fake_env.write("demo", pip_script(os.path.realpath(link), "demo.cli:main"))
    result = by_name(run_detect(env), "demo")
    assert result.reason_code is ReasonCode.STALE_SHEBANG


def test_sibling_interpreter_name_is_accepted(fake_env: FakeEnv) -> None:
    python = fake_env.scripts / "python"
    python.symlink_to(fake_env.python)
    (fake_env.scripts / "python3").symlink_to(fake_env.python)
    fake_env.python = python
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    fake_env.write("demo", pip_script(str(fake_env.scripts / "python3"), "demo.cli:main"))
    assert by_name(run_detect(fake_env), "demo").detection_status is DetectionStatus.VALID


@posix_only
def test_missing_execute_bits_is_candidate(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    fake_env.write("demo", pip_script(str(fake_env.python), "demo.cli:main"), mode=0o644)
    result = by_name(run_detect(fake_env), "demo")
    assert result.candidate and result.reason_code is ReasonCode.MISSING_EXECUTE_PERMISSION


@posix_only
def test_access_denied_with_exec_bits_is_not_reduced_to_missing_bit(fake_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    path = fake_env.write("demo", pip_script(str(fake_env.python), "demo.cli:main"))
    real_access = os.access
    monkeypatch.setattr(os, "access", lambda p, mode: False if os.fspath(p) == str(path) else real_access(p, mode))
    result = by_name(run_detect(fake_env), "demo")
    assert result.detection_status is DetectionStatus.INVALID
    assert result.reason_code is ReasonCode.EXECUTE_ACCESS_DENIED
    assert not result.candidate


def test_missing_artifact_is_candidate(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    result = by_name(run_detect(fake_env), "demo")
    assert result.detection_status is DetectionStatus.MISSING and result.candidate


def test_standalone_binary_without_entry_point_is_never_enumerated(fake_env: FakeEnv) -> None:
    fake_env.write("uv", b"\x7fELF\x02\x01\x01" + b"\0" * 100)
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    results = run_detect(fake_env)
    assert all(result.script.name != "uv" for result in results.values())


def test_name_collision_with_binary_is_not_owned(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"ruff": "demo.cli:main"})
    fake_env.write("ruff", b"\x7fELF\x02\x01\x01" + b"\0" * 100)
    result = by_name(run_detect(fake_env), "ruff")
    assert result.detection_status is DetectionStatus.SKIPPED
    assert result.reason_code is ReasonCode.ARTIFACT_NOT_OWNED
    assert not result.candidate


def test_wrapper_for_other_entry_point_is_unknown(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    fake_env.write("demo", pip_script("/old/venv/bin/python", "other.module:run"))
    result = by_name(run_detect(fake_env), "demo")
    assert result.detection_status is DetectionStatus.UNKNOWN
    assert result.reason_code is ReasonCode.UNRECOGNIZED_WRAPPER
    assert not result.candidate


@pytest.mark.parametrize(
    "first_lines",
    [
        b"#!/usr/bin/env python\n",
        b"#!/bin/sh\n'''exec' \"$(dirname -- \"$(realpath -- \"$0\")\")\"/'python' \"$0\" \"$@\"\n' '''\n",
    ],
)
def test_unsupported_wrapper_forms_are_unknown(fake_env: FakeEnv, first_lines: bytes) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    body = pip_script("/x/python", "demo.cli:main").split(b"\n", 1)[1]
    fake_env.write("demo", first_lines + body)
    result = by_name(run_detect(fake_env), "demo")
    assert result.detection_status is DetectionStatus.UNKNOWN
    assert result.reason_code is ReasonCode.UNRECOGNIZED_WRAPPER


def test_shell_wrapper_is_not_confused_with_wrong_interpreter(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    body = pip_script("/x/python", "demo.cli:main").split(b"\n", 1)[1]
    wrapper = f"#!/bin/sh\n'''exec' \"{fake_env.python}\" \"$0\" \"$@\"\n' '''\n".encode() + body
    fake_env.write("demo", wrapper)
    result = by_name(run_detect(fake_env), "demo")
    assert result.detection_status is DetectionStatus.VALID
    assert result.script.launcher is not None and result.script.launcher.kind is ArtifactKind.SHELL_WRAPPER


def test_unquoted_distlib_wrapper_is_candidate(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    body = pip_script("/x/python", "demo.cli:main").split(b"\n", 1)[1]
    fake_env.write("demo", b"#!/bin/sh\n'''exec' /opt/my venv/bin/python \"$0\" \"$@\"\n' '''\n" + body)
    result = by_name(run_detect(fake_env), "demo")
    assert result.candidate and result.reason_code is ReasonCode.UNQUOTED_INTERPRETER


def test_parse_unix_launcher_forms() -> None:
    direct = parse_unix_launcher(b"#!/v/bin/python -E\nx")
    assert direct is not None and direct.interpreter == "/v/bin/python" and direct.interpreter_args == "-E"
    quoted = parse_unix_launcher(b'#!"/my venv/bin/python"\nx')
    assert quoted is not None and quoted.interpreter == "/my venv/bin/python"
    wrapper = parse_unix_launcher(b"#!/bin/sh\n'''exec' \"/my venv/bin/python\" \"$0\" \"$@\"\n' '''\nbody")
    assert wrapper is not None and wrapper.kind is ArtifactKind.SHELL_WRAPPER and wrapper.body == b"body"
    # distlib's unquoted output for an interpreter path containing spaces.
    broken = parse_unix_launcher(b"#!/bin/sh\n'''exec' /my venv/bin/python \"$0\" \"$@\"\n' '''\n")
    assert broken is not None and broken.unquoted_space and broken.interpreter == "/my venv/bin/python"
    assert parse_unix_launcher(b"#!/usr/bin/env python\n") is None
    assert parse_unix_launcher(b"#!/bin/bash\n") is None
    assert parse_unix_launcher(b"\x7fELF") is None


def test_metadata_scope_excludes_other_roots(fake_env: FakeEnv, tmp_path: Path) -> None:
    outside = tmp_path / "user-site"
    outside.mkdir()
    fake_env.add_dist("ambient", "1.0", {"ambient": "ambient:main"}, root=outside)
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    results = run_detect(fake_env)
    assert [result.script.name for result in results.values()] == ["demo"]


def test_duplicate_entry_point_owners_are_rejected(fake_env: FakeEnv) -> None:
    fake_env.add_dist("one", "1.0", {"tool": "one:main"})
    fake_env.add_dist("two", "1.0", {"tool": "two:main"})
    results = run_detect(fake_env)
    assert {result.reason_code for result in results.values()} == {ReasonCode.ENTRY_POINT_CONFLICT}
    assert not any(result.candidate for result in results.values())


@pytest.mark.parametrize("platform", [Platform.WINDOWS, Platform.MACOS])
def test_case_insensitive_collision(tmp_path: Path, platform: Platform) -> None:
    env = FakeEnv(tmp_path, platform=platform)
    env.add_dist("one", "1.0", {"Tool": "one:main"})
    env.add_dist("two", "1.0", {"tool": "two:main"})
    results = run_detect(env)
    assert {result.reason_code for result in results.values()} == {ReasonCode.NAME_COLLISION}


def test_linux_names_differing_in_case_are_distinct(fake_env: FakeEnv) -> None:
    fake_env.add_dist("one", "1.0", {"Tool": "one:main"})
    fake_env.add_dist("two", "1.0", {"tool": "two:main"})
    assert all(result.candidate for result in run_detect(fake_env).values())


@pytest.mark.parametrize("name", ["../escape", "a/b", "a\\b", "..", "with space", "ctl\x07", "-flag"])
def test_unsafe_names_are_rejected(fake_env: FakeEnv, name: str) -> None:
    assert validate_entry_name(name, Platform.LINUX) is not None


@pytest.mark.parametrize("name", ["CON", "nul.txt", "a:b", "trail.", "q?"])
def test_windows_invalid_names(name: str) -> None:
    assert validate_entry_name(name, Platform.WINDOWS) is not None
    assert validate_entry_name("normal-name_1.2", Platform.WINDOWS) is None


def test_invalid_entry_value_is_skipped(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "not a reference", "ok": "demo:main"})
    results = run_detect(fake_env)
    assert by_name(results, "demo").reason_code is ReasonCode.INVALID_ENTRY_POINT
    assert by_name(results, "ok").candidate


def test_protected_interpreter_name(fake_env: FakeEnv) -> None:
    fake_env.add_dist("evil", "1.0", {"python3": "evil:main"})
    result = by_name(run_detect(fake_env), "python3")
    assert result.reason_code is ReasonCode.PROTECTED_INTERPRETER and not result.candidate


def test_symlink_artifact_is_not_writable(fake_env: FakeEnv, tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_bytes(pip_script("/old/python", "demo.cli:main"))
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    (fake_env.scripts / "demo").symlink_to(target)
    result = by_name(run_detect(fake_env), "demo")
    assert result.reason_code is ReasonCode.SYMLINK_NOT_SUPPORTED and not result.candidate


def test_hardlinked_stale_artifact_is_not_writable(fake_env: FakeEnv, tmp_path: Path) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    path = fake_env.write("demo", pip_script("/old/python", "demo.cli:main"))
    os.link(path, tmp_path / "other-link")
    result = by_name(run_detect(fake_env), "demo")
    assert result.reason_code is ReasonCode.HARDLINK_NOT_SUPPORTED and not result.candidate


def test_installer_names_follow_pip_rules() -> None:
    names = installer_names([("pip", "pip:main"), ("pip3", "pip:main"), ("pip3.10", "pip:main"), ("other", "x:y")], "3.11.4")
    assert [(name, alias) for name, _, alias in names] == [("pip", True), ("pip3", True), ("pip3.11", True), ("other", False)]


def test_absent_installer_alias_is_not_created(fake_env: FakeEnv) -> None:
    fake_env.add_dist("pip", "26.0", {"pip": "pip._internal.cli.main:main", "pip3.10": "pip._internal.cli.main:main"})
    fake_env.write("pip3.11", pip_script(str(fake_env.python), "pip._internal.cli.main:main"))
    results = run_detect(fake_env)
    assert by_name(results, "pip3.11").detection_status is DetectionStatus.VALID
    assert by_name(results, "pip").reason_code is ReasonCode.INSTALLER_ALIAS_ABSENT
    assert not any(result.script.name == "pip3.10" for result in results.values())


def test_script_ids_are_deterministic(fake_env: FakeEnv) -> None:
    fake_env.add_dist("b", "1.0", {"zeta": "b:main", "alpha": "b:main"})
    fake_env.add_dist("a", "1.0", {"Beta": "a:main"})
    first = [(result.script.script_id, result.script.name) for result in run_detect(fake_env).values()]
    second = [(result.script.script_id, result.script.name) for result in run_detect(fake_env).values()]
    assert first == second == [("script-0001", "alpha"), ("script-0002", "Beta"), ("script-0003", "zeta")]


# Windows detection logic, exercised with synthetic launchers on any OS. This is not
# native Windows launcher validation.


def test_windows_launcher_without_evidence_is_unknown(windows_env: FakeEnv) -> None:
    windows_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    windows_env.write("demo.exe", windows_launcher("demo.cli:main"))
    result = by_name(run_detect(windows_env), "demo")
    assert result.detection_status is DetectionStatus.UNKNOWN
    assert result.reason_code is ReasonCode.WINDOWS_LAUNCHER_UNVERIFIABLE
    assert not result.candidate


def test_windows_relocation_assertion_rebuilds_only_owned_launchers(windows_env: FakeEnv) -> None:
    windows_env.add_dist("demo", "1.0", {"demo": "demo.cli:main", "uv": "demo.fake:main"})
    windows_env.write("demo.exe", windows_launcher("demo.cli:main"))
    windows_env.write("uv.exe", b"MZ" + b"\0" * 200)
    windows_env.write("ruff.exe", b"MZ" + b"\0" * 200)
    results = run_detect(windows_env, RelocationContext(source=RelocationSource.CALLER_ASSERTION))
    assert by_name(results, "demo").reason_code is ReasonCode.RELOCATION_CONFIRMED
    assert by_name(results, "demo").candidate
    assert by_name(results, "uv").reason_code is ReasonCode.ARTIFACT_NOT_OWNED
    assert not any(result.script.name == "ruff" for result in results.values())


def test_windows_previous_manifest_evidence(windows_env: FakeEnv) -> None:
    windows_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    path = windows_env.write("demo.exe", windows_launcher("demo.cli:main"))
    from python_env_repair.detector import sha256_bytes

    digest = sha256_bytes(path.read_bytes())
    moved = RelocationContext(source=RelocationSource.PREVIOUS_MANIFEST, previous_python="D:/old/venv/Scripts/python.exe", previous_artifacts={"demo": (PreviousArtifact("demo.exe", digest),)})
    assert by_name(run_detect(windows_env, moved), "demo").reason_code is ReasonCode.RELOCATION_MANIFEST
    same = RelocationContext(source=RelocationSource.PREVIOUS_MANIFEST, previous_python="C:/new/venv/Scripts/python.exe", previous_artifacts={"demo": (PreviousArtifact("demo.exe", digest),)})
    assert by_name(run_detect(windows_env, same), "demo").reason_code is ReasonCode.MANIFEST_MATCHES_ENVIRONMENT
    changed = RelocationContext(source=RelocationSource.PREVIOUS_MANIFEST, previous_python="C:/new/venv/Scripts/python.exe", previous_artifacts={"demo": (PreviousArtifact("demo.exe", "0" * 64),)})
    assert by_name(run_detect(windows_env, changed), "demo").reason_code is ReasonCode.WINDOWS_LAUNCHER_UNVERIFIABLE


def test_windows_legacy_sidecar_layout_is_reported_not_changed(windows_env: FakeEnv) -> None:
    windows_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    windows_env.write("demo.exe", b"MZ" + b"\0" * 200)
    windows_env.write("demo-script.py", pip_script("C:/old/python.exe", "demo.cli:main"))
    results = run_detect(windows_env, RelocationContext(source=RelocationSource.CALLER_ASSERTION))
    result = by_name(results, "demo")
    assert result.reason_code is ReasonCode.LEGACY_SIDECAR_LAYOUT and not result.candidate
    assert any(artifact.role.value == "legacy_sidecar" for artifact in result.script.artifacts)


def test_windows_missing_launcher_is_candidate(windows_env: FakeEnv) -> None:
    windows_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    result = by_name(run_detect(windows_env), "demo")
    assert result.candidate and result.script.launcher is not None and result.script.launcher.path.name == "demo.exe"


def test_hand_written_wrapper_is_not_owned_without_record(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    custom = b"#!/old/venv/bin/python\nimport os\nos.environ['DEMO_MODE'] = 'custom'\nfrom demo.cli import main\nmain()\n"
    fake_env.write("demo", custom)
    result = by_name(run_detect(fake_env), "demo")
    assert result.reason_code is ReasonCode.UNRECOGNIZED_WRAPPER and not result.candidate


def test_record_listed_wrapper_with_other_template_is_owned(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"}, record_scripts=("demo",))
    fake_env.write("demo", b"#!/old/venv/bin/python\nimport sys\nfrom demo.cli import main\nraise SystemExit(main())\n")
    assert by_name(run_detect(fake_env), "demo").reason_code is ReasonCode.STALE_SHEBANG


def test_windows_py_suffix_maps_like_distlib(windows_env: FakeEnv) -> None:
    from python_env_repair.platform import launcher_filename

    assert launcher_filename("foo.py", Platform.WINDOWS) == "foo.exe"
    assert launcher_filename("foo.pyw", Platform.WINDOWS) == "foo.exe"
    windows_env.add_dist("one", "1.0", {"foo": "one:main"})
    windows_env.add_dist("two", "1.0", {"foo.py": "two:main"})
    assert {result.reason_code for result in run_detect(windows_env).values()} == {ReasonCode.NAME_COLLISION}


def test_previous_report_hashes_only_trusted_entries(tmp_path: Path) -> None:
    import json

    from python_env_repair.manifest import load_previous_manifest

    def entry(name: str, status: str) -> dict:
        return {"name": name, "overall_status": status, "artifacts": [{"role": "launcher", "path": f"C:\\\\new\\\\Scripts\\\\{name}.exe", "sha256": "ab" * 32}]}

    report = {
        "schema_version": 1,
        "kind": "python_env_repair.report",
        "environment": {"python": "C:\\new\\python.exe"},
        "entries": [entry("a", "unverified"), entry("b", "repaired"), entry("c", "planned")],
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    evidence = load_previous_manifest(path).previous_artifacts
    assert {name: items[0].sha256 for name, items in evidence.items()} == {"a": None, "b": "ab" * 32, "c": None}
    assert evidence["b"][0].filename == "b.exe"


def test_pip26_template_is_owned_without_record(fake_env: FakeEnv) -> None:
    fake_env.add_dist("demo", "1.0", {"demo": "demo.cli:main"})
    body = b"import sys\nfrom demo.cli import main\nif __name__ == '__main__':\n    sys.argv[0] = sys.argv[0].removesuffix('.exe')\n    sys.exit(main())\n"
    fake_env.write("demo", b"#!/old/venv/bin/python\n" + body)
    assert by_name(run_detect(fake_env), "demo").reason_code is ReasonCode.STALE_SHEBANG
