"""Staged repair, recovery, and verification integration (POSIX, real distlib)."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from python_env_repair import repair as repair_module
from python_env_repair.detector import parse_unix_launcher
from python_env_repair.lock import EnvironmentLock
from python_env_repair.models import (
    Operation,
    OverallStatus,
    ReasonCode,
    RepairReport,
    RepairStatus,
    VerificationCommand,
    VerificationMode,
    VerificationPolicy,
    VerificationStatus,
)
from python_env_repair.repair import STAGING_PREFIX
from python_env_repair.workflow import RunOptions, run
from tests.helpers import FakeEnv, pip_script, posix_only, snapshot

pytestmark = posix_only

JSON_TOOL = "json.tool:main"


def repair(env: FakeEnv, policy: VerificationPolicy | None = None, dry_run: bool = False) -> RepairReport:
    return run(RunOptions(operation=Operation.REPAIR, dry_run=dry_run, verification=policy or VerificationPolicy()), env=env.info())


def entry(report: RepairReport, name: str):
    return next(result for result in report.results if result.script.name == name)


def no_staging_left(env: FakeEnv) -> bool:
    return not any(path.name.startswith(STAGING_PREFIX) for path in env.scripts.iterdir())


def test_stale_script_is_regenerated_and_runs(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    fake_env.write("jt", pip_script("/old/venv/bin/python", JSON_TOOL))
    report = repair(fake_env)
    result = entry(report, "jt")
    assert result.overall_status is OverallStatus.REPAIRED
    assert result.repair_status is RepairStatus.WRITTEN
    assert result.verification[0].message == "structural verification passed; startup not checked"
    launcher = parse_unix_launcher((fake_env.scripts / "jt").read_bytes())
    assert launcher is not None and launcher.interpreter == str(fake_env.python)
    completed = subprocess.run([str(fake_env.scripts / "jt"), "--help"], capture_output=True, timeout=60)
    assert completed.returncode == 0
    assert report.exit_code == 0 and no_staging_left(fake_env)


def test_valid_scripts_stay_byte_identical_and_second_run_writes_nothing(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL, "stale": JSON_TOOL})
    fake_env.write("jt", pip_script(str(fake_env.python), JSON_TOOL))
    fake_env.write("stale", pip_script("/old/python", JSON_TOOL))
    before = (fake_env.scripts / "jt").read_bytes(), os.stat(fake_env.scripts / "jt").st_mtime_ns
    first = repair(fake_env)
    assert entry(first, "stale").overall_status is OverallStatus.REPAIRED
    assert ((fake_env.scripts / "jt").read_bytes(), os.stat(fake_env.scripts / "jt").st_mtime_ns) == before
    snap = snapshot(fake_env.root)
    second = repair(fake_env)
    assert second.summary.artifacts_modified == 0
    assert all(result.overall_status is OverallStatus.VALID for result in second.results)
    assert snapshot(fake_env.root) == snap


def test_missing_artifact_created_without_version_variants(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    report = repair(fake_env)
    assert entry(report, "jt").overall_status is OverallStatus.REPAIRED
    assert sorted(path.name for path in fake_env.scripts.iterdir()) == ["jt"]
    assert os.stat(fake_env.scripts / "jt").st_mode & 0o111


def test_mode_is_preserved_and_execute_added_for_readers(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    fake_env.write("jt", pip_script(str(fake_env.python), JSON_TOOL), mode=0o640)
    report = repair(fake_env)
    assert entry(report, "jt").reason_code is ReasonCode.MISSING_EXECUTE_PERMISSION
    assert stat.S_IMODE(os.stat(fake_env.scripts / "jt").st_mode) == 0o750


def test_dry_run_writes_nothing(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL, "gone": JSON_TOOL})
    fake_env.write("jt", pip_script("/old/python", JSON_TOOL))
    before = snapshot(fake_env.root)
    report = repair(fake_env, dry_run=True)
    assert {result.overall_status for result in report.results} == {OverallStatus.PLANNED}
    assert snapshot(fake_env.root) == before


def test_standalone_binary_collision_is_left_unchanged(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"ruff": JSON_TOOL})
    binary = b"\x7fELF\x02\x01\x01" + b"\0" * 64
    fake_env.write("ruff", binary)
    report = repair(fake_env)
    assert entry(report, "ruff").overall_status is OverallStatus.SKIPPED
    assert (fake_env.scripts / "ruff").read_bytes() == binary


def test_target_changed_after_detection_is_not_replaced(fake_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    path = fake_env.write("jt", pip_script("/old/python", JSON_TOOL))
    real_generate = repair_module.generate

    def generate_then_change(*args, **kwargs):
        produced = real_generate(*args, **kwargs)
        path.write_bytes(pip_script("/someone/else/python", JSON_TOOL))
        return produced

    monkeypatch.setattr(repair_module, "generate", generate_then_change)
    report = repair(fake_env)
    result = entry(report, "jt")
    assert result.reason_code is ReasonCode.TARGET_CHANGED
    assert result.repair_status is RepairStatus.FAILED and not result.modified_paths
    assert b"/someone/else/python" in path.read_bytes()
    assert report.exit_code == 1 and no_staging_left(fake_env)


def test_replace_failure_leaves_original_and_other_items(fake_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_env.add_dist("jt", "1.0", {"aaa": JSON_TOOL, "bbb": JSON_TOOL})
    original = pip_script("/old/python", JSON_TOOL)
    fake_env.write("aaa", original)
    fake_env.write("bbb", original)
    real_replace = os.replace

    def failing_replace(src, dst):
        if os.path.basename(dst) == "aaa":
            raise PermissionError(13, "Permission denied", str(dst))
        return real_replace(src, dst)

    monkeypatch.setattr(repair_module.os, "replace", failing_replace)
    report = repair(fake_env)
    assert entry(report, "aaa").reason_code is ReasonCode.PERMISSION_DENIED
    assert (fake_env.scripts / "aaa").read_bytes() == original
    assert entry(report, "bbb").overall_status is OverallStatus.REPAIRED
    assert report.exit_code == 1 and report.outcome.value == "partially_failed"
    assert no_staging_left(fake_env)


def test_failed_startup_check_rolls_back(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    original = pip_script("/old/python", JSON_TOOL)
    fake_env.write("jt", original)
    policy = VerificationPolicy(mode=VerificationMode.EXECUTE, commands={"jt": VerificationCommand(args=("--no-such-option",), timeout=60)})
    report = repair(fake_env, policy)
    result = entry(report, "jt")
    assert result.overall_status is OverallStatus.FAILED
    assert result.repair_status is RepairStatus.ROLLED_BACK
    assert result.recovery is not None and result.recovery.rollback_succeeded
    assert result.modified_paths == [fake_env.scripts / "jt"]
    assert (fake_env.scripts / "jt").read_bytes() == original
    assert report.exit_code == 1 and no_staging_left(fake_env)


def test_failed_rollback_retains_recovery_copy(fake_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    original = pip_script("/old/python", JSON_TOOL)
    fake_env.write("jt", original)
    real_replace = os.replace
    calls = {"n": 0}

    def replace_once(src, dst):
        calls["n"] += 1
        if calls["n"] > 1:
            raise OSError(5, "I/O error", str(dst))
        return real_replace(src, dst)

    monkeypatch.setattr(repair_module.os, "replace", replace_once)
    policy = VerificationPolicy(mode=VerificationMode.EXECUTE, commands={"jt": VerificationCommand(args=("--no-such-option",), timeout=60)})
    report = repair(fake_env, policy)
    result = entry(report, "jt")
    assert result.recovery is not None and result.recovery.rollback_succeeded is False
    retained = result.recovery.retained_path
    assert retained is not None and retained.read_bytes() == original
    assert result.repair_status is RepairStatus.WRITTEN and result.overall_status is OverallStatus.FAILED


def test_passing_startup_check_is_recorded(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL, "other": JSON_TOOL})
    policy = VerificationPolicy(mode=VerificationMode.EXECUTE, commands={"jt": VerificationCommand(args=("--help",), timeout=60)})
    report = repair(fake_env, policy)
    jt = entry(report, "jt")
    assert jt.overall_status is OverallStatus.REPAIRED
    assert [check.status for check in jt.verification] == [VerificationStatus.PASSED, VerificationStatus.PASSED]
    other = entry(report, "other")
    assert other.overall_status is OverallStatus.UNVERIFIED
    assert other.verification[1].reason_code is ReasonCode.VERIFICATION_NOT_CONFIGURED
    assert report.exit_code == 1


def test_interpreter_path_with_spaces_is_quoted(fake_env: FakeEnv, tmp_path: Path) -> None:
    spaced = tmp_path / "dir with space" / "bin"
    spaced.mkdir(parents=True)
    (spaced / "python").symlink_to(fake_env.python)
    fake_env.python = spaced / "python"
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    report = repair(fake_env)
    assert entry(report, "jt").overall_status is OverallStatus.REPAIRED
    data = (fake_env.scripts / "jt").read_bytes()
    assert f"'''exec' \"{spaced / 'python'}\"".encode() in data
    assert subprocess.run([str(fake_env.scripts / "jt"), "--help"], capture_output=True, timeout=60).returncode == 0


def test_concurrent_mutating_run_reports_busy(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    with EnvironmentLock(fake_env.scripts):
        report = repair(fake_env)
    assert report.exit_code == 3
    assert report.run_errors[0].reason_code is ReasonCode.ENVIRONMENT_BUSY
    assert not (fake_env.scripts / "jt").exists()
    # Read-only operations do not take the lock.
    with EnvironmentLock(fake_env.scripts):
        assert repair(fake_env, dry_run=True).exit_code == 0


def test_cross_platform_generation_is_refused(tmp_path: Path) -> None:
    from python_env_repair.models import Platform

    env = FakeEnv(tmp_path, platform=Platform.WINDOWS)
    env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    report = repair(env)
    assert entry(report, "jt").reason_code is ReasonCode.UNSUPPORTED_PLATFORM
    assert report.exit_code == 1 and list(env.scripts.iterdir()) == []


def test_unquotable_interpreter_path_fails_without_writing(fake_env: FakeEnv, tmp_path: Path) -> None:
    odd = tmp_path / "my $dir" / "bin"
    odd.mkdir(parents=True)
    (odd / "python").symlink_to(fake_env.python)
    fake_env.python = odd / "python"
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    report = repair(fake_env)
    assert entry(report, "jt").reason_code is ReasonCode.GENERATION_FAILED
    assert not (fake_env.scripts / "jt").exists() and no_staging_left(fake_env)


def test_created_launcher_has_single_link(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    report = repair(fake_env)
    assert os.stat(fake_env.scripts / "jt").st_nlink == 1
    assert report.to_dict()["modified_paths"] == [str(fake_env.scripts / "jt")]


def test_rollback_reports_restored_paths_separately(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    fake_env.write("jt", pip_script("/old/python", JSON_TOOL))
    policy = VerificationPolicy(mode=VerificationMode.EXECUTE, commands={"jt": VerificationCommand(args=("--no-such-option",), timeout=60)})
    report = repair(fake_env, policy)
    data = report.to_dict()
    assert data["modified_paths"] == [] and data["restored_paths"] == [str(fake_env.scripts / "jt")]
    assert (report.summary.artifacts_modified, report.summary.artifacts_restored) == (0, 1)


@pytest.mark.skipif(os.name != "posix" or os.geteuid() != 0, reason="needs root to create files owned by another user")
def test_rollback_restores_original_owner(fake_env: FakeEnv) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    path = fake_env.write("jt", pip_script("/old/python", JSON_TOOL))
    assert sys.platform != "win32"
    os.chown(path, 12345, 12345)
    policy = VerificationPolicy(mode=VerificationMode.EXECUTE, commands={"jt": VerificationCommand(args=("--no-such-option",), timeout=60)})
    result = entry(repair(fake_env, policy), "jt")
    assert result.repair_status is RepairStatus.ROLLED_BACK
    st = os.stat(path)
    assert (st.st_uid, st.st_gid) == (12345, 12345)


def test_interrupt_after_write_is_unverified(fake_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL})
    fake_env.write("jt", pip_script("/old/python", JSON_TOOL))

    def interrupt(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(repair_module, "verify_committed", interrupt)
    report = repair(fake_env)
    result = entry(report, "jt")
    assert report.exit_code == 130
    assert result.repair_status is RepairStatus.WRITTEN and result.overall_status is OverallStatus.UNVERIFIED
    assert result.recovery is not None and result.recovery.retained_path is not None and result.recovery.retained_path.exists()
