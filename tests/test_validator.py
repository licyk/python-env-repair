"""Bounded subprocess execution and verification states."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from python_env_repair.models import ReasonCode, VerificationCheck, VerificationStatus, VerificationResult
from python_env_repair.validator import BoundedCapture, STREAM_RETENTION_BYTES, aggregate, requirements_met, run_bounded
from tests.helpers import posix_only


def test_bounded_capture_keeps_head_and_tail() -> None:
    capture = BoundedCapture(limit=10)
    for chunk in (b"abcde", b"fghij", b"klmno", b"pqrst"):
        capture.feed(chunk)
    assert capture.bytes_seen == 20 and capture.bytes_retained == 10 and capture.truncated
    text = capture.text()
    assert text.startswith("abcde") and text.endswith("pqrst") and "10 bytes omitted" in text


def test_flood_is_drained_and_bounded() -> None:
    code = "import sys\nfor _ in range(200):\n    sys.stdout.write('x' * 50000)\n    sys.stderr.write('y' * 50000)\n"
    outcome = run_bounded([sys.executable, "-c", code], timeout=60)
    assert outcome.returncode == 0 and not outcome.timed_out
    for capture in (outcome.stdout, outcome.stderr):
        assert capture.bytes_seen == 10_000_000
        assert capture.bytes_retained == STREAM_RETENTION_BYTES
        assert capture.truncated


def test_no_stdin_and_nonzero_exit() -> None:
    outcome = run_bounded([sys.executable, "-c", "import sys; data = sys.stdin.read(); sys.exit(3 if data == '' else 4)"], timeout=30)
    assert outcome.returncode == 3


def test_missing_executable_is_an_error_not_a_crash(tmp_path: Path) -> None:
    outcome = run_bounded([str(tmp_path / "missing")], timeout=5)
    assert outcome.error is not None and outcome.returncode is None


@posix_only
def test_timeout_kills_process_group_including_grandchild(tmp_path: Path) -> None:
    marker = tmp_path / "grandchild.pid"
    code = f"import subprocess, sys, time\nchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\nopen({str(marker)!r}, 'w').write(str(child.pid))\ntime.sleep(60)\n"
    started = time.monotonic()
    outcome = run_bounded([sys.executable, "-c", code], timeout=2)
    assert outcome.timed_out and outcome.cleanup == "terminated"
    assert time.monotonic() - started < 20
    pid = int(marker.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        raise AssertionError("grandchild survived the timeout")


def check(status: VerificationStatus, required: bool = True) -> VerificationResult:
    return VerificationResult(check=VerificationCheck.ARTIFACT, required=required, status=status, reason_code=ReasonCode.VERIFICATION_PASSED, message="")


def test_aggregate_states() -> None:
    assert aggregate([]) is VerificationStatus.NOT_RUN
    assert aggregate([check(VerificationStatus.PASSED)]) is VerificationStatus.PASSED
    assert aggregate([check(VerificationStatus.PASSED), check(VerificationStatus.NOT_RUN)]) is VerificationStatus.PARTIAL
    assert aggregate([check(VerificationStatus.PASSED), check(VerificationStatus.FAILED)]) is VerificationStatus.FAILED
    assert requirements_met([check(VerificationStatus.PASSED), check(VerificationStatus.NOT_RUN, required=False)])
    assert not requirements_met([check(VerificationStatus.PASSED), check(VerificationStatus.NOT_RUN)])


@posix_only
def test_background_child_is_cleaned_up_after_normal_exit(tmp_path: Path) -> None:
    marker = tmp_path / "bg.pid"
    code = f"import subprocess, sys\nchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\nopen({str(marker)!r}, 'w').write(str(child.pid))\n"
    outcome = run_bounded([sys.executable, "-c", code], timeout=30)
    assert outcome.returncode == 0 and outcome.cleanup == "process_group_terminated"
    pid = int(marker.read_text())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    raise AssertionError("background child survived")
