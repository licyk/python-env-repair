"""Structural verification and explicitly configured execution checks.

Structural checks are the default. A CLI is executed only when the caller configured an
approved command for that entry point; there is no automatic fallback between ``--help``,
``--version``, or importing the entry point, because each of them can run package code.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Optional

from python_env_repair.detector import interpreter_matches, parse_unix_launcher, read_bounded, sha256_bytes, windows_launcher_matches
from python_env_repair.logger import redact
from python_env_repair.models import (
    ConsoleScript,
    DetectionStatus,
    EnvironmentInfo,
    JsonDict,
    Platform,
    ReasonCode,
    RepairResult,
    VerificationCheck,
    VerificationMode,
    VerificationPolicy,
    VerificationResult,
    VerificationStatus,
)

logger = logging.getLogger(__name__)

STREAM_RETENTION_BYTES = 64 * 1024
_READ_CHUNK = 64 * 1024
_READER_JOIN_SECONDS = 5.0
STRUCTURAL_ONLY_MESSAGE = "structural verification passed; startup not checked"


class BoundedCapture:
    """Keep the head and tail of a stream within a fixed budget while counting every byte."""

    def __init__(self, limit: int = STREAM_RETENTION_BYTES) -> None:
        self._head_limit = limit // 2
        self._tail_limit = limit - self._head_limit
        self._head = bytearray()
        self._tail = bytearray()
        self.bytes_seen = 0

    def feed(self, chunk: bytes) -> None:
        """Add a chunk of output."""
        self.bytes_seen += len(chunk)
        room = self._head_limit - len(self._head)
        if room > 0:
            self._head += chunk[:room]
            chunk = chunk[room:]
        if chunk:
            self._tail += chunk
            excess = len(self._tail) - self._tail_limit
            if excess > 0:
                del self._tail[:excess]

    @property
    def bytes_retained(self) -> int:
        """Number of bytes kept."""
        return len(self._head) + len(self._tail)

    @property
    def truncated(self) -> bool:
        """Whether some output was dropped."""
        return self.bytes_seen > self.bytes_retained

    def text(self) -> str:
        """Decoded retained output with a marker where bytes were dropped."""
        head = bytes(self._head).decode("utf-8", "replace")
        tail = bytes(self._tail).decode("utf-8", "replace")
        if self.truncated:
            return f"{head}\n[... {self.bytes_seen - self.bytes_retained} bytes omitted ...]\n{tail}"
        return head + tail

    def to_dict(self) -> JsonDict:
        """Serialize a redacted summary."""
        return {"text": redact(self.text()), "truncated": self.truncated, "bytes_seen": self.bytes_seen, "bytes_retained": self.bytes_retained}


@dataclass
class ExecutionOutcome:
    """Result of running one verification subprocess."""

    args: list[str]
    timeout: float
    cwd: str
    returncode: Optional[int] = None
    timed_out: bool = False
    duration_ms: int = 0
    stdout: BoundedCapture = field(default_factory=BoundedCapture)
    stderr: BoundedCapture = field(default_factory=BoundedCapture)
    cleanup: str = "not_needed"
    error: Optional[str] = None

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "executable": self.args[0] if self.args else None,
            "args": [redact(arg) for arg in self.args[1:]],
            "cwd": self.cwd,
            "timeout": self.timeout,
            "returncode": self.returncode,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
            "cleanup": self.cleanup,
            "error": self.error,
            "stdout": self.stdout.to_dict(),
            "stderr": self.stderr.to_dict(),
        }


def _drain(stream: IO[bytes], capture: BoundedCapture) -> None:
    try:
        reader = getattr(stream, "read1", stream.read)
        while True:
            chunk = reader(_READ_CHUNK)
            if not chunk:
                break
            capture.feed(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _kill_tree(process: subprocess.Popen[bytes]) -> str:
    """Terminate a managed process (and its process group on POSIX) and reap it."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        pass
    try:
        process.wait(timeout=_READER_JOIN_SECONDS)
    except subprocess.TimeoutExpired:
        return "kill_failed"
    return "terminated"


def run_bounded(args: list[str], timeout: float, cwd: Optional[Path] = None) -> ExecutionOutcome:
    """Run an executable without a shell, with no stdin, bounded output, and a timeout.

    Both output streams are drained continuously by reader threads, so large output
    never blocks the child, and only :data:`STREAM_RETENTION_BYTES` per stream are kept.

    Args:
        args: Absolute executable path followed by arguments.
        timeout: Seconds before the process (group) is killed.
        cwd: Working directory; defaults to the current directory.

    Returns:
        The execution outcome.

    Raises:
        KeyboardInterrupt: Re-raised after the child has been terminated and reaped.
    """
    working_dir = str(cwd) if cwd else os.getcwd()
    outcome = ExecutionOutcome(args=list(args), timeout=timeout, cwd=working_dir)
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=working_dir,
            env=env,
            shell=False,
            # A new session/process group lets a timeout terminate the whole tree on POSIX.
            start_new_session=os.name == "posix",
            creationflags=0 if os.name == "posix" else getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
    except OSError as exc:
        outcome.error = f"{type(exc).__name__}: {exc}"
        outcome.duration_ms = int((time.monotonic() - started) * 1000)
        return outcome
    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(target=_drain, args=(process.stdout, outcome.stdout), daemon=True),
        threading.Thread(target=_drain, args=(process.stderr, outcome.stderr), daemon=True),
    ]
    for reader in readers:
        reader.start()
    try:
        try:
            outcome.returncode = process.wait(timeout=timeout)
            if os.name == "posix":
                # Do not leave background children of a verification command running.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    outcome.cleanup = "process_group_terminated"
                except (ProcessLookupError, PermissionError):
                    pass
        except subprocess.TimeoutExpired:
            outcome.timed_out = True
            outcome.cleanup = _kill_tree(process)
            outcome.returncode = process.returncode
    except KeyboardInterrupt:
        _kill_tree(process)
        raise
    finally:
        for reader in readers:
            reader.join(_READER_JOIN_SECONDS)
        if any(reader.is_alive() for reader in readers):
            # A grandchild outside the managed process group still holds a pipe open.
            outcome.cleanup = "output_readers_detached"
        outcome.duration_ms = int((time.monotonic() - started) * 1000)
    return outcome


def _result(
    check: VerificationCheck, status: VerificationStatus, reason: ReasonCode, message: str, *, required: bool = True, details: Optional[JsonDict] = None, duration_ms: Optional[int] = None
) -> VerificationResult:
    return VerificationResult(check=check, required=required, status=status, reason_code=reason, message=message, details=details or {}, duration_ms=duration_ms)


def check_unix_artifact(path: Path, env: EnvironmentInfo, expected_sha256: Optional[str] = None) -> VerificationResult:
    """Structurally verify a Unix console script.

    Checks content (when the generated bytes are known), interpreter binding, and
    execute permission. Does not execute anything.
    """
    check = VerificationCheck.ARTIFACT
    started = time.monotonic()
    try:
        data = read_bounded(path, 1024 * 1024)
        st = os.stat(path)
    except OSError as exc:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, f"cannot read artifact: {exc}")
    details: JsonDict = {"mode": oct(st.st_mode & 0o7777)}
    if data is None:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, "artifact is unexpectedly large", details=details)
    details["sha256"] = sha256_bytes(data)
    if expected_sha256 is not None and details["sha256"] != expected_sha256:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, "artifact content differs from the generated output", details=details)
    launcher = parse_unix_launcher(data)
    if launcher is None:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, "artifact is not a recognized console-script wrapper", details=details)
    details["interpreter"] = launcher.interpreter
    if launcher.unquoted_space:
        return _result(check, VerificationStatus.FAILED, ReasonCode.UNQUOTED_INTERPRETER, "wrapper has an unquoted interpreter path containing spaces", details=details)
    if not interpreter_matches(launcher.interpreter, env):
        return _result(check, VerificationStatus.FAILED, ReasonCode.STALE_SHEBANG, "artifact is not bound to the current Python", details=details)
    if not st.st_mode & 0o111 or not os.access(path, os.X_OK):
        return _result(check, VerificationStatus.FAILED, ReasonCode.MISSING_EXECUTE_PERMISSION, "artifact is not executable", details=details)
    if not os.access(launcher.interpreter, os.X_OK):
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, "bound interpreter is not executable", details=details)
    return _result(check, VerificationStatus.PASSED, ReasonCode.VERIFICATION_PASSED, STRUCTURAL_ONLY_MESSAGE, details=details, duration_ms=int((time.monotonic() - started) * 1000))


def check_windows_artifact(path: Path, script: ConsoleScript, expected_sha256: Optional[str]) -> VerificationResult:
    """Structurally verify a Windows launcher against trusted generation output.

    The interpreter path embedded in the launcher is not extracted. Without the bytes
    generated in this run the binding cannot be checked, and the check is reported as
    not run rather than passed.
    """
    check = VerificationCheck.ARTIFACT
    try:
        data = read_bounded(path, 32 * 1024 * 1024)
    except OSError as exc:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, f"cannot read launcher: {exc}")
    if data is None or not windows_launcher_matches(data, script):
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, "launcher does not embed this entry point")
    digest = sha256_bytes(data)
    if expected_sha256 is None:
        return _result(
            check, VerificationStatus.NOT_RUN, ReasonCode.WINDOWS_LAUNCHER_UNVERIFIABLE, "launcher interpreter binding cannot be inspected without relocation evidence", details={"sha256": digest}
        )
    if digest != expected_sha256:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, "launcher differs from the output generated for the current Python", details={"sha256": digest})
    return _result(check, VerificationStatus.PASSED, ReasonCode.VERIFICATION_PASSED, STRUCTURAL_ONLY_MESSAGE, details={"sha256": digest})


def structural_check(env: EnvironmentInfo, script: ConsoleScript, path: Path, expected_sha256: Optional[str] = None) -> VerificationResult:
    """Run the platform's structural check for a committed artifact."""
    if env.platform is Platform.WINDOWS:
        return check_windows_artifact(path, script, expected_sha256)
    return check_unix_artifact(path, env, expected_sha256)


def execution_check(script: ConsoleScript, path: Path, policy: VerificationPolicy) -> VerificationResult:
    """Run the approved verification command for an entry point, if one is configured."""
    check = VerificationCheck.LAUNCHER_INVOCATION
    command = policy.commands.get(script.name)
    if command is None:
        return _result(check, VerificationStatus.NOT_RUN, ReasonCode.VERIFICATION_NOT_CONFIGURED, "startup check requested but no approved command is configured for this entry point")
    outcome = run_bounded([str(path), *command.args], command.timeout)
    details = outcome.to_dict()
    if outcome.error is not None:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_ERROR, f"could not start artifact: {outcome.error}", details=details, duration_ms=outcome.duration_ms)
    if outcome.timed_out:
        return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_TIMEOUT, f"startup check timed out after {command.timeout:g}s", details=details, duration_ms=outcome.duration_ms)
    if outcome.returncode in command.allowed_return_codes:
        return _result(check, VerificationStatus.PASSED, ReasonCode.VERIFICATION_PASSED, f"startup check passed (exit code {outcome.returncode})", details=details, duration_ms=outcome.duration_ms)
    return _result(check, VerificationStatus.FAILED, ReasonCode.VERIFICATION_FAILED, f"startup check returned exit code {outcome.returncode}", details=details, duration_ms=outcome.duration_ms)


def verify_committed(env: EnvironmentInfo, script: ConsoleScript, path: Path, expected_sha256: str, policy: VerificationPolicy) -> list[VerificationResult]:
    """Verify an artifact that this run just wrote."""
    results = [structural_check(env, script, path, expected_sha256)]
    if policy.mode is VerificationMode.EXECUTE and results[0].status is VerificationStatus.PASSED:
        results.append(execution_check(script, path, policy))
    return results


def verify_existing(env: EnvironmentInfo, result: RepairResult, policy: VerificationPolicy) -> list[VerificationResult]:
    """Verify an entry point without modifying it (the ``verify`` command)."""
    script = result.script
    launcher = script.launcher
    check = VerificationCheck.ARTIFACT
    if launcher is None or result.detection_status is DetectionStatus.MISSING:
        return [_result(check, VerificationStatus.FAILED, ReasonCode.MISSING_ARTIFACT, "artifact is missing")]
    if result.detection_status is DetectionStatus.INVALID:
        return [_result(check, VerificationStatus.FAILED, result.reason_code, result.message)]
    if result.detection_status is DetectionStatus.UNKNOWN:
        return [_result(check, VerificationStatus.NOT_RUN, result.reason_code, result.message)]
    if env.platform is Platform.WINDOWS:
        # Valid only through manifest evidence; the recorded hash was compared during detection.
        structural = _result(check, VerificationStatus.PASSED, ReasonCode.MANIFEST_MATCHES_ENVIRONMENT, STRUCTURAL_ONLY_MESSAGE, details={"evidence": "previous_manifest"})
    else:
        structural = check_unix_artifact(launcher.path, env)
    results = [structural]
    if policy.mode is VerificationMode.EXECUTE and structural.status is VerificationStatus.PASSED:
        results.append(execution_check(script, launcher.path, policy))
    return results


def aggregate(results: list[VerificationResult]) -> VerificationStatus:
    """Combine individual checks into one verification status."""
    if not results:
        return VerificationStatus.NOT_RUN
    if any(item.status is VerificationStatus.FAILED for item in results):
        return VerificationStatus.FAILED
    required = [item for item in results if item.required]
    if all(item.status is VerificationStatus.PASSED for item in required):
        return VerificationStatus.PASSED
    if any(item.status is VerificationStatus.PASSED for item in results):
        return VerificationStatus.PARTIAL
    return VerificationStatus.NOT_RUN


def requirements_met(results: list[VerificationResult]) -> bool:
    """Whether every required check ran and passed."""
    return bool(results) and all(item.status is VerificationStatus.PASSED for item in results if item.required)
