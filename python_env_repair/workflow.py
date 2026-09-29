"""Shared detect / repair / verify workflow used by the CLI and the library API.

The workflow never configures logging. Callers that want console or file output attach
handlers themselves (the CLI does this through :class:`~python_env_repair.logger.LoggingSession`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from python_env_repair import __version__
from python_env_repair.detector import detect
from python_env_repair.discovery import discover_console_scripts
from python_env_repair.environment import EnvironmentDetectionError, current_environment
from python_env_repair.lock import EnvironmentBusyError, EnvironmentLock, LockError
from python_env_repair.logger import EventEmitter, RunContext, new_run_id, utc_timestamp
from python_env_repair.manifest import build_manifest, write_json_atomic
from python_env_repair.models import (
    DetectionStatus,
    DiagnosticsInfo,
    EnvironmentInfo,
    Operation,
    OverallStatus,
    ReasonCode,
    RelocationContext,
    RepairManifest,
    RepairReport,
    RepairResult,
    RepairStatus,
    RunError,
    VerificationPolicy,
    VerificationStatus,
)
from python_env_repair.platform import UnsupportedPlatformError
from python_env_repair.generator import generator_info
from python_env_repair.repair import repair_item
from python_env_repair.reporting import finalize
from python_env_repair.validator import aggregate, requirements_met, verify_existing

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RunOptions:
    """Inputs for one run. Relocation evidence and verification policy are explicit."""

    operation: Operation
    dry_run: bool = False
    relocation: RelocationContext = field(default_factory=RelocationContext)
    verification: VerificationPolicy = field(default_factory=VerificationPolicy)
    run_id: Optional[str] = None


class DiagnosticFiles:
    """Explicitly requested manifest/report files inside one run directory."""

    def __init__(self, run_dir: Path, jsonl_path: Optional[Path] = None, jsonl_failed: Callable[[], bool] = lambda: False) -> None:
        self.run_dir = run_dir
        self.jsonl_path = jsonl_path
        self._jsonl_failed = jsonl_failed
        self.error: Optional[str] = None
        self.files: list[Path] = [jsonl_path] if jsonl_path else []

    @property
    def failed(self) -> bool:
        """Whether any diagnostic output has failed."""
        return self.error is not None or self._jsonl_failed()

    def _write(self, name: str, payload: dict) -> bool:
        path = self.run_dir / name
        try:
            write_json_atomic(path, payload)
        except OSError as exc:
            if self.error is None:
                self.error = f"cannot write {path}: {exc}"
            return False
        if path not in self.files:
            self.files.append(path)
        return True

    def write_manifest(self, manifest: RepairManifest) -> bool:
        """Persist the plan before the first modification."""
        return self._write("manifest.json", manifest.to_dict())

    def write_report(self, report: RepairReport) -> bool:
        """Persist the final report."""
        return self._write("report.json", report.to_dict())


def _assign_plan_statuses(results: list[RepairResult]) -> None:
    for result in results:
        if result.detection_status is DetectionStatus.VALID:
            result.repair_status, result.overall_status = RepairStatus.NOT_NEEDED, OverallStatus.VALID
        elif result.candidate:
            result.repair_status, result.overall_status = RepairStatus.PLANNED, OverallStatus.PLANNED
        elif result.detection_status is DetectionStatus.SKIPPED:
            result.repair_status, result.overall_status = RepairStatus.NOT_NEEDED, OverallStatus.SKIPPED
            result.verification_status = VerificationStatus.SKIPPED
        elif result.detection_status is DetectionStatus.UNKNOWN:
            result.repair_status, result.overall_status = RepairStatus.NOT_NEEDED, OverallStatus.UNVERIFIED
        else:
            result.repair_status, result.overall_status = RepairStatus.NOT_NEEDED, OverallStatus.FAILED


def _plan(env: EnvironmentInfo, options: RunOptions, emitter: EventEmitter) -> list[RepairResult]:
    discovery = discover_console_scripts(env)
    for problem in discovery.problems:
        emitter.emit(logger, logging.WARNING, "discovery.problem", problem.message, phase="discovery", path=problem.path)
    total = len(discovery.scripts) + len(discovery.invalid_values)
    emitter.emit(
        logger,
        logging.INFO,
        "discovery.completed",
        f"Found {total} console_scripts in {discovery.distributions} distributions",
        phase="discovery",
        details={"entries": total, "distributions": discovery.distributions},
    )
    results = detect(env, discovery, options.relocation)
    _assign_plan_statuses(results)
    for result in results:
        launcher = result.script.launcher
        path = launcher.path if launcher else None
        if result.candidate:
            emitter.emit(
                logger,
                logging.INFO,
                "repair.planned",
                result.message,
                phase="detection",
                script=result.script,
                path=path,
                status="needs_repair",
                reason_code=result.reason_code.value,
                details=result.evidence,
            )
        elif result.detection_status is DetectionStatus.SKIPPED:
            emitter.emit(
                logger,
                logging.DEBUG,
                "script.skipped",
                result.message,
                phase="detection",
                script=result.script,
                path=path,
                status=result.detection_status.value,
                reason_code=result.reason_code.value,
                details=result.evidence,
            )
        elif result.detection_status in (DetectionStatus.UNKNOWN, DetectionStatus.INVALID):
            emitter.emit(
                logger,
                logging.WARNING,
                "script.checked",
                result.message,
                phase="detection",
                script=result.script,
                path=path,
                status=result.detection_status.value,
                reason_code=result.reason_code.value,
                details=result.evidence,
            )
        else:
            emitter.emit(
                logger,
                logging.DEBUG,
                "script.checked",
                result.message,
                phase="detection",
                script=result.script,
                path=path,
                status=result.detection_status.value,
                reason_code=result.reason_code.value,
                details=result.evidence,
            )
    valid = sum(1 for result in results if result.detection_status is DetectionStatus.VALID)
    planned = sum(1 for result in results if result.candidate)
    other = len(results) - valid - planned
    emitter.emit(logger, logging.INFO, "detection.completed", f"{valid} valid; {planned} need repair; {other} other", phase="detection", details={"valid": valid, "planned": planned, "other": other})
    return results


def _overall_after_repair(result: RepairResult) -> OverallStatus:
    if result.repair_status is RepairStatus.WRITTEN:
        if result.verification_status is VerificationStatus.FAILED:
            return OverallStatus.FAILED
        return OverallStatus.REPAIRED if requirements_met(result.verification) else OverallStatus.UNVERIFIED
    return OverallStatus.FAILED


def _execute_repairs(report: RepairReport, env: EnvironmentInfo, options: RunOptions, emitter: EventEmitter, diagnostics: Optional[DiagnosticFiles]) -> None:
    candidates = [result for result in report.results if result.candidate]
    for index, result in enumerate(candidates, start=1):
        if diagnostics is not None and diagnostics.failed:
            report.stopped_early = True
            break
        progress = f"{index}/{len(candidates)}"
        reason = result.reason_code.value
        repair_item(result, env, options.verification, emitter, progress)
        result.overall_status = _overall_after_repair(result)
        launcher = result.script.launcher
        if result.overall_status is OverallStatus.REPAIRED:
            checks = "; ".join(check.message for check in result.verification)
            emitter.emit(
                logger,
                logging.INFO,
                "repair.completed",
                f"repaired ({reason}); {checks}",
                phase="repair",
                script=result.script,
                path=launcher.path if launcher else None,
                status="repaired",
                reason_code=reason,
                progress=progress,
            )
        elif result.overall_status is OverallStatus.UNVERIFIED:
            emitter.emit(
                logger,
                logging.WARNING,
                "repair.completed",
                f"written ({reason}) but required verification did not complete",
                phase="repair",
                script=result.script,
                path=launcher.path if launcher else None,
                status="unverified",
                reason_code=result.reason_code.value,
                progress=progress,
            )


def _mark_unfinished(report: RepairReport) -> None:
    """Give candidates of a stopped mutating run an accurate final state."""
    if report.operation is not Operation.REPAIR or report.dry_run:
        return
    for result in report.results:
        if not result.candidate or result.overall_status is not OverallStatus.PLANNED:
            continue
        if result.repair_status is RepairStatus.PLANNED:
            result.overall_status = OverallStatus.FAILED
            result.reason_code = ReasonCode.REPAIR_NOT_ATTEMPTED
            result.message = "repair was planned but not attempted because the run stopped"
        elif result.repair_status is RepairStatus.WRITTEN:
            result.overall_status = OverallStatus.UNVERIFIED
            result.reason_code = ReasonCode.INTERRUPTED
            result.message = "file was written but the run stopped before verification completed"
        else:
            result.overall_status = OverallStatus.FAILED


def _verify(report: RepairReport, env: EnvironmentInfo, options: RunOptions, emitter: EventEmitter) -> None:
    for result in report.results:
        if result.detection_status is DetectionStatus.SKIPPED:
            continue
        result.verification = verify_existing(env, result, options.verification)
        result.verification_status = aggregate(result.verification)
        launcher = result.script.launcher
        path = launcher.path if launcher else None
        if result.verification_status is VerificationStatus.FAILED:
            result.overall_status = OverallStatus.FAILED
            failed = next(check for check in result.verification if check.status is VerificationStatus.FAILED)
            result.reason_code, result.message = failed.reason_code, failed.message
            emitter.emit(
                logger,
                logging.ERROR,
                "verification.failed",
                failed.message,
                phase="verify",
                script=result.script,
                path=path,
                status="failed",
                reason_code=failed.reason_code.value,
                details={"checks": [check.to_dict() for check in result.verification]},
            )
        elif requirements_met(result.verification):
            result.overall_status = OverallStatus.VALID
            emitter.emit(
                logger,
                logging.DEBUG,
                "verification.completed",
                "; ".join(check.message for check in result.verification),
                phase="verify",
                script=result.script,
                path=path,
                status="passed",
                details={"checks": [check.to_dict() for check in result.verification]},
            )
        else:
            result.overall_status = OverallStatus.UNVERIFIED
            unmet = next(check for check in result.verification if check.required and check.status is not VerificationStatus.PASSED)
            result.reason_code, result.message = unmet.reason_code, unmet.message
            emitter.emit(
                logger,
                logging.WARNING,
                "verification.completed",
                f"required verification not completed: {unmet.message}",
                phase="verify",
                script=result.script,
                path=path,
                status="unverified",
                reason_code=unmet.reason_code.value,
            )


def run(
    options: RunOptions,
    *,
    env: Optional[EnvironmentInfo] = None,
    diagnostics: Optional[DiagnosticFiles] = None,
    on_environment: Optional[Callable[[EnvironmentInfo, str], None]] = None,
) -> RepairReport:
    """Execute one detect, repair, dry-run, or verify operation.

    Args:
        options: Operation and explicit evidence/policy.
        env: Target environment; defaults to the running interpreter's environment.
        diagnostics: Explicitly enabled diagnostic files, or ``None`` (the default: no files).
        on_environment: Callback invoked once the environment is known (used for headers).

    Returns:
        The final report, including ``exit_code``. Exceptions other than a second
        interruption are converted into run errors.
    """
    run_id = options.run_id or new_run_id()
    emitter = EventEmitter(RunContext(run_id=run_id, operation=options.operation, dry_run=options.dry_run))
    report = RepairReport(
        run_id=run_id,
        tool_version=__version__,
        operation=options.operation,
        dry_run=options.dry_run,
        started_at=utc_timestamp(),
        relocation=options.relocation,
        verification_policy=options.verification,
        generator=generator_info(),
    )
    if diagnostics is not None:
        report.diagnostics = DiagnosticsInfo(file_logging=True, run_dir=diagnostics.run_dir)
    mutating = options.operation is Operation.REPAIR and not options.dry_run
    try:
        target = env or current_environment()
        report.environment = target
        emitter.emit(
            logger,
            logging.DEBUG,
            "run.started",
            f"{options.operation.value} started",
            phase="run",
            details={"tool_version": __version__, "generator": report.generator, "relocation": options.relocation.to_dict(), "verification": options.verification.to_dict(), **target.to_dict()},
        )
        emitter.emit(logger, logging.DEBUG, "environment.detected", f"Python {target.python_version} at {target.python}", phase="environment", path=target.scripts_dir)
        if on_environment is not None:
            on_environment(target, run_id)
        lock = EnvironmentLock(target.scripts_dir) if mutating else None
        if lock is not None:
            lock.acquire()
        try:
            # Discovery and detection run after the lock is held, so a mutating run
            # always decides on current metadata and artifact identities.
            report.results = _plan(target, options, emitter)
            if mutating:
                manifest = build_manifest(run_id, utc_timestamp(), options.operation, options.dry_run, target, options.relocation, report.results, __version__)
                if diagnostics is not None and not diagnostics.write_manifest(manifest):
                    raise _DiagnosticsFailure()
                _execute_repairs(report, target, options, emitter, diagnostics)
            elif options.operation is Operation.VERIFY:
                _verify(report, target, options, emitter)
        finally:
            if lock is not None:
                lock.release()
    except KeyboardInterrupt:
        report.interrupted = True
        report.run_errors.append(RunError(ReasonCode.INTERRUPTED, "interrupted by the user"))
        emitter.emit(logger, logging.ERROR, "run.interrupted", "interrupted; completed items are reported", phase="run")
    except _DiagnosticsFailure:
        pass
    except UnsupportedPlatformError as exc:
        report.run_errors.append(RunError(ReasonCode.UNSUPPORTED_PLATFORM, str(exc)))
        emitter.emit(logger, logging.CRITICAL, "run.failed", str(exc), phase="environment", reason_code=ReasonCode.UNSUPPORTED_PLATFORM.value)
    except EnvironmentDetectionError as exc:
        report.run_errors.append(RunError(ReasonCode.ENVIRONMENT_DETECTION_FAILED, str(exc)))
        emitter.emit(logger, logging.CRITICAL, "run.failed", str(exc), phase="environment", reason_code=ReasonCode.ENVIRONMENT_DETECTION_FAILED.value)
    except EnvironmentBusyError as exc:
        report.run_errors.append(RunError(ReasonCode.ENVIRONMENT_BUSY, str(exc)))
        emitter.emit(logger, logging.CRITICAL, "run.failed", str(exc), phase="lock", reason_code=ReasonCode.ENVIRONMENT_BUSY.value)
    except LockError as exc:
        report.run_errors.append(RunError(ReasonCode.LOCK_FAILED, str(exc)))
        emitter.emit(logger, logging.CRITICAL, "run.failed", str(exc), phase="lock", reason_code=ReasonCode.LOCK_FAILED.value)
    except Exception as exc:
        report.run_errors.append(RunError(ReasonCode.INTERNAL_ERROR, f"{type(exc).__name__}: {exc}"))
        emitter.emit(logger, logging.CRITICAL, "run.failed", f"unexpected error: {type(exc).__name__}: {exc}", phase="run", reason_code=ReasonCode.INTERNAL_ERROR.value, exc_info=exc)

    if diagnostics is not None and diagnostics.failed:
        report.diagnostics.complete = False
        report.diagnostics.error = diagnostics.error or "diagnostic event log could not be written"
        report.run_errors.append(RunError(ReasonCode.DIAGNOSTICS_FAILED, report.diagnostics.error))
    if report.interrupted or report.stopped_early or report.run_errors:
        _mark_unfinished(report)
    report.finished_at = utc_timestamp()
    finalize(report)
    emitter.emit(logger, logging.DEBUG, "run.completed", f"{report.outcome.value}; exit code {report.exit_code}", phase="run", status=report.outcome.value, details=report.summary.to_dict())
    if diagnostics is not None:
        report.diagnostics.files = list(diagnostics.files) + [diagnostics.run_dir / "report.json"]
        if not diagnostics.write_report(report) or diagnostics.failed:
            report.diagnostics.complete = False
            report.diagnostics.error = diagnostics.error or "diagnostic event log could not be written"
            if not any(error.reason_code is ReasonCode.DIAGNOSTICS_FAILED for error in report.run_errors):
                report.run_errors.append(RunError(ReasonCode.DIAGNOSTICS_FAILED, report.diagnostics.error))
            finalize(report)
        report.diagnostics.files = list(diagnostics.files)
    return report


class _DiagnosticsFailure(Exception):
    """Internal signal: requested diagnostics failed before any modification."""
