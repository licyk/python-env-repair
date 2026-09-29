"""Summaries, exit codes, and result rendering derived from per-entry results.

Counts come from ``RepairResult`` objects, never from log messages.
"""

from __future__ import annotations

import json

from python_env_repair.logger import Style, sanitize_for_terminal
from python_env_repair.models import (
    Operation,
    Outcome,
    OverallStatus,
    RepairReport,
    RepairResult,
    RepairStatus,
    Summary,
    VerificationCheck,
    VerificationStatus,
)

EXIT_OK = 0
EXIT_ITEM_FAILED = 1
EXIT_USAGE = 2
EXIT_RUN_FAILED = 3
EXIT_INTERRUPTED = 130


def summarize(results: list[RepairResult]) -> Summary:
    """Count entries, modified artifacts, and verification checks separately."""
    summary = Summary(entries_total=len(results))
    for result in results:
        summary.initially_valid += int(result.initially_valid)
        status = result.overall_status
        summary.valid += int(status is OverallStatus.VALID)
        summary.planned += int(status is OverallStatus.PLANNED)
        summary.repaired += int(status is OverallStatus.REPAIRED)
        summary.failed += int(status is OverallStatus.FAILED)
        summary.skipped += int(status is OverallStatus.SKIPPED)
        summary.unverified += int(status is OverallStatus.UNVERIFIED)
        if result.repair_status is RepairStatus.WRITTEN:
            summary.artifacts_modified += len(result.modified_paths)
        elif result.repair_status is RepairStatus.ROLLED_BACK:
            summary.artifacts_restored += len(result.modified_paths)
        for check in result.verification:
            summary.checks_passed += int(check.status is VerificationStatus.PASSED)
            summary.checks_failed += int(check.status is VerificationStatus.FAILED)
            summary.checks_not_run += int(check.status in (VerificationStatus.NOT_RUN, VerificationStatus.SKIPPED))
    return summary


def _item_failures(report: RepairReport) -> bool:
    if report.operation is Operation.DETECT or report.dry_run:
        return False
    for result in report.results:
        if result.overall_status is OverallStatus.FAILED:
            return True
        if result.overall_status is OverallStatus.UNVERIFIED and (report.operation is Operation.VERIFY or result.repair_status is RepairStatus.WRITTEN):
            return True
    return False


def finalize(report: RepairReport) -> None:
    """Compute summary, outcome, and exit code (priority: 130, then 3, then 1)."""
    report.summary = summarize(report.results)
    if report.interrupted:
        report.outcome, report.exit_code = Outcome.INTERRUPTED, EXIT_INTERRUPTED
    elif report.run_errors:
        report.outcome, report.exit_code = Outcome.FAILED, EXIT_RUN_FAILED
    elif _item_failures(report):
        succeeded = report.summary.valid + report.summary.repaired
        report.outcome = Outcome.PARTIALLY_FAILED if succeeded else Outcome.FAILED
        report.exit_code = EXIT_ITEM_FAILED
    else:
        report.outcome, report.exit_code = Outcome.COMPLETED, EXIT_OK


def to_json(report: RepairReport) -> str:
    """The single JSON object printed on stdout for ``--json``."""
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


def _t(text: str) -> str:
    return sanitize_for_terminal(text)


def _package_label(result: RepairResult) -> str:
    script = result.script
    return f"{script.package} {script.version}" if script.version else script.package


def _verification_line(report: RepairReport) -> str:
    summary = report.summary
    line = f"Verification: {summary.checks_passed} passed; {summary.checks_failed} failed; {summary.checks_not_run} not run"
    checks = [check for result in report.results for check in result.verification]
    passed_structural = any(check.check is VerificationCheck.ARTIFACT and check.status is VerificationStatus.PASSED for check in checks)
    startup_run = any(check.check is VerificationCheck.LAUNCHER_INVOCATION and check.status is not VerificationStatus.NOT_RUN for check in checks)
    if passed_structural and not startup_run:
        line += " (structural verification passed; startup not checked)"
    not_attempted = sum(1 for result in report.results if result.repair_status is RepairStatus.FAILED and not result.verification)
    if not_attempted:
        line += f"; {not_attempted} not run because repair failed"
    return line


OUTCOME_STYLES = {
    Outcome.COMPLETED: (Style.GREEN, Style.BOLD),
    Outcome.PARTIALLY_FAILED: (Style.YELLOW, Style.BOLD),
    Outcome.FAILED: (Style.RED, Style.BOLD),
    Outcome.INTERRUPTED: (Style.YELLOW, Style.BOLD),
}
STATUS_STYLES = {
    OverallStatus.FAILED: (Style.RED, Style.BOLD),
    OverallStatus.UNVERIFIED: (Style.YELLOW,),
    OverallStatus.SKIPPED: (Style.DIM,),
}


def render_text(report: RepairReport, *, quiet: bool = False, color: bool = False) -> str:
    """Render the human-readable final result for stdout.

    Args:
        report: Finalized report.
        quiet: Only the summary lines and entries that need attention.
        color: Emit ANSI colors (never used for JSON output).

    Returns:
        The text, without a trailing newline.
    """
    style = Style(color)
    summary = report.summary
    lines: list[str] = []
    mode = report.operation.value + (" --dry-run" if report.dry_run else "")
    outcome = style(report.outcome.value.replace("_", " "), *OUTCOME_STYLES[report.outcome])
    lines.append(f"{style('Result:', Style.BOLD)} {outcome} ({mode})")
    counts = f"Entry points: {summary.entries_total} total; initially valid: {summary.initially_valid}"
    if report.operation is Operation.REPAIR and not report.dry_run:
        counts += f"; repaired: {summary.repaired}; failed: {summary.failed}"
    elif report.operation is Operation.VERIFY:
        counts += f"; passed: {summary.valid}; failed: {summary.failed}"
    else:
        counts += f"; need repair: {summary.planned}; failed: {summary.failed}"
    counts += f"; skipped: {summary.skipped}; unverified: {summary.unverified}"
    lines.append(counts)

    planned = [result for result in report.results if result.overall_status is OverallStatus.PLANNED]
    if planned and not quiet:
        lines.append("")
        lines.append(style("Would repair:" if report.dry_run or report.operation is Operation.DETECT else "Planned:", Style.BOLD))
        for result in planned:
            launcher = result.script.launcher
            path = style(_t(str(launcher.path)), Style.DIM) if launcher else ""
            lines.append(f"  {style(_t(result.script.name), Style.CYAN)} ({result.reason_code.value}): {path}")

    repaired = [result for result in report.results if result.overall_status is OverallStatus.REPAIRED]
    if repaired and not quiet:
        lines.append("")
        lines.append(style("Repaired:", Style.BOLD))
        for result in repaired:
            lines.append(f"  {style(_t(result.script.name), Style.GREEN)}: {'; '.join(check.message for check in result.verification)}")

    attention = [result for result in report.results if result.overall_status in (OverallStatus.FAILED, OverallStatus.UNVERIFIED, OverallStatus.SKIPPED)]
    if attention:
        lines.append("")
        lines.append(style("Needs attention:", Style.BOLD))
        for result in attention:
            launcher = result.script.launcher
            tag = style(f"[{result.overall_status.value}]", *STATUS_STYLES[result.overall_status])
            # The owning distribution tells apart entries that share a name (entry_point_conflict).
            owner = style(f"({_t(_package_label(result))})", Style.DIM)
            lines.append(f"  {style(_t(result.script.name), Style.BOLD)} {owner} {tag} {result.reason_code.value}: {_t(result.message)}")
            if launcher is not None and result.overall_status is OverallStatus.FAILED:
                lines.append(f"      Path: {_t(str(launcher.path))}")
            if result.recovery is not None and result.recovery.retained_path is not None:
                lines.append(f"      {style('Recovery copy retained at:', Style.YELLOW)} {_t(str(result.recovery.retained_path))}")

    if report.run_errors:
        lines.append("")
        lines.append(style("Run errors:", Style.RED, Style.BOLD))
        for error in report.run_errors:
            lines.append(f"  {style(error.reason_code.value, Style.RED)}: {_t(error.message)}")

    if report.operation is not Operation.DETECT and not report.dry_run:
        lines.append(_verification_line(report))
    if report.operation is Operation.REPAIR and not report.dry_run:
        lines.append(f"Modified artifacts: {summary.artifacts_modified}" + (f"; written then restored: {summary.artifacts_restored}" if summary.artifacts_restored else ""))
    if report.stopped_early:
        lines.append(style("Repair stopped early; remaining candidates were not attempted.", Style.YELLOW))
    if report.diagnostics.file_logging:
        state = style("complete", Style.GREEN) if report.diagnostics.complete else style("INCOMPLETE", Style.RED, Style.BOLD)
        lines.append(f"File logging: {_t(str(report.diagnostics.run_dir))} ({state})")
    else:
        lines.append(f"File logging: {style('not enabled', Style.DIM)}")
    code_style = (Style.GREEN,) if report.exit_code == 0 else (Style.RED, Style.BOLD)
    lines.append(f"Exit code: {style(str(report.exit_code), *code_style)}")
    return "\n".join(lines)
