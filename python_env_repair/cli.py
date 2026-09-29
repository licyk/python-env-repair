"""Command-line interface: arguments, output modes, logging lifecycle, and exit code."""

from __future__ import annotations

import argparse
import shlex
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO

from python_env_repair import __version__
from python_env_repair.logger import (
    DiagnosticsSetupError,
    LoggingSession,
    Verbosity,
    create_run_directory,
    new_run_id,
    sanitize_for_terminal,
    COLOR_MODES,
    Style,
    should_use_color,
    utc_timestamp,
)
from python_env_repair.manifest import ManifestError, load_previous_manifest
from python_env_repair.models import (
    EnvironmentInfo,
    Operation,
    ReasonCode,
    RelocationContext,
    RelocationSource,
    RepairReport,
    RunError,
    VerificationCommand,
    VerificationMode,
    VerificationPolicy,
)
from python_env_repair.reporting import EXIT_INTERRUPTED, EXIT_USAGE, finalize, render_text, to_json
from python_env_repair.workflow import DiagnosticFiles, RunOptions, run

PROG = "python -B -m python_env_repair"
MAX_VERIFY_TIMEOUT = 3600.0


class UsageError(Exception):
    """Invalid or conflicting arguments (exit code 2)."""


def _add_common(parser: argparse.ArgumentParser) -> None:
    output = parser.add_argument_group("output")
    output.add_argument("--json", action="store_true", help="print exactly one JSON report object on stdout")
    level = output.add_mutually_exclusive_group()
    level.add_argument("-v", "--verbose", action="store_true", help="show detection evidence and tracebacks on stderr")
    level.add_argument("-q", "--quiet", action="store_true", help="show only warnings and errors on stderr and a brief summary")
    output.add_argument(
        "--color",
        choices=COLOR_MODES,
        default="on",
        help="colored logs and summary: on (default; off when NO_COLOR is set or TERM=dumb), auto (terminals only), always (ignores NO_COLOR), never. JSON output and log files are never colored",
    )
    output.add_argument("--log-dir", type=Path, metavar="PATH", help="enable diagnostic files (events.jsonl, manifest.json, report.json) in a new run directory under PATH")
    evidence = parser.add_argument_group("relocation evidence (Windows launchers)").add_mutually_exclusive_group()
    evidence.add_argument("--relocated", action="store_true", help="assert that this environment was moved; allows conservative rebuilding of owned launchers")
    evidence.add_argument("--previous-manifest", type=Path, metavar="PATH", help="read evidence from a manifest.json or report.json written by an earlier run")


def _add_verification(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("verification")
    group.add_argument("--verification", choices=("structural", "execute"), default="structural", help="structural checks only (default), or also run approved commands")
    group.add_argument(
        "--verify-command",
        action="append",
        default=[],
        metavar="NAME=ARGS",
        help="approved startup check for entry NAME, e.g. 'mytool=--version'; ARGS are split like a POSIX shell but never run through a shell",
    )
    group.add_argument("--verify-timeout", type=float, default=30.0, metavar="SECONDS", help="timeout for each startup check (default: 30)")
    group.add_argument("--verify-allow-code", type=int, action="append", metavar="CODE", help="exit code accepted by startup checks (repeatable; default: 0)")


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(prog=PROG, description="Detect and repair console_scripts launchers of this Python environment without reinstalling packages.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.required = True
    detect = commands.add_parser("detect", help="inspect entry points and report what would change")
    _add_common(detect)
    repair = commands.add_parser("repair", help="regenerate entry points that need it")
    repair.add_argument("--dry-run", action="store_true", help="build and print the plan only; writes nothing")
    _add_common(repair)
    _add_verification(repair)
    verify = commands.add_parser("verify", help="verify entry points without modifying them")
    _add_common(verify)
    _add_verification(verify)
    return parser


def _parse_verify_commands(values: list[str], timeout: float, allowed: frozenset[int]) -> dict[str, VerificationCommand]:
    commands: dict[str, VerificationCommand] = {}
    for value in values:
        name, sep, raw_args = value.partition("=")
        name = name.strip()
        if not sep or not name:
            raise UsageError(f"--verify-command expects NAME=ARGS, got {value!r}")
        if name in commands:
            raise UsageError(f"--verify-command given twice for {name!r}")
        try:
            args = tuple(shlex.split(raw_args, posix=True))
        except ValueError as exc:
            raise UsageError(f"cannot parse arguments for {name!r}: {exc}") from exc
        commands[name] = VerificationCommand(args=args, timeout=timeout, allowed_return_codes=allowed)
    return commands


def options_from_args(args: argparse.Namespace) -> RunOptions:
    """Validate arguments and build run options without creating any file or lock.

    Raises:
        UsageError: For invalid or conflicting arguments.
    """
    operation = Operation(args.command)
    dry_run = bool(getattr(args, "dry_run", False))
    if dry_run and args.log_dir is not None:
        raise UsageError("--dry-run cannot be combined with --log-dir: a dry run writes no files (redirect --json output instead)")
    policy = VerificationPolicy()
    if operation is not Operation.DETECT:
        mode = VerificationMode(args.verification)
        if args.verify_command and mode is not VerificationMode.EXECUTE:
            raise UsageError("--verify-command requires --verification execute")
        if not 0 < args.verify_timeout <= MAX_VERIFY_TIMEOUT:
            raise UsageError(f"--verify-timeout must be greater than 0 and at most {MAX_VERIFY_TIMEOUT:g} seconds")
        if dry_run and mode is VerificationMode.EXECUTE:
            raise UsageError("--dry-run never executes entry points; --verification execute is not allowed")
        allowed = frozenset(args.verify_allow_code or [0])
        policy = VerificationPolicy(mode=mode, commands=_parse_verify_commands(args.verify_command, args.verify_timeout, allowed))
    relocation = RelocationContext()
    if args.relocated:
        relocation = RelocationContext(source=RelocationSource.CALLER_ASSERTION)
    elif args.previous_manifest is not None:
        try:
            relocation = load_previous_manifest(args.previous_manifest)
        except ManifestError as exc:
            raise UsageError(f"--previous-manifest: {exc}") from exc
    return RunOptions(operation=operation, dry_run=dry_run, relocation=relocation, verification=policy)


def _write(stream: TextIO, text: str) -> None:
    try:
        stream.write(text + "\n")
    except UnicodeEncodeError:
        encoding = getattr(stream, "encoding", None) or "ascii"
        stream.write(text.encode(encoding, "backslashreplace").decode(encoding) + "\n")
    stream.flush()


def _emit_result(report: RepairReport, *, as_json: bool, quiet: bool, stdout: TextIO, color: bool = False) -> None:
    _write(stdout, to_json(report) if as_json else render_text(report, quiet=quiet, color=color))


def _early_failure(options: RunOptions, message: str, *, as_json: bool, quiet: bool, stdout: TextIO, stderr: TextIO, color_out: bool = False, color_err: bool = False) -> int:
    """Report a run-level failure that happened before the workflow started."""
    report = RepairReport(run_id=new_run_id(), tool_version=__version__, operation=options.operation, dry_run=options.dry_run, started_at=utc_timestamp())
    report.run_errors.append(RunError(ReasonCode.DIAGNOSTICS_FAILED, message))
    report.diagnostics.file_logging = True
    report.diagnostics.complete = False
    report.diagnostics.error = message
    report.finished_at = utc_timestamp()
    finalize(report)
    _write(stderr, f"{Style(color_err)('error:', Style.RED, Style.BOLD)} {sanitize_for_terminal(message)}")
    _emit_result(report, as_json=as_json, quiet=quiet, stdout=stdout, color=color_out)
    return report.exit_code


def main(argv: Optional[Sequence[str]] = None, *, stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None) -> int:
    """Run the CLI and return the process exit code."""
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        options = options_from_args(args)
    except UsageError as exc:
        _write(err, f"{PROG}: error: {exc}")
        return EXIT_USAGE

    verbosity = Verbosity.VERBOSE if args.verbose else Verbosity.QUIET if args.quiet else Verbosity.NORMAL
    color_err = should_use_color(args.color, err)
    color_out = not args.json and should_use_color(args.color, out)
    try:
        run_id = new_run_id()
        diagnostics: Optional[DiagnosticFiles] = None
        jsonl_path: Optional[Path] = None
        if args.log_dir is not None:
            try:
                run_dir, run_id = create_run_directory(args.log_dir, run_id)
            except DiagnosticsSetupError as exc:
                return _early_failure(options, str(exc), as_json=args.json, quiet=args.quiet, stdout=out, stderr=err, color_out=color_out, color_err=color_err)
            jsonl_path = run_dir / "events.jsonl"
        session = LoggingSession(verbosity=verbosity, color=color_err, stream=err, jsonl_path=jsonl_path)
        try:
            session.start()
        except OSError as exc:
            session.close()
            return _early_failure(options, f"cannot create diagnostic log {jsonl_path}: {exc}", as_json=args.json, quiet=args.quiet, stdout=out, stderr=err, color_out=color_out, color_err=color_err)
        if jsonl_path is not None:
            diagnostics = DiagnosticFiles(jsonl_path.parent, jsonl_path, lambda: session.diagnostics_failed)

        def header(env: EnvironmentInfo, current_run_id: str) -> None:
            if verbosity is Verbosity.QUIET:
                return
            mode = options.operation.value + (" --dry-run" if options.dry_run else "")
            style = Style(color_err)
            lines = [
                style("Python Console Script Repair", Style.BOLD),
                f"{style('Run:', Style.DIM)} {current_run_id}",
                f"{style('Mode:', Style.DIM)} {style(mode, Style.CYAN)}    {style('Platform:', Style.DIM)} {env.platform.value}",
                f"{style('Python:', Style.DIM)} {sanitize_for_terminal(str(env.python))}",
                f"{style('Scripts:', Style.DIM)} {sanitize_for_terminal(str(env.scripts_dir))}",
                "",
            ]
            _write(err, "\n".join(lines))

        try:
            report = run(
                RunOptions(operation=options.operation, dry_run=options.dry_run, relocation=options.relocation, verification=options.verification, run_id=run_id),
                diagnostics=diagnostics,
                on_environment=header,
            )
        finally:
            session.close()
        _emit_result(report, as_json=args.json, quiet=args.quiet, stdout=out, color=color_out)
        return report.exit_code
    except KeyboardInterrupt:
        _write(err, "interrupted")
        return EXIT_INTERRUPTED
