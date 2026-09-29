"""Logging configuration, event formatting, and handler lifecycle.

Business modules only call :func:`logging.getLogger` and emit events through
:class:`EventEmitter`. Handlers are attached exclusively by :class:`LoggingSession`, which the
CLI owns. Importing the package never opens files or configures the console.
"""

from __future__ import annotations

import enum
import itertools
import json
import logging
import os
import re
import secrets
import sys
import threading
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Mapping, Optional, TextIO

from python_env_repair.models import ConsoleScript, JsonDict, JsonValue, Operation

PACKAGE_LOGGER_NAME = "python_env_repair"
LOG_SCHEMA_VERSION = 1
EVENT_ATTR = "python_env_repair_event"
_OWNED_ATTR = "_python_env_repair_owned"

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[@-_]")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_URL_CREDENTIALS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s:@]+(:[^/\s@]*)?@")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(?P<key>token|password|passwd|secret|api[_-]?key|access[_-]?key|auth)(?P<sep>\s*[=:]\s*)(?P<value>[^\s&;,]+)")


class Verbosity(str, enum.Enum):
    """Console verbosity."""

    QUIET = "quiet"
    NORMAL = "normal"
    VERBOSE = "verbose"


def utc_timestamp(moment: Optional[datetime] = None) -> str:
    """UTC ISO 8601 timestamp with milliseconds, e.g. ``2026-09-29T10:30:12.182Z``."""
    value = (moment or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


def new_run_id() -> str:
    """Run identifier made of a UTC timestamp and random suffix; safe as a Windows filename."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)


def redact(text: str) -> str:
    """Redact credentials in URLs and ``token=...``-style assignments."""
    text = _URL_CREDENTIALS.sub(lambda match: f"{match.group('scheme')}***@", text)
    return _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group('key')}{match.group('sep')}***", text)


def sanitize_for_terminal(text: str) -> str:
    """Remove ANSI/terminal control sequences so external text cannot fake log lines."""
    text = _ANSI.sub("", text)
    return _CONTROL.sub("?", text)


def sanitize_json_value(value: JsonValue) -> JsonValue:
    """Redact strings recursively inside a JSON-compatible value."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [sanitize_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_json_value(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class RunContext:
    """Static run fields attached to every event."""

    run_id: str
    operation: Operation
    dry_run: bool


@dataclass(frozen=True)
class EventData:
    """Structured fields of one event; frozen at the producer."""

    event: str
    phase: str
    run_id: str
    sequence: int
    operation: str
    dry_run: bool
    script_id: Optional[str] = None
    script: Optional[str] = None
    package: Optional[str] = None
    package_version: Optional[str] = None
    entry_point: Optional[str] = None
    path: Optional[str] = None
    status: Optional[str] = None
    reason_code: Optional[str] = None
    duration_ms: Optional[int] = None
    progress: Optional[str] = None
    details: JsonDict = field(default_factory=dict)


class EventEmitter:
    """Emit structured events with run context and a per-run sequence number."""

    def __init__(self, context: RunContext) -> None:
        self.context = context
        self._sequence = itertools.count(1)
        self._lock = threading.Lock()

    def emit(
        self,
        log: logging.Logger,
        level: int,
        event: str,
        message: str,
        *,
        phase: str,
        script: Optional[ConsoleScript] = None,
        path: Optional[Path] = None,
        status: Optional[str] = None,
        reason_code: Optional[str] = None,
        duration_ms: Optional[int] = None,
        progress: Optional[str] = None,
        details: Optional[JsonDict] = None,
        exc_info: Optional[BaseException] = None,
    ) -> None:
        """Emit one event.

        Args:
            log: Module logger that owns the event.
            level: Logging level.
            event: Stable event name such as ``repair.started``.
            message: Readable description.
            phase: Phase label, e.g. ``detect``.
            script: Associated entry point, if any.
            path: Artifact path involved in the event.
            status: Business state for this phase.
            reason_code: Stable reason code.
            duration_ms: Duration measured with a monotonic clock.
            progress: Progress label such as ``2/7``.
            details: Known structured evidence.
            exc_info: Exception to record with traceback.
        """
        with self._lock:
            sequence = next(self._sequence)
        event_details: JsonDict = {}
        if details:
            event_details.update(details)
        data = EventData(
            event=event,
            phase=phase,
            run_id=self.context.run_id,
            sequence=sequence,
            operation=self.context.operation.value,
            dry_run=self.context.dry_run,
            script_id=script.script_id if script else None,
            script=script.name if script else None,
            package=script.package if script else None,
            package_version=script.version if script else None,
            entry_point=script.value if script else None,
            path=str(path) if path is not None else None,
            status=status,
            reason_code=reason_code,
            duration_ms=duration_ms,
            progress=progress,
            details=event_details,
        )
        exc: Optional[tuple[type[BaseException], BaseException, Optional[TracebackType]]] = None
        if exc_info is not None:
            exc = (type(exc_info), exc_info, exc_info.__traceback__)
        log.log(level, message, extra={EVENT_ATTR: data}, exc_info=exc)


def _event_of(record: logging.LogRecord) -> Optional[EventData]:
    value = getattr(record, EVENT_ATTR, None)
    return value if isinstance(value, EventData) else None


def exception_to_dict(exc_info: tuple[type[BaseException], BaseException, Optional[TracebackType]]) -> JsonDict:
    """Serialize exception information without local variables."""
    exc_type, exc, tb = exc_info
    data: JsonDict = {
        "type": exc_type.__name__,
        "message": redact(str(exc)),
        "traceback": redact("".join(traceback.format_exception(exc_type, exc, tb))),
    }
    if isinstance(exc, OSError):
        data["errno"] = exc.errno
        data["strerror"] = exc.strerror
        data["filename"] = os.fspath(exc.filename) if isinstance(exc.filename, (str, os.PathLike)) else None
        winerror = getattr(exc, "winerror", None)
        data["winerror"] = winerror if isinstance(winerror, int) else None
    return data


class JsonLineFormatter(logging.Formatter):
    """Format records as single-line JSON objects with explicit fields only."""

    def format(self, record: logging.LogRecord) -> str:
        """Format one record."""
        event = _event_of(record)
        data: JsonDict = {
            "schema_version": LOG_SCHEMA_VERSION,
            "timestamp": utc_timestamp(datetime.fromtimestamp(record.created, timezone.utc)),
            "run_id": event.run_id if event else None,
            "sequence": event.sequence if event else None,
            "level": record.levelname,
            "event": event.event if event else "log.message",
            "message": redact(record.getMessage()),
            "logger": record.name,
            "phase": event.phase if event else None,
            "operation": event.operation if event else None,
            "dry_run": event.dry_run if event else None,
            "script_id": event.script_id if event else None,
            "script": event.script if event else None,
            "package": event.package if event else None,
            "package_version": event.package_version if event else None,
            "entry_point": event.entry_point if event else None,
            "path": event.path if event else None,
            "status": event.status if event else None,
            "reason_code": event.reason_code if event else None,
            "duration_ms": event.duration_ms if event else None,
            "details": sanitize_json_value(event.details) if event else {},
            "exception": exception_to_dict(record.exc_info) if record.exc_info and record.exc_info[1] is not None else None,
        }
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


class Style:
    """ANSI styling that collapses to plain text when color is disabled."""

    RESET = "\x1b[0m"
    BOLD = "1"
    DIM = "2"
    RED = "31"
    GREEN = "32"
    YELLOW = "33"
    BLUE = "34"
    CYAN = "36"
    ON_RED = "1;37;41"

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        """Wrap already-sanitized ``text`` in the given SGR codes."""
        if not self.enabled or not codes or not text:
            return text
        return f"\x1b[{';'.join(codes)}m{text}{self.RESET}"


LEVEL_STYLES = {
    logging.DEBUG: (Style.DIM,),
    logging.INFO: (Style.GREEN,),
    logging.WARNING: (Style.YELLOW, Style.BOLD),
    logging.ERROR: (Style.RED, Style.BOLD),
    logging.CRITICAL: (Style.ON_RED,),
}
MESSAGE_STYLES = {
    logging.DEBUG: (Style.DIM,),
    logging.WARNING: (Style.YELLOW,),
    logging.ERROR: (Style.RED,),
    logging.CRITICAL: (Style.RED, Style.BOLD),
}


class ConsoleFormatter(logging.Formatter):
    """Human-readable phase-tagged lines for stderr. Never mutates the shared record.

    With color enabled the time is dimmed, the level and message are colored by severity,
    the phase tag is cyan, and the entry name is bold. Text from records is sanitized
    before styling, so it cannot inject its own escape sequences.
    """

    def __init__(self, *, verbose: bool, color: bool) -> None:
        super().__init__()
        self.verbose = verbose
        self.color = color
        self.style = Style(color)

    def format(self, record: logging.LogRecord) -> str:
        """Format one record."""
        style = self.style
        event = _event_of(record)
        clock = style(datetime.fromtimestamp(record.created, timezone.utc).astimezone().strftime("%H:%M:%S"), Style.DIM)
        level = style(f"{record.levelname:<5}", *LEVEL_STYLES.get(record.levelno, ()))
        label = ""
        if event:
            label = style(f"[{event.phase.capitalize()}{' ' + event.progress if event.progress else ''}]", Style.CYAN) + " "
            if event.script:
                label += style(sanitize_for_terminal(event.script), Style.BOLD) + ": "
        message = style(sanitize_for_terminal(redact(record.getMessage())), *MESSAGE_STYLES.get(record.levelno, ()))
        lines = [f"{clock} {level} {label}{message}"]
        indent = " " * 15
        if event and event.path and (record.levelno >= logging.WARNING or self.verbose):
            lines.append(f"{indent}{style('Path:', Style.DIM)} {sanitize_for_terminal(event.path)}")
        if event and self.verbose:
            for key, value in event.details.items():
                rendered = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
                lines.append(f"{indent}{style(key + ':', Style.DIM)} {sanitize_for_terminal(redact(rendered))}")
        if record.exc_info and record.exc_info[1] is not None:
            exc = record.exc_info[1]
            if self.verbose:
                text = "".join(traceback.format_exception(record.exc_info[0], exc, record.exc_info[2])).rstrip()
                lines.extend(indent + style(sanitize_for_terminal(redact(line)), Style.DIM) for line in text.splitlines())
            else:
                lines.append(f"{indent}{style(type(exc).__name__ + ':', Style.RED)} {sanitize_for_terminal(redact(str(exc)))}")
        return "\n".join(lines)


class JsonLineFileHandler(logging.Handler):
    """Append JSONL events and expose write failures to the run coordinator."""

    def __init__(self, path: Path, emergency_stream: Optional[TextIO] = None) -> None:
        super().__init__(logging.DEBUG)
        self.path = path
        self.emergency_stream = emergency_stream
        self.failed = False
        self.error: Optional[BaseException] = None
        self._stream: Optional[TextIO] = open(path, "x", encoding="utf-8", newline="\n")
        self.setFormatter(JsonLineFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        """Write one record; on failure record the error and stop writing."""
        if self.failed or self._stream is None:
            return
        try:
            self._stream.write(self.format(record) + "\n")
            self._stream.flush()
        except Exception as exc:
            self.failed = True
            self.error = exc
            # Emergency output bypasses the failed handler (and logging) to avoid recursion.
            try:
                stream = self.emergency_stream or sys.stderr
                stream.write(f"ERROR: writing diagnostic log {self.path} failed: {exc}; diagnostic files are incomplete\n")
                stream.flush()
            except Exception:
                pass

    def close(self) -> None:
        """Flush and close the file."""
        try:
            if self._stream is not None:
                try:
                    self._stream.flush()
                except Exception as exc:
                    if not self.failed:
                        self.failed = True
                        self.error = exc
                self._stream.close()
                self._stream = None
        finally:
            super().close()


COLOR_MODES = ("on", "auto", "always", "never")


def should_use_color(mode: str, stream: TextIO, environ: Optional[Mapping[str, str]] = None) -> bool:
    """Decide whether to colorize a console stream.

    Args:
        mode: ``on`` (the default: color unless ``NO_COLOR`` is set or ``TERM=dumb``),
            ``auto`` (like ``on``, but only on terminals), ``always`` (even with ``NO_COLOR``),
            or ``never``.
        stream: Output stream.
        environ: Environment mapping; defaults to ``os.environ``.

    Returns:
        Whether to emit ANSI color codes on ``stream``.
    """
    if mode == "never":
        return False
    if mode != "always":
        env = os.environ if environ is None else environ
        if env.get("NO_COLOR") or env.get("TERM") == "dumb":
            return False
        if mode == "auto":
            isatty = getattr(stream, "isatty", None)
            try:
                if not (isatty and isatty()):
                    return False
            except Exception:
                return False
    return enable_ansi(stream) or mode == "always"


def enable_ansi(stream: TextIO) -> bool:
    """Make a Windows console interpret ANSI sequences; a no-op elsewhere.

    Returns:
        ``False`` only for a Windows console that cannot enable virtual terminal
        processing (legacy consoles), where escape codes would print as garbage.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        import msvcrt

        handle = msvcrt.get_osfhandle(stream.fileno())
        kernel32 = ctypes.windll.kernel32
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return True  # a file or pipe: the bytes pass through unchanged
        enable_virtual_terminal_processing = 0x0004
        if mode.value & enable_virtual_terminal_processing:
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | enable_virtual_terminal_processing))
    except Exception:
        # Not a real file descriptor (e.g. an in-memory stream): nothing to enable.
        return True


class LoggingSession:
    """Owns the handlers attached to the package logger for one CLI run."""

    def __init__(self, *, verbosity: Verbosity, color: bool, stream: TextIO, jsonl_path: Optional[Path] = None) -> None:
        self.verbosity = verbosity
        self.color = color
        self.stream = stream
        self.jsonl_path = jsonl_path
        self._handlers: list[logging.Handler] = []
        self._jsonl: Optional[JsonLineFileHandler] = None
        self._saved: Optional[tuple[int, bool]] = None

    @property
    def diagnostics_failed(self) -> bool:
        """Whether the JSONL handler failed to write."""
        return bool(self._jsonl and self._jsonl.failed)

    @property
    def diagnostics_error(self) -> Optional[BaseException]:
        """The first JSONL write error, if any."""
        return self._jsonl.error if self._jsonl else None

    def start(self) -> LoggingSession:
        """Attach handlers. Handlers owned by an earlier session are removed first.

        Raises:
            OSError: If the requested JSONL file cannot be created.
        """
        package = logging.getLogger(PACKAGE_LOGGER_NAME)
        for handler in list(package.handlers):
            if getattr(handler, _OWNED_ATTR, False):
                package.removeHandler(handler)
                handler.close()
        self._saved = (package.level, package.propagate)
        console = logging.StreamHandler(self.stream)
        console.setLevel({Verbosity.QUIET: logging.WARNING, Verbosity.NORMAL: logging.INFO, Verbosity.VERBOSE: logging.DEBUG}[self.verbosity])
        console.setFormatter(ConsoleFormatter(verbose=self.verbosity is Verbosity.VERBOSE, color=self.color))
        handlers: list[logging.Handler] = [console]
        if self.jsonl_path is not None:
            self._jsonl = JsonLineFileHandler(self.jsonl_path, emergency_stream=self.stream)
            handlers.append(self._jsonl)
        for handler in handlers:
            setattr(handler, _OWNED_ATTR, True)
            package.addHandler(handler)
            self._handlers.append(handler)
        package.setLevel(logging.DEBUG)
        package.propagate = False
        return self

    def close(self) -> None:
        """Flush and close only the handlers this session created."""
        package = logging.getLogger(PACKAGE_LOGGER_NAME)
        for handler in self._handlers:
            package.removeHandler(handler)
            try:
                handler.flush()
            finally:
                # StreamHandler.close() leaves the underlying stream (stderr) open.
                handler.close()
        self._handlers = []
        if self._saved is not None:
            package.setLevel(self._saved[0])
            package.propagate = self._saved[1]
            self._saved = None

    def __enter__(self) -> LoggingSession:
        return self.start()

    def __exit__(self, exc_type: Optional[type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        self.close()


class DiagnosticsSetupError(RuntimeError):
    """Raised when an explicitly requested log directory cannot be prepared."""


def create_run_directory(log_dir: Path, run_id: str) -> tuple[Path, str]:
    """Create a new, exclusive run directory under ``log_dir``.

    Args:
        log_dir: Directory given with ``--log-dir``.
        run_id: Preferred run identifier.

    Returns:
        The created directory and the run identifier actually used.

    Raises:
        DiagnosticsSetupError: If the directory cannot be created.
    """
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DiagnosticsSetupError(f"cannot create log directory {log_dir}: {exc}") from exc
    for attempt in range(10):
        candidate = run_id if attempt == 0 else new_run_id()
        path = log_dir / candidate
        try:
            path.mkdir()
        except FileExistsError:
            continue
        except OSError as exc:
            raise DiagnosticsSetupError(f"cannot create run directory {path}: {exc}") from exc
        return path, candidate
    raise DiagnosticsSetupError(f"could not create a unique run directory in {log_dir}")
