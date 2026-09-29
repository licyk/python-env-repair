"""CLI contract: arguments, output streams, exit codes, and opt-in diagnostic files."""

from __future__ import annotations

import io
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from python_env_repair import cli, workflow
from python_env_repair.logger import EVENT_ATTR, PACKAGE_LOGGER_NAME, EventData, JsonLineFileHandler, LoggingSession, Verbosity, redact, sanitize_for_terminal
from tests.helpers import FakeEnv, pip_script, posix_only, snapshot

JSON_TOOL = "json.tool:main"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def cli_env(fake_env: FakeEnv, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeEnv:
    """Point the CLI at a fake environment and run from an empty working directory."""
    monkeypatch.setattr(workflow, "current_environment", fake_env.info)
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    fake_env.add_dist("jt", "1.0", {"jt": JSON_TOOL, "ok": JSON_TOOL})
    fake_env.write("jt", pip_script("/old/venv/bin/python", JSON_TOOL))
    fake_env.write("ok", pip_script(str(fake_env.python), JSON_TOOL))
    return fake_env


def invoke(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(args), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_detect_reports_candidates_with_exit_zero(cli_env: FakeEnv) -> None:
    code, out, err = invoke("detect", "--color", "never")
    assert code == 0
    assert "jt (stale_shebang)" in out and "File logging: not enabled" in out
    assert "[Detection] jt: shebang points to a different Python" in err


def test_entry_point_conflicts_name_each_package(cli_env: FakeEnv) -> None:
    cli_env.add_dist("one", "1.0", {"tool": "one:main"})
    cli_env.add_dist("two", "2.0", {"tool": "two:main"})
    code, out, _ = invoke("detect", "--color", "never")
    assert code == 0
    assert "tool (one 1.0) [skipped] entry_point_conflict" in out
    assert "tool (two 2.0) [skipped] entry_point_conflict" in out


def test_json_stdout_is_one_object_and_logs_go_to_stderr(cli_env: FakeEnv) -> None:
    code, out, err = invoke("repair", "--dry-run", "--json", "--verbose")
    assert code == 0
    report = json.loads(out)
    assert report["kind"] == "python_env_repair.report" and report["dry_run"] is True
    assert report["diagnostics"]["file_logging"] is False and report["diagnostics_complete"] is True
    assert "[Discovery]" in err and "[Discovery]" not in out
    statuses = {entry["name"]: entry["overall_status"] for entry in report["entries"]}
    assert statuses == {"jt": "planned", "ok": "valid"}


@posix_only
@pytest.mark.parametrize("args", [("detect",), ("repair", "--dry-run"), ("repair", "--verbose"), ("repair", "--json"), ("verify", "--quiet")])
def test_no_diagnostic_files_without_log_dir(cli_env: FakeEnv, tmp_path: Path, args: tuple[str, ...]) -> None:
    cwd = Path.cwd()
    invoke(*args)
    assert list(cwd.iterdir()) == []
    assert not any(name.startswith(".python-env-repair") for name in os.listdir(cli_env.scripts))


def test_dry_run_with_log_dir_is_usage_error_and_creates_nothing(cli_env: FakeEnv, tmp_path: Path) -> None:
    target = tmp_path / "logs"
    code, out, err = invoke("repair", "--dry-run", "--log-dir", str(target))
    assert code == 2 and "cannot be combined" in err and out == ""
    assert not target.exists()


@posix_only
def test_log_dir_creates_parseable_artifacts(cli_env: FakeEnv, tmp_path: Path) -> None:
    target = tmp_path / "logs"
    code, out, err = invoke("repair", "--log-dir", str(target))
    assert code == 0
    runs = list(target.iterdir())
    assert len(runs) == 1
    run_dir = runs[0]
    assert sorted(path.name for path in run_dir.iterdir()) == ["events.jsonl", "manifest.json", "report.json"]
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    names = [event["event"] for event in events]
    assert names[0] == "run.started" and names[-1] == "run.completed"
    assert "repair.replaced" in names and "script.checked" in names  # DEBUG events are kept in the file
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    assert all(event["schema_version"] == 1 and event["run_id"] == run_dir.name for event in events)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["kind"] == "python_env_repair.manifest"
    assert {entry["name"]: entry["repair_status"] for entry in manifest["entries"]} == {"jt": "planned", "ok": "not_needed"}
    report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    assert report["exit_code"] == 0 and report["diagnostics"]["complete"] is True
    assert str(run_dir) in out
    assert "repair.replaced" not in err  # console stays at INFO


@posix_only
def test_unwritable_log_dir_fails_before_repair(cli_env: FakeEnv, tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    before = snapshot(cli_env.scripts)
    code, out, err = invoke("repair", "--json", "--log-dir", str(blocker / "logs"))
    assert code == 3
    assert json.loads(out)["run_errors"][0]["reason_code"] == "diagnostics_failed"
    assert snapshot(cli_env.scripts) == before


def test_log_write_failure_stops_new_repairs(cli_env: FakeEnv, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cli_env.add_dist("more", "1.0", {"zz1": JSON_TOOL, "zz2": JSON_TOOL})
    real_emit = JsonLineFileHandler.emit

    def failing_emit(self: JsonLineFileHandler, record: logging.LogRecord) -> None:
        event = getattr(record, EVENT_ATTR, None)
        if isinstance(event, EventData) and event.event == "repair.replaced" and self._stream is not None:
            self._stream.close()  # simulate the log file becoming unwritable mid-run
        real_emit(self, record)

    monkeypatch.setattr(JsonLineFileHandler, "emit", failing_emit)
    code, out, err = invoke("repair", "--json", "--log-dir", str(tmp_path / "logs"))
    report = json.loads(out)
    assert code == 3
    assert report["diagnostics_complete"] is False and report["stopped_early"] is True
    assert "diagnostic files are incomplete" in err
    statuses = [entry["overall_status"] for entry in report["entries"]]
    assert statuses.count("repaired") == 1
    assert any(entry["reason_code"] == "repair_not_attempted" for entry in report["entries"])


def test_verify_exit_codes(cli_env: FakeEnv) -> None:
    code, out, _ = invoke("verify", "--json")
    report = json.loads(out)
    assert code == 1
    assert {entry["name"]: entry["overall_status"] for entry in report["entries"]} == {"jt": "failed", "ok": "valid"}
    invoke("repair")
    code, out, _ = invoke("verify", "--verification", "execute", "--verify-command", "jt=--help", "--verify-command", "ok=--help", "--json")
    assert code == 0, out
    code, out, _ = invoke("verify", "--verification", "execute", "--verify-command", "jt=--help", "--json")
    ok = next(entry for entry in json.loads(out)["entries"] if entry["name"] == "ok")
    assert code == 1 and ok["overall_status"] == "unverified" and ok["reason_code"] == "verification_not_configured"


@pytest.mark.parametrize(
    "args",
    [
        ("verify", "--verify-command", "jt=--help"),
        ("repair", "--relocated", "--previous-manifest", "x.json"),
        ("repair", "--verbose", "--quiet"),
        ("repair", "--previous-manifest", "missing.json"),
        ("repair", "--dry-run", "--verification", "execute"),
        ("verify", "--verification", "execute", "--verify-command", "novalue"),
        ("detect", "--dry-run"),
    ],
)
def test_invalid_arguments_exit_2(cli_env: FakeEnv, args: tuple[str, ...], capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = invoke(*args)
    assert code == 2 and out == ""


def test_previous_report_serves_as_relocation_evidence(cli_env: FakeEnv, tmp_path: Path) -> None:
    code, out, _ = invoke("repair", "--json")
    evidence = tmp_path / "report.json"
    evidence.write_text(out, encoding="utf-8")
    code, out, _ = invoke("detect", "--json", "--previous-manifest", str(evidence))
    report = json.loads(out)
    assert code == 0 and report["relocation"]["source"] == "previous_manifest"


def test_run_level_environment_failure_exit_3(cli_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    from python_env_repair.environment import EnvironmentDetectionError

    def broken() -> None:
        raise EnvironmentDetectionError("no scripts directory")

    monkeypatch.setattr(workflow, "current_environment", broken)
    code, out, err = invoke("detect", "--json")
    assert code == 3 and json.loads(out)["run_errors"][0]["reason_code"] == "environment_detection_failed"


def test_interrupt_exit_130(cli_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(workflow, "repair_item", interrupt)
    code, out, _ = invoke("repair", "--json")
    report = json.loads(out)
    assert code == 130 and report["outcome"] == "interrupted"
    jt = next(entry for entry in report["entries"] if entry["name"] == "jt")
    assert jt["reason_code"] == "repair_not_attempted"


def test_logging_session_is_owned_and_idempotent() -> None:
    package = logging.getLogger(PACKAGE_LOGGER_NAME)
    before = list(package.handlers)
    stream = io.StringIO()
    first = LoggingSession(verbosity=Verbosity.NORMAL, color=False, stream=stream).start()
    second = LoggingSession(verbosity=Verbosity.NORMAL, color=False, stream=stream).start()
    logging.getLogger(PACKAGE_LOGGER_NAME + ".x").info("once")
    assert stream.getvalue().count("once") == 1
    second.close()
    first.close()
    assert package.handlers == before and package.propagate is True


def test_import_is_passive() -> None:
    code = "import logging, python_env_repair; h = logging.getLogger('python_env_repair').handlers; print(len(h), type(h[0]).__name__, logging.getLogger().handlers)"
    completed = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60)
    assert completed.stdout.strip() == "1 NullHandler []"


def test_sanitizers() -> None:
    assert redact("https://user:secret@example.com/x token=abc123 password: hunter2") == "https://***@example.com/x token=*** password: ***"
    assert sanitize_for_terminal("ok\x1b[31mred\x1b[0m\x07") == "okred?"


def test_module_invocation_help() -> None:
    completed = subprocess.run([sys.executable, "-B", "-m", "python_env_repair", "--help"], capture_output=True, text=True, cwd=PROJECT_ROOT, timeout=60)
    assert completed.returncode == 0 and "detect" in completed.stdout and "repair" in completed.stdout


@posix_only
def test_manifest_write_failure_prevents_any_modification(cli_env: FakeEnv, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_manifest(self: workflow.DiagnosticFiles, manifest: object) -> bool:
        self.error = "cannot write manifest.json: disk full"
        return False

    monkeypatch.setattr(workflow.DiagnosticFiles, "write_manifest", fail_manifest)
    before = snapshot(cli_env.scripts)
    code, out, _ = invoke("repair", "--json", "--log-dir", str(tmp_path / "logs"))
    report = json.loads(out)
    assert code == 3 and report["diagnostics_complete"] is False
    jt = next(entry for entry in report["entries"] if entry["name"] == "jt")
    assert jt["overall_status"] == "failed" and jt["reason_code"] == "repair_not_attempted"
    assert snapshot(cli_env.scripts) == before


def test_detect_run_error_does_not_invent_failed_repairs(cli_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(workflow, "_verify", interrupt)
    code, out, _ = invoke("verify", "--json")
    report = json.loads(out)
    assert code == 130
    assert not any(entry["reason_code"] == "repair_not_attempted" for entry in report["entries"])


def test_verify_timeout_is_bounded(cli_env: FakeEnv) -> None:
    assert invoke("verify", "--verification", "execute", "--verify-timeout", "inf")[0] == 2
    assert invoke("verify", "--verification", "execute", "--verify-timeout", "0")[0] == 2


ANSI = "\x1b["


def test_color_is_on_by_default(cli_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    code, out, err = invoke("detect")
    assert code == 0
    assert "\x1b[36m[Detection]\x1b[0m" in err and "\x1b[1mjt\x1b[0m" in err
    assert "\x1b[32mINFO \x1b[0m" in err
    assert "\x1b[32;1mcompleted\x1b[0m" in out and "Exit code: \x1b[32m0\x1b[0m" in out


def test_json_stdout_is_never_colored(cli_env: FakeEnv, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    code, out, err = invoke("detect", "--json", "--color", "always")
    assert ANSI not in out and json.loads(out)["exit_code"] == 0
    assert ANSI in err


@pytest.mark.parametrize(
    ("args", "no_color", "colored"),
    [
        ((), "1", False),
        (("--color", "always"), "1", True),
        (("--color", "never"), None, False),
        (("--color", "auto"), None, False),  # StringIO is not a terminal
    ],
)
def test_color_modes(cli_env: FakeEnv, monkeypatch: pytest.MonkeyPatch, args: tuple[str, ...], no_color: str | None, colored: bool) -> None:
    if no_color is None:
        monkeypatch.delenv("NO_COLOR", raising=False)
    else:
        monkeypatch.setenv("NO_COLOR", no_color)
    _, out, err = invoke("detect", *args)
    assert (ANSI in out) is colored and (ANSI in err) is colored


@posix_only
def test_log_files_are_never_colored(cli_env: FakeEnv, tmp_path: Path) -> None:
    code, out, err = invoke("repair", "--color", "always", "--log-dir", str(tmp_path / "logs"))
    assert code == 0 and ANSI in err
    run_dir = next((tmp_path / "logs").iterdir())
    for name in ("events.jsonl", "manifest.json", "report.json"):
        assert "\\u001b" not in (run_dir / name).read_text(encoding="utf-8") and ANSI not in (run_dir / name).read_text(encoding="utf-8")


def test_colored_log_lines_neutralize_embedded_escapes() -> None:
    from python_env_repair.logger import ConsoleFormatter

    record = logging.LogRecord("python_env_repair.x", logging.ERROR, __file__, 1, "bad \x1b[2Jclear", None, None)
    line = ConsoleFormatter(verbose=False, color=True).format(record)
    assert "\x1b[2J" not in line and "bad clear" in line
    assert line.count(ANSI) == line.count("\x1b[0m") * 2
