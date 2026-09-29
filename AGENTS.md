# AGENTS.md

Guidelines and specifications for working on python-env-repair. User-facing behavior is documented in [README.md](README.md); keep the two consistent when behavior changes.

## Core principle

Do not scan files that look like scripts. Use Python package metadata to decide which files should be console scripts, then detect and repair them according to the platform's launcher format. A pip package's console script gets repaired; uv, ruff, and other standalone binaries stay untouched.

## Safety boundaries

The utility may only:

- read package metadata and the current scripts directory,
- replace or create launchers that metadata declares and that are confirmed to belong to that `console_scripts` entry,
- generate launchers for the current interpreter.

It must never:

- install, download, upgrade, or resolve packages, or connect to the network;
- modify package source, native libraries, distribution metadata, or `RECORD`;
- modify or execute a file just because it is in the scripts directory or has a familiar name;
- write outside the scripts directory, except diagnostic files under an explicit `--log-dir`;
- replace the target interpreter, follow symlinks or junctions to a write target, or write through ambiguous hard links;
- elevate privileges or terminate processes;
- import entry points or run package code, except approved startup checks in `--verification execute`;
- write anything during `detect` or `repair --dry-run` (no logs, reports, backups, staging files, locks, or bytecode under `python -B`).

## Behavioral contracts

These are settled decisions. Change them only deliberately, and update the README and tests together.

- **Target environment.** The running interpreter: `sys.executable` made absolute but not symlink-resolved, `sys.prefix`, and `sysconfig` paths. The metadata scope is `purelib` and `platlib`; ambient user/system distributions and `PYTHONPATH` never enlarge the repair set. The resolved interpreter path may be used for containment checks, never as the launch command.
- **Artifact model.** An entry owns a list of observed and expected artifacts, not one fixed path or a Windows `.exe` + `-script.py` pair. Current generators write a single `foo.exe`; legacy sidecars are reported and never deleted.
- **Names.** Reject entry names that escape the scripts directory, contain separators or control characters, are invalid on Windows, or collide after platform mapping (including `.py*` → `.exe` on Windows and case-insensitive collisions). Generate the exact name only (`variants = {""}`); any other output is `generation_failed`.
- **Ownership.** Metadata authorizes a name; ownership authorizes replacing an existing file. Owned means every line matches a known generator template for this entry, or `RECORD` lists the file and it imports the entry point. A missing `RECORD` or hash mismatch is uncertainty, not permission. Unrecognized wrappers are `unknown` and left alone rather than rewritten speculatively.
- **Unix detection.** Compare the shebang (direct or `/bin/sh` wrapper) with the target interpreter, and check execute mode bits separately from actual accessibility; an ACL or mount policy failure is not a missing execute bit. Unchanged paths never justify skipping detection of missing or non-executable entries.
- **Windows detection.** Never parse PE internals. Without `--relocated` or `--previous-manifest`, an existing owned launcher is `unknown`; existence alone is never proof of validity. A previous manifest is read-only evidence: reconcile it with current metadata and recompute destination paths.
- **Repair.** Take the per-environment lock, then re-read metadata and artifact identity; a changed target needs a new decision, not the stale plan. Generate into fresh staging on the destination filesystem, verify the output set, preserve the original bytes and mode for recovery, commit with closed handles and atomic replace, then recheck content and mode. Never let a generator write to live files. Replaced files keep their mode plus execute for each class that can read; new files get `(mode | 0o555) & 0o7777`. Refuse ownership/permission cases that cannot be preserved rather than broadening access.
- **Failure isolation.** One entry failing does not stop the others. Run-wide integrity failures, lock contention, and failed requested diagnostics stop the run. After a write, a failed required check triggers rollback; the write and rollback outcomes are reported independently. A failed rollback keeps the recovery copy and reports its path even without `--log-dir`.
- **Verification.** Structural by default and reported as "startup not checked". Execution only runs approved commands by absolute artifact path, as an argument list, no shell, no stdin, with a timeout, continuous draining of both streams, at most 64 KiB kept per stream (head and tail, with `truncated`, `bytes_seen`, `bytes_retained`), and the process group terminated and reaped on timeout. Decide results from the exit code and policy, not from stderr content. No automatic fallback to `--help`, `--version`, or entry-point import. `repaired` is set only after the required checks pass.
- **Idempotence.** A second repair of a healthy environment writes nothing. Without persisted evidence a Windows run may truthfully report `unknown`, but must not rebuild blindly.
- **Persistence.** The manifest and report stay in memory unless `--log-dir` is given. `--verbose`, `--json`, CI, and exceptions never enable file output. No hidden state is saved to help later runs.
- **Exit codes.** `0` completed (candidates in `detect`/dry-run are not failures), `1` item or required verification failed, `2` invalid arguments, `3` run-level failure, `130` interrupted. Priority 130 > 3 > 1; the report keeps every known failure.

## Architecture

| Module | Responsibility | Boundary |
| --- | --- | --- |
| `__init__.py` | Public API (`run`, `RunOptions`, ...) and passive package logger | No discovery, file creation, or repair on import; only a `NullHandler` |
| `__main__.py` | Delegate to the CLI | No business logic |
| `environment.py` | Runtime identity, scripts path, metadata roots | No guesses about ambient environments |
| `platform.py` | Platform selection and path policy | Unsupported platforms are reported explicitly |
| `models.py` | Typed dataclasses and enums: environment, entries, artifacts, plan, results, verification policy, report | Serializable, versioned schemas; stable reason codes |
| `discovery.py` | Read distributions and `console_scripts` | Never calls `EntryPoint.load()` or imports packages |
| `detector.py` | Ownership, path checks, platform inspection, reasons | Read-only; produces evidence and candidates |
| `manifest.py` | Build and validate the plan; atomic JSON persistence | Stored paths never bypass current checks |
| `generator.py` | Built-in launcher generator and vendored stub loading | Pinned stub hashes; mismatching stubs are refused |
| `repair.py` | Staged generation, replacement, recovery | Processes only validated candidates |
| `lock.py` | Cooperative per-environment lock | Coordinates this utility only |
| `validator.py` | Structural checks and explicit execution policy | Never runs unknown commands |
| `workflow.py` | Shared detect/repair/verify flow for the CLI and API | Does not configure logging |
| `logger.py` | Formatters, event output, context, handler lifecycle | Does not decide repair behavior |
| `reporting.py` | Text summary, JSON report | Counts come from results, not log lines |
| `cli.py` | Arguments, output modes, run lifecycle, exit code | Configures logging once; validates conflicting arguments before locks or files |

Keep the layout flat. Do not add a plugin framework; extract a module only when its size warrants it.

## Logging specification

- Standard-library `logging` only; no Loguru, and Rich only as an optional display layer if ever added. Modules use `logging.getLogger(__name__)` under `python_env_repair.*` and never attach handlers or touch the root logger.
- The CLI sets the package logger to DEBUG with `propagate=False`, a console handler at INFO/DEBUG/WARNING (default/`--verbose`/`--quiet`), and a DEBUG JSONL handler only with `--log-dir`. Repeated configuration must not duplicate handlers; shutdown closes only owned handlers.
- stderr carries progress; stdout carries only the final result, and with `--json` exactly one object. Subprocess output is captured, never inherited.
- Severity is separate from business state: `needs_repair` is INFO. DEBUG = evidence and path comparisons; INFO = phases and per-item results; WARNING = limited verification or degraded diagnostics; ERROR = an item failed; CRITICAL = the run cannot continue.
- Event names are stable identifiers: `run.started|completed|failed|interrupted`, `environment.detected`, `discovery.completed|problem`, `script.checked|skipped`, `repair.planned|started|generated|replaced|completed|failed|cleanup_failed`, `verification.started|completed|failed`, `rollback.completed|failed`. Emit `rollback.*` only when a rollback actually ran.
- JSONL records (schema version 1) carry `timestamp` (UTC, ms), `run_id`, `sequence`, `level`, `event`, `message`, `logger`, `phase`, `operation`, `dry_run`, `script_id`, `script`, `package`, `package_version`, `entry_point`, `path`, `status`, `reason_code`, `duration_ms` (monotonic clock), `details`, and `exception`. Serialize explicit fields only, never `LogRecord.__dict__` or arbitrary `repr()`. Record only evidence actually obtained; never present an inferred Windows interpreter path as read from the `.exe`.
- Log an exception once, at the per-item boundary. Tracebacks go to the console only with `--verbose`, always to the file log, and never with local variables. Formatters copy a record before coloring it.
- Sanitize consistently: escape control characters in JSONL, strip ANSI from subprocess text shown on the terminal, redact tokens, passwords, and authenticated URLs. Show failure paths in full.
- With `--log-dir`, create a new `<UTC timestamp>-<id>` directory exclusively, save the manifest before the first modification, write JSON through a temporary file plus replace, and save the report on completion, failure, or interruption. A log-write failure is reported once on stderr, marks diagnostics incomplete, and stops new repairs after the current file operation. No rotation or cleanup of other runs.

## Tooling rules

- Python 3.10 is the minimum; keep `requires-python`, Ruff `target-version = "py310"`, and ty `python-version = "3.10"` aligned.
- The Ruff configuration is inherited from `sd-webui-all-in-one`: its 52 unique ignore rules (deduplicated, original order), line length 200, 4-space indent, double quotes, magic trailing commas respected. Do not add or re-enable ignores as part of unrelated work, do not set `select = ["ALL"]`, and do not broaden rules through command-line overrides.
- Ignored lint rules do not relax behavior: `S110`/`BLE001` never justify silently swallowing backup, replacement, permission, or verification failures; `SIM115` never justifies leaving handles open (Windows replacement depends on closed handles); `PLW1510` never justifies ignoring subprocess return codes.
- ty keeps its default diagnostics with no global `[tool.ty.rules]` ignores. Fix the dependency environment or types first; use a narrow, commented local suppression only for a confirmed tool limitation. Never exclude core modules.
- ty's platform switch is static analysis only; it does not validate behavior on another OS.
- Development dependencies are intentionally unpinned (`ruff`, `ty`, `pytest`, test-only `distlib`); `setuptools` builds. Treat new tool diagnostics after an upstream release as maintenance, not as a reason to widen ignores.
- Never hard-code a machine-specific interpreter path in project configuration or CI.

## Checks

Run from the repository root with the development interpreter (the one that has the dev group installed):

```bash
python -m ruff check python_env_repair tests
python -m ruff format --check python_env_repair tests
python -m ty check --python <dev-python> python_env_repair tests
python -m ty check --python <dev-python> --python-platform win32 python_env_repair tests
python -m ty check --python <dev-python> --python-platform darwin python_env_repair tests
python -B -m pytest tests
```

Passing Ruff and ty does not prove launcher repair is correct; behavior tests do.

## Testing guidelines

- Assert observable outcomes: reason codes, statuses, report and event schemas, file bytes, modes and mtimes, and subprocess behavior. Do not snapshot human-readable log lines or mirror implementation branches.
- Use disposable fixtures only; never touch a real user environment. Take file snapshots after fixture preparation, and keep that preparation separate from the repair run.
- Read-only operations must leave fixture contents, modes, and mtimes unchanged, and a helper that must never execute must stay unexecuted.
- `tests/test_generator.py` is the byte-equivalence gate with distlib; any generator change must keep it passing or document the intentional difference in the README table.
- Mocked Windows tests on Linux are not Windows validation. Report native coverage honestly in the README's platform table and never describe a skipped or simulated case as passed.

## Vendored launcher stubs

`python_env_repair/_launchers/` holds `t32.exe`, `t64.exe`, and `t64-arm.exe` copied unmodified from distlib 0.4.3 with their PSF-2.0 license. Their SHA-256 hashes are pinned in `generator.py` and in `_launchers/README.md`. Updating a stub is deliberate: replace the file, update both hash tables, and rerun the equivalence tests against the matching distlib release. `LICENSE.txt` must ship in every distribution.

## Release

`.github/workflows/release.yml` runs on a version change in `python_env_repair/version.py` on `main`, on `v*` tags, and manually. It lints, tests, and type-checks on Python 3.10–3.14, builds, checks that the wheel carries the pinned stubs and both licenses, runs `twine check --strict`, probes a no-dependency install, publishes to PyPI (environment `pypi`, secret `TWINE_PASSWORD`), and creates a GitHub release for tags. A tag must match `VERSION`. Committing, tagging, pushing, and publishing are separate actions that need explicit approval.

## Open work

- Native Windows and macOS runs, including checking that generated Windows launchers start, and CI jobs on all three OSes.
- A run on Python 3.10, the declared minimum.
- Windows timeout cleanup of the whole process tree (only the direct child is killed today).
- Confirm the `python-env-repair` name on PyPI and set up the `pypi` environment and secret. The workflow has not run on GitHub yet.

Out of scope unless planned separately: external-interpreter orchestration, process discovery or termination, parallel repair, crash-recovery transactions, a shebang-only editing mode, custom-wrapper migration, `gui_scripts`, entry-point import verification, log retention, Rich output, and full environment relocation (`pyvenv.cfg`, `.pth`, `.egg-link`, package configuration, native dependencies).
