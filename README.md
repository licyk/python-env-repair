# python-env-repair

Detect and repair `console_scripts` launchers of a Python environment after the environment has been moved or copied, without reinstalling, downloading, or modifying any package.

Package metadata is the authority: only entry points declared in the environment's own `*.dist-info` / `*.egg-info` are considered, and an existing file is replaced only when it is a recognized wrapper for that same entry point. Standalone binaries in the scripts directory (uv, ruff, git, node, ...) are never modified or executed.

## Why

Moving or copying a venv leaves its console scripts pointing at the old interpreter. On Linux and macOS this shows up as `bad interpreter: No such file or directory`, and on Windows the `.exe` launchers still start the old Python. `pip install --force-reinstall` fixes this but downloads, resolves, and reinstalls everything, which is expensive for large environments (PyTorch, CUDA, ComfyUI, Stable Diffusion). This tool regenerates only the launchers that need it and leaves `site-packages` untouched.

## How it works

1. **Environment.** The target is the interpreter that runs the tool: `sys.executable` (absolute, symlinks not resolved), `sys.prefix`, and the `sysconfig` `scripts`, `purelib`, and `platlib` paths. User site-packages, base site-packages under `--system-site-packages`, and `PYTHONPATH` never enlarge the repair set.
2. **Discovery.** `console_scripts` entry points are read from distribution metadata without importing any package. pip's naming rules apply to installer aliases (`pip`, `pipX`, `pipX.Y`, `easy_install-X.Y`). Entries with unsafe names, names that escape the scripts directory, duplicate owners, or names that collide after platform filename mapping are rejected before anything is planned.
3. **Detection.** An existing file counts as owned only if every line matches a known generator template (pip, distlib, uv, setuptools) for that entry, or if the owning distribution's `RECORD` lists it and it imports the entry point. Hand-written wrappers are left alone.
   - **Linux/macOS:** the shebang (a direct `#!python` line or the `/bin/sh` wrapper used for long paths or paths with spaces) and the execute bits are inspected. A shebang is valid if it equals the target interpreter, or names a file in the same directory that is the same file (`python3` next to `python`). A shebang naming the base interpreter behind a venv symlink is stale.
   - **Windows:** the interpreter path embedded in an `.exe` launcher is not parsed. Missing launchers are created. Existing ones are rebuilt only with explicit relocation evidence (see [Windows](#windows-launchers-and-relocation-evidence)).
4. **Repair.** Each candidate is generated into a staging directory on the same filesystem, checked, and moved into place with an atomic replace. A recovery copy is kept until verification finishes. Repairs run one at a time under a per-environment lock.
5. **Verification.** Structural checks run by default. Startup checks run only for commands you approve.

The launcher generator is built in and matches what pip 26.2.1 installs (distlib's `ScriptMaker` with pip's script template), byte for byte, apart from these safety fixes:

| Case | distlib | python-env-repair |
| --- | --- | --- |
| Explicit interpreter path with spaces | Written unquoted, so the script is broken | Always quoted. Existing unquoted wrappers are detected as `unquoted_interpreter` and repaired |
| Long path without spaces (`/bin/sh` wrapper) | Unquoted | Quoted |
| Path containing `"`, `$`, backtick, or `\` that needs the wrapper | Written as is | Rejected with `generation_failed` |
| ZIP timestamp in Windows launchers | Current local time | Fixed 1980-01-01, so the same inputs always give the same bytes |

Only the exact entry name is generated. Version-suffixed variants such as `foo-3.11` are not created.

## Deployment

The utility operates on the environment of the interpreter that runs it, and it never installs anything itself. It has no runtime dependencies: the script generator is built in, and the Windows console launcher stubs are shipped inside the package (copied unmodified from distlib 0.4.3, PSF-2.0; see `python_env_repair/_launchers/`). Ways to provide it:

- install the wheel into the target environment ahead of time, or
- put `python_env_repair/` (a directory or a zip) on `PYTHONPATH` for the repair run.

## Usage

Always call the target interpreter by its absolute path, not a console script that may itself be broken:

```bash
/path/to/venv/bin/python -B -m python_env_repair detect
/path/to/venv/bin/python -B -m python_env_repair repair --dry-run --json > plan.json
/path/to/venv/bin/python -B -m python_env_repair repair
/path/to/venv/bin/python -B -m python_env_repair repair --verbose
/path/to/venv/bin/python -B -m python_env_repair repair --log-dir ./repair-logs
/path/to/venv/bin/python -B -m python_env_repair verify --json
```

`-B` stops the utility's own imports from writing bytecode. It does not sandbox package code; only explicitly configured startup checks run package code. `detect` and `repair --dry-run` write nothing and never import or run entry points.

On Windows, after moving or copying an environment, use `--relocated` (see [Windows launchers](#windows-launchers-and-relocation-evidence)):

```powershell
C:\path\to\venv\Scripts\python.exe -B -m python_env_repair repair --dry-run --relocated
C:\path\to\venv\Scripts\python.exe -B -m python_env_repair repair --relocated
```

### Output

- stderr: phase-tagged progress (`--verbose` adds evidence and tracebacks, `--quiet` shows warnings and errors only).
- Color: logs and the text summary are colored by default, including when redirected. `NO_COLOR` (any non-empty value) or `TERM=dumb` turns it off. `--color auto` colors only terminals, `--color always` ignores `NO_COLOR`, and `--color never` disables it. JSON output and diagnostic files are never colored. On Windows, ANSI support is switched on for the console first; legacy consoles that cannot enable it get plain text.
- stdout: the final result as a text summary, or with `--json` exactly one JSON report object.
- Files: none by default. `--log-dir PATH` alone enables `events.jsonl` (DEBUG events), `manifest.json` (plan saved before the first modification) and `report.json` in a new `PATH/<UTC timestamp>-<id>/` directory. `--dry-run --log-dir` is rejected, because a dry run writes nothing.

### Report

Every entry has four separate states, so a written file is never mistaken for a working one:

| Field | Values |
| --- | --- |
| `detection_status` | `valid`, `missing`, `invalid`, `skipped`, `unknown` |
| `repair_status` | `not_needed`, `planned`, `written`, `failed`, `rolled_back` |
| `verification_status` | `not_run`, `passed`, `failed`, `partial`, `skipped` |
| `overall_status` | `valid`, `planned`, `repaired`, `failed`, `skipped`, `unverified` |

Each result also carries a stable `reason_code` (for example `stale_shebang`, `missing_artifact`, `unquoted_interpreter`, `missing_execute_permission`, `relocation_confirmed`, `windows_launcher_unverifiable`, `artifact_not_owned`, `entry_point_conflict`, `file_in_use`, `permission_denied`, `verification_timeout`); the full list is `ReasonCode` in `python_env_repair/models.py`. The report also includes `exit_code`, `outcome`, `diagnostics_complete`, the paths actually modified, and `restored_paths` for files that were written and then rolled back. Programs should read these fields rather than parse log text.

### Verification

Default verification is structural: generated bytes, interpreter binding (Unix), execute permission, and the replacement outcome. The output then says "structural verification passed; startup not checked". To also run a CLI, approve a command for each entry explicitly:

```bash
python -B -m python_env_repair repair --verification execute --verify-command "mytool=--version" --verify-timeout 20
```

Commands run by absolute artifact path, without a shell, with no stdin, a timeout (at most 3600 s), and at most 64 KiB kept per output stream. `--verify-allow-code` adds accepted exit codes (default 0). An entry without an approved command is reported as `unverified`. There is no automatic fallback to `--help`, `--version`, or importing the entry point, because any of them can run package code (start a server, open a GUI, download files).

If a required check fails after writing, the original file is restored from the recovery copy, and both the write and the rollback are reported. If the rollback itself fails, the recovery copy is kept and its path is printed.

### Windows launchers and relocation evidence

The interpreter path inside a Windows `.exe` launcher is not parsed. An existing, owned launcher is `unknown` unless explicit evidence is given. Without evidence, `repair` on Windows only creates missing launchers and leaves every existing one unchanged, even when the environment was moved.

**Recommended on Windows:** whenever the environment has been moved or copied, run `repair` with `--relocated`. Missing launchers are created without the flag, but existing ones are rebuilt only with it. Launchers are regenerated only when metadata declares them and the existing file is a recognized launcher for that same entry point, so standalone binaries and unrecognized files stay untouched. Run `repair --dry-run --relocated` first to see the list.

- `--relocated`: the caller asserts the environment was moved; owned launchers are rebuilt. On Linux and macOS it changes nothing, because shebangs are inspected directly.
- `--previous-manifest PATH`: a `manifest.json` or `report.json` from an earlier run (or `{"python": ..., "console_scripts": [...]}`). A different recorded Python means rebuild. The same Python plus an unchanged hash means valid, and only hashes of entries that run reported as `repaired` or `valid` count. Paths in the file are never used as write targets.

The two options are mutually exclusive. Nothing is saved automatically to help later runs. Keep `report.json` (from a `--log-dir` run) if you want future evidence.

A generated Windows launcher is a single `foo.exe`: a console stub (`t32`, `t64`, or `t64-arm`), a `#!` line, and a ZIP holding `__main__.py`. Legacy `foo-script.py` sidecars are reported, never deleted.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Command completed. Finding candidates in `detect`/`--dry-run` is not a failure; read the report. |
| 1 | A repair or required verification failed or did not complete (`verify` also fails on `unverified` entries). |
| 2 | Invalid or conflicting arguments. |
| 3 | Run-level failure: environment not identifiable, environment busy (another repair holds the lock), requested diagnostics could not be written. |
| 130 | Interrupted. |

Priority when several apply: 130, then 3, then 1.

## Library use

```python
from python_env_repair import Operation, RunOptions, run

report = run(RunOptions(operation=Operation.DETECT))
print(report.exit_code, [(r.script.name, r.overall_status.value) for r in report.results])
```

`run()` does not configure logging. Events go to the `python_env_repair.*` loggers, which have only a `NullHandler` unless the host attaches one.

## Platform support

| OS | Python | Arch | Status |
| --- | --- | --- | --- |
| Linux | 3.11 | x86_64 | Unit, behavior, and native acceptance tests pass (real venv, offline pip-installed wheel, moved to a path containing a space, network and subprocesses blocked, `site-packages` unchanged) |
| Linux | 3.10, 3.12–3.14 | x86_64 | In the release workflow's matrix, which has not run on GitHub yet; ty checks the code against 3.10 |
| macOS | any | any | Not run natively; ty passes with `--python-platform darwin` |
| Windows | any | any | Not run natively; ty passes with `--python-platform win32`; detection is covered with synthetic launchers only, and launcher bytes are checked against distlib on Linux |

On Unix the lock is `flock` on the scripts directory (no file is created) and replacement uses `os.replace`. On Windows the lock is `msvcrt.locking` on `Scripts/.python-env-repair.lock`, and a replacement blocked by a running process (`winerror` 32/33) is reported as `file_in_use`. Staging and recovery files live in `.python-env-repair-*` inside the scripts directory and are removed after each item unless a recovery copy has to be kept.

## Known limitations

- Launcher repair is not full environment relocation. `pyvenv.cfg`, `.pth` files, `.egg-link`, package configuration, and native dependencies are out of scope. Python documents venvs as non-portable.
- The interpreter itself must still start; an environment whose Python cannot run cannot repair itself.
- `gui_scripts` are not handled, and GUI launcher stubs are not shipped.
- Regenerated scripts are not written back to `RECORD`, so their recorded hash can go stale. Validity never depends on the recorded hash.
- Unsupported wrapper forms (for example `#!/usr/bin/env python`, relocatable `$(dirname ...)` wrappers, legacy Windows `-script.py` sidecar layouts) are reported as `unknown` and left unchanged.
- pip/setuptools installer aliases (`pip`, `pipX`, `pipX.Y`, `easy_install-X.Y`) follow pip's naming rules. Missing aliases are reported as `installer_alias_absent` and not created, because installers may omit them on purpose.
- Repairs run one at a time. Replacing several files is not one atomic transaction, and recovery after a machine crash is not provided.
- The lock only coordinates instances of this utility, not package installers or other Python processes. Running processes are never terminated, and privileges are never elevated; a protected directory gives `permission_denied`.
- On Windows, a timed-out startup check kills only the direct child process, not its process tree.
- Native validation has been run on Linux only; see [Platform support](#platform-support).

## License

GPL-3.0-only; see [LICENSE](LICENSE). The Windows launcher stubs in `python_env_repair/_launchers/` are copied from distlib and keep their PSF-2.0 license ([LICENSE.txt](python_env_repair/_launchers/LICENSE.txt)).

## Development

```bash
pip install -e . --group dev   # pip 25.1 or newer
python -m ruff check python_env_repair tests
python -m ruff format --check python_env_repair tests
python -m ty check --python <dev-python> python_env_repair tests
python -B -m pytest tests
```

Development tools are listed without version constraints in `[dependency-groups]` in `pyproject.toml`, so the latest releases are installed. `distlib` is a test-only dependency: `tests/test_generator.py` checks that the built-in generator's output is byte-for-byte identical to distlib's, and is skipped when distlib is not installed. The check that the vendored stubs equal distlib's files runs only against distlib 0.4.3, the stubs' source release.

Contributor guidelines, design rules, and the release process are in [AGENTS.md](AGENTS.md).
