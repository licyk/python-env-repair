"""Read-only inspection of console-script artifacts.

Detection produces evidence and candidates. It never writes, imports entry points, or
executes artifacts. Metadata authorizes a *name*; replacing an existing file additionally
requires that the file is a recognized wrapper for that same entry point.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import re
import stat
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from python_env_repair.discovery import DiscoveryResult
from python_env_repair.models import (
    ArtifactKind,
    ArtifactRole,
    ConsoleScript,
    DetectionStatus,
    EnvironmentInfo,
    FileIdentity,
    JsonDict,
    Platform,
    ReasonCode,
    RelocationContext,
    RelocationSource,
    RepairResult,
    ScriptArtifact,
)
from python_env_repair.platform import (
    collision_key,
    is_protected_interpreter_name,
    launcher_filename,
    legacy_sidecar_filename,
    validate_entry_name,
)

logger = logging.getLogger(__name__)

MAX_SCRIPT_BYTES = 1024 * 1024
MAX_LAUNCHER_BYTES = 32 * 1024 * 1024
_PYTHON_NAME = re.compile(r"^(python|pypy)[\w.\-]*(\.exe)?$", re.IGNORECASE)
_SH_EXEC_LINE = re.compile(r"^'''exec' (?P<exe>.+) \"\$0\" \"\$@\"$")


@dataclass(frozen=True)
class UnixLauncher:
    """Parsed first lines of a Unix console script."""

    kind: ArtifactKind
    interpreter: str
    interpreter_args: str
    body: bytes
    unquoted_space: bool = False


def _split_command(text: str) -> Optional[tuple[str, str]]:
    """Split ``interpreter [args]`` where the interpreter may be double-quoted."""
    text = text.strip()
    if not text:
        return None
    if text.startswith('"'):
        end = text.find('"', 1)
        if end == -1:
            return None
        return text[1:end], text[end + 1 :].strip()
    interpreter, _, args = text.partition(" ")
    return interpreter, args.strip()


def parse_unix_launcher(data: bytes) -> Optional[UnixLauncher]:
    """Parse a direct Python shebang or distlib's ``/bin/sh`` wrapper.

    Args:
        data: Complete file contents.

    Returns:
        The parsed launcher, or ``None`` if the file is not a supported form. Dynamic
        wrappers (for example ones computing the interpreter with ``$(dirname ...)``)
        and ``/usr/bin/env`` shebangs are not supported forms.
    """
    if not data.startswith(b"#!"):
        return None
    lines = data.split(b"\n", 3)
    try:
        first = lines[0].rstrip(b"\r")[2:].decode("utf-8").strip()
    except UnicodeDecodeError:
        return None
    if first == "/bin/sh":
        if len(lines) < 3:
            return None
        try:
            second = lines[1].rstrip(b"\r").decode("utf-8")
        except UnicodeDecodeError:
            return None
        match = _SH_EXEC_LINE.match(second)
        if not match or lines[2].rstrip(b"\r") != b"' '''":
            return None
        exe_text = match.group("exe")
        if "$" in exe_text or "`" in exe_text:
            return None
        body = lines[3] if len(lines) > 3 else b""
        if not exe_text.startswith('"') and " " in exe_text and _PYTHON_NAME.match(os.path.basename(exe_text)):
            # distlib writes an explicit interpreter path containing spaces unquoted; the
            # shell splits it, so such a wrapper cannot start even if the path is current.
            return UnixLauncher(kind=ArtifactKind.SHELL_WRAPPER, interpreter=exe_text, interpreter_args="", body=body, unquoted_space=True)
        split = _split_command(exe_text)
        if split is None:
            return None
        kind = ArtifactKind.SHELL_WRAPPER
    else:
        split = _split_command(first)
        if split is None:
            return None
        body = data.split(b"\n", 1)[1] if b"\n" in data else b""
        kind = ArtifactKind.PYTHON_SHEBANG
    interpreter, args = split
    if not os.path.isabs(interpreter) or not _PYTHON_NAME.match(os.path.basename(interpreter)):
        return None
    return UnixLauncher(kind=kind, interpreter=interpreter, interpreter_args=args, body=body)


def imports_entry(body: bytes, script: ConsoleScript) -> bool:
    """Whether code imports or loads this entry point anywhere (a loose hint, not ownership)."""
    text = body.decode("utf-8", "replace")
    module = re.escape(script.module)
    attr_root = re.escape(script.attribute.split(".", 1)[0])
    if re.search(rf"^[ \t]*from[ \t]+{module}[ \t]+import[ \t]+{attr_root}\b", text, re.MULTILINE):
        return True
    name = re.escape(script.name)
    return bool(re.search(rf"load_entry_point\(\s*['\"][^'\"]*['\"]\s*,\s*['\"]console_scripts['\"]\s*,\s*['\"]{name}['\"]\s*\)", text))


def _generated_line_patterns(script: ConsoleScript) -> list[re.Pattern[str]]:
    module = re.escape(script.module)
    attr_root = re.escape(script.attribute.split(".", 1)[0])
    call = re.escape(script.attribute)
    patterns = [
        r"#.*coding[:=].*",
        r"import (re|sys)",
        rf"from {module} import {attr_root}",
        r"if __name__ == (['\"])__main__\1:",
        r"sys\.argv\[0\] = re\.sub\(.*, sys\.argv\[0\]\)",
        rf"sys\.exit\({call}\(\)\)",
        r"if sys\.argv\[0\]\.endswith\((['\"])-script\.pyw\1\):",
        r"elif sys\.argv\[0\]\.endswith\((['\"])\.exe\1\):",
        r"sys\.argv\[0\] = sys\.argv\[0\]\[:-\d+\]",
        r"sys\.argv\[0\] = sys\.argv\[0\]\.removesuffix\((['\"])\.exe\1\)",
    ]
    return [re.compile(pattern) for pattern in patterns]


def is_generated_wrapper(body: bytes, script: ConsoleScript) -> bool:
    """Whether code is exactly a generator template (pip, distlib, uv, setuptools) for this entry.

    Every non-blank line must belong to a known template, so hand-written wrappers that
    merely import the entry point are not treated as generated.
    """
    text = body.decode("utf-8", "replace")
    name = re.escape(script.name)
    if re.search(rf"^# EASY-INSTALL-ENTRY-SCRIPT: '[^']*','console_scripts','{name}'\s*$", text, re.MULTILINE):
        return True
    patterns = _generated_line_patterns(script)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or not all(any(pattern.fullmatch(line) for pattern in patterns) for line in lines):
        return False
    return patterns[2].fullmatch(next((line for line in lines if line.startswith("from ")), "")) is not None and any(patterns[5].fullmatch(line) for line in lines)


def body_matches_entry(body: bytes, script: ConsoleScript, listed_in_record: bool = False) -> bool:
    """Whether wrapper code is owned by this entry point.

    Ownership requires an exact generator template, or a RECORD listing by the owning
    distribution together with an import of the entry point.
    """
    return is_generated_wrapper(body, script) or (listed_in_record and imports_entry(body, script))


def identity_from_stat(st: os.stat_result) -> FileIdentity:
    """Build a :class:`FileIdentity` from an ``lstat`` result."""
    return FileIdentity(
        device=st.st_dev,
        inode=st.st_ino,
        size=st.st_size,
        mtime_ns=st.st_mtime_ns,
        mode=st.st_mode,
        nlink=st.st_nlink,
        uid=getattr(st, "st_uid", 0),
        gid=getattr(st, "st_gid", 0),
        ctime_ns=st.st_ctime_ns,
    )


def lstat_identity(path: Path) -> Optional[FileIdentity]:
    """Return the file identity, or ``None`` if nothing exists at ``path``."""
    try:
        return identity_from_stat(os.lstat(path))
    except FileNotFoundError:
        return None


def read_bounded(path: Path, limit: int) -> Optional[bytes]:
    """Read a file if it is not larger than ``limit`` bytes."""
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        return None
    return data


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _norm(path: str | Path) -> str:
    return os.path.normcase(os.path.normpath(os.fspath(path)))


def interpreter_matches(interpreter: str, env: EnvironmentInfo) -> bool:
    """Whether a shebang interpreter is the target interpreter.

    The path must equal the target interpreter lexically, or sit in the same directory
    and refer to the same file (for example ``python3`` next to ``python``). A path
    elsewhere that resolves to the same binary, such as the base interpreter behind a
    venv symlink, does not match because it would run outside the environment.
    """
    if _norm(interpreter) == _norm(env.python):
        return True
    if os.path.dirname(_norm(interpreter)) != os.path.dirname(_norm(env.python)):
        return False
    try:
        return os.path.samefile(interpreter, env.python)
    except OSError:
        return False


def _windows_main_script(data: bytes) -> Optional[bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if "__main__.py" not in archive.namelist():
                return None
            return archive.read("__main__.py")
    except (zipfile.BadZipFile, OSError, KeyError, ValueError):
        return None


def windows_launcher_matches(data: bytes, script: ConsoleScript, listed_in_record: bool = False) -> bool:
    """Whether a Windows launcher embeds a ``__main__.py`` owned by this entry point."""
    if not data.startswith(b"MZ"):
        return False
    main = _windows_main_script(data)
    return main is not None and body_matches_entry(main, script, listed_in_record)


class _Inspection:
    """Mutable helper holding the result for one entry while it is inspected."""

    def __init__(self, script: ConsoleScript) -> None:
        self.script = script
        self.evidence: JsonDict = {}

    def result(self, status: DetectionStatus, reason: ReasonCode, message: str, *, candidate: bool = False) -> RepairResult:
        return RepairResult(
            script=self.script,
            detection_status=status,
            reason_code=reason,
            message=message,
            candidate=candidate,
            evidence=self.evidence,
            initially_valid=status is DetectionStatus.VALID,
        )


def _inspect_unix(inspection: _Inspection, env: EnvironmentInfo, artifact: ScriptArtifact) -> RepairResult:
    script = inspection.script
    try:
        data = read_bounded(artifact.path, MAX_SCRIPT_BYTES)
    except OSError as exc:
        inspection.evidence["read_error"] = str(exc)
        return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.ARTIFACT_UNREADABLE, "cannot read existing file")
    if data is None:
        artifact.kind = ArtifactKind.BINARY
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.ARTIFACT_NOT_OWNED, "existing file is too large to be a console-script wrapper; left unchanged")
    artifact.sha256 = sha256_bytes(data)
    launcher = parse_unix_launcher(data)
    if launcher is None:
        if data.startswith(b"#!"):
            artifact.kind = ArtifactKind.UNRECOGNIZED
            inspection.evidence["first_line"] = data.split(b"\n", 1)[0][:200].decode("utf-8", "replace")
            if artifact.listed_in_record or imports_entry(data, script):
                return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.UNRECOGNIZED_WRAPPER, "wrapper form is not supported; left unchanged")
        else:
            artifact.kind = ArtifactKind.BINARY
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.ARTIFACT_NOT_OWNED, "existing file is not a console-script wrapper for this entry point; left unchanged")

    artifact.kind = launcher.kind
    inspection.evidence.update(
        {
            "wrapper_form": launcher.kind.value,
            "observed_interpreter": launcher.interpreter,
            "expected_python": str(env.python),
        }
    )
    if launcher.interpreter_args:
        inspection.evidence["interpreter_args"] = launcher.interpreter_args
    if not body_matches_entry(launcher.body, script, artifact.listed_in_record):
        return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.UNRECOGNIZED_WRAPPER, "wrapper does not launch this entry point; left unchanged")

    identity = artifact.identity
    mode = identity.mode if identity else 0
    exec_bits = mode & 0o111
    inspection.evidence["mode"] = oct(stat.S_IMODE(mode))
    if launcher.unquoted_space:
        inspection.evidence["unquoted_interpreter"] = True
        return inspection.result(DetectionStatus.INVALID, ReasonCode.UNQUOTED_INTERPRETER, "shell wrapper has an unquoted interpreter path containing spaces; regeneration planned", candidate=True)
    stale = not interpreter_matches(launcher.interpreter, env)
    if stale:
        inspection.evidence["interpreter_exists"] = os.path.exists(launcher.interpreter)
        return inspection.result(DetectionStatus.INVALID, ReasonCode.STALE_SHEBANG, "shebang points to a different Python; regeneration planned", candidate=True)
    if not exec_bits:
        return inspection.result(DetectionStatus.INVALID, ReasonCode.MISSING_EXECUTE_PERMISSION, "execute permission missing; regeneration planned", candidate=True)
    accessible = os.access(artifact.path, os.X_OK)
    inspection.evidence["accessible"] = accessible
    if not accessible:
        return inspection.result(
            DetectionStatus.INVALID,
            ReasonCode.EXECUTE_ACCESS_DENIED,
            "execute bits are set but the file is not executable by this user (mount policy, ACL, or ownership); not repairable by regeneration",
        )
    return inspection.result(DetectionStatus.VALID, ReasonCode.CURRENT_INTERPRETER, "shebang uses the current Python")


def _inspect_windows(inspection: _Inspection, env: EnvironmentInfo, artifact: ScriptArtifact, relocation: RelocationContext) -> RepairResult:
    script = inspection.script
    try:
        data = read_bounded(artifact.path, MAX_LAUNCHER_BYTES)
    except OSError as exc:
        inspection.evidence["read_error"] = str(exc)
        return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.ARTIFACT_UNREADABLE, "cannot read existing launcher")
    if data is None:
        artifact.kind = ArtifactKind.BINARY
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.ARTIFACT_NOT_OWNED, "existing file is too large to be a console-script launcher; left unchanged")
    artifact.sha256 = sha256_bytes(data)
    sidecar = next((item for item in script.artifacts if item.role is ArtifactRole.LEGACY_SIDECAR and item.exists), None)
    if windows_launcher_matches(data, script, artifact.listed_in_record):
        artifact.kind = ArtifactKind.WINDOWS_LAUNCHER
        inspection.evidence["launcher_form"] = "embedded_zip"
    else:
        artifact.kind = ArtifactKind.BINARY if data.startswith(b"MZ") else ArtifactKind.UNRECOGNIZED
        if sidecar is not None and _sidecar_matches(sidecar, script):
            return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.LEGACY_SIDECAR_LAYOUT, "legacy launcher with -script.py sidecar is not a supported layout; left unchanged")
        if artifact.listed_in_record:
            return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.UNRECOGNIZED_WRAPPER, "launcher listed in RECORD but its form is not recognized; left unchanged")
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.ARTIFACT_NOT_OWNED, "existing file is not a console-script launcher for this entry point; left unchanged")
    if sidecar is not None:
        inspection.evidence["legacy_sidecar"] = str(sidecar.path)

    if relocation.source is RelocationSource.CALLER_ASSERTION:
        inspection.evidence["relocation_source"] = relocation.source.value
        return inspection.result(DetectionStatus.INVALID, ReasonCode.RELOCATION_CONFIRMED, "caller confirmed the environment was relocated; regeneration planned", candidate=True)
    if relocation.source is RelocationSource.PREVIOUS_MANIFEST:
        inspection.evidence["relocation_source"] = relocation.source.value
        inspection.evidence["previous_python"] = relocation.previous_python
        previous = relocation.previous_artifacts.get(script.name)
        if previous is not None and relocation.previous_python and _norm(relocation.previous_python) != _norm(env.python):
            return inspection.result(DetectionStatus.INVALID, ReasonCode.RELOCATION_MANIFEST, "previous manifest records a different Python for this entry; regeneration planned", candidate=True)
        if previous is not None and relocation.previous_python:
            recorded = {item.filename.casefold(): item.sha256 for item in previous}
            if recorded.get(artifact.path.name.casefold()) == artifact.sha256:
                return inspection.result(DetectionStatus.VALID, ReasonCode.MANIFEST_MATCHES_ENVIRONMENT, "launcher is unchanged since it was recorded for the current Python")
    return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.WINDOWS_LAUNCHER_UNVERIFIABLE, "launcher exists but there is no relocation evidence; its interpreter binding is unknown")


def _sidecar_matches(sidecar: ScriptArtifact, script: ConsoleScript) -> bool:
    try:
        data = read_bounded(sidecar.path, MAX_SCRIPT_BYTES)
    except OSError:
        return False
    return data is not None and imports_entry(data, script)


def _observe_sidecar(script: ConsoleScript, env: EnvironmentInfo) -> None:
    name = legacy_sidecar_filename(script.name, env.platform)
    if name is None:
        return
    path = env.scripts_dir / name
    try:
        identity = lstat_identity(path)
    except OSError:
        identity = None
    if identity is None:
        return
    script.artifacts.append(
        ScriptArtifact(path=path, role=ArtifactRole.LEGACY_SIDECAR, kind=ArtifactKind.PYTHON_SCRIPT, identity=identity, listed_in_record=os.path.normcase(name) in script.record_paths)
    )


def _is_same_path_as_interpreter(path: Path, env: EnvironmentInfo) -> bool:
    if _norm(path) == _norm(env.python):
        return True
    try:
        return os.path.samefile(path, env.python)
    except OSError:
        return False


def inspect_script(script: ConsoleScript, env: EnvironmentInfo, relocation: RelocationContext) -> RepairResult:
    """Inspect one uniquely named entry point.

    Args:
        script: Entry point with a validated, non-colliding name.
        env: Target environment.
        relocation: Explicit relocation evidence.

    Returns:
        Detection result with evidence.
    """
    inspection = _Inspection(script)
    filename = launcher_filename(script.name, env.platform)
    path = env.scripts_dir / filename
    artifact = ScriptArtifact(path=path, role=ArtifactRole.LAUNCHER, kind=ArtifactKind.MISSING, listed_in_record=os.path.normcase(filename) in script.record_paths)
    script.artifacts = [artifact]
    inspection.evidence["listed_in_record"] = artifact.listed_in_record

    if os.path.dirname(_norm(path)) != _norm(env.scripts_dir):
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.PATH_OUTSIDE_SCRIPTS, "artifact path escapes the scripts directory")
    if is_protected_interpreter_name(filename) or _is_same_path_as_interpreter(path, env):
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.PROTECTED_INTERPRETER, "name refers to a Python interpreter; never replaced")
    _observe_sidecar(script, env)
    try:
        identity = lstat_identity(path)
    except OSError as exc:
        inspection.evidence["stat_error"] = str(exc)
        return inspection.result(DetectionStatus.UNKNOWN, ReasonCode.ARTIFACT_UNREADABLE, "cannot inspect artifact path")
    if identity is None:
        if script.installer_alias:
            return inspection.result(DetectionStatus.SKIPPED, ReasonCode.INSTALLER_ALIAS_ABSENT, "installer alias is absent; installers may omit it intentionally, so it is not created")
        return inspection.result(DetectionStatus.MISSING, ReasonCode.MISSING_ARTIFACT, "artifact is missing; generation planned", candidate=True)
    artifact.identity = identity
    if stat.S_ISLNK(identity.mode):
        artifact.kind = ArtifactKind.SYMLINK
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.SYMLINK_NOT_SUPPORTED, "artifact is a symlink; not replaced")
    if not stat.S_ISREG(identity.mode):
        artifact.kind = ArtifactKind.NOT_REGULAR_FILE
        return inspection.result(DetectionStatus.SKIPPED, ReasonCode.NOT_REGULAR_FILE, "artifact path is not a regular file")
    if identity.nlink > 1:
        inspection.evidence["nlink"] = identity.nlink
        result = _inspect_windows(inspection, env, artifact, relocation) if env.platform is Platform.WINDOWS else _inspect_unix(inspection, env, artifact)
        if result.candidate or result.detection_status is DetectionStatus.UNKNOWN:
            return inspection.result(DetectionStatus.SKIPPED, ReasonCode.HARDLINK_NOT_SUPPORTED, "artifact has multiple hard links; not replaced")
        return result
    if env.platform is Platform.WINDOWS:
        return _inspect_windows(inspection, env, artifact, relocation)
    return _inspect_unix(inspection, env, artifact)


def detect(env: EnvironmentInfo, discovery: DiscoveryResult, relocation: RelocationContext) -> list[RepairResult]:
    """Build detection results for every discovered entry point.

    Names are validated and checked for duplicates and platform-mapped collisions before
    any artifact is inspected, so conflicting entries are never repair candidates.

    Args:
        env: Target environment.
        discovery: Entry points from :func:`discover_console_scripts`.
        relocation: Explicit relocation evidence.

    Returns:
        Results ordered by ``script_id``.
    """
    results: list[RepairResult] = []
    for script in discovery.invalid_values:
        inspection = _Inspection(script)
        inspection.evidence["entry_point"] = script.value
        results.append(inspection.result(DetectionStatus.SKIPPED, ReasonCode.INVALID_ENTRY_POINT, "entry-point value is not a module:attribute reference"))

    valid_names: list[ConsoleScript] = []
    for script in discovery.scripts:
        problem = validate_entry_name(script.name, env.platform)
        if problem:
            inspection = _Inspection(script)
            inspection.evidence["problem"] = problem
            results.append(inspection.result(DetectionStatus.SKIPPED, ReasonCode.INVALID_ENTRY_NAME, f"unsafe entry-point name: {problem}"))
        else:
            valid_names.append(script)

    groups: dict[str, list[ConsoleScript]] = defaultdict(list)
    for script in valid_names:
        groups[collision_key(launcher_filename(script.name, env.platform), env.platform)].append(script)
    for members in groups.values():
        if len(members) == 1:
            results.append(inspect_script(members[0], env, relocation))
            continue
        owners = [f"{member.package} ({member.name} = {member.value})" for member in members]
        same_name = len({member.name for member in members}) == 1
        for member in members:
            inspection = _Inspection(member)
            member.artifacts = [ScriptArtifact(path=env.scripts_dir / launcher_filename(member.name, env.platform), role=ArtifactRole.LAUNCHER, kind=ArtifactKind.MISSING)]
            try:
                identity = lstat_identity(member.artifacts[0].path)
            except OSError:
                identity = None
            if identity is not None:
                member.artifacts[0].kind = ArtifactKind.UNRECOGNIZED
                member.artifacts[0].identity = identity
            inspection.evidence["owners"] = list(owners)
            if same_name:
                results.append(inspection.result(DetectionStatus.SKIPPED, ReasonCode.ENTRY_POINT_CONFLICT, "several distributions declare this entry point; not repaired"))
            else:
                results.append(inspection.result(DetectionStatus.SKIPPED, ReasonCode.NAME_COLLISION, "entry-point names map to the same file on this platform; not repaired"))
    results.sort(key=lambda item: item.script.script_id)
    return results
