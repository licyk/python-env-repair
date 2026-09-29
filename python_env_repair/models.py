"""Typed data contracts shared by discovery, detection, repair, verification, and reporting.

Every value that reaches a report, manifest, or log file is converted explicitly by the
``to_dict`` helpers in this module, so serialization never depends on ``repr()`` of
arbitrary objects.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, TypeAlias

REPORT_SCHEMA_VERSION = 1
MANIFEST_SCHEMA_VERSION = 1
REPORT_KIND = "python_env_repair.report"
MANIFEST_KIND = "python_env_repair.manifest"

JsonValue: TypeAlias = "None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]"
JsonDict: TypeAlias = "dict[str, JsonValue]"


class Platform(str, enum.Enum):
    """Operating systems supported by the first release."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class Operation(str, enum.Enum):
    """Top-level command being executed."""

    DETECT = "detect"
    REPAIR = "repair"
    VERIFY = "verify"


class DetectionStatus(str, enum.Enum):
    """What detection concluded about an entry point's artifacts."""

    VALID = "valid"
    MISSING = "missing"
    INVALID = "invalid"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


class RepairStatus(str, enum.Enum):
    """What happened (or would happen) to an entry point's artifacts."""

    NOT_NEEDED = "not_needed"
    PLANNED = "planned"
    WRITTEN = "written"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class VerificationStatus(str, enum.Enum):
    """Aggregate verification state for one entry point."""

    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"


class OverallStatus(str, enum.Enum):
    """Single final state for one entry point."""

    VALID = "valid"
    PLANNED = "planned"
    REPAIRED = "repaired"
    FAILED = "failed"
    SKIPPED = "skipped"
    UNVERIFIED = "unverified"


class ArtifactRole(str, enum.Enum):
    """Why an artifact is associated with an entry point."""

    LAUNCHER = "launcher"
    LEGACY_SIDECAR = "legacy_sidecar"


class ArtifactKind(str, enum.Enum):
    """Observed on-disk form of an artifact."""

    MISSING = "missing"
    PYTHON_SHEBANG = "python_shebang"
    SHELL_WRAPPER = "shell_wrapper"
    WINDOWS_LAUNCHER = "windows_launcher"
    PYTHON_SCRIPT = "python_script"
    SYMLINK = "symlink"
    NOT_REGULAR_FILE = "not_regular_file"
    BINARY = "binary"
    UNRECOGNIZED = "unrecognized"


class VerificationCheck(str, enum.Enum):
    """Individual verification checks. They are independent, not nested levels."""

    ARTIFACT = "artifact"
    LAUNCHER_INVOCATION = "launcher_invocation"


class VerificationMode(str, enum.Enum):
    """Verification policy selected by the caller."""

    STRUCTURAL = "structural"
    EXECUTE = "execute"


class RelocationSource(str, enum.Enum):
    """Where evidence about environment relocation came from."""

    NONE = "none"
    CALLER_ASSERTION = "caller_assertion"
    PREVIOUS_MANIFEST = "previous_manifest"


class Outcome(str, enum.Enum):
    """Run-level outcome recorded in the report."""

    COMPLETED = "completed"
    PARTIALLY_FAILED = "partially_failed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class ReasonCode(str, enum.Enum):
    """Stable reason codes. Each code describes an observed fact, not a guess."""

    CURRENT_INTERPRETER = "current_interpreter"
    MISSING_ARTIFACT = "missing_artifact"
    INSTALLER_ALIAS_ABSENT = "installer_alias_absent"
    STALE_SHEBANG = "stale_shebang"
    UNQUOTED_INTERPRETER = "unquoted_interpreter"
    MISSING_EXECUTE_PERMISSION = "missing_execute_permission"
    EXECUTE_ACCESS_DENIED = "execute_access_denied"
    RELOCATION_CONFIRMED = "relocation_confirmed"
    RELOCATION_MANIFEST = "relocation_manifest"
    MANIFEST_MATCHES_ENVIRONMENT = "manifest_matches_environment"
    WINDOWS_LAUNCHER_UNVERIFIABLE = "windows_launcher_unverifiable"
    LEGACY_SIDECAR_LAYOUT = "legacy_sidecar_layout"
    UNRECOGNIZED_WRAPPER = "unrecognized_wrapper"
    ARTIFACT_NOT_OWNED = "artifact_not_owned"
    ENTRY_POINT_CONFLICT = "entry_point_conflict"
    NAME_COLLISION = "name_collision"
    INVALID_ENTRY_NAME = "invalid_entry_name"
    INVALID_ENTRY_POINT = "invalid_entry_point"
    PATH_OUTSIDE_SCRIPTS = "path_outside_scripts"
    PROTECTED_INTERPRETER = "protected_interpreter"
    SYMLINK_NOT_SUPPORTED = "symlink_not_supported"
    HARDLINK_NOT_SUPPORTED = "hardlink_not_supported"
    NOT_REGULAR_FILE = "not_regular_file"
    ARTIFACT_UNREADABLE = "artifact_unreadable"
    TARGET_CHANGED = "target_changed"
    FILE_IN_USE = "file_in_use"
    PERMISSION_DENIED = "permission_denied"
    OWNERSHIP_PRESERVATION_UNSUPPORTED = "ownership_preservation_unsupported"
    GENERATION_FAILED = "generation_failed"
    GENERATOR_UNAVAILABLE = "generator_unavailable"
    REPLACE_FAILED = "replace_failed"
    ROLLBACK_FAILED = "rollback_failed"
    VERIFICATION_PASSED = "verification_passed"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_TIMEOUT = "verification_timeout"
    VERIFICATION_NOT_CONFIGURED = "verification_not_configured"
    VERIFICATION_ERROR = "verification_error"
    REPAIR_NOT_ATTEMPTED = "repair_not_attempted"
    UNSUPPORTED_PLATFORM = "unsupported_platform"
    ENVIRONMENT_DETECTION_FAILED = "environment_detection_failed"
    ENVIRONMENT_BUSY = "environment_busy"
    LOCK_FAILED = "lock_failed"
    DIAGNOSTICS_FAILED = "diagnostics_failed"
    PREVIOUS_MANIFEST_INVALID = "previous_manifest_invalid"
    INTERRUPTED = "interrupted"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class EnvironmentInfo:
    """Identity of the target environment (the interpreter running this utility)."""

    python: Path
    prefix: Path
    base_prefix: Path
    scripts_dir: Path
    metadata_roots: tuple[Path, ...]
    platform: Platform
    python_version: str
    implementation: str

    @property
    def is_venv(self) -> bool:
        """Whether the target interpreter runs inside a virtual environment."""
        return self.prefix != self.base_prefix

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "python": str(self.python),
            "prefix": str(self.prefix),
            "base_prefix": str(self.base_prefix),
            "scripts_dir": str(self.scripts_dir),
            "metadata_roots": [str(root) for root in self.metadata_roots],
            "platform": self.platform.value,
            "python_version": self.python_version,
            "implementation": self.implementation,
            "is_venv": self.is_venv,
        }


@dataclass(frozen=True)
class FileIdentity:
    """Result of ``lstat`` used to notice changes between inspection and replacement."""

    device: int
    inode: int
    size: int
    mtime_ns: int
    mode: int
    nlink: int
    uid: int
    gid: int
    ctime_ns: int = 0

    def same_file_state(self, other: FileIdentity) -> bool:
        """Whether two identities describe the same unchanged file (content, links, and owner)."""
        return self == other

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "size": self.size,
            "mtime_ns": self.mtime_ns,
            "mode": oct(self.mode & 0o7777),
            "nlink": self.nlink,
        }


@dataclass
class ScriptArtifact:
    """One file that belongs, or is expected to belong, to a console entry point."""

    path: Path
    role: ArtifactRole
    kind: ArtifactKind
    identity: Optional[FileIdentity] = None
    sha256: Optional[str] = None
    listed_in_record: bool = False
    evidence: JsonDict = field(default_factory=dict)

    @property
    def exists(self) -> bool:
        """Whether the artifact was present when inspected."""
        return self.kind is not ArtifactKind.MISSING

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "path": str(self.path),
            "role": self.role.value,
            "kind": self.kind.value,
            "exists": self.exists,
            "sha256": self.sha256,
            "listed_in_record": self.listed_in_record,
            "identity": self.identity.to_dict() if self.identity else None,
            "evidence": self.evidence,
        }


@dataclass
class ConsoleScript:
    """A ``console_scripts`` entry point declared by an environment-owned distribution."""

    script_id: str
    name: str
    value: str
    package: str
    version: Optional[str]
    metadata_path: Path
    record_paths: frozenset[str] = frozenset()
    installer_alias: bool = False
    artifacts: list[ScriptArtifact] = field(default_factory=list)

    @property
    def module(self) -> str:
        """Module part of the entry-point value."""
        return self.value.split(":", 1)[0].strip()

    @property
    def attribute(self) -> str:
        """Attribute part of the entry-point value, without extras."""
        attr = self.value.split(":", 1)[1] if ":" in self.value else ""
        return attr.split("[", 1)[0].strip()

    @property
    def launcher(self) -> Optional[ScriptArtifact]:
        """The primary launcher artifact, if one was assigned."""
        for artifact in self.artifacts:
            if artifact.role is ArtifactRole.LAUNCHER:
                return artifact
        return None

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "script_id": self.script_id,
            "name": self.name,
            "entry_point": self.value,
            "package": self.package,
            "package_version": self.version,
            "metadata_path": str(self.metadata_path),
            "installer_alias": self.installer_alias,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }


@dataclass(frozen=True)
class VerificationCommand:
    """An approved verification invocation: arguments only, never a shell string."""

    args: tuple[str, ...]
    timeout: float = 30.0
    allowed_return_codes: frozenset[int] = frozenset({0})

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        args: list[JsonValue] = [arg for arg in self.args]
        codes: list[JsonValue] = [code for code in sorted(self.allowed_return_codes)]
        return {"args": args, "timeout": self.timeout, "allowed_return_codes": codes}


@dataclass(frozen=True)
class VerificationPolicy:
    """Which checks are required. Execution happens only for explicitly configured entries."""

    mode: VerificationMode = VerificationMode.STRUCTURAL
    commands: Mapping[str, VerificationCommand] = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {"mode": self.mode.value, "commands": {name: command.to_dict() for name, command in sorted(self.commands.items())}}


@dataclass
class VerificationResult:
    """Outcome of one verification check."""

    check: VerificationCheck
    required: bool
    status: VerificationStatus
    reason_code: ReasonCode
    message: str
    duration_ms: Optional[int] = None
    details: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "check": self.check.value,
            "required": self.required,
            "status": self.status.value,
            "reason_code": self.reason_code.value,
            "message": self.message,
            "duration_ms": self.duration_ms,
            "details": self.details,
        }


@dataclass(frozen=True)
class PreviousArtifact:
    """Artifact evidence read from a previous manifest or report."""

    filename: str
    sha256: Optional[str]


@dataclass(frozen=True)
class RelocationContext:
    """Explicit relocation evidence. Absence of evidence means relocation is unknown."""

    source: RelocationSource = RelocationSource.NONE
    previous_python: Optional[str] = None
    previous_manifest_path: Optional[Path] = None
    previous_artifacts: Mapping[str, tuple[PreviousArtifact, ...]] = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "source": self.source.value,
            "previous_python": self.previous_python,
            "previous_manifest_path": str(self.previous_manifest_path) if self.previous_manifest_path else None,
            "previous_entries": len(self.previous_artifacts),
        }


@dataclass
class RecoveryInfo:
    """What recovery was possible and what happened for one entry."""

    recovery_path: Optional[Path] = None
    rollback_attempted: bool = False
    rollback_succeeded: Optional[bool] = None
    retained_path: Optional[Path] = None
    message: str = ""

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "rollback_attempted": self.rollback_attempted,
            "rollback_succeeded": self.rollback_succeeded,
            "retained_recovery_path": str(self.retained_path) if self.retained_path else None,
            "message": self.message,
        }


@dataclass
class RepairResult:
    """Per-entry state. Detection, repair, verification, and overall status stay separate."""

    script: ConsoleScript
    detection_status: DetectionStatus
    reason_code: ReasonCode
    message: str
    candidate: bool = False
    repair_status: RepairStatus = RepairStatus.NOT_NEEDED
    verification_status: VerificationStatus = VerificationStatus.NOT_RUN
    overall_status: OverallStatus = OverallStatus.VALID
    evidence: JsonDict = field(default_factory=dict)
    verification: list[VerificationResult] = field(default_factory=list)
    modified_paths: list[Path] = field(default_factory=list)
    recovery: Optional[RecoveryInfo] = None
    initially_valid: bool = False

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        data = self.script.to_dict()
        data.update(
            {
                "detection_status": self.detection_status.value,
                "repair_status": self.repair_status.value,
                "verification_status": self.verification_status.value,
                "overall_status": self.overall_status.value,
                "reason_code": self.reason_code.value,
                "message": self.message,
                "candidate": self.candidate,
                "evidence": self.evidence,
                "verification": [item.to_dict() for item in self.verification],
                "modified_paths": [str(path) for path in self.modified_paths],
                "recovery": self.recovery.to_dict() if self.recovery else None,
            }
        )
        return data


@dataclass
class RunError:
    """A run-level problem that is not tied to one entry point."""

    reason_code: ReasonCode
    message: str
    details: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {"reason_code": self.reason_code.value, "message": self.message, "details": self.details}


@dataclass
class DiagnosticsInfo:
    """State of explicitly requested diagnostic files."""

    file_logging: bool = False
    run_dir: Optional[Path] = None
    complete: bool = True
    files: list[Path] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "file_logging": self.file_logging,
            "run_dir": str(self.run_dir) if self.run_dir else None,
            "complete": self.complete,
            "files": [str(path) for path in self.files],
            "error": self.error,
        }


@dataclass
class RepairManifest:
    """In-memory plan built before any mutation."""

    run_id: str
    created_at: str
    operation: Operation
    dry_run: bool
    environment: EnvironmentInfo
    relocation: RelocationContext
    results: list[RepairResult]
    tool_version: str

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "kind": MANIFEST_KIND,
            "tool_version": self.tool_version,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "operation": self.operation.value,
            "dry_run": self.dry_run,
            "environment": self.environment.to_dict(),
            "relocation": self.relocation.to_dict(),
            "entries": [result.to_dict() for result in self.results],
        }


@dataclass
class Summary:
    """Counts derived from per-entry results. Entry, artifact, and check counts stay separate."""

    entries_total: int = 0
    initially_valid: int = 0
    valid: int = 0
    planned: int = 0
    repaired: int = 0
    failed: int = 0
    skipped: int = 0
    unverified: int = 0
    artifacts_modified: int = 0
    artifacts_restored: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_not_run: int = 0

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        return {
            "entries": {
                "total": self.entries_total,
                "initially_valid": self.initially_valid,
                "valid": self.valid,
                "planned": self.planned,
                "repaired": self.repaired,
                "failed": self.failed,
                "skipped": self.skipped,
                "unverified": self.unverified,
            },
            "artifacts": {"modified": self.artifacts_modified, "restored": self.artifacts_restored},
            "verification_checks": {"passed": self.checks_passed, "failed": self.checks_failed, "not_run": self.checks_not_run},
        }


@dataclass
class RepairReport:
    """Final result of one run; the single source for summaries, JSON output, and exit codes."""

    run_id: str
    tool_version: str
    operation: Operation
    dry_run: bool
    started_at: str
    finished_at: str = ""
    environment: Optional[EnvironmentInfo] = None
    relocation: RelocationContext = field(default_factory=RelocationContext)
    verification_policy: VerificationPolicy = field(default_factory=VerificationPolicy)
    generator: JsonDict = field(default_factory=dict)
    results: list[RepairResult] = field(default_factory=list)
    run_errors: list[RunError] = field(default_factory=list)
    interrupted: bool = False
    stopped_early: bool = False
    diagnostics: DiagnosticsInfo = field(default_factory=DiagnosticsInfo)
    summary: Summary = field(default_factory=Summary)
    outcome: Outcome = Outcome.COMPLETED
    exit_code: int = 0

    def to_dict(self) -> JsonDict:
        """Serialize to JSON-compatible values."""
        # Paths left changed by this run; rolled-back paths are listed separately.
        modified: list[JsonValue] = [path for path in sorted({str(path) for result in self.results if result.repair_status is RepairStatus.WRITTEN for path in result.modified_paths})]
        restored: list[JsonValue] = [path for path in sorted({str(path) for result in self.results if result.repair_status is RepairStatus.ROLLED_BACK for path in result.modified_paths})]
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "kind": REPORT_KIND,
            "tool_version": self.tool_version,
            "run_id": self.run_id,
            "operation": self.operation.value,
            "dry_run": self.dry_run,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "outcome": self.outcome.value,
            "exit_code": self.exit_code,
            "interrupted": self.interrupted,
            "stopped_early": self.stopped_early,
            "environment": self.environment.to_dict() if self.environment else None,
            "relocation": self.relocation.to_dict(),
            "verification_policy": self.verification_policy.to_dict(),
            "generator": self.generator,
            "summary": self.summary.to_dict(),
            "entries": [result.to_dict() for result in self.results],
            "modified_paths": modified,
            "restored_paths": restored,
            "run_errors": [error.to_dict() for error in self.run_errors],
            "diagnostics": self.diagnostics.to_dict(),
            "diagnostics_complete": self.diagnostics.complete,
        }
