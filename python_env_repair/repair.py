"""Staged regeneration, replacement, verification, and per-item recovery.

Only validated candidates reach this module. Each candidate is generated into a fresh
staging directory on the destination filesystem, checked, and committed with an atomic
replace (or an exclusive create for missing artifacts). Live files are never handed to
the generator, which only writes into an empty staging directory.
"""

from __future__ import annotations

import errno
import logging
import os
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

from python_env_repair.detector import identity_from_stat, lstat_identity, parse_unix_launcher, sha256_bytes
from python_env_repair.logger import EventEmitter
from python_env_repair.models import (
    ArtifactKind,
    EnvironmentInfo,
    FileIdentity,
    Platform,
    ReasonCode,
    RecoveryInfo,
    RepairResult,
    RepairStatus,
    VerificationPolicy,
    VerificationStatus,
)
from python_env_repair.generator import GenerationError, build_artifact, write_artifact
from python_env_repair.platform import UnsupportedPlatformError, detect_platform
from python_env_repair.validator import aggregate, verify_committed

logger = logging.getLogger(__name__)

STAGING_PREFIX = ".python-env-repair-"


class ItemFailure(Exception):
    """A per-item failure with a stable reason code."""

    def __init__(self, reason: ReasonCode, message: str, cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.cause = cause


def generate(script_name: str, module: str, attribute: str, env: EnvironmentInfo, staging_dir: Path) -> Path:
    """Generate exactly one launcher for an entry point into an empty staging directory.

    Args:
        script_name: Entry point name.
        module: Entry point module.
        attribute: Entry point attribute path.
        env: Target environment; must be the running platform.
        staging_dir: Empty directory that receives the output.

    Returns:
        Path of the generated launcher inside ``staging_dir``.

    Raises:
        ItemFailure: If generation is impossible or unsafe.
    """
    try:
        host = detect_platform()
    except UnsupportedPlatformError as exc:
        raise ItemFailure(ReasonCode.UNSUPPORTED_PLATFORM, str(exc), exc) from exc
    if host is not env.platform:
        raise ItemFailure(ReasonCode.UNSUPPORTED_PLATFORM, f"cannot generate {env.platform.value} launchers on {host.value}")
    try:
        data = build_artifact(module, attribute, str(env.python), env.platform)
        path = write_artifact(script_name, data, env.platform, staging_dir)
    except GenerationError as exc:
        raise ItemFailure(exc.reason, exc.message, exc) from exc
    except OSError as exc:
        raise ItemFailure(ReasonCode.GENERATION_FAILED, f"cannot write generated launcher: {exc}", exc) from exc
    real_staging = os.path.normcase(os.path.realpath(staging_dir))
    if os.path.normcase(os.path.realpath(path.parent)) != real_staging or sorted(os.listdir(staging_dir)) != [path.name]:
        raise ItemFailure(ReasonCode.GENERATION_FAILED, "generator produced an unexpected artifact set")
    return path


def classify_os_error(exc: BaseException) -> ReasonCode:
    """Map an OS error from a replacement to a reason code, using only concrete evidence."""
    if isinstance(exc, FileExistsError):
        return ReasonCode.TARGET_CHANGED
    winerror = getattr(exc, "winerror", None)
    if winerror in (32, 33):  # ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
        return ReasonCode.FILE_IN_USE
    if isinstance(exc, OSError) and exc.errno == errno.ETXTBSY:
        return ReasonCode.FILE_IN_USE
    if isinstance(exc, PermissionError):
        return ReasonCode.PERMISSION_DENIED
    return ReasonCode.REPLACE_FAILED


def _preserve_attributes(generated: Path, original: FileIdentity, env: EnvironmentInfo) -> None:
    """Carry permission bits and ownership of the file being replaced over to the new file."""
    if env.platform is Platform.WINDOWS or sys.platform == "win32":
        return
    perm = stat.S_IMODE(original.mode) & 0o777
    # Add execute for every class that can read; never add read or write access.
    os.chmod(generated, perm | ((perm & 0o444) >> 2))
    current = os.lstat(generated)
    if (current.st_uid, current.st_gid) != (original.uid, original.gid):
        try:
            os.chown(generated, original.uid, original.gid)
        except PermissionError as exc:
            raise ItemFailure(ReasonCode.OWNERSHIP_PRESERVATION_UNSUPPORTED, "cannot preserve the owner/group of the existing file", exc) from exc


def _restore_owner(path: Path, original: FileIdentity, env: EnvironmentInfo) -> None:
    """Give a recovery copy the original owner so that a rollback restores it exactly."""
    if env.platform is Platform.WINDOWS or sys.platform == "win32":
        return
    current = os.lstat(path)
    if (current.st_uid, current.st_gid) != (original.uid, original.gid):
        try:
            os.chown(path, original.uid, original.gid)
        except PermissionError as exc:
            raise ItemFailure(ReasonCode.OWNERSHIP_PRESERVATION_UNSUPPORTED, "cannot preserve the owner/group of the existing file for recovery", exc) from exc


def _exclusive_create(staged: Path, target: Path) -> None:
    """Create ``target`` from ``staged`` only if nothing exists at ``target``.

    Raises:
        FileExistsError: If the target appeared in the meantime.
        OSError: For other failures.
    """
    if os.name == "nt":
        os.rename(staged, target)  # fails if the target exists
        return
    try:
        os.link(staged, target)  # atomic, fails if the target exists
    except FileExistsError:
        raise
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.EMLINK):
            raise
    else:
        os.unlink(staged)  # leave the new launcher with a single link
        return
    mode = stat.S_IMODE(os.lstat(staged).st_mode)
    data = staged.read_bytes()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def repair_item(result: RepairResult, env: EnvironmentInfo, policy: VerificationPolicy, emitter: EventEmitter, progress: str) -> None:
    """Regenerate, commit, and verify one candidate, recovering on failure.

    The result is updated in place: ``repair_status``, ``verification``,
    ``verification_status``, ``modified_paths``, ``recovery``, ``reason_code``, and
    ``message``. ``overall_status`` is derived by the caller.

    Raises:
        KeyboardInterrupt: Re-raised after staging is cleaned up (or the recovery copy is
            retained when the live file had already been replaced).
    """
    script = result.script
    artifact = script.launcher
    assert artifact is not None
    target = artifact.path
    original = artifact.identity
    original_sha = artifact.sha256
    original_kind = artifact.kind
    started = time.monotonic()
    phase = "repair"
    emitter.emit(
        logger,
        logging.DEBUG,
        "repair.started",
        f"regenerating ({result.reason_code.value})",
        phase=phase,
        script=script,
        path=target,
        status="started",
        reason_code=result.reason_code.value,
        progress=progress,
    )

    staging: Optional[Path] = None
    recovery_path: Optional[Path] = None
    committed = False
    retain = False
    try:
        try:
            staging = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=env.scripts_dir))
        except OSError as exc:
            raise ItemFailure(classify_os_error(exc), f"cannot create staging directory in {env.scripts_dir}: {exc}", exc) from exc
        new_dir = staging / "new"
        new_dir.mkdir()
        generated = generate(script.name, script.module, script.attribute, env, new_dir)
        new_bytes = generated.read_bytes()
        new_sha = sha256_bytes(new_bytes)
        emitter.emit(
            logger,
            logging.DEBUG,
            "repair.generated",
            "launcher generated in staging",
            phase=phase,
            script=script,
            path=generated,
            status="generated",
            progress=progress,
            details={"sha256": new_sha, "size": len(new_bytes)},
        )

        if original is not None:
            try:
                _preserve_attributes(generated, original, env)
                recovery_dir = staging / "recovery"
                recovery_dir.mkdir()
                recovery_path = recovery_dir / target.name
                shutil.copy2(target, recovery_path, follow_symlinks=False)
                _restore_owner(recovery_path, original, env)
            except ItemFailure:
                raise
            except OSError as exc:
                raise ItemFailure(classify_os_error(exc), f"cannot prepare replacement: {exc}", exc) from exc
            if artifact.sha256 is not None and sha256_bytes(recovery_path.read_bytes()) != artifact.sha256:
                raise ItemFailure(ReasonCode.TARGET_CHANGED, "file content changed after inspection; not replaced")

        try:
            current = lstat_identity(target)
        except OSError as exc:
            raise ItemFailure(classify_os_error(exc), f"cannot re-inspect target: {exc}", exc) from exc
        if (original is None) != (current is None) or (original is not None and current is not None and not original.same_file_state(current)):
            raise ItemFailure(ReasonCode.TARGET_CHANGED, "file changed after inspection; not replaced")

        try:
            if original is None:
                _exclusive_create(generated, target)
            else:
                os.replace(generated, target)
        except OSError as exc:
            raise ItemFailure(classify_os_error(exc), f"cannot write {target}: {exc}", exc) from exc
        committed = True
        result.repair_status = RepairStatus.WRITTEN
        result.modified_paths.append(target)
        new_stat = os.lstat(target)
        artifact.identity = identity_from_stat(new_stat)
        artifact.sha256 = new_sha
        artifact.kind = _kind_of(new_bytes, env)
        emitter.emit(
            logger,
            logging.DEBUG,
            "repair.replaced",
            "launcher committed",
            phase=phase,
            script=script,
            path=target,
            status="written",
            progress=progress,
            details={"created": original is None, "mode": oct(stat.S_IMODE(new_stat.st_mode))},
        )

        verification_started = time.monotonic()
        emitter.emit(logger, logging.DEBUG, "verification.started", "verifying committed launcher", phase="verify", script=script, path=target, status="started", progress=progress)
        result.verification = verify_committed(env, script, target, new_sha, policy)
        result.verification_status = aggregate(result.verification)
        if result.verification_status is VerificationStatus.FAILED:
            failed = next(item for item in result.verification if item.status is VerificationStatus.FAILED)
            result.reason_code = failed.reason_code
            result.message = f"verification failed after writing: {failed.message}"
            emitter.emit(
                logger,
                logging.ERROR,
                "verification.failed",
                result.message,
                phase="verify",
                script=script,
                path=target,
                status="failed",
                reason_code=failed.reason_code.value,
                duration_ms=_elapsed_ms(verification_started),
                progress=progress,
                details={"checks": [item.to_dict() for item in result.verification]},
            )
            recovery = _rollback(result, target, recovery_path, (original_kind, original_sha), emitter, progress)
            result.recovery = recovery
            retain = not recovery.rollback_succeeded
        else:
            emitter.emit(
                logger,
                logging.DEBUG,
                "verification.completed",
                "; ".join(item.message for item in result.verification),
                phase="verify",
                script=script,
                path=target,
                status=result.verification_status.value,
                duration_ms=_elapsed_ms(verification_started),
                progress=progress,
                details={"checks": [item.to_dict() for item in result.verification]},
            )
    except ItemFailure as failure:
        result.repair_status = RepairStatus.FAILED if not committed else result.repair_status
        result.reason_code = failure.reason
        result.message = failure.message
        emitter.emit(
            logger,
            logging.ERROR,
            "repair.failed",
            failure.message,
            phase=phase,
            script=script,
            path=target,
            status="failed",
            reason_code=failure.reason.value,
            duration_ms=_elapsed_ms(started),
            progress=progress,
            exc_info=failure.cause,
        )
        if committed:
            result.recovery = _rollback(result, target, recovery_path, (original_kind, original_sha), emitter, progress)
            retain = not result.recovery.rollback_succeeded
    except Exception as exc:
        result.repair_status = RepairStatus.FAILED if not committed else result.repair_status
        result.reason_code = ReasonCode.INTERNAL_ERROR
        result.message = f"unexpected error: {type(exc).__name__}: {exc}"
        emitter.emit(
            logger,
            logging.ERROR,
            "repair.failed",
            result.message,
            phase=phase,
            script=script,
            path=target,
            status="failed",
            reason_code=result.reason_code.value,
            duration_ms=_elapsed_ms(started),
            progress=progress,
            exc_info=exc,
        )
        if committed:
            result.recovery = _rollback(result, target, recovery_path, (original_kind, original_sha), emitter, progress)
            retain = not result.recovery.rollback_succeeded
    except BaseException:
        if committed and recovery_path is not None:
            retain = True
            result.recovery = RecoveryInfo(recovery_path=recovery_path, retained_path=recovery_path, message="interrupted after replacement; original retained for manual recovery")
        raise
    finally:
        if staging is not None:
            if retain:
                if result.recovery is not None and recovery_path is not None and recovery_path.exists():
                    result.recovery.retained_path = recovery_path
            else:
                try:
                    shutil.rmtree(staging)
                except OSError as exc:
                    emitter.emit(
                        logger,
                        logging.WARNING,
                        "repair.cleanup_failed",
                        f"could not remove staging directory: {exc}",
                        phase=phase,
                        script=script,
                        path=staging,
                        status="cleanup_failed",
                        progress=progress,
                    )


def _kind_of(data: bytes, env: EnvironmentInfo) -> ArtifactKind:
    if env.platform is Platform.WINDOWS:
        return ArtifactKind.WINDOWS_LAUNCHER
    launcher = parse_unix_launcher(data)
    return launcher.kind if launcher else ArtifactKind.UNRECOGNIZED


def _rollback(result: RepairResult, target: Path, recovery_path: Optional[Path], original: tuple[ArtifactKind, Optional[str]], emitter: EventEmitter, progress: str) -> RecoveryInfo:
    """Restore the original file (or remove a newly created one) after a failed verification."""
    script = result.script
    info = RecoveryInfo(recovery_path=recovery_path, rollback_attempted=True)
    started = time.monotonic()
    try:
        if recovery_path is not None:
            os.replace(recovery_path, target)
        else:
            os.unlink(target)
    except OSError as exc:
        info.rollback_succeeded = False
        info.retained_path = recovery_path
        info.message = f"rollback failed: {exc}"
        emitter.emit(
            logger,
            logging.CRITICAL,
            "rollback.failed",
            info.message,
            phase="rollback",
            script=script,
            path=target,
            status="failed",
            reason_code=ReasonCode.ROLLBACK_FAILED.value,
            duration_ms=_elapsed_ms(started),
            progress=progress,
            details={"retained_recovery_path": str(recovery_path) if recovery_path else None},
            exc_info=exc,
        )
        return info
    info.rollback_succeeded = True
    info.message = "original restored" if recovery_path is not None else "newly created artifact removed"
    result.repair_status = RepairStatus.ROLLED_BACK
    artifact = script.launcher
    if artifact is not None:
        artifact.kind, artifact.sha256 = original
        try:
            artifact.identity = identity_from_stat(os.lstat(target)) if recovery_path is not None else None
        except OSError:
            artifact.identity = None
    emitter.emit(logger, logging.WARNING, "rollback.completed", info.message, phase="rollback", script=script, path=target, status="rolled_back", duration_ms=_elapsed_ms(started), progress=progress)
    return info
