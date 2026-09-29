"""Cooperative per-environment lock for mutating runs.

The lock coordinates repair processes of this utility only; it does not stop package
installers or other Python processes. The operating system releases it when the process
exits. On POSIX an advisory ``flock`` is taken on the scripts directory itself, so no lock
file is created. On Windows a lock file inside the scripts directory is locked with
``msvcrt.locking`` and removed on release when possible.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import TracebackType
from typing import Optional

WINDOWS_LOCK_NAME = ".python-env-repair.lock"


class EnvironmentBusyError(RuntimeError):
    """Another repair process holds the environment lock."""


class LockError(RuntimeError):
    """The lock could not be acquired for a reason other than contention."""


class EnvironmentLock:
    """Non-blocking exclusive lock on an environment's scripts directory."""

    def __init__(self, scripts_dir: Path) -> None:
        self.scripts_dir = scripts_dir
        self._fd: Optional[int] = None
        self._path: Optional[Path] = None

    def acquire(self) -> None:
        """Acquire the lock without waiting.

        Raises:
            EnvironmentBusyError: If another process holds it.
            LockError: If locking is not possible.
        """
        if sys.platform == "win32":
            self._acquire_windows()
        else:
            self._acquire_posix()

    def _acquire_posix(self) -> None:
        if sys.platform == "win32":
            raise LockError("POSIX locking is not available on Windows")
        import fcntl

        try:
            fd = os.open(self.scripts_dir, os.O_RDONLY)
        except OSError as exc:
            raise LockError(f"cannot open scripts directory for locking: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise EnvironmentBusyError("another repair process is running for this environment") from exc
        except OSError as exc:
            os.close(fd)
            raise LockError(f"cannot lock scripts directory: {exc}") from exc
        self._fd = fd

    def _acquire_windows(self) -> None:
        if sys.platform != "win32":
            raise LockError("Windows locking is only available on Windows")
        import msvcrt

        path = self.scripts_dir / WINDOWS_LOCK_NAME
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            raise LockError(f"cannot create lock file {path}: {exc}") from exc
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            os.close(fd)
            raise EnvironmentBusyError("another repair process is running for this environment") from exc
        self._fd = fd
        self._path = path

    def release(self) -> None:
        """Release the lock; safe to call more than once."""
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt

                try:
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            if self._path is not None:
                try:
                    os.unlink(self._path)
                except OSError:
                    pass
                self._path = None

    def __enter__(self) -> EnvironmentLock:
        self.acquire()
        return self

    def __exit__(self, exc_type: Optional[type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]) -> None:
        self.release()
