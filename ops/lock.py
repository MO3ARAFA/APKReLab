"""Cross-process run lock: the state file has one writer at a time (daemon cycle, web job or CLI run).

An advisory flock on a sidecar file. The lock is held by the open file descriptor, so it disappears if the process dies.
On platforms without fcntl it degrades to a no-op (the in-process JobManager lock still applies).
"""
from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None


class RunLock:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._fd: int | None = None
        self._mutex = threading.Lock()

    def acquire(self, blocking: bool = False) -> bool:
        if fcntl is None:
            return True
        with self._mutex:
            if self._fd is not None:
                return False  # already held through this object
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except OSError:
                os.close(fd)
                return False
            self._fd = fd
            return True

    def release(self) -> None:
        if fcntl is None:
            return
        with self._mutex:
            if self._fd is not None:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
                finally:
                    os.close(self._fd)
                    self._fd = None

    def busy(self) -> bool:
        """Is somebody else (another process or object) holding the lock right now?"""
        probe = RunLock(self.path)
        if probe.acquire():
            probe.release()
            return False
        return True

    @contextmanager
    def held(self):
        if not self.acquire():
            raise BlockingIOError("another agency run holds the lock")
        try:
            yield
        finally:
            self.release()
