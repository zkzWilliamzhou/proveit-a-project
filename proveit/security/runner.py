"""The only place proveit starts a child process.

Fixed argv lists come from application code. Untrusted values are validated
separately and appended as single items. No shell, no inherited environment, no
unbounded output, and a process-group kill on timeout.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..errors import ExecutionError, PolicyViolation
from ..limits import (
    KILL_GRACE_SECONDS,
    MAX_ARGV_ITEM_CHARS,
    MAX_ARGV_ITEMS,
    MAX_OUTPUT_BYTES,
    PROCESS_TIMEOUT_SECONDS,
)

_BASE_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "NO_COLOR": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
}


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    truncated: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.truncated

    def text(self, limit: int = 4_096) -> str:
        out = self.stdout.decode("utf-8", errors="replace")
        err = self.stderr.decode("utf-8", errors="replace")
        return (out + ("\n" + err if err else ""))[:limit]


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(OSError):
            proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=KILL_GRACE_SECONDS)


def run_isolated(
    argv: list[str] | tuple[str, ...],
    *,
    cwd: Path,
    timeout: float = PROCESS_TIMEOUT_SECONDS,
    max_output: int = MAX_OUTPUT_BYTES,
) -> CommandResult:
    if not isinstance(argv, (list, tuple)) or not argv:
        raise PolicyViolation("argv must be a non-empty list")
    if len(argv) > MAX_ARGV_ITEMS:
        raise PolicyViolation("argv too long")
    for item in argv:
        if not isinstance(item, str):
            raise PolicyViolation("argv items must be strings")
        if len(item) > MAX_ARGV_ITEM_CHARS or "\x00" in item:
            raise PolicyViolation("invalid argv item")
        if any(ord(ch) < 32 for ch in item):
            raise PolicyViolation("control character in argv item")

    env = dict(_BASE_ENV)
    timed_out = False
    with tempfile.TemporaryDirectory(prefix="proveit-home-") as home:
        env["HOME"] = home
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                proc = subprocess.Popen(
                    list(argv),
                    cwd=str(cwd),
                    env=env,
                    shell=False,
                    close_fds=True,
                    stdin=subprocess.DEVNULL,
                    stdout=out,
                    stderr=err,
                    start_new_session=True,
                )
            except (OSError, ValueError) as exc:
                raise ExecutionError(f"cannot start process: {exc}") from exc
            try:
                returncode = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_group(proc)
                returncode = -9
                timed_out = True
            out.seek(0)
            err.seek(0)
            stdout = out.read(max_output + 1)
            stderr = err.read(max_output + 1)
    truncated = len(stdout) > max_output or len(stderr) > max_output
    return CommandResult(
        returncode=returncode,
        stdout=stdout[:max_output],
        stderr=stderr[:max_output],
        timed_out=timed_out,
        truncated=truncated,
    )
