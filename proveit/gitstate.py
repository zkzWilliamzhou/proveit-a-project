"""Read-only git facts.

This is the only module that talks to git. Output is NUL-delimited where paths
are involved, capped in bytes, and converted to plain primitives before it
reaches a witness. Nothing here writes to the repository.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from .errors import ExecutionError, LimitExceeded, PolicyViolation, WitnessUnavailable
from .limits import MAX_DIFF_BYTES, MAX_FILE_BYTES, MAX_TAR_BYTES
from .security.paths import decode, require_relative, validate_ref
from .security.runner import run_isolated

_GIT = shutil.which("git") or "/usr/bin/git"

DEP_FILES = (
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
)


class GitState:
    def __init__(self, root: Path, base: str) -> None:
        self.root = root
        self.base = validate_ref(base)

    def _run(self, args: list[str], max_output: int = MAX_DIFF_BYTES) -> bytes:
        result = run_isolated(
            [_GIT, "-C", str(self.root), *args],
            cwd=self.root,
            max_output=max_output,
        )
        if result.truncated or result.timed_out:
            raise LimitExceeded("git output exceeded its bound")
        if result.returncode != 0:
            raise WitnessUnavailable(
                f"git {' '.join(args[:2])} failed ({result.returncode}): "
                f"{decode(result.stderr, 300)}"
            )
        return result.stdout

    def is_repo(self) -> bool:
        try:
            return self._run(["rev-parse", "--is-inside-work-tree"]).strip() == b"true"
        except (WitnessUnavailable, ExecutionError, PolicyViolation):
            return False

    def head(self) -> str:
        value = decode(self._run(["rev-parse", "HEAD"], max_output=4096)).strip()
        if len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            raise WitnessUnavailable("could not resolve HEAD")
        return value

    def base_exists(self) -> bool:
        try:
            self._run(["rev-parse", "--verify", self.base], max_output=4096)
            return True
        except WitnessUnavailable:
            return False

    def _nul_paths(self, args: list[str]) -> list[str]:
        raw = self._run(args)
        paths: list[str] = []
        for chunk in raw.split(b"\x00"):
            if not chunk:
                continue
            text = decode(chunk, 1024)
            paths.append(require_relative(text))
        return sorted(set(paths))

    def changed_files(self) -> list[str]:
        tracked = self._nul_paths(["diff", "--name-only", "-z", self.base])
        untracked = self._nul_paths(["ls-files", "--others", "--exclude-standard", "-z"])
        return sorted(set(tracked) | set(untracked))

    def name_status(self) -> list[tuple[str, str]]:
        raw = self._run(["diff", "--name-status", "-z", self.base])
        chunks = [c for c in raw.split(b"\x00") if c]
        out: list[tuple[str, str]] = []
        i = 0
        while i < len(chunks):
            status = decode(chunks[i], 16).strip()
            i += 1
            if i >= len(chunks):
                break
            path = require_relative(decode(chunks[i], 1024))
            i += 1
            if status[:1] in ("R", "C") and i < len(chunks):
                i += 1  # skip the second path of a rename/copy record
            out.append((status[:1], path))
        return out

    def diff_text(self) -> str:
        return decode(self._run(["diff", "--no-color", "--unified=0", self.base]), MAX_DIFF_BYTES)

    def added_lines(self) -> list[tuple[str, int, str]]:
        """(origin, line_number, content) for every line introduced by the change."""
        out: list[tuple[str, int, str]] = []
        for number, line in enumerate(self.diff_text().splitlines(), start=1):
            if line.startswith("+") and not line.startswith("+++"):
                out.append(("diff", number, line[1:][:4096]))
            if len(out) >= 20_000:
                break
        for path in self._nul_paths(["ls-files", "--others", "--exclude-standard", "-z"]):
            from .security.paths import read_file_bounded

            try:
                data = read_file_bounded(self.root, path, max_bytes=MAX_FILE_BYTES)
            except (PolicyViolation, LimitExceeded):
                continue
            for number, line in enumerate(decode(data).splitlines(), start=1):
                out.append(("untracked:" + path, number, line[:4096]))
                if len(out) >= 20_000:
                    return out
        return out

    def status_porcelain(self) -> list[str]:
        return decode(self._run(["status", "--porcelain"], max_output=MAX_DIFF_BYTES)).splitlines()

    def base_file_bytes(self, relative: str) -> bytes:
        rel = require_relative(relative)
        return self._run(["show", f"{self.base}:{rel}"], max_output=MAX_FILE_BYTES)

    def base_tree_tar(self) -> bytes:
        return self._run(["archive", "--format=tar", self.base], max_output=MAX_TAR_BYTES)

    def worktree_bytes(self, relative: str) -> bytes:
        from .security.paths import read_file_bounded

        return read_file_bounded(self.root, relative, max_bytes=MAX_FILE_BYTES)

    def diff_hash(self) -> str:
        digest = hashlib.sha256()
        digest.update(self._run(["diff", "--no-color", "--binary", self.base]))
        for path in self._nul_paths(["ls-files", "--others", "--exclude-standard", "-z"]):
            digest.update(b"\x00untracked\x00")
            digest.update(path.encode("utf-8", errors="replace"))
            try:
                digest.update(self.worktree_bytes(path))
            except (PolicyViolation, LimitExceeded):
                digest.update(b"<unreadable>")
        return digest.hexdigest()
