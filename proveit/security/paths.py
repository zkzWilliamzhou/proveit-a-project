"""Path containment.

A repository is attacker-controlled data. ``..`` segments, absolute paths,
symlinks that escape the checkout, and option-looking values are all rejected
before any open or subprocess call.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..errors import LimitExceeded, PolicyViolation
from ..limits import MAX_FILE_BYTES, MAX_PARAM_STR

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_REF = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/~^\-]{0,127}\Z")
_SAFE_VALUE = re.compile(r"\A[A-Za-z0-9._/+~^\-=]{1,256}\Z")


def canonical_root(root: str | Path) -> Path:
    try:
        resolved = Path(root).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PolicyViolation(f"repository root cannot be resolved: {exc}") from exc
    if not resolved.is_dir():
        raise PolicyViolation("repository root is not a directory")
    return resolved


def validate_ref(ref: str) -> str:
    """Only plain git revisions. Never a ref:path spec or an option."""
    if not isinstance(ref, str) or not _REF.match(ref):
        raise PolicyViolation("invalid git ref")
    if ".." in ref or ":" in ref or ref.startswith("-"):
        raise PolicyViolation("invalid git ref")
    return ref


def validate_value(value: str, label: str = "value") -> str:
    """Bound an untrusted string before it becomes an argv item."""
    if not isinstance(value, str):
        raise PolicyViolation(f"{label} must be a string")
    if not value or len(value) > MAX_PARAM_STR:
        raise PolicyViolation(f"{label} has an invalid length")
    if _CONTROL.search(value):
        raise PolicyViolation(f"{label} contains control characters")
    if value.startswith("-"):
        raise PolicyViolation(f"{label} must not look like an option")
    if not _SAFE_VALUE.match(value):
        raise PolicyViolation(f"{label} contains disallowed characters")
    return value


def require_relative(relative: str) -> str:
    if not isinstance(relative, str) or not relative:
        raise PolicyViolation("path must be a non-empty string")
    if len(relative) > 512 or _CONTROL.search(relative):
        raise PolicyViolation("path has invalid length or characters")
    if relative.startswith(("/", "\\")) or "\\" in relative:
        raise PolicyViolation("absolute or Windows-style paths are not allowed")
    if ":" in relative:
        raise PolicyViolation("drive-qualified paths are not allowed")
    parts = relative.split("/")
    if any(part in ("", ".", "..", "~") for part in parts):
        raise PolicyViolation("path traversal is not allowed")
    if relative.startswith("-"):
        raise PolicyViolation("path must not look like an option")
    return relative


def safe_path(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    """Resolve a repo-relative path and prove it stays inside the checkout.

    Resolution is repeated on every security-sensitive use. Returning a Path is
    safe here because callers open immediately; ``read_file_bounded`` uses
    O_NOFOLLOW on the final component to close the remaining TOCTOU window.
    """
    rel = require_relative(relative)
    base = root.resolve(strict=True)
    try:
        candidate = (base / rel).resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise PolicyViolation(f"path cannot be resolved: {exc}") from exc
    if candidate != base and base not in candidate.parents:
        raise PolicyViolation("path escapes repository root")

    cursor = base
    for part in Path(rel).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            try:
                target = cursor.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise PolicyViolation(f"symlink cannot be resolved: {exc}") from exc
            if target != base and base not in target.parents:
                raise PolicyViolation("symlink escapes repository root")
    return candidate


def read_file_bounded(
    root: Path, relative: str, max_bytes: int = MAX_FILE_BYTES
) -> bytes:
    """Read a file with a hard byte cap and no final-component symlink."""
    rel = require_relative(relative)
    # safe_path resolves symlinks away, so check the literal final component
    # before resolving. A refused read must never be reported as a missing file.
    if (root / rel).is_symlink():
        raise PolicyViolation("final path component is a symlink")
    path = safe_path(root, rel, must_exist=True)
    if not path.is_file():
        raise PolicyViolation("path is not a regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PolicyViolation(f"cannot open path: {exc}") from exc
    try:
        size = os.fstat(fd).st_size
        if size > max_bytes:
            raise LimitExceeded(f"file exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            block = os.read(fd, min(65_536, max_bytes - total + 1))
            if not block:
                break
            total += len(block)
            if total > max_bytes:
                raise LimitExceeded(f"file exceeds {max_bytes} bytes")
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def decode(data: bytes, max_chars: int = 1_000_000) -> str:
    """Lossy but never-failing decode for untrusted bytes."""
    text = data.decode("utf-8", errors="replace")
    return text[:max_chars]
