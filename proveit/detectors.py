"""Secret detection behind one deep interface.

This module hides the detector catalog, entropy screening, per-line caps and
finding shape. Callers supply a stream of introduced lines and receive a
bounded result. Deleting this module would push every one of those concerns
back into each witness, so the deletion test says it concentrates complexity.

The interface is intentionally small:

    scan_added_lines([(origin, line_number, text), ...]) -> ScanResult

Nothing here reads a repository, starts a process, or decides a verdict.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable

MAX_SCANNED_LINES = 20_000
MAX_FINDINGS = 64
MAX_LINE_CHARS = 4_096
MAX_TOKENS_PER_LINE = 32
ENTROPY_THRESHOLD = 4.6

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,200}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,200}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]{0,24}PRIVATE KEY-----")),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)"
            r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._\-/+]{8,256}"
        ),
    ),
)
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-.]{24,256}")
_HEX_ONLY = re.compile(r"\A[0-9a-fA-F]+\Z")


@dataclass(frozen=True)
class Finding:
    kind: str
    origin: str
    line: int

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "origin": self.origin, "line": self.line}


@dataclass(frozen=True)
class ScanResult:
    findings: tuple[Finding, ...]
    lines_scanned: int

    def as_evidence(self) -> list[dict[str, object]]:
        return [f.to_dict() for f in self.findings]


def _entropy(token: str) -> float:
    counts: dict[str, int] = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    length = len(token)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _finding_for_line(content: str, origin: str, number: int) -> Finding | None:
    for kind, pattern in _PATTERNS:
        if pattern.search(content):
            return Finding(kind, origin, number)
    for match in list(_TOKEN.finditer(content))[:MAX_TOKENS_PER_LINE]:
        token = match.group(0)
        if _HEX_ONLY.match(token):
            continue
        if _entropy(token) > ENTROPY_THRESHOLD:
            return Finding("high_entropy_token", origin, number)
    return None


def scan_added_lines(lines: Iterable[tuple[str, int, str]]) -> ScanResult:
    """Screen introduced lines. Bounded work, no I/O, no raw content retained."""
    findings: list[Finding] = []
    scanned = 0
    for origin, number, raw_line in lines:
        scanned += 1
        if scanned > MAX_SCANNED_LINES:
            break
        content = raw_line[:MAX_LINE_CHARS]
        match = _finding_for_line(content, origin, number)
        if match is not None:
            findings.append(match)
        if len(findings) >= MAX_FINDINGS:
            break
    return ScanResult(tuple(findings), scanned)


def detector_names() -> tuple[str, ...]:
    """Expose only the catalog names, for audit and documentation."""
    return (*tuple(kind for kind, _ in _PATTERNS), "high_entropy_token")
