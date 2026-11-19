"""Deterministic, bounded claim extraction.

Claim text is opaque evidence. It is never used to build a command, import a
module, or influence control flow beyond a lookup in a fixed pattern table. A
prompt-injection payload inside a transcript therefore produces an abstention,
not an action.
"""

from __future__ import annotations

import re

from ..errors import InputError, LimitExceeded
from ..limits import MAX_CLAIM_CHARS, MAX_CLAIMS, MAX_LINE_CHARS, MAX_TRANSCRIPT_LINES
from ..model import Claim

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(all\s+)?tests?\s+(pass|are\s+passing|are\s+green)\b"), "tests_pass"),
    (re.compile(r"(?i)\b(added|wrote|created)\s+(unit\s+|regression\s+)?tests?\b"), "tests_added"),
    (re.compile(r"(?i)\bno\s+(new\s+)?(secrets?|credentials?|api\s*keys?)\b"), "no_secrets"),
    (re.compile(r"(?i)\bno\s+new\s+(dependencies|deps|packages)\b"), "no_new_dependencies"),
    (re.compile(r"(?i)\b(backward[s]?\s+compatible|no\s+breaking\s+changes)\b"), "backward_compatible"),
    (re.compile(r"(?i)\b(only\s+(touched|changed|modified)|only\s+files)\b"), "only_changed_files"),
    (re.compile(r"(?i)\bno\s+(files?\s+)?(were\s+)?deleted\b"), "no_deleted_files"),
    (re.compile(r"(?i)\b(fixed|resolved)\s+(the\s+)?(bug|issue|defect)\b"), "bug_fixed"),
    (re.compile(r"(?i)\b(clean|empty)\s+work(tree|ing\s+tree)\b"), "clean_worktree"),
    (re.compile(r"(?i)\b(syntax\s+(is\s+)?(ok|valid)|compiles?\s+cleanly)\b"), "python_syntax_ok"),
    (re.compile(r"(?i)\b(valid|well[- ]formed)\s+json\b"), "json_valid"),
    (re.compile(r"(?i)\b(small|minimal|tiny)\s+(diff|change)\b"), "small_diff"),
    (re.compile(r"(?i)\b(production\s+ready|ready\s+for\s+production)\b"), "production_ready"),
    (re.compile(r"(?i)\b(more\s+secure|security\s+improved|is\s+secure)\b"), "secure"),
    (re.compile(r"(?i)\b(faster|performance\s+improved|optimized)\b"), "performance_improved"),
    (re.compile(r"(?i)\b(handles?\s+all\s+edge\s+cases|handles?\s+every\s+case)\b"), "handles_edge_cases"),
    (re.compile(r"(?i)\b(lint(er)?\s+(is\s+)?clean|no\s+lint\s+errors)\b"), "lint_clean"),
)

_BACKTICK = re.compile(r"`([^`]{1,256})`")
_CONJUNCTION = re.compile(r"(?i)\s+and\s+|\s+plus\s+|\s*;\s*")


def _segments(line: str) -> list[str]:
    """Split a compound sentence only when the pieces are independently claims.

    A bare split would destroy ``I only touched `a.py` and `b.py```: the second
    backticked path is not a claim. Keep the whole line unless at least two
    segments match the closed pattern table.
    """
    parts = [p.strip() for p in _CONJUNCTION.split(line) if p.strip()]
    if len(parts) < 2:
        return [line]
    matched = sum(1 for part in parts if _classify(part) != "unrecognized")
    return parts if matched >= 2 else [line]


def _split_lines(text: str) -> list[str]:
    if len(text) > MAX_TRANSCRIPT_LINES * MAX_LINE_CHARS:
        raise LimitExceeded("transcript is too large")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(lines) > MAX_TRANSCRIPT_LINES:
        raise LimitExceeded("too many transcript lines")
    return [line[:MAX_LINE_CHARS] for line in lines]


def _classify(line: str) -> str:
    for pattern, kind in _RULES:
        if pattern.search(line):
            return kind
    return "unrecognized"


def _backticked_paths(line: str) -> list[str]:
    return [m.group(1)[:256] for m in _BACKTICK.finditer(line)][:128]


def extract_from_text(text: str, source: str = "transcript") -> list[Claim]:
    if not isinstance(text, str):
        raise InputError("transcript text must be a string")
    claims: list[Claim] = []
    for raw in _split_lines(text):
        line = raw.strip().lstrip("*-").strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if line.startswith("```"):
            continue
        for segment in _segments(line):
            kind = _classify(segment)
            params: dict = {}
            if kind == "only_changed_files":
                paths = _backticked_paths(segment)
                if paths:
                    params["files"] = paths
            claims.append(
                Claim(
                    id=f"T{len(claims) + 1}",
                    text=segment[:MAX_CLAIM_CHARS],
                    kind=kind,
                    params=params,
                    source=source,
                )
            )
            if len(claims) >= MAX_CLAIMS:
                return claims
    return claims


def claims_from_cli(text: str) -> list[Claim]:
    return extract_from_text(text, source="cli")


def claims_from_manifest(doc: dict) -> list[Claim]:
    return [
        Claim(
            id=c["id"],
            text=c["statement"],
            kind=c["kind"],
            params=dict(c["params"]),
            source="manifest",
        )
        for c in doc["claims"]
    ]
