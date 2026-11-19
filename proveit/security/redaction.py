"""Redaction applied before ANY evidence is serialized or printed.

CI logs and SARIF uploads are public artifacts. Filtering terminal output is not
enough: redaction must happen on the structured receipt itself. Patterns are
deliberately simple bounded expressions so the redactor cannot become a ReDoS
vector.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,200}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]{0,24}PRIVATE KEY-----")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,200}\b")),
    ("bearer", re.compile(r"\bBearer [A-Za-z0-9._\-]{16,256}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,256}\.eyJ[A-Za-z0-9_\-]{8,256}\.[A-Za-z0-9_\-]{8,256}\b")),
    (
        "secret_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)"
            r"[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._\-/+]{8,256}"
        ),
    ),
    (
        "email",
        re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,128}\.[A-Za-z]{2,24}\b"),
    ),
)

_MAX_TEXT = 2 * 1024 * 1024


def redact_text(text: str, counts: Counter[str] | None = None) -> str:
    if not isinstance(text, str):
        return ""
    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT] + "[TRUNCATED]"
    for kind, pattern in _PATTERNS:
        text, hits = pattern.subn(f"[REDACTED:{kind}]", text)
        if counts is not None and hits:
            counts[kind] += hits
    return text


def redact_structure(value: Any, counts: Counter[str] | None = None, _depth: int = 0) -> Any:
    """Walk a receipt-shaped structure. Bounded depth; no recursion into objects."""
    if counts is None:
        counts = Counter()
    if _depth > 32:
        return "[TRUNCATED:depth]"
    if isinstance(value, str):
        return redact_text(value, counts)
    if isinstance(value, bytes):
        return redact_text(value.decode("utf-8", errors="replace"), counts)
    if isinstance(value, dict):
        return {
            redact_text(str(k), counts): redact_structure(v, counts, _depth + 1)
            for k, v in list(value.items())[:512]
        }
    if isinstance(value, (list, tuple)):
        return [redact_structure(v, counts, _depth + 1) for v in list(value)[:512]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_text(str(value), counts)


def redact_receipt(body: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    counts: Counter[str] = Counter()
    cleaned = redact_structure(body, counts)
    report = {"applied": True, "total": sum(counts.values()), "by_kind": dict(sorted(counts.items()))}
    return cleaned, report
