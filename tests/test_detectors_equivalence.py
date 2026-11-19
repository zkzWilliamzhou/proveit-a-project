"""Differential regression test for the detectors deepening.

The legacy inline algorithm is kept here as a reference oracle. If anyone
changes the detector catalog, caps or entropy threshold, the reference and the
deep module must agree on a fixed corpus. This is the permanent guard behind
docs/fingerprint_equivalence.json.
"""

from __future__ import annotations

import math
import re

import pytest

from proveit.detectors import scan_added_lines

_LEGACY_PATTERNS = (
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
_LEGACY_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-.]{24,256}")
_LEGACY_HEX = re.compile(r"\A[0-9a-fA-F]+\Z")


def _legacy_entropy(token: str) -> float:
    counts: dict[str, int] = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    n = len(token)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def legacy_scan(lines):
    findings = []
    scanned = 0
    for origin, number, raw_line in lines:
        scanned += 1
        if scanned > 20_000:
            break
        content = raw_line[:4096]
        for kind, pattern in _LEGACY_PATTERNS:
            if pattern.search(content):
                findings.append({"kind": kind, "origin": origin, "line": number})
                break
        else:
            for match in list(_LEGACY_TOKEN.finditer(content))[:32]:
                token = match.group(0)
                if _LEGACY_HEX.match(token):
                    continue
                if _legacy_entropy(token) > 4.6:
                    findings.append({"kind": "high_entropy_token", "origin": origin, "line": number})
                    break
        if len(findings) >= 64:
            break
    return findings, scanned


CORPUS = [
    ("diff", 1, "def public_func(): return 1"),
    ("diff", 2, 'api_key = "AKIA\x49OSFODNN7EXAMPLE"'),
    ("untracked:a.txt", 1, "ghp_\x61bcdefghijklmnopqrstuvwxyz0123456789"),
    ("untracked:b.txt", 2, "-----BEGIN \x52SA PRIVATE KEY-----"),
    ("diff", 3, "xoxb-\x31323456789012-abcdefghijklmnop"),
    ("diff", 4, "digest = 0123456789abcdef0123456789abcdef"),
    ("diff", 5, "value = aZ9pQ2xLmN8vR4tY6wB1kS5dF0hJ"),
    ("diff", 6, "token: abcdefghijklmnop"),
    ("diff", 7, "PASSWORD=correcthorsebatterystaple"),
    ("diff", 8, "x = " + "a" * 5_000),
    ("diff", 9, ""),
    ("diff", 10, "secret = " + "z" * 300),
]


@pytest.mark.parametrize("lines", [
    CORPUS,
    CORPUS * 3,
    [("diff", i, "plain = 1") for i in range(500)],
    [("diff", i, 'api_key = "AKIA\x49OSFODNN7EXAMPLE"') for i in range(200)],
])
def test_deepened_module_matches_legacy(lines):
    expected, expected_scanned = legacy_scan(lines)
    actual = scan_added_lines(lines)
    assert actual.as_evidence() == expected
    assert actual.lines_scanned == expected_scanned
