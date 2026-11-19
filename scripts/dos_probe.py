#!/usr/bin/env python3
"""Bounded resource probes. Prints measured timings; fails on a hard ceiling.

Rejection at a declared limit is a PASS for this probe, not a crash.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from proveit.claims.parser import extract_from_text
from proveit.errors import LimitExceeded
from proveit.security.policy import load_manifest_bytes
from proveit.security.redaction import redact_text

CEILING_SECONDS = 5.0


def timed(fn):
    start = time.monotonic()
    value = fn()
    return round(time.monotonic() - start, 4), value


def main() -> int:
    results: dict = {}

    huge_claims = "\n".join("All tests pass" for _ in range(50_000))
    rejected = False
    start = time.monotonic()
    try:
        claims = extract_from_text(huge_claims)
    except LimitExceeded:
        claims = []
        rejected = True
    results["50k_claim_lines"] = {
        "seconds": round(time.monotonic() - start, 4),
        "claims_emitted": len(claims),
        "rejected_at_limit": rejected,
    }

    long_line = "x" * 200_000 + " and no secrets were introduced"
    elapsed, claims = timed(lambda: extract_from_text(long_line))
    results["200k_char_line"] = {"seconds": elapsed, "claims_emitted": len(claims)}

    redos = "a" * 5_000 + "!" + " api_key = " + "A" * 5_000
    elapsed, _ = timed(lambda: redact_text(redos))
    results["redos_probe"] = {"seconds": elapsed}

    elapsed, redacted = timed(lambda: redact_text("token = abcdefghijklmnop " * 20_000))
    results["1mb_redaction"] = {"seconds": elapsed, "output_chars": len(redacted)}

    oversize_rejected = False
    try:
        load_manifest_bytes(b" " * (1024 * 1024))
    except LimitExceeded:
        oversize_rejected = True
    results["oversize_manifest_rejected"] = oversize_rejected

    slowest = max(v["seconds"] for v in results.values() if isinstance(v, dict) and "seconds" in v)
    results["slowest_seconds"] = slowest
    results["ceiling_seconds"] = CEILING_SECONDS
    results["passed"] = (
        slowest < CEILING_SECONDS
        and oversize_rejected
        and rejected
        and len(claims) <= 200
    )
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
