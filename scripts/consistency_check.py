#!/usr/bin/env python3
"""Cross-check the claim grammar, witness registry and documented kinds."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from proveit.claims.grammar import known_kinds, plan_for
from proveit.witnesses import all_witnesses

SAMPLE_PARAMS = {
    "files": ["app.py"],
    "deny": ["docs"],
    "max": 10,
    "path": "app.py",
    "literal": "x",
    "sha256": "0" * 64,
    "target": "tests",
    "test": "tests/test_x.py",
}


def main() -> int:
    registered = {w.name for w in all_witnesses()}
    problems: list[str] = []
    reachable: set[str] = set()
    for kind in known_kinds():
        outcome = plan_for(kind, SAMPLE_PARAMS)
        if outcome.reason_code and outcome.reason_code not in (
            "NO_SOUND_WITNESS", "NO_DISCRIMINATING_TEST", "UNRECOGNIZED_CLAIM_KIND"
        ):
            problems.append(f"{kind}: unexpected abstention {outcome.reason_code}")
        for spec in outcome.specs:
            reachable.add(spec.name)
            if spec.name not in registered:
                problems.append(f"{kind}: unregistered witness {spec.name}")
    for name in sorted(registered - reachable):
        problems.append(f"orphan witness never selected by a claim kind: {name}")
    for kind in known_kinds():
        if plan_for(kind, {}).reason_code == "UNRECOGNIZED_CLAIM_KIND":
            problems.append(f"known_kinds() advertises an unmapped kind: {kind}")
    report = {
        "known_kinds": len(known_kinds()),
        "registered_witnesses": len(registered),
        "reachable_witnesses": len(reachable),
        "problems": problems,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
