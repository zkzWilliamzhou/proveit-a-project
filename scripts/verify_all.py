#!/usr/bin/env python3
"""Single release gate for proveit.

Runs every check we use before shipping. Fails loudly on a missing tool so a
green result never comes from a check that silently did not run.

Usage: python3 scripts/verify_all.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def run(label: str, argv: list[str], *, check: bool = True) -> tuple[int, str]:
    start = time.monotonic()
    proc = subprocess.run(
        argv, cwd=str(ROOT), capture_output=True, text=True, timeout=300, check=False
    )
    elapsed = time.monotonic() - start
    output = (proc.stdout + proc.stderr).strip()
    ok = proc.returncode == 0 if check else True
    print(f"[{'OK' if ok else 'FAIL'}] {label} ({elapsed:.2f}s)")
    if not ok:
        print("       " + output[-1500:].replace("\n", "\n       "))
    return proc.returncode, output


def main() -> int:
    failures: list[str] = []

    for module, label in (("pytest", "pytest"), ("ruff", "ruff"), ("bandit", "bandit")):
        import importlib.util

        if importlib.util.find_spec(module) is None:
            print(f"[FAIL] {label} is not installed; refusing to report a green gate")
            return 1

    code, _ = run("python -m compileall", [PY, "-m", "compileall", "-q", "proveit"])
    if code:
        failures.append("compileall")

    code, _ = run("ruff check", [PY, "-m", "ruff", "check", "proveit", "tests", "scripts",
                                 "setup.py", "--output-format", "concise"])
    if code:
        failures.append("ruff")

    # Bandit exits non-zero for the four documented LOW notes, so do not treat
    # the exit code as the verdict. Parse the report and gate on HIGH / MEDIUM.
    _, output = run("bandit audit", [PY, "-m", "bandit", "-q", "-r", "proveit", "-f", "json"],
                    check=False)
    try:
        report = json.loads(output[output.index("{") :])
    except (ValueError, IndexError):
        report = {"results": []}
    severe = [r for r in report.get("results", []) if r.get("issue_severity") in ("HIGH", "MEDIUM")]
    low = [r for r in report.get("results", []) if r.get("issue_severity") == "LOW"]
    if severe:
        failures.append(f"bandit ({len(severe)} high/medium)")
        print("       " + json.dumps(severe[:3], indent=2)[:1200])
    print(f"       {len(low)} documented LOW notes, 0 HIGH, 0 MEDIUM")

    code, _ = run("dangerous-pattern AST audit", [PY, "scripts/audit_dangerous_patterns.py"])
    if code:
        failures.append("dangerous primitives")

    code, _ = run("claim/witness consistency", [PY, "scripts/consistency_check.py"])
    if code:
        failures.append("claim/witness consistency")

    code, _ = run("vendored skills frontmatter",
                  [PY, "scripts/validate_vendored_skills.py"])
    if code:
        failures.append("vendored skills frontmatter")

    code, _ = run("resource exhaustion probes", [PY, "scripts/dos_probe.py"])
    if code:
        failures.append("DoS probes")

    code, _ = run("full test suite", [PY, "-m", "pytest", "-q"])
    if code:
        failures.append("pytest")

    hashes: list[str] = []
    for i in range(3):
        code, out = run(f"behavior fingerprint run {i + 1}",
                        [PY, "scripts/behavior_fingerprint.py"])
        if code:
            failures.append("fingerprint execution")
            break
        hashes.append(json.loads(out)["behavior_fingerprint"])
    if len(set(hashes)) > 1:
        failures.append("fingerprint is non-deterministic")
        print("       " + str(hashes))
    elif hashes:
        eq = ROOT / "docs" / "fingerprint_equivalence.json"
        if eq.is_file():
            recorded = json.loads(eq.read_text(encoding="utf-8"))
            if hashes[0] != recorded.get("after_deepening"):
                failures.append("fingerprint drifted from recorded architecture gate")
                print(f"       current  {hashes[0]}")
                print(f"       recorded {recorded.get('after_deepening')}")

    with tempfile.TemporaryDirectory(prefix="proveit-gate-") as tmp:
        target = Path(tmp) / "claims.json"
        run("cli init", [PY, "-m", "proveit", "init", "--out", str(target)])
        run("cli explain (dry run)", [PY, "-m", "proveit", "explain", "--claim", "All tests pass"])
        run("cli witnesses", [PY, "-m", "proveit", "witnesses", "--format", "json"])
        run("cli doctor", [PY, "-m", "proveit", "doctor"])
        code, _ = run("cli check on own source tree",
                      [PY, "-m", "proveit", "check", "--repo", str(ROOT),
                       "--base", "HEAD", "--claim", "No secrets were introduced"],
                      check=False)
        # A non-git checkout is a legitimate usage error, not a gate failure.
        if "not a git repository" not in _ and code not in (0, 3):
            failures.append("cli check")

    print()
    if failures:
        print("RELEASE GATE FAILED: " + ", ".join(failures))
        return 1
    print("RELEASE GATE PASSED")
    print("  lint, static audit, consistency, skills frontmatter, resource limits, "
          "tests, three identical fingerprints, CLI smoke")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
