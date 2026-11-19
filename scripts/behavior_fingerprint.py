#!/usr/bin/env python3
"""Deterministic behavior fingerprint.

Runs a fixed battery of claim-evaluation scenarios against fresh git fixtures,
masks volatile fields (hashes, timestamps, temp paths, timings) and prints a
single SHA-256. Use it before and after a refactor: identical hash means no
observable function changed.

Usage: python3 scripts/behavior_fingerprint.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from proveit.claims import claims_from_manifest
from proveit.engine import build_context, evaluate
from proveit.model import canonical_json
from proveit.reporters import FORMATS, render

VOLATILE_KEYS = {
    "receipt_id", "created_at", "content_id", "head", "diff_hash",
    "root_name", "duration_ms", "python", "platform",
}
_HEX = re.compile(r"\b[0-9a-f]{8,64}\b")
_TS = re.compile(r"\d{4}-\d{2}-\d{2}T[0-9:+\-Z]+")
_TMP = re.compile(r"/tmp/[^\s\"'|,]+")
_SECS = re.compile(r"\b\d+\.\d+s\b")
# Rendered JSON is a *string*, so key-based masking cannot reach nested timing
# fields. Normalize them in the string too, otherwise the fingerprint drifts
# with wall-clock scheduling and cannot be used as a regression gate.
_DURATION = re.compile(r'("duration_ms"\s*:\s*)\d+')


def mask(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("<masked>" if k in VOLATILE_KEYS else mask(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [mask(v) for v in value]
    if isinstance(value, str):
        text = _TS.sub("<ts>", value)
        text = _TMP.sub("<tmp>", text)
        text = _HEX.sub("<hex>", text)
        text = _SECS.sub("<secs>", text)
        text = _DURATION.sub(r"\1<masked>", text)
        return text
    return value


def git(repo: Path, *args: str) -> None:
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="Fingerprint", GIT_AUTHOR_EMAIL="f@example.com",
        GIT_COMMITTER_NAME="Fingerprint", GIT_COMMITTER_EMAIL="f@example.com",
        GIT_AUTHOR_DATE="2020-01-01T00:00:00Z", GIT_COMMITTER_DATE="2020-01-01T00:00:00Z",
    )
    subprocess.run(["git", "-C", str(repo), *args], env=env, check=True, capture_output=True)


def fixture(variant: str) -> Path:
    repo = Path(tempfile.mkdtemp(prefix="proveit-fp-")) / "repo"
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    (repo / "app.py").write_text(
        "def public_func():\n    return 1\n\ndef helper():\n    return 2\n", encoding="utf-8"
    )
    (repo / "requirements.txt").write_text("foo==1.0\n", encoding="utf-8")
    (repo / "data.json").write_text('{"ok": true}\n', encoding="utf-8")
    (repo / "tests").mkdir()
    (repo / "tests" / "test_app.py").write_text("def test_app():\n    assert True\n", encoding="utf-8")
    git(repo, "add", ".")
    git(repo, "commit", "-q", "-m", "base")

    if variant == "secret":
        (repo / "app.py").write_text('api_key = "AKIA\x49OSFODNN7EXAMPLE"\n', encoding="utf-8")
    elif variant == "syntax":
        (repo / "app.py").write_text("def broken(:\n", encoding="utf-8")
    elif variant == "api":
        (repo / "app.py").write_text("def helper():\n    return 2\n", encoding="utf-8")
    elif variant == "changed":
        (repo / "app.py").write_text("def public_func():\n    return 9\n", encoding="utf-8")
        (repo / "tests" / "test_new.py").write_text("def test_new():\n    assert True\n", encoding="utf-8")
    return repo


def claims_for(variant: str):
    def c(cid, statement, kind, params=None):
        return {"id": cid, "statement": statement, "kind": kind,
                "params": params or {}, "source": "manifest"}

    table = {
        "clean": [
            c("C1", "no secrets", "no_secrets"),
            c("C2", "no new deps", "no_new_dependencies"),
            c("C3", "valid json", "json_valid", {"files": ["data.json"]}),
            c("C4", "app exists", "file_exists", {"path": "app.py"}),
            c("C5", "clean worktree", "clean_worktree"),
        ],
        "secret": [
            c("C1", "no secrets", "no_secrets"),
            c("C2", "syntax ok", "python_syntax_ok"),
            c("C3", "no deletions", "no_deleted_files"),
        ],
        "syntax": [
            c("C1", "syntax ok", "python_syntax_ok"),
            c("C2", "small diff", "small_diff", {"max": 100}),
        ],
        "api": [
            c("C1", "backward compatible", "backward_compatible"),
            c("C2", "no new deps", "no_new_dependencies"),
        ],
        "changed": [
            c("C1", "only these files", "only_changed_files",
              {"files": ["app.py", "tests/test_new.py"]}),
            c("C2", "tests added", "tests_added"),
            c("C3", "no forbidden paths", "no_forbidden_paths", {"deny": [".github"]}),
            c("C4", "small diff", "small_diff", {"max": 50}),
        ],
        "abstain": [
            c("C1", "production ready", "production_ready"),
            c("C2", "all tests pass", "tests_pass"),
            c("C3", "fixed the bug", "bug_fixed"),
            c("C4", "unknown thing", "made_up_kind"),
        ],
    }
    return claims_from_manifest({"claims": table[variant]})


def main() -> int:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--dump", default=None, help="write masked observations to this JSON file")
    args = parser.parse_args()
    collected: list[dict[str, Any]] = []
    for variant in ("clean", "secret", "syntax", "api", "changed", "abstain"):
        repo = fixture(variant)
        receipt = evaluate(
            claims_for(variant),
            build_context(str(repo), "HEAD", False),
        ).to_dict()
        collected.append({"variant": variant, "receipt": mask(receipt)})
        for fmt in FORMATS:
            collected.append(
                {"variant": variant, "format": fmt, "output": mask(render(receipt, fmt))}
            )
    if args.dump:
        Path(args.dump).write_text(canonical_json(collected), encoding="utf-8")
    digest = hashlib.sha256(canonical_json(collected).encode("utf-8")).hexdigest()
    print(json.dumps({
        "scenarios": 6,
        "formats_per_scenario": len(FORMATS),
        "observations": len(collected),
        "behavior_fingerprint": digest,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
