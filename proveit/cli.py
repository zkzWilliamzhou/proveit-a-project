"""Command line interface.

Exit codes are part of the contract: 0 all claims verified, 1 a claim was
falsified, 2 at least one claim is unverifiable, 3 operator or policy error.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .adapters import parse_transcript_bytes, read_external_bytes
from .claims import claims_from_cli, claims_from_manifest, normalize, plan_for
from .engine import build_context, evaluate
from .errors import ProveitError, UsageError
from .model import FAIL, UNVERIFIABLE, canonical_json
from .receipt import load_receipt, replay, write_receipt
from .reporters import FORMATS, render
from .security.policy import load_config_bytes, load_manifest_bytes
from .witnesses import describe

_TEMPLATE: dict[str, Any] = {
    "version": 1,
    "claims": [
        {"id": "C1", "statement": "I only touched src/app.py", "kind": "only_changed_files",
         "params": {"files": ["src/app.py"]}},
        {"id": "C2", "statement": "No secrets were introduced", "kind": "no_secrets"},
        {"id": "C3", "statement": "All tests pass", "kind": "tests_pass"},
        {"id": "C4", "statement": "The change is backward compatible",
         "kind": "backward_compatible"},
        {"id": "C5", "statement": "I fixed the bug", "kind": "bug_fixed"},
    ],
}


def _write_text(path: str | Path, text: str, *, exclusive: bool = False) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= os.O_EXCL if exclusive else os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(target, flags, 0o644)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(target)
        raise


def _load_config(repo: str, explicit: str | None) -> dict[str, Any]:
    if explicit:
        return load_config_bytes(read_external_bytes(explicit))
    candidate = Path(repo) / ".proveit.json"
    if candidate.is_file():
        return load_config_bytes(read_external_bytes(candidate))
    return {"version": 1}


def _collect_claims(args: argparse.Namespace) -> tuple[list[Any], str, str]:
    from .model import Claim

    claims: list[Claim] = []
    transcript_hash, manifest_hash = "", ""
    if args.manifest:
        raw = read_external_bytes(args.manifest)
        manifest_hash = hashlib.sha256(raw).hexdigest()
        claims.extend(claims_from_manifest(load_manifest_bytes(raw)))
    if args.transcript:
        raw = read_external_bytes(args.transcript)
        transcript_hash = hashlib.sha256(raw).hexdigest()
        text = parse_transcript_bytes(raw, args.transcript_format)
        claims.extend(claims_from_cli(text))
    for statement in args.claim or []:
        claims.extend(claims_from_cli(statement))
    if not claims:
        raise UsageError("no claims supplied. Use --claim, --transcript, --manifest, or run `proveit init`.")
    return normalize(claims), transcript_hash, manifest_hash


def _cmd_check(args: argparse.Namespace) -> int:
    config = _load_config(args.repo, args.config)
    base = args.base or config.get("base", "HEAD")
    claims, transcript_hash, manifest_hash = _collect_claims(args)
    ctx = build_context(args.repo, base, args.trust_tests, config)
    receipt = evaluate(claims, ctx, transcript_hash=transcript_hash, manifest_hash=manifest_hash)
    body = receipt.to_dict()
    report = render(body, args.format)
    if args.out:
        _write_text(args.out, report)
    else:
        sys.stdout.write(report)
    if args.receipt:
        write_receipt(body, args.receipt)
    overall = body["summary"]["overall"]
    if overall == FAIL:
        return 1
    if overall == UNVERIFIABLE:
        return 1 if args.strict else 2
    return 0


def _cmd_explain(args: argparse.Namespace) -> int:
    claims, _, _ = _collect_claims(args)
    rows = []
    for claim in claims:
        outcome = plan_for(claim.kind, claim.params)
        rows.append(
            {
                "claim_id": claim.id,
                "statement": claim.text,
                "kind": claim.kind,
                "witnesses": [s.to_dict() for s in outcome.specs],
                "abstention": outcome.reason_code,
                "note": outcome.note,
                "executes_nothing": True,
            }
        )
    sys.stdout.write(canonical_json({"dry_run": True, "claims": rows}) + "\n")
    return 0


def _cmd_witnesses(args: argparse.Namespace) -> int:
    items = describe()
    if args.format == "json":
        sys.stdout.write(canonical_json({"witnesses": items}) + "\n")
    else:
        for item in items:
            trust = " [opt-in]" if item["trust_required"] else ""
            sys.stdout.write(f"{item['name']}{trust}\n    {item['description']}\n")
            if item["caveat"]:
                sys.stdout.write(f"    caveat: {item['caveat']}\n")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.out or "proveit.claims.json")
    if target.exists():
        raise UsageError(f"refusing to overwrite existing file: {target}")
    _write_text(target, json.dumps(_TEMPLATE, indent=2) + "\n", exclusive=True)
    sys.stdout.write(
        f"wrote {target}\n"
        f"try: proveit check --manifest {target} --base HEAD~1 --format markdown\n"
        "note: --trust-tests is required for witnesses that execute repository tests.\n"
    )
    return 0


def _cmd_replay(args: argparse.Namespace) -> int:
    doc = load_receipt(args.receipt)
    config = _load_config(args.repo, args.config)
    base = args.base or doc.get("repo", {}).get("base") or config.get("base", "HEAD")
    ctx = build_context(args.repo, base, args.trust_tests, config)
    outcome = replay(doc, ctx, execute=args.execute)
    sys.stdout.write(canonical_json(outcome) + "\n")
    return 0 if outcome["freshness"]["status"] == "CURRENT" and not outcome.get("verdict_drift") else 2


def _cmd_doctor(args: argparse.Namespace) -> int:
    info = {
        "proveit": __version__,
        "python": platform.python_version(),
        "platform": platform.system(),
        "git": shutil.which("git"),
        "pytest_available": importlib.util.find_spec("pytest") is not None,
        "ruff": shutil.which("ruff"),
        "trust_tests_default": False,
        "arbitrary_commands_allowed": False,
    }
    sys.stdout.write(canonical_json(info) + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proveit",
        description="Claim receipts for AI coding agents. No model judges a model.",
    )
    parser.add_argument("--version", action="version", version=f"proveit {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="compile claims into witnesses and issue a receipt")
    check.add_argument("--repo", default=".", help="git checkout to inspect (default: .)")
    check.add_argument("--base", default=None, help="base git ref (default: config, then HEAD)")
    check.add_argument("--config", default=None, help="path to .proveit.json")
    check.add_argument("--claim", action="append", help="a claim string; repeatable")
    check.add_argument("--transcript", default=None, help="agent transcript (text or JSONL)")
    check.add_argument("--transcript-format", default="auto", choices=("auto", "text", "jsonl"))
    check.add_argument("--manifest", default=None, help="strict JSON claim manifest")
    check.add_argument("--format", default="terminal", choices=FORMATS)
    check.add_argument("--out", default=None, help="write the report to this file")
    check.add_argument("--receipt", default=None, help="write the canonical receipt JSON here")
    check.add_argument("--trust-tests", action="store_true",
                        help="opt in to witnesses that execute repository test code")
    check.add_argument("--strict", action="store_true",
                        help="exit 1 instead of 2 when any claim is unverifiable")
    check.set_defaults(func=_cmd_check)

    explain = sub.add_parser("explain", help="show the plan without executing anything")
    explain.add_argument("--claim", action="append")
    explain.add_argument("--transcript", default=None)
    explain.add_argument("--transcript-format", default="auto", choices=("auto", "text", "jsonl"))
    explain.add_argument("--manifest", default=None)
    explain.add_argument("--config", default=None)
    explain.add_argument("--base", default=None)
    explain.add_argument("--repo", default=".")
    explain.set_defaults(func=_cmd_explain)

    witnesses = sub.add_parser("witnesses", help="list the closed witness registry")
    witnesses.add_argument("--format", default="terminal", choices=("terminal", "json"))
    witnesses.set_defaults(func=_cmd_witnesses)

    init = sub.add_parser("init", help="write a starter claim manifest")
    init.add_argument("--out", default=None)
    init.set_defaults(func=_cmd_init)

    replay_cmd = sub.add_parser("replay", help="check a receipt for staleness and drift")
    replay_cmd.add_argument("receipt")
    replay_cmd.add_argument("--repo", default=".")
    replay_cmd.add_argument("--base", default=None)
    replay_cmd.add_argument("--config", default=None)
    replay_cmd.add_argument("--execute", action="store_true", help="re-run the plan")
    replay_cmd.add_argument("--trust-tests", action="store_true")
    replay_cmd.set_defaults(func=_cmd_replay)

    doctor = sub.add_parser("doctor", help="report the local runner environment")
    doctor.set_defaults(func=_cmd_doctor)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ProveitError as exc:
        if os.environ.get("PROVEIT_DEBUG") == "1":
            raise
        sys.stderr.write(f"proveit: {type(exc).__name__}: {exc}\n")
        return 3
    except (OSError, ValueError, TypeError) as exc:
        if os.environ.get("PROVEIT_DEBUG") == "1":
            raise
        sys.stderr.write(f"proveit: {type(exc).__name__}: {str(exc)[:300]}\n")
        return 3
