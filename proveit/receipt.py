"""Content-addressed claim receipts.

A receipt is redacted before hashing, written atomically, and verified on load.
Replay compares the recorded repository state with the current one and can
optionally re-execute the whole plan to detect verdict drift.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from .adapters import read_external_bytes
from .context import Context
from .errors import InputError, LimitExceeded, ProveitError
from .limits import MAX_RECEIPT_BYTES, MAX_REPLAY_BYTES
from .model import canonical_json


def write_receipt(receipt: dict[str, Any], path: str | Path) -> None:
    data = canonical_json(receipt).encode("utf-8")
    if len(data) > MAX_RECEIPT_BYTES:
        raise LimitExceeded("receipt exceeds its size bound")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".proveit-", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def load_receipt(path: str | Path) -> dict[str, Any]:
    raw = read_external_bytes(path, cap=MAX_REPLAY_BYTES)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise InputError(f"receipt is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != "1.0":
        raise InputError("unsupported or missing receipt schema_version")
    recorded = doc.get("receipt_id")
    body = {k: v for k, v in doc.items() if k != "receipt_id"}
    computed = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    if recorded != computed:
        raise InputError("receipt integrity check failed: content does not match receipt_id")
    return doc


def freshness(receipt: dict[str, Any], ctx: Context) -> dict[str, Any]:
    recorded = receipt.get("repo", {})
    try:
        head = ctx.git.head()
    except (ProveitError, OSError, ValueError, RuntimeError):
        head = "unknown"
    try:
        diff_hash = ctx.git.diff_hash()
    except (ProveitError, OSError, ValueError, RuntimeError):
        diff_hash = "unavailable"
    reasons = []
    if recorded.get("head") != head:
        reasons.append("HEAD changed")
    if recorded.get("diff_hash") != diff_hash:
        reasons.append("diff changed")
    if recorded.get("base") != ctx.base:
        reasons.append("base ref changed")
    return {
        "status": "CURRENT" if not reasons else "STALE",
        "reasons": reasons,
        "recorded": {"head": recorded.get("head"), "diff_hash": recorded.get("diff_hash")},
        "current": {"head": head, "diff_hash": diff_hash, "base": ctx.base},
    }


def replay(receipt: dict[str, Any], ctx: Context, execute: bool = False) -> dict[str, Any]:
    fresh = freshness(receipt, ctx)
    out: dict[str, Any] = {
        "receipt_id": receipt.get("receipt_id"),
        "created_at": receipt.get("created_at"),
        "freshness": fresh,
        "recorded_overall": receipt.get("summary", {}).get("overall"),
    }
    if not execute:
        out["note"] = "Freshness check only. Pass --execute to re-run the plan."
        return out
    from .claims import normalize
    from .claims.parser import claims_from_cli  # noqa: F401
    from .engine import claims_from_receipt, evaluate

    claims = normalize(claims_from_receipt(receipt))
    fresh_receipt = evaluate(claims, ctx).to_dict()
    old = {
        v["claim_id"]: v["status"]
        for v in receipt.get("verdicts", [])
        if isinstance(v, dict) and "claim_id" in v
    }
    new = {v["claim_id"]: v["status"] for v in fresh_receipt["verdicts"]}
    drift = [
        {"claim_id": cid, "before": status, "after": new[cid]}
        for cid, status in old.items()
        if cid in new and new[cid] != status
    ]
    out["re_executed"] = True
    out["current_overall"] = fresh_receipt["summary"]["overall"]
    out["verdict_drift"] = drift
    return out
