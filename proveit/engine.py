"""Plan compilation, witness execution and verdict aggregation.

The engine never upgrades an error into PASS. FAIL is reserved for evidence that
contradicts a claim; every other uncertainty becomes UNVERIFIABLE with a reason
code a human can act on.
"""

from __future__ import annotations

import hashlib
import platform
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .claims.grammar import plan_for
from .claims.normalizer import normalize
from .context import Context
from .errors import (
    ExecutionError,
    InputError,
    LimitExceeded,
    PolicyViolation,
    ProveitError,
    UsageError,
    WitnessUnavailable,
)
from .gitstate import GitState
from .limits import LIMITS_SNAPSHOT
from .model import FAIL, PASS, UNVERIFIABLE, Claim, ClaimVerdict, Receipt, WitnessResult, canonical_json
from .security.paths import canonical_root
from .security.redaction import redact_receipt
from .witnesses import get

SCHEMA_VERSION = "1.0"


def build_context(
    root: str,
    base: str,
    trust_tests: bool,
    config: dict[str, Any] | None = None,
) -> Context:
    canonical = canonical_root(root)
    git = GitState(canonical, base)
    if not git.is_repo():
        raise UsageError(f"not a git repository: {canonical}")
    return Context(
        root=canonical,
        git=git,
        base=git.base,
        trust_tests=bool(trust_tests),
        config=config or {},
    )


def _exception_result(name: str, exc: BaseException) -> WitnessResult:
    if isinstance(exc, PolicyViolation):
        code = "POLICY_BLOCKED"
    elif isinstance(exc, LimitExceeded):
        code = "LIMIT_EXCEEDED"
    elif isinstance(exc, WitnessUnavailable):
        code = "TOOL_UNAVAILABLE"
    elif isinstance(exc, InputError):
        code = "INVALID_PARAMETERS"
    elif isinstance(exc, ExecutionError):
        code = "EXECUTION_ERROR"
    else:
        code = "INTERNAL_ERROR"
    return WitnessResult(
        name=name,
        status=UNVERIFIABLE,
        reason_code=code,
        detail=f"{type(exc).__name__}: {str(exc)[:400]}",
        evidence={},
        duration_ms=0,
    )


def _aggregate(results: list[WitnessResult]) -> tuple[str, str]:
    if any(r.status == FAIL for r in results):
        first = next(r for r in results if r.status == FAIL)
        return FAIL, first.reason_code
    if any(r.status != PASS for r in results):
        first = next(r for r in results if r.status != PASS)
        return UNVERIFIABLE, first.reason_code
    return PASS, "OK"


def _repo_facts(ctx: Context) -> dict[str, Any]:
    try:
        head = ctx.git.head()
    except (ProveitError, OSError, ValueError, RuntimeError):
        head = "unknown"
    try:
        diff_hash = ctx.git.diff_hash()
    except (ProveitError, OSError, ValueError, RuntimeError):
        diff_hash = "unavailable"
    return {
        "root_name": ctx.root.name,
        "head": head,
        "base": ctx.base,
        "base_available": ctx.git.base_exists(),
        "diff_hash": diff_hash,
    }


def evaluate(
    claims: list[Claim],
    ctx: Context,
    *,
    transcript_hash: str = "",
    manifest_hash: str = "",
) -> Receipt:
    claims = normalize(claims)
    if not claims:
        raise UsageError("no claims to evaluate")

    plan: list[dict[str, Any]] = []
    verdicts: list[ClaimVerdict] = []

    for claim in claims:
        outcome = plan_for(claim.kind, claim.params)
        plan.append(
            {
                "claim_id": claim.id,
                "kind": claim.kind,
                "witnesses": [spec.to_dict() for spec in outcome.specs],
                "abstention": outcome.reason_code,
                "note": outcome.note,
            }
        )
        if outcome.reason_code is not None:
            verdicts.append(
                ClaimVerdict(claim.id, claim.text, claim.kind, UNVERIFIABLE,
                             outcome.reason_code, ())
            )
            continue

        results: list[WitnessResult] = []
        for spec in outcome.specs:
            try:
                witness = get(spec.name)
            except PolicyViolation as exc:
                results.append(_exception_result(spec.name, exc))
                continue
            if (witness.trust_required or spec.trust_required) and not ctx.trust_tests:
                results.append(
                    WitnessResult(
                        name=spec.name,
                        status=UNVERIFIABLE,
                        reason_code="TRUST_REQUIRED",
                        detail="This witness executes repository code. Re-run with --trust-tests.",
                    )
                )
                continue
            try:
                results.append(witness.fn(ctx, spec.params))
            except Exception as exc:  # noqa: BLE001 - fail closed: never PASS, never silently drop
                results.append(_exception_result(spec.name, exc))

        status, reason = _aggregate(results)
        verdicts.append(ClaimVerdict(claim.id, claim.text, claim.kind, status, reason, tuple(results)))

    counts = {PASS: 0, FAIL: 0, UNVERIFIABLE: 0}
    for verdict in verdicts:
        counts[verdict.status] += 1
    if counts[FAIL]:
        overall = FAIL
    elif counts[UNVERIFIABLE]:
        overall = UNVERIFIABLE
    else:
        overall = PASS
    verifiable = sum(1 for p in plan if not p["abstention"])
    summary = {
        "overall": overall,
        "claim_count": len(claims),
        "counts": counts,
        "claim_coverage": round(counts[PASS] / len(claims), 4),
        "verifiable_claim_count": verifiable,
        "evidence_coverage": round(counts[PASS] / verifiable, 4) if verifiable else 0.0,
        "note": "PASS means reproducible evidence exists, not that the code is correct.",
    }

    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": {
            "name": "proveit",
            "version": __version__,
            "python": platform.python_version(),
            "platform": platform.system(),
        },
        "repo": _repo_facts(ctx),
        "inputs": {
            "transcript_sha256": transcript_hash,
            "manifest_sha256": manifest_hash,
            "claims": [c.to_dict() for c in claims],
        },
        "plan": plan,
        "verdicts": [v.to_dict() for v in verdicts],
        "summary": summary,
        "redaction": {"applied": False, "total": 0, "by_kind": {}},
        "policy": {
            "trust_tests": ctx.trust_tests,
            "limits": LIMITS_SNAPSHOT,
            "no_llm_judgement": True,
            "arbitrary_commands_allowed": False,
        },
    }
    cleaned, redaction_report = redact_receipt(body)
    cleaned["redaction"] = redaction_report
    receipt_id = hashlib.sha256(canonical_json(cleaned).encode("utf-8")).hexdigest()
    return Receipt(
        schema_version=SCHEMA_VERSION,
        receipt_id=receipt_id,
        created_at=str(cleaned["created_at"]),
        tool=dict(cleaned["tool"]),
        repo=dict(cleaned["repo"]),
        inputs=dict(cleaned["inputs"]),
        plan=tuple(dict(p) for p in cleaned["plan"]),
        verdicts=_rebuild_verdicts(cleaned["verdicts"]),
        summary=dict(cleaned["summary"]),
        redaction=dict(cleaned["redaction"]),
        policy=dict(cleaned["policy"]),
    )


def _rebuild_verdicts(raw: list[dict[str, Any]]) -> tuple[ClaimVerdict, ...]:
    out: list[ClaimVerdict] = []
    for item in raw:
        witnesses = tuple(
            WitnessResult(
                name=w.get("name", ""),
                status=w.get("status", UNVERIFIABLE),
                reason_code=w.get("reason_code", "INTERNAL_ERROR"),
                detail=w.get("detail", ""),
                evidence=dict(w.get("evidence", {})),
                duration_ms=int(w.get("duration_ms", 0)),
            )
            for w in item.get("witnesses", [])
        )
        out.append(
            ClaimVerdict(
                claim_id=str(item.get("claim_id", "")),
                statement=str(item.get("statement", "")),
                kind=str(item.get("kind", "")),
                status=str(item.get("status", UNVERIFIABLE)),
                reason_code=str(item.get("reason_code", "INTERNAL_ERROR")),
                witnesses=witnesses,
            )
        )
    return tuple(out)


def claims_from_receipt(receipt: dict[str, Any]) -> list[Claim]:
    out: list[Claim] = []
    for raw in receipt.get("inputs", {}).get("claims", []):
        if not isinstance(raw, dict):
            continue
        out.append(
            Claim(
                id=str(raw.get("id", ""))[:64],
                text=str(raw.get("text", ""))[:512],
                kind=str(raw.get("kind", "unrecognized"))[:64],
                params=dict(raw.get("params", {})),
                source=str(raw.get("source", "manifest")),
            )
        )
    return out
