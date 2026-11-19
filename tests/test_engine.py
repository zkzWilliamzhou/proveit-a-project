from pathlib import Path

import pytest

from proveit.claims import claims_from_manifest
from proveit.engine import build_context, claims_from_receipt, evaluate
from proveit.errors import UsageError
from proveit.model import FAIL, PASS, UNVERIFIABLE
from proveit.witnesses import get


def _claims(*items):
    return claims_from_manifest({"claims": [
        {"id": f"C{i + 1}", "statement": kind, "kind": kind, "params": params, "source": "manifest"}
        for i, (kind, params) in enumerate(items)
    ]})


def test_all_pass(repo: Path):
    ctx = build_context(str(repo), "HEAD", False)
    receipt = evaluate(_claims(("no_secrets", {}), ("no_new_dependencies", {})), ctx)
    assert receipt.summary["overall"] == PASS
    assert receipt.summary["claim_coverage"] == 1.0


def test_fail_when_contradicted(repo: Path):
    (repo / "requirements.txt").write_text("foo==9\n", encoding="utf-8")
    ctx = build_context(str(repo), "HEAD", False)
    receipt = evaluate(_claims(("no_new_dependencies", {})), ctx)
    assert receipt.summary["overall"] == FAIL
    assert receipt.verdicts[0].reason_code == "DEPENDENCY_MANIFEST_CHANGED"


def test_unverifiable_is_first_class(repo: Path):
    ctx = build_context(str(repo), "HEAD", False)
    receipt = evaluate(_claims(("production_ready", {}), ("tests_pass", {})), ctx)
    assert receipt.summary["overall"] == UNVERIFIABLE
    codes = {v.reason_code for v in receipt.verdicts}
    assert "NO_SOUND_WITNESS" in codes and "TRUST_REQUIRED" in codes


def test_fail_closed_on_unexpected_exception(repo: Path):
    witness = get("git.clean")
    original = witness.fn

    def boom(ctx, params):
        raise RuntimeError("simulated witness crash")

    object.__setattr__(witness, "fn", boom)
    try:
        ctx = build_context(str(repo), "HEAD", False)
        receipt = evaluate(_claims(("clean_worktree", {})), ctx)
    finally:
        object.__setattr__(witness, "fn", original)
    assert receipt.summary["overall"] == UNVERIFIABLE
    assert receipt.verdicts[0].witnesses[0].reason_code == "INTERNAL_ERROR"
    assert receipt.verdicts[0].witnesses[0].status == UNVERIFIABLE


def test_unknown_kind_abstains(repo: Path):
    ctx = build_context(str(repo), "HEAD", False)
    receipt = evaluate(_claims(("totally_made_up", {})), ctx)
    assert receipt.verdicts[0].reason_code == "UNRECOGNIZED_CLAIM_KIND"


def test_no_claims_is_usage_error(repo: Path):
    with pytest.raises(UsageError):
        evaluate([], build_context(str(repo), "HEAD", False))


def test_redaction_is_applied_and_recorded(repo: Path):
    from proveit.model import Claim

    # An agent transcript can carry a credential into the receipt. Redaction
    # must run on the structured body, not just the terminal renderer.
    claims = [Claim("C1", "token = abcdefghijklmnop", "no_secrets", {}, "cli")]
    ctx = build_context(str(repo), "HEAD", False)
    receipt = evaluate(claims, ctx)
    assert receipt.redaction["applied"] is True
    assert receipt.redaction["total"] >= 1
    assert "abcdefghijklmnop" not in str(receipt.to_dict())


def test_claims_round_trip_through_receipt(repo: Path):
    ctx = build_context(str(repo), "HEAD", False)
    receipt = evaluate(_claims(("no_secrets", {}), ("only_changed_files", {"files": ["app.py"]})), ctx)
    back = claims_from_receipt(receipt.to_dict())
    assert len(back) == 2
    assert back[1].params["files"] == ["app.py"]


def test_policy_flags_are_recorded(repo: Path):
    ctx = build_context(str(repo), "HEAD", False)
    receipt = evaluate(_claims(("no_secrets", {})), ctx)
    assert receipt.policy["no_llm_judgement"] is True
    assert receipt.policy["arbitrary_commands_allowed"] is False
