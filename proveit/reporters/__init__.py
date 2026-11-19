"""Render an already-redacted receipt into five output formats.

One deep interface: ``render(receipt, fmt)``. Callers never learn how SARIF or
JUnit are assembled, and no reporter ever re-reads the repository. Every string
that can originate in an untrusted transcript is stripped of control characters
before it reaches a terminal, a PR comment or an XML document.
"""

from __future__ import annotations

import re
from typing import Any
from xml.sax.saxutils import escape, quoteattr

from ..errors import UsageError
from ..model import canonical_json

FORMATS = ("terminal", "json", "markdown", "sarif", "junit")

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def render(receipt: dict[str, Any], fmt: str = "terminal") -> str:
    if fmt == "terminal":
        return _terminal(receipt)
    if fmt == "json":
        return canonical_json(receipt)
    if fmt == "markdown":
        return _markdown(receipt)
    if fmt == "sarif":
        return canonical_json(_sarif(receipt))
    if fmt == "junit":
        return _junit(receipt)
    raise UsageError(f"unsupported format: {fmt}")


def _clean(value: Any, limit: int = 2000) -> str:
    """Strip terminal escapes and XML-illegal control characters."""
    text = "" if value is None else str(value)
    # Fold LF/CR/TAB to a space. A newline inside an untrusted claim statement
    # would otherwise inject a new terminal line or a new Markdown table row.
    return _CONTROL.sub(" ", text)[:limit]


def _rows(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    return [v for v in receipt.get("verdicts", []) if isinstance(v, dict)]


def _terminal(receipt: dict[str, Any]) -> str:
    summary = receipt.get("summary", {})
    repo = receipt.get("repo", {})
    lines = [
        "proveit - claim receipts",
        "receipt  " + _clean(receipt.get("receipt_id", ""))[:16],
        ("repo     " + _clean(repo.get("root_name", ""))[:64]
         + " @ " + _clean(repo.get("head", ""))[:12]
         + " (base " + _clean(repo.get("base", ""))[:32] + ")"),
        "",
    ]
    for row in _rows(receipt):
        status = _clean(row.get("status", "UNVERIFIABLE"))[:12]
        claim_id = _clean(row.get("claim_id", ""))[:32]
        statement = _clean(row.get("statement", ""))[:120]
        lines.append("[" + status + "] " + claim_id + ": " + statement)
        lines.append("         " + _clean(row.get("reason_code", ""))[:120])
        for witness in row.get("witnesses", []):
            if isinstance(witness, dict) and witness.get("status") != "PASS":
                lines.append(
                    "         - " + _clean(witness.get("name", ""))[:64]
                    + ": " + _clean(witness.get("detail", ""))[:160]
                )
    counts = summary.get("counts", {})
    lines += [
        "",
        "overall  " + _clean(summary.get("overall", "UNVERIFIABLE"))[:12],
        ("claims   " + str(counts.get("PASS", 0)) + " pass / "
         + str(counts.get("FAIL", 0)) + " fail / "
         + str(counts.get("UNVERIFIABLE", 0)) + " unverifiable"),
        ("coverage " + f"{summary.get('claim_coverage', 0.0):.0%}"
         + " (" + str(summary.get("verifiable_claim_count", 0))
         + " claims had a registered witness)"),
        "redacted " + str(receipt.get("redaction", {}).get("total", 0)) + " value(s)",
        "",
        "PASS means reproducible evidence exists. UNVERIFIABLE is a result, not an error.",
    ]
    return "\n".join(lines) + "\n"


def _markdown(receipt: dict[str, Any]) -> str:
    summary = receipt.get("summary", {})
    lines = [
        "## proveit claim receipt",
        "",
        "**Overall:** `" + _clean(summary.get("overall", "UNVERIFIABLE"))[:12] + "`  ",
        "**Claims:** " + str(summary.get("claim_count", 0)) + "  ",
        "**Evidence coverage:** " + f"{summary.get('claim_coverage', 0.0):.0%}" + "  ",
        "**Receipt:** `" + _clean(receipt.get("receipt_id", ""))[:16] + "`",
        "",
        "| Claim | Kind | Status | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for row in _rows(receipt):
        statement = _clean(row.get("statement", "")).replace("|", "\\|").replace("\n", " ")[:120]
        kind = _clean(row.get("kind", "")).replace("|", "\\|")[:64]
        status = _clean(row.get("status", ""))[:12]
        reason = _clean(row.get("reason_code", ""))[:64]
        lines.append("| " + statement + " | `" + kind + "` | `" + status + "` | `" + reason + "` |")
    lines += ["", "_PASS means reproducible evidence exists, not that the code is correct._", ""]
    return "\n".join(lines)


def _sarif(receipt: dict[str, Any]) -> dict[str, Any]:
    fallback_id = "claim.abstention"
    rules: list[dict[str, Any]] = [
        {
            "id": fallback_id,
            "name": fallback_id,
            "shortDescription": {"text": "proveit could not select an executable witness"},
        }
    ]
    seen: set[str] = {fallback_id}
    for row in _rows(receipt):
        for witness in row.get("witnesses", []):
            if isinstance(witness, dict) and witness.get("name") not in seen:
                name = _clean(witness.get("name", ""))[:128]
                seen.add(name)
                rules.append(
                    {
                        "id": name,
                        "name": name,
                        "shortDescription": {"text": "proveit witness"},
                    }
                )
    results: list[dict[str, Any]] = []
    for row in _rows(receipt):
        status = row.get("status")
        level = "error" if status == "FAIL" else "warning" if status == "UNVERIFIABLE" else "none"
        witnesses = [w for w in row.get("witnesses", []) if isinstance(w, dict)]
        rule_id = _clean(witnesses[0].get("name", fallback_id))[:128] if witnesses else fallback_id
        if rule_id not in seen:
            rule_id = fallback_id
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": _clean(
                        _clean(row.get("claim_id", ""))[:64] + ": "
                        + _clean(row.get("reason_code", ""))[:64] + " | "
                        + _clean(row.get("statement", ""))[:800]
                    )[:2000]
                },
                "properties": {
                    "claimId": _clean(row.get("claim_id", ""))[:64],
                    "status": _clean(status)[:12],
                    "reasonCode": _clean(row.get("reason_code", ""))[:64],
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "proveit",
                        "version": _clean(receipt.get("tool", {}).get("version", "1.0.0"))[:32],
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {"receiptId": _clean(receipt.get("receipt_id", ""))[:128]},
            }
        ],
    }


def _junit(receipt: dict[str, Any]) -> str:
    rows = _rows(receipt)
    counts = receipt.get("summary", {}).get("counts", {})
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        ('<testsuites name="proveit" tests="' + str(len(rows))
         + '" failures="' + str(counts.get("FAIL", 0))
         + '" skipped="' + str(counts.get("UNVERIFIABLE", 0)) + '">'),
        ('<testsuite name="claims" tests="' + str(len(rows))
         + '" failures="' + str(counts.get("FAIL", 0))
         + '" skipped="' + str(counts.get("UNVERIFIABLE", 0)) + '">'),
    ]
    for row in rows:
        cid = escape(_clean(row.get("claim_id", ""))[:128])
        kind = escape(_clean(row.get("kind", ""))[:64])
        statement = escape(_clean(row.get("statement", ""))[:200])
        attrs = "name=" + quoteattr(cid) + " classname=" + quoteattr("proveit." + kind)
        status = row.get("status")
        if status == "PASS":
            lines.append("  <testcase " + attrs + " />")
        elif status == "FAIL":
            reason = escape(_clean(row.get("reason_code", ""))[:128])
            lines.append(
                "  <testcase " + attrs + "><failure message=" + quoteattr(reason) + ">"
                + statement + "</failure></testcase>"
            )
        else:
            reason = escape(_clean(row.get("reason_code", ""))[:128])
            lines.append(
                "  <testcase " + attrs + "><skipped message=" + quoteattr(reason)
                + " /></testcase>"
            )
    lines += ["</testsuite>", "</testsuites>", ""]
    return "\n".join(lines)
