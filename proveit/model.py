"""Core value objects.

Everything is a frozen dataclass of primitives so a receipt can be hashed
deterministically. Paths, file handles and subprocess objects never enter the
model; they stay in the execution context.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

PASS = "PASS"
FAIL = "FAIL"
UNVERIFIABLE = "UNVERIFIABLE"

STATUS_ORDER = {FAIL: 0, UNVERIFIABLE: 1, PASS: 2}


def canonical_json(value: Any) -> str:
    """Stable serialization used for all content addressing."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Claim:
    id: str
    text: str
    kind: str
    params: dict[str, Any] = field(default_factory=dict)
    source: str = "cli"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WitnessSpec:
    name: str
    params: dict[str, Any]
    trust_required: bool
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class WitnessResult:
    name: str
    status: str
    reason_code: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ClaimVerdict:
    claim_id: str
    statement: str
    kind: str
    status: str
    reason_code: str
    witnesses: tuple[WitnessResult, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        # asdict preserves tuples; JSON does not. Keep the receipt JSON-native so
        # render(..., "json") round-trips exactly.
        payload["witnesses"] = [w for w in payload["witnesses"]]
        return payload


@dataclass(frozen=True)
class Receipt:
    schema_version: str
    receipt_id: str
    created_at: str
    tool: dict[str, Any]
    repo: dict[str, Any]
    inputs: dict[str, Any]
    plan: tuple[dict[str, Any], ...]
    verdicts: tuple[ClaimVerdict, ...]
    summary: dict[str, Any]
    redaction: dict[str, Any]
    policy: dict[str, Any]

    def body(self) -> dict[str, Any]:
        """Everything except the id; hashing this yields the id."""
        return {
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "tool": self.tool,
            "repo": self.repo,
            "inputs": self.inputs,
            "plan": [dict(p) for p in self.plan],
            "verdicts": [v.to_dict() for v in self.verdicts],
            "summary": self.summary,
            "redaction": self.redaction,
            "policy": self.policy,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"receipt_id": self.receipt_id, **self.body()}
