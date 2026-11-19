"""A closed registry of witnesses.

Registration happens only at import time from ``builtin.py``. There is no
plugin loading, no entry-point scanning, and no dynamic import: a repository
cannot add a witness by dropping a file into the checkout.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from ..context import Context
from ..errors import PolicyViolation
from ..limits import MAX_EVIDENCE_CHARS
from ..model import WitnessResult

WitnessFn = Callable[[Context, dict[str, Any]], WitnessResult]


@dataclass(frozen=True)
class Witness:
    name: str
    description: str
    fn: WitnessFn
    trust_required: bool
    required_params: tuple[str, ...]
    caveat: str


_REGISTRY: dict[str, Witness] = {}


def register(
    name: str,
    description: str,
    *,
    trust: bool = False,
    required: tuple[str, ...] = (),
    caveat: str = "",
):
    def decorator(fn: WitnessFn) -> WitnessFn:
        if name in _REGISTRY:
            raise RuntimeError(f"duplicate witness registration: {name}")
        _REGISTRY[name] = Witness(
            name=name,
            description=description,
            fn=fn,
            trust_required=trust,
            required_params=required,
            caveat=caveat,
        )
        return fn

    return decorator


def get(name: str) -> Witness:
    if not isinstance(name, str) or name not in _REGISTRY:
        raise PolicyViolation(f"unknown witness: {name!r}")
    return _REGISTRY[name]


def all_witnesses() -> tuple[Witness, ...]:
    return tuple(_REGISTRY[key] for key in sorted(_REGISTRY))


def describe() -> list[dict[str, Any]]:
    return [
        {
            "name": w.name,
            "description": w.description,
            "trust_required": w.trust_required,
            "required_params": list(w.required_params),
            "caveat": w.caveat,
        }
        for w in all_witnesses()
    ]


def result(
    name: str,
    status: str,
    reason_code: str,
    detail: str,
    evidence: dict[str, Any] | None = None,
    started: float | None = None,
) -> WitnessResult:
    safe_evidence = evidence or {}
    return WitnessResult(
        name=name,
        status=status,
        reason_code=reason_code,
        detail=detail[:MAX_EVIDENCE_CHARS],
        evidence={k: _clip(v) for k, v in list(safe_evidence.items())[:32]},
        duration_ms=0 if started is None else int((time.monotonic() - started) * 1000),
    )


def _clip(value: Any) -> Any:
    if isinstance(value, str):
        return value[:MAX_EVIDENCE_CHARS]
    if isinstance(value, (list, tuple)):
        return [_clip(v) for v in list(value)[:128]]
    if isinstance(value, dict):
        return {str(k)[:64]: _clip(v) for k, v in list(value.items())[:64]}
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:MAX_EVIDENCE_CHARS]
