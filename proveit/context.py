"""Runtime context passed to witnesses; never serialized into a receipt."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gitstate import GitState


@dataclass(frozen=True)
class Context:
    root: Path
    git: GitState
    base: str
    trust_tests: bool
    config: dict[str, Any]
