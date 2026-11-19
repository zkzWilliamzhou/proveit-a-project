"""Normalization: cap, deduplicate and fingerprint claims before planning."""

from __future__ import annotations

import hashlib

from ..errors import InputError
from ..limits import MAX_CLAIMS
from ..model import Claim, canonical_json


def normalize(claims: list[Claim]) -> list[Claim]:
    if len(claims) > MAX_CLAIMS:
        raise InputError("too many claims")
    seen: set[str] = set()
    out: list[Claim] = []
    for claim in claims:
        key = canonical_json([claim.kind, claim.params, claim.text])
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        if digest in seen:
            continue
        seen.add(digest)
        out.append(claim)
    return out
