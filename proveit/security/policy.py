"""Strict JSON policy loader.

proveit deliberately accepts JSON only. YAML tags, ``eval``, ``pickle``, plugin
paths and repo-supplied commands are all deserialization or code-execution
surfaces (CWE-502 / CWE-94). A declarative rule is data, never behaviour.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..errors import InputError, LimitExceeded, PolicyViolation
from ..limits import (
    MAX_CLAIM_CHARS,
    MAX_CLAIMS,
    MAX_CONFIG_BYTES,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    MAX_LIST_ITEMS,
    MAX_MANIFEST_BYTES,
    MAX_PARAM_STR,
    MAX_PARAMS,
)

_FORBIDDEN_KEYS = {
    "command", "cmd", "shell", "exec", "execute", "plugin", "plugins",
    "module", "import", "eval", "code", "script", "loader", "pickle",
    "regex", "pattern", "env", "environment", "preexec", "subprocess",
}
_ALLOWED_MANIFEST_KEYS = {"version", "claims"}
_ALLOWED_CLAIM_KEYS = {"id", "statement", "kind", "params"}
_ALLOWED_CONFIG_KEYS = {"version", "base", "deny_paths", "max_diff_lines"}
_KIND = re.compile(r"\A[a-z0-9_.]{1,64}\Z")


def _reject_constant(value: str) -> None:
    raise InputError(f"non-finite JSON constant is not allowed: {value}")


def _check_shape(node: Any, depth: int, counter: list[int]) -> None:
    if depth > MAX_JSON_DEPTH:
        raise LimitExceeded("JSON nesting too deep")
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES:
        raise LimitExceeded("JSON document too large in node count")
    if isinstance(node, dict):
        if len(node) > 512:
            raise LimitExceeded("too many object keys")
        for key, value in node.items():
            if not isinstance(key, str):
                raise InputError("object keys must be strings")
            if key.strip().lower() in _FORBIDDEN_KEYS:
                raise PolicyViolation(f"forbidden key in policy document: {key}")
            _check_shape(value, depth + 1, counter)
    elif isinstance(node, list):
        if len(node) > MAX_LIST_ITEMS:
            raise LimitExceeded("too many list items")
        for item in node:
            _check_shape(item, depth + 1, counter)
    elif isinstance(node, str):
        if len(node) > MAX_PARAM_STR * 4:
            raise LimitExceeded("string value too long")
    elif isinstance(node, bool) or node is None or isinstance(node, int):
        return
    elif isinstance(node, float):
        raise InputError("floating point values are not allowed in policy documents")
    else:
        raise InputError("unsupported JSON value type")


def _parse(data: bytes, cap: int, label: str) -> dict[str, Any]:
    if len(data) > cap:
        raise LimitExceeded(f"{label} exceeds {cap} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"{label} is not valid UTF-8") from exc
    try:
        doc = json.loads(text, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise InputError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise InputError(f"{label} must be a JSON object")
    _check_shape(doc, 0, [0])
    return doc


def _string(value: Any, label: str, cap: int = MAX_PARAM_STR) -> str:
    if not isinstance(value, str) or not value or len(value) > cap:
        raise InputError(f"{label} must be a non-empty string of at most {cap} chars")
    return value


def load_manifest_bytes(data: bytes) -> dict[str, Any]:
    doc = _parse(data, MAX_MANIFEST_BYTES, "claim manifest")
    unknown = set(doc) - _ALLOWED_MANIFEST_KEYS
    if unknown:
        raise PolicyViolation(f"unknown manifest keys: {sorted(unknown)}")
    version = doc.get("version", 1)
    if version != 1 or not isinstance(version, int):
        raise InputError("manifest version must be the integer 1")
    raw_claims = doc.get("claims")
    if not isinstance(raw_claims, list) or not raw_claims:
        raise InputError("manifest must contain a non-empty 'claims' array")
    if len(raw_claims) > MAX_CLAIMS:
        raise LimitExceeded("too many claims")

    claims: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_claims):
        if not isinstance(raw, dict):
            raise InputError(f"claim {i} must be an object")
        unknown = set(raw) - _ALLOWED_CLAIM_KEYS
        if unknown:
            raise PolicyViolation(f"unknown claim keys: {sorted(unknown)}")
        cid = _string(raw.get("id", f"C{i + 1}"), f"claim {i} id", 64)
        if cid in seen:
            raise InputError(f"duplicate claim id: {cid}")
        seen.add(cid)
        statement = _string(raw.get("statement"), f"claim {cid} statement", MAX_CLAIM_CHARS)
        kind = _string(raw.get("kind"), f"claim {cid} kind", 64).lower()
        if not _KIND.match(kind):
            raise InputError(f"claim {cid} has an invalid kind")
        params = raw.get("params", {})
        if not isinstance(params, dict):
            raise InputError(f"claim {cid} params must be an object")
        if len(params) > MAX_PARAMS:
            raise LimitExceeded(f"claim {cid} has too many params")
        checked: dict[str, Any] = {}
        for key, value in params.items():
            if not isinstance(key, str) or len(key) > 64:
                raise InputError(f"claim {cid} has an invalid param name")
            if key.strip().lower() in _FORBIDDEN_KEYS:
                raise PolicyViolation(f"forbidden param: {key}")
            if isinstance(value, str):
                if len(value) > MAX_PARAM_STR:
                    raise LimitExceeded(f"param {key} too long")
                checked[key] = value
            elif isinstance(value, (bool, int)):
                checked[key] = value
            elif isinstance(value, list):
                if len(value) > MAX_LIST_ITEMS:
                    raise LimitExceeded(f"param {key} has too many items")
                if not all(isinstance(v, str) and len(v) <= MAX_PARAM_STR for v in value):
                    raise InputError(f"param {key} must be a list of short strings")
                checked[key] = list(value)
            else:
                raise InputError(f"param {key} has an unsupported type")
        claims.append(
            {"id": cid, "statement": statement, "kind": kind, "params": checked, "source": "manifest"}
        )
    return {"version": 1, "claims": claims}


def load_config_bytes(data: bytes) -> dict[str, Any]:
    doc = _parse(data, MAX_CONFIG_BYTES, "config")
    unknown = set(doc) - _ALLOWED_CONFIG_KEYS
    if unknown:
        raise PolicyViolation(f"unknown config keys: {sorted(unknown)}")
    if doc.get("version", 1) != 1:
        raise InputError("config version must be the integer 1")
    out: dict[str, Any] = {"version": 1}
    if "base" in doc:
        out["base"] = _string(doc["base"], "base", 128)
    if "deny_paths" in doc:
        value = doc["deny_paths"]
        if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
            raise InputError("deny_paths must be a short list")
        if not all(isinstance(v, str) and len(v) <= MAX_PARAM_STR for v in value):
            raise InputError("deny_paths must contain short strings")
        out["deny_paths"] = list(value)
    if "max_diff_lines" in doc:
        value = doc["max_diff_lines"]
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 1_000_000:
            raise InputError("max_diff_lines must be a bounded non-negative integer")
        out["max_diff_lines"] = value
    return out
