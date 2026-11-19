"""Read agent transcripts from any harness without executing their contents."""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..errors import InputError, LimitExceeded, PolicyViolation
from ..limits import MAX_LINE_CHARS, MAX_TRANSCRIPT_BYTES, MAX_TRANSCRIPT_LINES
from ..security.paths import decode


def read_external_bytes(path: str | Path, cap: int = MAX_TRANSCRIPT_BYTES) -> bytes:
    p = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(p, flags)
    except OSError as exc:
        raise InputError(f"cannot read transcript: {exc}") from exc
    try:
        if os.fstat(fd).st_size > cap:
            raise LimitExceeded(f"transcript exceeds {cap} bytes")
        chunks: list[bytes] = []
        total = 0
        while total <= cap:
            block = os.read(fd, min(65_536, cap - total + 1))
            if not block:
                break
            total += len(block)
            if total > cap:
                raise LimitExceeded(f"transcript exceeds {cap} bytes")
            chunks.append(block)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _content_text(node: object) -> str:
    """Extract plain text from a small, closed set of known shapes only."""
    if isinstance(node, str):
        return node[:MAX_LINE_CHARS]
    if isinstance(node, list):
        parts: list[str] = []
        for item in node[:64]:
            if isinstance(item, dict) and item.get("type") == "text":
                value = item.get("text")
                if isinstance(value, str):
                    parts.append(value[:MAX_LINE_CHARS])
        return "\n".join(parts)
    return ""


def _jsonl_text(raw: bytes) -> str:
    lines = raw.split(b"\n")
    if len(lines) > MAX_TRANSCRIPT_LINES:
        raise LimitExceeded("transcript has too many lines")
    parts: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            obj = json.loads(line.decode("utf-8", errors="strict")[: MAX_LINE_CHARS * 4])
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(obj, dict):
            continue
        message = obj.get("message")
        if isinstance(message, dict):
            role = message.get("role")
            if role is not None and role != "assistant":
                continue
            text = _content_text(message.get("content"))
        else:
            text = _content_text(obj.get("content")) or _content_text(obj.get("text"))
        if text:
            parts.append(text)
        if len(parts) >= MAX_TRANSCRIPT_LINES:
            break
    return "\n".join(parts)


def parse_transcript_bytes(raw: bytes, fmt: str = "auto") -> str:
    if fmt == "auto":
        stripped = raw.lstrip()
        fmt = "jsonl" if stripped.startswith(b"{") else "text"
    if fmt == "jsonl":
        return _jsonl_text(raw)
    if fmt == "text":
        return decode(raw, MAX_TRANSCRIPT_BYTES)
    raise PolicyViolation(f"unsupported transcript format: {fmt}")


def load_transcript(path: str | Path, fmt: str = "auto") -> str:
    return parse_transcript_bytes(read_external_bytes(path), fmt)
