import sys
from pathlib import Path

from proveit.security.redaction import redact_structure, redact_text
from proveit.security.runner import run_isolated


def test_secrets_are_redacted():
    text = (
        "api_key = AKIA\x49OSFODNN7EXAMPLE and "
        "ghp_\x61bcdefghijklmnopqrstuvwxyz0123456789 and "
        "-----BEGIN \x52SA PRIVATE KEY----- and dev@example.com"
    )
    out = redact_text(text)
    assert "AKIA\x49OSFODNN7EXAMPLE" not in out
    assert "ghp_\x61bcdefghijklmnopqrstuvwxyz0123456789" not in out
    assert "BEGIN RSA PRIVATE KEY" not in out
    assert "dev@example.com" not in out
    assert "[REDACTED:" in out


def test_normal_text_survives():
    assert redact_text("def public_func(): return 1") == "def public_func(): return 1"


def test_structure_counts():
    from collections import Counter

    counts: Counter = Counter()
    cleaned = redact_structure({"msg": "token = abcdefghijklmnop", "n": 3, "items": ["x", "y"]}, counts)
    assert cleaned["n"] == 3
    assert cleaned["items"] == ["x", "y"]
    assert counts.total() >= 1


def test_oversize_text_is_bounded():
    out = redact_text("a" * (3 * 1024 * 1024))
    assert len(out) < 3 * 1024 * 1024


def test_runner_happy_path(tmp_path: Path):
    res = run_isolated([sys.executable, "-c", "print('hi')"], cwd=tmp_path)
    assert res.ok and res.stdout.strip() == b"hi"


def test_runner_does_not_inherit_secrets(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "ghp_SECRETSHOULDNOTLEAK")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leaky")
    res = run_isolated(
        [sys.executable, "-c", "import os; print(os.environ.get('GH_TOKEN','NONE')); print(os.environ.get('AWS_SECRET_ACCESS_KEY','NONE'))"],
        cwd=tmp_path,
    )
    assert b"SECRETSHOULDNOTLEAK" not in res.stdout
    assert b"leaky" not in res.stdout
    assert b"NONE" in res.stdout


def test_runner_timeout_kills_process_group(tmp_path: Path):
    res = run_isolated(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        cwd=tmp_path,
        timeout=0.4,
    )
    assert res.timed_out is True
    assert res.returncode == -9


def test_runner_caps_output(tmp_path: Path):
    res = run_isolated(
        [sys.executable, "-c", "print('x' * 100000)"],
        cwd=tmp_path,
        max_output=512,
    )
    assert res.truncated is True
    assert len(res.stdout) == 512


def test_runner_rejects_nul_in_argv(tmp_path: Path):
    import pytest

    from proveit.errors import PolicyViolation

    with pytest.raises(PolicyViolation):
        run_isolated(["echo", "a\x00b"], cwd=tmp_path)
