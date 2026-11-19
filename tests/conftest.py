from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[1]


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="Tester",
        GIT_AUTHOR_EMAIL="tester@example.com",
        GIT_COMMITTER_NAME="Tester",
        GIT_COMMITTER_EMAIL="tester@example.com",
    )
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        env=env,
        capture_output=True,
        check=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q")
    (r / "app.py").write_text(
        "def public_func():\n    return 1\n\ndef helper():\n    return 2\n",
        encoding="utf-8",
    )
    (r / "requirements.txt").write_text("foo==1.0\n", encoding="utf-8")
    (r / "data.json").write_text('{"ok": true}\n', encoding="utf-8")
    (r / "tests").mkdir()
    (r / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert 1 == 1\n", encoding="utf-8"
    )
    (r / "README.md").write_text("demo\n", encoding="utf-8")
    git(r, "add", ".")
    git(r, "-c", "user.name=Tester", "-c", "user.email=tester@example.com",
        "commit", "-q", "-m", "base")
    return r


def cli_env() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(PROJECT)
    env.pop("PROVEIT_DEBUG", None)
    return env


def cli(*args: str, cwd: Path | None = None, timeout: int = 90):
    return subprocess.run(
        [sys.executable, "-m", "proveit", *args],
        cwd=str(cwd or PROJECT),
        env=cli_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


from proveit.context import Context
from proveit.engine import build_context


@pytest.fixture
def ctx_for():
    def make(repo: Path, base: str = "HEAD", trust: bool = False) -> Context:
        return build_context(str(repo), base, trust)

    return make
